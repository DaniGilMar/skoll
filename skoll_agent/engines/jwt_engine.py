from __future__ import annotations

import base64
import json
import subprocess
from typing import Any

import requests

from skoll_agent.engines.base_engine import BaseEngine, EngineResult


class JwtEngine(BaseEngine):
    name = "jwt"
    description = "JWT security auditor. Analiza tokens JWT, verifica firma, detecta alg=none, expiración débil, y claims inseguros."
    capabilities = ["api_audit", "jwt", "authentication"]

    COMMON_TOOL_ARGS = {
        "jwt_tool": ["jwt_tool", "-v"],
        "jwtcrack": ["jwtcrack"],
    }

    def scan(self, target: str, **kwargs: Any) -> EngineResult:
        findings = []
        raw_lines: list[str] = []
        token = kwargs.get("token", target)  # target can be a JWT string or URL

        # If target looks like a URL, try to extract JWT from auth headers
        if target.startswith(("http://", "https://")):
            extracted = self._extract_jwt_from_url(target, kwargs.get("timeout", 30))
            if extracted:
                raw_lines.append(f"[INFO] Extracted JWT from {target}")
                for t in extracted:
                    findings.append(t)
            else:
                return EngineResult(
                    success=True,
                    raw_output="jwt: no JWT found in response",
                    summary="jwt: no JWT found",
                )
            token = extracted[0].get("token", "") if extracted else ""

        if not token:
            return EngineResult(
                success=True,
                raw_output="jwt: no token provided",
                summary="jwt: no token to analyze",
            )

        # 1. Decode JWT (inspect header and payload)
        parts = token.split(".")
        if len(parts) != 3:
            findings.append({
                "file_path": "",
                "line_start": 0, "line_end": 0,
                "severity": "high",
                "title": "Invalid JWT format",
                "description": f"Token has {len(parts)} parts (expected 3). Not a valid JWT.",
                "tool": self.name,
                "rule_id": "jwt-invalid-format",
            })
            return EngineResult(
                success=True,
                raw_output="jwt: invalid format",
                findings=findings,
                summary="jwt: invalid format",
            )

        header_b64, payload_b64, signature_b64 = parts

        def _decode_b64(b64_str: str) -> dict[str, Any] | None:
            try:
                padded = b64_str + "=" * (4 - len(b64_str) % 4) if len(b64_str) % 4 else b64_str
                return json.loads(base64.urlsafe_b64decode(padded))
            except Exception:
                return None

        header = _decode_b64(header_b64)
        payload = _decode_b64(payload_b64)

        raw_lines.append(f"[INFO] JWT header: {json.dumps(header)}")
        raw_lines.append(f"[INFO] JWT payload: {json.dumps(payload)}")

        # 2. Check alg=none
        if header and header.get("alg", "").lower() == "none":
            findings.append({
                "file_path": "",
                "line_start": 0, "line_end": 0,
                "severity": "critical",
                "title": "JWT alg=none vulnerability",
                "description": "JWT uses alg=none. Attacker can forge arbitrary tokens without signature.",
                "tool": self.name,
                "rule_id": "jwt-alg-none",
            })

        # 3. Check weak algorithms
        if header:
            alg = header.get("alg", "").lower()
            weak_algs = ["none", "hs256", "hs384", "hs512"]
            if alg == "none":
                pass  # Already flagged
            elif alg.startswith("hs") or alg in weak_algs:
                findings.append({
                    "file_path": "",
                    "line_start": 0, "line_end": 0,
                    "severity": "medium",
                    "title": f"JWT uses symmetric algorithm: {header['alg']}",
                    "description": f"JWT uses {header['alg']} which is symmetric. If secret is weak, tokens can be forged.",
                    "tool": self.name,
                    "rule_id": f"jwt-alg-{alg}",
                })

        # 4. Check for empty signature
        if not signature_b64.strip() or signature_b64.strip() == "":
            findings.append({
                "file_path": "",
                "line_start": 0, "line_end": 0,
                "severity": "critical",
                "title": "JWT empty signature",
                "description": "JWT has an empty signature. Token can be easily forged.",
                "tool": self.name,
                "rule_id": "jwt-empty-signature",
            })

        # 5. Check payload security
        if payload:
            now_ts = __import__("time").time()

            # Expiration
            exp = payload.get("exp")
            if exp is None:
                findings.append({
                    "file_path": "",
                    "line_start": 0, "line_end": 0,
                    "severity": "medium",
                    "title": "JWT missing expiration (exp)",
                    "description": "JWT has no expiration claim. Token is valid indefinitely.",
                    "tool": self.name,
                    "rule_id": "jwt-no-exp",
                })
            elif isinstance(exp, (int, float)) and exp > now_ts + 86400 * 7:
                findings.append({
                    "file_path": "",
                    "line_start": 0, "line_end": 0,
                    "severity": "low",
                    "title": "JWT expiration too long",
                    "description": f"JWT exp claim is {exp - now_ts:.0f}s from now (>7 days). Long-lived tokens increase risk.",
                    "tool": self.name,
                    "rule_id": "jwt-long-exp",
                })

            # Issuer not set
            if "iss" not in payload:
                findings.append({
                    "file_path": "",
                    "line_start": 0, "line_end": 0,
                    "severity": "low",
                    "title": "JWT missing issuer (iss)",
                    "description": "JWT has no iss claim. Cannot verify token origin.",
                    "tool": self.name,
                    "rule_id": "jwt-no-iss",
                })

            # Sensitive data in payload
            sensitive_keys = ["password", "secret", "api_key", "token", "key", "credential", "passwd"]
            for key in payload:
                if any(sk in key.lower() for sk in sensitive_keys):
                    findings.append({
                        "file_path": "",
                        "line_start": 0, "line_end": 0,
                        "severity": "high",
                        "title": f"Sensitive data in JWT payload: {key}",
                        "description": f"JWT payload contains '{key}' which may expose sensitive information.",
                        "tool": self.name,
                        "rule_id": f"jwt-sensitive-{key.lower()}",
                    })

            # Weak subject
            if payload.get("sub") in ("admin", "root", "superuser", "anonymous"):
                findings.append({
                    "file_path": "",
                    "line_start": 0, "line_end": 0,
                    "severity": "medium",
                    "title": f"Suspicious JWT subject: {payload.get('sub')}",
                    "description": f"JWT sub claim is '{payload.get('sub')}'. May indicate hardcoded or over-privileged accounts.",
                    "tool": self.name,
                    "rule_id": "jwt-suspicious-sub",
                })

        # 6. Try common secret keys (algorithm confusion test)
        if header and header.get("alg", "").lower() in ("hs256", "hs384", "hs512"):
            common_secrets = ["secret", "password", "123456", "admin", "key", "changeme", "pass", "token", "jwt_secret"]
            for secret in common_secrets:
                try:
                    import hmac, hashlib

                    def _sign_hs(alg: str, msg: str, secret: str) -> str:
                        alg_map = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
                        h = hmac.new(secret.encode(), msg.encode(), alg_map.get(alg.upper(), hashlib.sha256))
                        return base64.urlsafe_b64encode(h.digest()).rstrip("=").decode()

                    msg = f"{header_b64}.{payload_b64}"
                    candidate = _sign_hs(header["alg"], msg, secret)
                    if candidate == signature_b64.rstrip("="):
                        findings.append({
                            "file_path": "",
                            "line_start": 0, "line_end": 0,
                            "severity": "critical",
                            "title": f"JWT weak secret key cracked: '{secret}'",
                            "description": f"JWT HMAC secret is the common password '{secret}'. Token can be forged.",
                            "tool": self.name,
                            "rule_id": "jwt-weak-secret",
                            "cracked_secret": secret,
                        })
                        raw_lines.append(f"[CRITICAL] JWT secret cracked: '{secret}'")
                        break
                except Exception:
                    continue

                # Try alg=none bypass
                try:
                    modified_header = base64.urlsafe_b64encode(
                        json.dumps({"alg": "none", "typ": "JWT"}).encode()
                    ).rstrip("=").decode()
                    modified_token = f"{modified_header}.{payload_b64}."
                    # Could test against endpoint
                except Exception:
                    pass

        summary = f"jwt: {len(findings)} issues in token"
        return EngineResult(
            success=True,
            raw_output="\n".join(raw_lines),
            findings=findings,
            summary=summary,
        )

    def _extract_jwt_from_url(self, url: str, timeout: int = 30) -> list[dict[str, Any]]:
        findings = []
        try:
            r = requests.get(url, timeout=timeout, verify=False)
            auth_header = r.headers.get("Authorization", "")
            if auth_header.lower().startswith("bearer "):
                token = auth_header[7:]
                findings.append({
                    "file_path": url,
                    "line_start": 0, "line_end": 0,
                    "severity": "info",
                    "title": "JWT extracted from Authorization header",
                    "description": f"Bearer token found in Authorization header for {url}",
                    "tool": self.name,
                    "rule_id": "jwt-extracted",
                    "token": token,
                })
            # Check cookies
            set_cookie = r.headers.get("Set-Cookie", "")
            if "jwt" in set_cookie.lower() or "token" in set_cookie.lower():
                findings.append({
                    "file_path": url,
                    "line_start": 0, "line_end": 0,
                    "severity": "info",
                    "title": "JWT found in cookie",
                    "description": f"Set-Cookie header contains JWT/token: {set_cookie[:200]}",
                    "tool": self.name,
                    "rule_id": "jwt-in-cookie",
                })
            return findings
        except Exception:
            return []

    def parse_output(self, raw_output: str) -> list[dict[str, Any]]:
        return []
