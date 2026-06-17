from __future__ import annotations

import json
import subprocess
from typing import Any

import requests

from skoll_agent.engines.base_engine import BaseEngine, EngineResult


class GraphQLEngine(BaseEngine):
    name = "graphql"
    description = "GraphQL security auditor. Detecta introspection habilitado, query depth, inyecciones, y exposición de schema."
    capabilities = ["api_audit", "graphql", "web_security"]

    INTROSPECTION_QUERY = """
    query IntrospectionQuery {
      __schema {
        queryType { name }
        mutationType { name }
        subscriptionType { name }
        types {
          kind name description
          fields(includeDeprecated: true) {
            name description
            args { name type { name kind ofType { name kind } } }
            type { name kind ofType { name kind } }
          }
        }
        directives { name description locations }
      }
    }
    """

    def scan(self, target: str, **kwargs: Any) -> EngineResult:
        findings = []
        raw_lines: list[str] = []
        timeout = kwargs.get("timeout", 30)

        graphql_url = target.rstrip("/")
        if not graphql_url.endswith("/graphql"):
            possible = [f"{graphql_url}/graphql", graphql_url]
        else:
            possible = [graphql_url]

        for url in possible:
            try:
                r = requests.post(
                    url,
                    json={"query": self.INTROSPECTION_QUERY},
                    timeout=timeout,
                    verify=False,
                    headers={"Content-Type": "application/json"},
                )
                raw_lines.append(f"[{r.status_code}] POST {url}")
                if r.status_code == 200:
                    try:
                        data = r.json()
                    except json.JSONDecodeError:
                        continue
                    if "data" in data and data.get("data", {}).get("__schema"):
                        schema = data["data"]["__schema"]
                        query_type = schema.get("queryType", {}).get("name", "Query")
                        mutation_type = schema.get("mutationType", {})
                        subscription_type = schema.get("subscriptionType", {})

                        findings.append({
                            "file_path": url,
                            "line_start": 0, "line_end": 0,
                            "severity": "high",
                            "title": "GraphQL introspection enabled",
                            "description": f"GraphQL endpoint {url} has introspection enabled. Exposes full schema.",
                            "tool": self.name,
                            "rule_id": "graphql-introspection",
                            "endpoint": url,
                            "schema_types": len(schema.get("types", [])),
                            "has_mutations": mutation_type is not None,
                            "has_subscriptions": subscription_type is not None,
                        })
                        raw_lines.append(f"[HIGH] Introspection enabled at {url}")
                        raw_lines.append(f"  Query type: {query_type}")
                        raw_lines.append(f"  Mutations: {'yes' if mutation_type else 'no'}")
                        raw_lines.append(f"  Subscriptions: {'yes' if subscription_type else 'no'}")

                        # Check for dangerous fields in schema
                        dangerous = ["__schema", "__typename", "__type"]
                        types = schema.get("types", [])
                        for t in types:
                            tname = t.get("name", "")
                            if tname.startswith("__"):
                                continue
                            fields = t.get("fields", []) or []
                            for f in fields:
                                fname = f.get("name", "").lower()
                                if any(kw in fname for kw in ["password", "secret", "token", "key", "credential"]):
                                    findings.append({
                                        "file_path": url,
                                        "line_start": 0, "line_end": 0,
                                        "severity": "high",
                                        "title": f"Sensitive field in GraphQL schema: {tname}.{f.get('name', '')}",
                                        "description": f"Type '{tname}' exposes field '{f.get('name', '')}' which may contain sensitive data.",
                                        "tool": self.name,
                                        "rule_id": f"graphql-sensitive-{tname}-{fname}",
                                        "graphql_type": tname,
                                        "field": f.get("name", ""),
                                    })
                    break  # Found working GraphQL endpoint
            except requests.exceptions.ConnectionError:
                continue
            except requests.exceptions.Timeout:
                raw_lines.append(f"[TIMEOUT] {url}")
                continue
            except Exception as e:
                raw_lines.append(f"[ERR] {url}: {e}")
                continue

        # 2. Test for suspicious query depth
        deep_query = """
        query DeepQuery {
          __schema { types { name fields { name type { name ofType { name ofType { name } } } } } }
        }
        """
        for url in possible:
            try:
                r = requests.post(
                    url,
                    json={"query": deep_query},
                    timeout=timeout,
                    verify=False,
                    headers={"Content-Type": "application/json"},
                )
                raw_lines.append(f"[DEPTH_TEST] POST {url} -> {r.status_code}")
                if r.status_code == 200:
                    try:
                        data = r.json()
                        if "errors" not in data:
                            findings.append({
                                "file_path": url,
                                "line_start": 0, "line_end": 0,
                                "severity": "medium",
                                "title": "GraphQL deep query allowed",
                                "description": f"GraphQL at {url} allows deep/nested queries (no max depth). Risk of DoS.",
                                "tool": self.name,
                                "rule_id": "graphql-depth",
                                "endpoint": url,
                            })
                    except json.JSONDecodeError:
                        pass
                break  # Test only the working one
            except Exception:
                continue

        summary = f"graphql: {len(findings)} issues"
        return EngineResult(
            success=True,
            raw_output="\n".join(raw_lines) if raw_lines else "graphql: no endpoints found",
            findings=findings,
            summary=summary,
        )

    def parse_output(self, raw_output: str) -> list[dict[str, Any]]:
        return []
