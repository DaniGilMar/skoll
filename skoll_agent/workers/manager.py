from __future__ import annotations

import time
from typing import Any, Callable

from skoll_agent.sandbox.human_in_loop import HumanInLoop
from skoll_agent.engines.credential_manager import COMMON_CREDENTIALS, brute_force_login, detect_login_forms, _fetch_page
from skoll_agent.workers.base_worker import WorkerResult
from skoll_agent.workers.subfinder_worker import SubfinderWorker
from skoll_agent.workers.amass_worker import AmassWorker
from skoll_agent.workers.naabu_worker import NaabuWorker
from skoll_agent.workers.httpx_worker import HttpxWorker
from skoll_agent.workers.katana_worker import KatanaWorker
from skoll_agent.workers.ffuf_worker import FfufWorker
from skoll_agent.workers.nuclei_worker import NucleiWorker
from skoll_agent.workers.nmap_worker import NmapWorker
from skoll_agent.workers.gobuster_worker import GobusterWorker

ProgressCallback = Callable[[str, str, float], None]


class WorkflowManager:
    """Orquesta el workflow completo de Ragnarök:

    1. subfinder — descubrimiento de subdominios (DNS)
    2. amass — enumeración ASN/DNS profunda
    3. naabu — escaneo de puertos masivo
    4. httpx — fingerprinting web
    5. credential check — detección de login + ask/brute-force
    6. katana — crawling profundo
    7. ffuf — fuzzing de endpoints
    8. nuclei — detección de vulnerabilidades
    """

    def __init__(self, progress_callback: ProgressCallback | None = None) -> None:
        self._results: dict[str, WorkerResult] = {}
        self._credentials: dict[str, dict[str, str]] = {}
        self._progress = progress_callback or (lambda *a: None)

    @property
    def results(self) -> dict[str, WorkerResult]:
        return dict(self._results)

    def run_all(self, target: str, event_queue: Any = None, session_id: str | None = None, skip_credentials: bool = False, **kwargs: Any) -> dict[str, WorkerResult]:
        # Fase 1: Descubrimiento DNS
        self._run_worker("subfinder", SubfinderWorker(), target, kwargs)

        # Fase 2: Enumeración profunda ASN/DNS
        self._run_worker("amass", AmassWorker(), target, {**kwargs, "passive": True})

        # Fase 3: Escaneo de puertos — naabu prioritario, nmap como fallback
        naabu_kw = {"top_ports": kwargs.get("top_ports", 100)}
        self._run_worker("naabu", NaabuWorker(), target, naabu_kw)
        naabu_result = self._results.get(f"naabu:{target}", WorkerResult(tool_name="naabu", target=target, success=False))
        if not naabu_result.success or len(naabu_result.findings) == 0:
            nmap_msg = "naabu no encontró puertos → fallback a nmap"
            if event_queue:
                event_queue.put({"type": "log", "data": {"message": nmap_msg}})
            nmap_ports = kwargs.get("nmap_ports", "80,443,8080,8443,22,21,5432,3306,27017,6379,9200,5000,9090")
            self._run_worker("nmap", NmapWorker(), target, {"ports": nmap_ports, "timeout": kwargs.get("nmap_timeout", 300)})

        # Fase 4: Fingerprinting web (sobre URLs descubiertas o target base)
        urls = self._collect_urls()
        if urls:
            for url in urls:
                self._run_worker("httpx", HttpxWorker(), url, {"tech_detect": True, "status_code": True, "title": True})
        else:
            self._run_worker("httpx", HttpxWorker(), f"http://{target}", {"tech_detect": True, "status_code": True, "title": True})
            self._run_worker("httpx", HttpxWorker(), f"https://{target}", {"tech_detect": True, "status_code": True, "title": True})

        # Fase 5: Detección de credenciales + brute-force
        web_targets = self._collect_web_targets()
        if not skip_credentials:
            creds_kwargs = {
                "event_queue": event_queue,
                "session_id": session_id,
                "timeout": kwargs.get("creds_timeout", 300),
                "skip_brute": kwargs.get("skip_brute", False),
            }
            self._check_web_credentials(web_targets, **creds_kwargs)

        # Fase 6: Crawling profundo — katana prioritario, gobuster como fallback
        for wt in web_targets:
            self._run_worker("katana", KatanaWorker(), wt, {"depth": kwargs.get("crawl_depth", 2)})
            katana_key = f"katana:{wt}"
            k_result = self._results.get(katana_key, WorkerResult(tool_name="katana", target=wt, success=False))
            if not k_result.success or len(k_result.findings) == 0:
                gb_msg = f"katana no encontró endpoints en {wt} → fallback a gobuster"
                if event_queue:
                    event_queue.put({"type": "log", "data": {"message": gb_msg}})
                self._run_worker("gobuster", GobusterWorker(), wt, {
                    "wordlist": kwargs.get("wordlist", "/usr/share/wordlists/dirb/common.txt"),
                    "timeout": kwargs.get("gobuster_timeout", 120),
                    "threads": kwargs.get("gobuster_threads", 20),
                })

        # Fase 7: Fuzzing de endpoints
        for wt in web_targets:
            wordlist = kwargs.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
            self._run_worker("ffuf", FfufWorker(), wt, {"wordlist": wordlist, "mc": "200,204,301,302,307,401,403,405,500"})

        # Fase 8: Escaneo de vulnerabilidades
        for wt in web_targets:
            self._run_worker("nuclei", NucleiWorker(), wt, {
                "severity": kwargs.get("nuclei_severity", "medium,high,critical"),
                "templates": kwargs.get("nuclei_templates", ""),
            })

        return self._results

    def _check_web_credentials(
        self,
        web_targets: list[str],
        event_queue: Any = None,
        session_id: str | None = None,
        timeout: int = 300,
        skip_brute: bool = False,
    ) -> None:
        """Detecta formularios de login en servicios web, pregunta usuario o brute-forcea."""
        for wt in web_targets:
            if wt in self._credentials:
                continue
            try:
                html = _fetch_page(wt, timeout=10)
            except Exception:
                continue

            forms = detect_login_forms(wt, html)
            if not forms:
                continue

            form = forms[0]
            self._progress("credentials", wt, 0.0)
            log_msg = f"Login detectado en {wt} — form action: {form.action}"
            if event_queue:
                event_queue.put({"type": "log", "data": {"message": log_msg}})

            hil = HumanInLoop(enabled=True)
            creds = hil.ask_credentials(wt, form.action, event_queue=event_queue, session_id=session_id, timeout=timeout)

            if creds:
                self._credentials[wt] = creds
                msg = f"Credenciales obtenidas para {wt}: {creds['username']}"
                if event_queue:
                    event_queue.put({"type": "log", "data": {"message": msg}})
                continue

            # Fallback: brute-force
            if skip_brute:
                if event_queue:
                    event_queue.put({"type": "log", "data": {"message": f"Brute-force omitido para {wt}"}})
                continue

            brute_msg = f"Iniciando brute-force contra {form.action} (diccionario: {len(COMMON_CREDENTIALS)} pares)"
            if event_queue:
                event_queue.put({"type": "log", "data": {"message": brute_msg}})

            found = brute_force_login(form, timeout=5)
            if found:
                self._credentials[wt] = {"username": found["username"], "password": found["password"]}
                if event_queue:
                    event_queue.put({"type": "log", "data": {
                        "message": f"Brute-force exitoso en {wt}: {found['username']}:{found['password']}",
                    }})
            else:
                if event_queue:
                    event_queue.put({"type": "log", "data": {"message": f"Brute-force fallido en {wt} — no se encontraron credenciales"}})

    def _run_worker(self, name: str, worker: Any, target: str, kwargs: dict[str, Any]) -> None:
        self._progress(name, target, 0.0)
        start = time.time()
        result = worker.run(target, **kwargs)
        elapsed = time.time() - start
        self._results[f"{name}:{target}"] = result
        self._progress(name, target, elapsed)

    def _collect_urls(self) -> list[str]:
        urls: set[str] = set()
        for key, res in self._results.items():
            if res.success:
                for f in res.findings:
                    host = f.get("name", "")
                    if host and ("." in host or "://" in host):
                        if not host.startswith("http"):
                            host = f"http://{host}"
                        urls.add(host)
        return sorted(urls)

    def _collect_web_targets(self) -> list[str]:
        targets: set[str] = set()
        for key, res in self._results.items():
            if res.success:
                for f in res.findings:
                    ftype = f.get("type", "")
                    name = f.get("name", "")
                    if ftype == "port":
                        # name format: "IP:port" from naabu/nmap
                        port = f.get("data", {}).get("port") or (name.split(":")[-1] if ":" in name else "80")
                        ip = name.split(":")[0] if ":" in name else name
                        if port in (80, 443, 8080, 8443, 3000, 5000, 8000, 8888, 9090, 9443):
                            targets.add(f"http://{ip}:{port}")
                            if port in (443, 8443, 9443):
                                targets.add(f"https://{ip}:{port}")
                    elif ftype in ("web", "endpoint"):
                        # name is already a URL
                        if "://" not in name:
                            name = f"http://{name}"
                        targets.add(name)
        if not targets:
            # Fallback: derivar de las claves de resultados httpx
            for key in self._results:
                if ":http" in key or ":https" in key:
                    targets.add(key.split(":", 1)[1])
        # Fallback final: target base con puertos web comunes
        if not targets:
            base = list(self._results.keys())[0].split(":", 1)[-1] if self._results else ""
            if base and not base.startswith("http"):
                for p in ("80", "443", "8080", "8443"):
                    targets.add(f"http://{base}:{p}")
                    if p in ("443", "8443"):
                        targets.add(f"https://{base}:{p}")
        return sorted(targets)

    def summary(self) -> dict[str, Any]:
        total = len(self._results)
        success = sum(1 for r in self._results.values() if r.success)
        total_findings = sum(len(r.findings) for r in self._results.values())
        return {
            "total_workers": total,
            "successful": success,
            "failed": total - success,
            "total_findings": total_findings,
            "duration": sum(r.duration for r in self._results.values()),
            "workers": {
                k: {"success": r.success, "findings": len(r.findings), "duration": round(r.duration, 2), "error": r.error[:100] if r.error else ""}
                for k, r in self._results.items()
            },
        }

    def to_structured(self) -> dict[str, Any]:
        workers_data = {}
        for key, res in self._results.items():
            wname = key.split(":", 1)[0]
            workers_data.setdefault(wname, [])
            workers_data[wname].append(res.to_dict())
        return {
            "target": list(self._results.keys())[0].split(":", 1)[-1] if self._results else "",
            "workflow_summary": self.summary(),
            "workers": workers_data,
        }
