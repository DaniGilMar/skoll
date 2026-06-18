from __future__ import annotations

import time
from typing import Any, Callable

from skoll_agent.workers.base_worker import WorkerResult
from skoll_agent.workers.subfinder_worker import SubfinderWorker
from skoll_agent.workers.amass_worker import AmassWorker
from skoll_agent.workers.naabu_worker import NaabuWorker
from skoll_agent.workers.httpx_worker import HttpxWorker
from skoll_agent.workers.katana_worker import KatanaWorker
from skoll_agent.workers.ffuf_worker import FfufWorker
from skoll_agent.workers.nuclei_worker import NucleiWorker

ProgressCallback = Callable[[str, str, float], None]


class WorkflowManager:
    """Orquesta el workflow completo de Ragnarök:

    1. subfinder — descubrimiento de subdominios (DNS)
    2. amass — enumeración ASN/DNS profunda
    3. naabu — escaneo de puertos masivo
    4. httpx — fingerprinting web
    5. katana — crawling profundo
    6. ffuf — fuzzing de endpoints
    7. nuclei — detección de vulnerabilidades
    """

    def __init__(self, progress_callback: ProgressCallback | None = None) -> None:
        self._results: dict[str, WorkerResult] = {}
        self._progress = progress_callback or (lambda *a: None)

    @property
    def results(self) -> dict[str, WorkerResult]:
        return dict(self._results)

    def run_all(self, target: str, **kwargs: Any) -> dict[str, WorkerResult]:
        # Fase 1: Descubrimiento DNS
        self._run_worker("subfinder", SubfinderWorker(), target, kwargs)

        # Fase 2: Enumeración profunda ASN/DNS
        self._run_worker("amass", AmassWorker(), target, {**kwargs, "passive": True})

        # Fase 3: Escaneo de puertos
        naabu_kw = {"top_ports": kwargs.get("top_ports", 100)}
        self._run_worker("naabu", NaabuWorker(), target, naabu_kw)

        # Fase 4: Fingerprinting web (sobre URLs descubiertas o target base)
        urls = self._collect_urls()
        if urls:
            for url in urls:
                self._run_worker("httpx", HttpxWorker(), url, {"tech_detect": True, "status_code": True, "title": True})
        else:
            self._run_worker("httpx", HttpxWorker(), f"http://{target}", {"tech_detect": True, "status_code": True, "title": True})
            self._run_worker("httpx", HttpxWorker(), f"https://{target}", {"tech_detect": True, "status_code": True, "title": True})

        # Fase 5: Crawling profundo
        web_targets = self._collect_web_targets()
        for wt in web_targets:
            self._run_worker("katana", KatanaWorker(), wt, {"depth": kwargs.get("crawl_depth", 2)})

        # Fase 6: Fuzzing de endpoints
        for wt in web_targets:
            wordlist = kwargs.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
            self._run_worker("ffuf", FfufWorker(), wt, {"wordlist": wordlist, "mc": "200,204,301,302,307,401,403,405,500"})

        # Fase 7: Escaneo de vulnerabilidades
        for wt in web_targets:
            self._run_worker("nuclei", NucleiWorker(), wt, {
                "severity": kwargs.get("nuclei_severity", "medium,high,critical"),
                "templates": kwargs.get("nuclei_templates", ""),
            })

        return self._results

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
                    if f.get("type") in ("web", "endpoint", "port"):
                        name = f.get("name", "")
                        if name and ("http" in name or ":80" in name or ":443" in name or ":8080" in name):
                            targets.add(name.split(":")[0] if "://" not in name else name)
        if not targets:
            # Fallback: derivar de las claves de resultados
            for key in self._results:
                if ":http" in key or ":https" in key:
                    targets.add(key.split(":", 1)[1])
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
