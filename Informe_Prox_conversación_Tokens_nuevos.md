# Skoll — Resumen de Sesión para Continuar

## Estado Actual (24 Jun 2026)

**Proyecto:** Skoll — Framework de pentesting autónomo
**Branch:** Ragnarök
**Directorio:** `/home/dani/Documentos/skoll/`
**Web:** `python3 -m skoll.main web --port 8080`

---

## Arquitectura Actual

Pipeline 4 fases: **RECON → ANALYZE → EXPLOIT → REPORT**

```
RECON:   naabu (top 1000) → masscan/nmap fallback
         Encuentra puertos abiertos, guarda en StateStore
         
ANALYZE: nmap -sV (service scan) + httpx + katana + hydra + smb/ftp/ssh según service_map
         Clasifica servicios y versiones
         
EXPLOIT: NUEVO → FindingClassifier + YAML strategies + legacy nuclei/cve2msf
         Clasifica findings por tipo de vulnerabilidad (no por servicio)
         Busca estrategias en config/strategies.yaml
         
REPORT:  Genera markdown + HTML en ~/.skoll/reports/
```

---

## Archivos Modificados/ Creados en esta Sesión

### Creados:
```
skoll_agent/exploit/finding_classifier.py   — Clasifica findings por keywords → tipo vuln
skoll_agent/exploit/strategy_loader.py       — Carga strategies.yaml, filtra por prerequisites
skoll_agent/engines/ghostcat_engine.py       — Ghostcat raw AJP (no usado, msfconsole mejor)
config/strategies.yaml                       — Estrategias YAML: SMB, GHOSTCAT, SQLi, WEB, RCE
SESSION_SUMMARY.md                           — Este archivo
```

### Modificados:
```
skoll_agent/engines/smb_engine.py            — REWRITE: parser SMB corregido (ya no captura headers como shares)
                                           — Añadido action="download": descarga archivos vía smbclient get
                                           — Encuentra share "Anonymous" correctamente
                                           
skoll_agent/engines/smbmap_engine.py         — Default user cambiado de "guest" a "" (NULL session)
                                           -R eliminado (no soportado en v1.10.7)

skoll_agent/engines/msfconsole_engine.py     — Ghostcat: captura loot files de msfconsole desde disco
                                           — Añadido _detect_creds_in_content (passwords, usernames, Tomcat creds)
                                           — Añadido servicio ajp13/tomcat con módulo ghostcat
                                           — success=True siempre (no se silencia si 0 findings)

skoll_agent/engines/hydra_engine.py          — Timeout reducido de 600s → 60s
skoll_agent/engines/katana_engine.py         — Timeout reducido de 120s → 30s

skoll_agent/pipeline/adaptive_router.py      — _route_exploit: YAML-driven (FindingClassifier + StrategyLoader)
                                           — _route_analyze: añadido nmap -sV sistemático
                                           — Timeout nmap analyze reducido 180→90s

skoll_agent/pipeline/orchestrator.py         — _filter_plan: ahora soporta engines sin binario (reporting, ghostcat)
                                           — _run_tool: solo loggea warning si hay error real (no vacío)
                                           — StateStore: pasa session_id para evitar acumulación entre runs
                                           — Eliminado doble append de findings (context + direct)

skoll_agent/pipeline/state_store.py          — Añadido session_id a la ruta: state/<hash>/<session_id>/
                                           — Ya no acumula findings entre ejecuciones

skoll_agent/utils/dependency_checker.py      — Añadidos: smb, smbmap, enum4linux, msfconsole, cve2msf, 
                                           exploit_dispatcher, reporting, ghostcat a REQUIRED_TOOLS
                                           — Añadidos TOOL_ALIASES para smb→smbclient, etc.

skoll_agent/engines/service_map.py           — PORT_MAP ampliado: 80, 443, 8080, 8443, 139, 445
skoll_agent/engines/__init__.py              — Registrado ghostcat engine
skoll_agent/engines/naabu_engine.py          — Dedup por (ip, port, protocol) set
```

---

## Problemas Resueltos

| # | Problema | Solución |
|---|----------|----------|
| 1 | Findings duplicados (217 en vez de 17) | session_id en StateStore path + eliminar doble append |
| 2 | SMB parser roto (share headers como "Sharename") | Nuevo parser con detección de tabla + stop en post-list noise |
| 3 | smbmap no encuentra shares (guest user) | Default user cambiado a "" (NULL session) |
| 4 | smbmap flag -R no soportada | Eliminada, usa --depth |
| 5 | smb, smbmap, enum4linux no disponibles en pipeline | Añadidos a REQUIRED_TOOLS + TOOL_ALIASES |
| 6 | msfconsole findings silenciados | success=True siempre |
| 7 | Warnings vacíos (⚠️ smbmap:) solo loggea si hay error real |
| 8 | hydra timeout 600s → 60s | timeouts reducidos |
| 9 | katana timeout 120s → 30s | timeouts reducidos |
| 10 | Pipeline 500s+ → 200s | timeouts + nmap analyze 180→90 |

---

## Lo que QUEDA PENDIENTE (ordenado)

### 1. *** Probar Ghostcat contra máquina con AJP real
```
- El código está listo (msfconsole + loot capture)
- Probar contra máquina THM con AJP abierto
- Verificar que lee web.xml y /etc/passwd
- Verificar que extrae credenciales de tomcat-users.xml
```

### 2. *** Probar SMB download contra máquina con SMB real
```
- El código smb_engine con action="download" está listo
- Probar contra máquina THM con SMB + share Anonymous
- Verificar que descarga archivos y detecta flags
```

### 3. ** Implementar RCE chain (Ghostcat → credenciales → WAR deploy)
```
- Si Ghostcat lee tomcat-users.xml con credenciales de manager
- Deploy automático de WAR maliciosa
- Listener nc → shell
```

### 4. ** Paralelizar tools dentro de cada fase
```
- Actualmente las tools se ejecutan secuencialmente
- Ejecutar en paralelo con asyncio + timeouts individuales
- reduciría tiempo de 200s a ~60s
```

### 5. * Añadir más estrategias YAML
```
- FTP anonymous → descargar archivos
- SSH con credenciales → conexión directa
- Web con SQLi → sqlmap automático
```

### 6. * Probar con máquinas reales (no solo THM)
```
- HTB, vulnhub, entornos reales
- Verificar que la arquitectura YAML escala
```

---

## Comandos Útiles

```bash
# Iniciar web
cd /home/dani/Documentos/skoll
python3 -m skoll.main web --port 8080

# Pipeline directo
python3 -m skoll.main pipeline <IP> --network --verbose

# Ver reportes
ls ~/.skoll/reports/

# Ver estado
ls ~/.skoll/state/<hash>/
```

---

## Target Anterior

**10.128.151.215** (antigua THM): Puertos 22, 80, 139, 445, 8009, 8080
**10.128.153.225** (nueva THM): Puertos 21, 22, 80
**10.128.188.30**: Puerto 80 con Apache 2.4.41

---

## Notas Técnicas

- SMB: La máquina anterior tenía `Anonymous` share con READ ONLY via NULL session
- Ghostcat: msfconsole da "Unable to read file" PERO también "File contents save to" con loot path (aunque el loot está vacío si no es vulnerable). Si el target es vulnerable, el loot TIENE contenido.
- El finding classifier prioriza SMB_ANONYMOUS_ACCESS si el título contiene "SMB"
- Las estrategias YAML se cargan una vez (caching en strategy_loader)
- Para NO perder el finding original al clasificar, classify_findings devuelve (vuln_type, confidence, original_finding)

---

## Para Continuar

1. Conseguir máquina THM con SMB + AJP
2. Ejecutar pipeline contra ella con `session_id='cont'`
3. Verificar que ghostcat lee archivos (msfconsole loot)
4. Verificar que SMB descarga archivos (smb action=download)
5. Reportar resultados
