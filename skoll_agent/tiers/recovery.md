# Recovery Guidance
# Auto-loads: When a phase fails or errors occur
# Token cost: ~400 tokens
# Purpose: Diagnose failures and decide whether to retry, skip, or abort

## Error Classification

| Error Pattern | Likely Cause | Recovery Action |
|---------------|-------------|-----------------|
| `Connection refused` | Service not running / wrong port | Skip this service, continue with others |
| `Connection timed out` | Firewall / host down | Skip, note as filtered |
| `Name or service not known` | DNS resolution failed | Try IP directly, check target name |
| `Permission denied` | Missing sudo / tool not installed | Log error, skip tool |
| `No route to host` | Network unreachable | Abort pipeline |
| `Tool not found` | Tool not installed | Log warning, skip tool |
| `Timeout expired` | Tool took too long | Use partial results, skip remaining |
| `Rate limited` | Too many requests | Wait and retry |
| `Authentication failed` | Bad API key / creds | Check credentials, try alternative |
| `Invalid target` | Target malformed | Skip, flag for manual review |

## Per-Phase Recovery

### RECON — nmap/whatweb fail
```
Problem: nmap failed → no ports discovered
Recovery: Check network connectivity first.
  - ping target → if fails, abort pipeline
  - Try nmap with -Pn (skip host discovery) → ports might still be found
  - Try different ports if specific ports fail
If nmap produces NO results after fallback: abort (nothing to test)
```

### ENUM — gobuster/nikto/ftp/smb fail
```
Problem: Tool fails on a specific service
Recovery: 
  - Single tool failure → log error, continue with next tool
  - All tools fail → check recon phase output, maybe wrong target
  - FTP/SMB fail → skip web-only tools, continue to exploit
IF at least one tool succeeded: continue
IF all tools failed: mark phase as skipped, continue with whatever findings exist
```

### VALIDATE — no findings
```
Problem: No findings discovered
Recovery: 
  - Check if recon phase had results
  - If recon had results but enum found nothing → likely hardened target
  - If recon had no results → target may be down or firewalled
Action: Continue to analyze with what we have, note as "no vulnerabilities found"
```

### ANALYZE — LLM failure
```
Problem: LLM API error, timeout, or invalid response
Recovery:
  - Retry once with fast model (llama-3.1-8b-instant)
  - If still fails: skip analysis, generate basic report from raw findings
  - Try alternative model (qwen-3-32b)
NEVER abort on LLM failure — raw tool output is still valuable
```

### EXPLOIT — hydra/sqlmap fail
```
Problem: Exploitation tools find nothing or fail
Recovery:
  - Check if service even supports the tool (e.g., sqlnap on non-SQL service)
  - If hydra fails due to lockout/rate limit → note for report, don't retry
  - If sqlmap fails → try manual parameters, skip if blind injection unlikely
  - If all exploitation fails → the finding is still valid (vulnerable version, misconfiguration)
Action: Document failed attempts as evidence of security control effectiveness
```

### CHAIN — LLM failure
```
Problem: Cross-finding analysis fails
Recovery:
  - Fall back to deterministic chain (flag detection only)
  - Group findings by tool/service programmatically
  - Generate report without LLM analysis
```

---

## Decision Matrix

| Scenario | Action |
|----------|--------|
| Single phase fails | Skip phase, continue pipeline |
| RECON fails completely | Abort (nothing to test) |
| All subsequent phases fail | Still complete with what RECON found |
| LLM fails 2 attempts | Skip LLM phases, report raw findings |
| Tool fails on port N | Skip port N, continue with port N+1 |
| Network down mid-pipeline | Abort, save partial state for resume |

## Golden Rule
**Partial results are better than no results.**
Never abort unless RECON fails completely — every tool output has value, even errors.
