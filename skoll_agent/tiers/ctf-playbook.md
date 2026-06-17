# CTF Playbook
# Auto-loads: When analyzing network targets (Phase ANALYZE)
# Token cost: ~500 tokens
# Purpose: Guide LLM to recognize CTF patterns and chain clues

## Common CTF Port-Service Combinations

| Port | Service | What to try | Flag hint |
|------|---------|-------------|-----------|
| 21 | FTP | anonymous login, download files, read hints from files | Files often contain wordlist hints |
| 22 | SSH | hydra brute force, key-based auth, version exploit | Try common creds, look for id_rsa |
| 80/443 | HTTP/HTTPS | gobuster, nikto, view source, check robots.txt | Look for hidden dirs from page titles |
| 139/445 | SMB | enum4linux, smbclient -L, smbmap | Shares often contain flags |
| 2049 | NFS | showmount -e, mount -t nfs | Exported FS often has flag |
| 3306 | MySQL | mysql -h, try root:root | DB might contain flag |
| 5432 | PostgreSQL | psql -h, try postgres:postgres | DB might contain flag |
| 6379 | Redis | redis-cli -h, CONFIG GET * | Sometimes unauthed with flag |
| 27017 | MongoDB | mongo --host | Sometimes unauthed with flag |
| 8080 | HTTP-ALT | tomcat mgr, jenkins, API docs | Default creds, /actuator |

## CTF Attack Chains

### Chain 1: FTP + Web
1. nmap finds FTP(21) + HTTP(80)
2. FTP anonymous → download file → file contains "secret" dir hint
3. gobuster on HTTP with "secret" → finds /secret/flag.txt
4. FLAG

### Chain 2: SMB + Exploit
1. nmap finds SMB(445)
2. smbclient -L → lists share "documents"
3. smbclient //target/documents → download notes.txt
4. notes.txt has password hint → hydra SSH → shell → flag

### Chain 3: Web-Only
1. nmap finds HTTP(80)
2. whatweb → Apache 2.4.29 (vulnerable)
3. gobuster → /robots.txt → /hidden/ → /hidden/notes.txt
4. notes.txt has SQLi creds → sqlmap → dump DB → flag

### Chain 4: All Ports
1. nmap finds FTP(21) + HTTP(80) + SMB(445)
2. FTP anonymous → hint word: "treasure"
3. gobuster with "treasure" → /treasure/ → login page
4. hydra on login → creds → dashboard → flag

## Priority-Based Exploitation Order

### HIGH PRIORITY (try first)
- FTP anonymous login
- SMB null session / guest
- Default credentials on all services
- Web directory bruteforce with small wordlist
- Version-based CVE search

### MEDIUM PRIORITY
- Hydra on SSH/FTP/HTTP-Basic
- SQLmap on forms/params
- Nikto on web servers
- NFS showmount

### LOW PRIORITY
- Full port scan (1-65535)
- Aggressive gobuster with medium wordlist
- Fuzzing

## Flag Patterns to Detect
- `flag{...}`
- `CTF{...}`
- `THM{...}`
- `HTB{...}`
- 32+ character hex/MD5 strings
- Base64-encoded strings (check for padding `=`)

## Common Default Credentials
- admin:admin, admin:password, root:root
- tomcat:tomcat, admin:tomcat
- jenkins:jenkins
- postgres:postgres
- mysql:root (no password)
- ftp:anonymous / ftp:ftp
- administrator:administrator
