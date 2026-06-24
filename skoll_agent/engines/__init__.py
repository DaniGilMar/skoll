from skoll_agent.engines.registry import register_engine

# SAST
from skoll_agent.engines.bandit_engine import BanditEngine
from skoll_agent.engines.semgrep_engine import SemgrepEngine

# Kali tools
from skoll_agent.engines.nmap_engine import NmapEngine
from skoll_agent.engines.gobuster_engine import GobusterEngine
from skoll_agent.engines.nikto_engine import NiktoEngine
from skoll_agent.engines.sqlmap_engine import SqlmapEngine
from skoll_agent.engines.nuclei_engine import NucleiEngine
from skoll_agent.engines.whatweb_engine import WhatWebEngine
from skoll_agent.engines.hydra_engine import HydraEngine

# Custom CTF engines
from skoll_agent.engines.ftp_engine import FTPEngine
from skoll_agent.engines.smb_engine import SMBEngine
from skoll_agent.engines.flag_engine import FlagEngine

# CVE research
from skoll_agent.engines.cve_engine import CVEEngine

# Fase 2 engines
from skoll_agent.engines.ffuf_engine import FfufEngine
from skoll_agent.engines.masscan_engine import MasscanEngine
from skoll_agent.engines.naabu_engine import NaabuEngine
from skoll_agent.engines.katana_engine import KatanaEngine
from skoll_agent.engines.smbmap_engine import SmbmapEngine
from skoll_agent.engines.db_engines import RedisEngine, MySqlEngine, PostgresEngine
from skoll_agent.engines.davtest_engine import DavtestEngine
from skoll_agent.engines.enum4linux_engine import Enum4linuxEngine
from skoll_agent.engines.cadaver_engine import CadaverEngine
from skoll_agent.engines.msfconsole_engine import MsfconsoleEngine

register_engine("bandit", BanditEngine)
register_engine("semgrep", SemgrepEngine)
register_engine("nmap", NmapEngine)
register_engine("gobuster", GobusterEngine)
register_engine("nikto", NiktoEngine)
register_engine("sqlmap", SqlmapEngine)
register_engine("nuclei", NucleiEngine)
register_engine("whatweb", WhatWebEngine)
register_engine("hydra", HydraEngine)
register_engine("ftp", FTPEngine)
register_engine("smb", SMBEngine)
register_engine("flag", FlagEngine)
register_engine("cve", CVEEngine)
register_engine("ffuf", FfufEngine)
register_engine("masscan", MasscanEngine)
register_engine("naabu", NaabuEngine)
register_engine("katana", KatanaEngine)
register_engine("smbmap", SmbmapEngine)
register_engine("redis", RedisEngine)
register_engine("mysql", MySqlEngine)
register_engine("postgres", PostgresEngine)
register_engine("davtest", DavtestEngine)
register_engine("enum4linux", Enum4linuxEngine)
register_engine("cadaver", CadaverEngine)
register_engine("msfconsole", MsfconsoleEngine)
from skoll_agent.engines.exploit_dispatcher import ExploitDispatcher
register_engine("exploit_dispatcher", ExploitDispatcher)

# Fase 4 — APIs
from skoll_agent.engines.rest_engine import RestEngine
from skoll_agent.engines.graphql_engine import GraphQLEngine
from skoll_agent.engines.jwt_engine import JwtEngine
from skoll_agent.engines.rate_limit_engine import RateLimitEngine
from skoll_agent.engines.authz_engine import AuthzEngine
from skoll_agent.engines.kiterunner_engine import KiterunnerEngine
from skoll_agent.engines.postman_engine import PostmanEngine
from skoll_agent.engines.burpsuite_engine import BurpSuiteEngine
from skoll_agent.engines.caido_engine import CaidoEngine

register_engine("rest", RestEngine)
register_engine("graphql", GraphQLEngine)
register_engine("jwt", JwtEngine)
register_engine("rate_limit", RateLimitEngine)
register_engine("authz", AuthzEngine)
register_engine("kiterunner", KiterunnerEngine)
register_engine("postman", PostmanEngine)
register_engine("burpsuite", BurpSuiteEngine)
register_engine("caido", CaidoEngine)

# Fase 5 — Active Directory
from skoll_agent.engines.ldap_engine import LdapEngine
from skoll_agent.engines.kerberos_engine import KerberosEngine
from skoll_agent.engines.impacket_engine import ImpacketEngine
from skoll_agent.engines.bloodhound_engine import BloodHoundEngine
from skoll_agent.engines.mimikatz_engine import MimikatzEngine
from skoll_agent.engines.rubeus_engine import RubeusEngine

register_engine("ldap", LdapEngine)
register_engine("kerberos", KerberosEngine)
register_engine("impacket", ImpacketEngine)
register_engine("bloodhound", BloodHoundEngine)
register_engine("mimikatz", MimikatzEngine)
register_engine("rubeus", RubeusEngine)

# Fase 6 — Password & Credentials
from skoll_agent.engines.hashcat_engine import HashcatEngine
from skoll_agent.engines.john_engine import JohnEngine
from skoll_agent.engines.spray_engine import SprayEngine

register_engine("hashcat", HashcatEngine)
register_engine("john", JohnEngine)
register_engine("spray", SprayEngine)

# Fase 7 — Cloud Security
from skoll_agent.engines.iam_engine import IamEngine
from skoll_agent.engines.storage_engine import StorageEngine
from skoll_agent.engines.secrets_engine import SecretsEngine
from skoll_agent.engines.k8s_engine import K8sEngine

register_engine("iam", IamEngine)
register_engine("storage", StorageEngine)
register_engine("secrets", SecretsEngine)
register_engine("k8s", K8sEngine)

# Fase 8 — Mobile Security
from skoll_agent.engines.mobsf_engine import MobsfEngine
from skoll_agent.engines.frida_engine import FridaEngine
from skoll_agent.engines.jadx_engine import JadxEngine
from skoll_agent.engines.apk_engine import ApkEngine

register_engine("mobsf", MobsfEngine)
register_engine("frida", FridaEngine)
register_engine("jadx", JadxEngine)
register_engine("apk", ApkEngine)

# Fase 9 — Red Team Simulation
from skoll_agent.engines.sliver_engine import SliverEngine
from skoll_agent.engines.empire_engine import EmpireEngine
from skoll_agent.engines.redteam_engine import RedteamEngine

register_engine("sliver", SliverEngine)
register_engine("empire", EmpireEngine)
register_engine("redteam", RedteamEngine)

# CVE-to-Metasploit bridge
from skoll_agent.engines.cve2msf_engine import CVE2MSFEngine
register_engine("cve2msf", CVE2MSFEngine)

# Ghostcat (CVE-2020-1938) — AJP file read
from skoll_agent.engines.ghostcat_engine import GhostcatEngine
register_engine("ghostcat", GhostcatEngine)

# httpx — web probing / fingerprinting
from skoll_agent.engines.httpx_engine import HttpxEngine
register_engine("httpx", HttpxEngine)

# Ragnarök workflow engine (ProjectDiscovery suite + ffuf)
from skoll_agent.engines.ragnarok_engine import RagnarokEngine
register_engine("ragnarok", RagnarokEngine)

# Fase 11 — Reporting
from skoll_agent.engines.reporting_engine import ReportingEngine
register_engine("reporting", ReportingEngine)
