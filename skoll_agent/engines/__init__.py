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
