"""Kali tool registry, conservative risk levels, and nmap XML parsing.

Risk levels (decide how much confirmation a command needs):
  local      local analysis (searchsploit, hashid)
  recon      light identification (nmap -sV, whatweb, curl, dig)
  active     broader enumeration (ffuf, full-port nmap)
  intrusive  state-changing or high-impact work; Nuclei is conservative intrusive

Policy decides approval; ask mode confirms even local commands.
JobManager is the only native tool execution implementation.
"""
import os
import re
import shutil
import xml.etree.ElementTree as ET
from dataclasses import dataclass

RISK_ORDER = {"local": 0, "recon": 1, "active": 2, "intrusive": 3}


@dataclass
class Tool:
    name: str
    category: str
    risk: str
    desc: str
    apt: str
    binaries: tuple = ()
    needs_target: bool = True
    timeout: int = 900

    def binary(self):
        for b in self.binaries or (self.name,):
            path = shutil.which(b)
            if path:
                return path
        return None


def _t(name, category, risk, desc, apt, binaries=(), needs_target=True, timeout=900):
    return Tool(name, category, risk, desc, apt, tuple(binaries), needs_target, timeout)


REGISTRY = {t.name: t for t in [
    # --- local (no target) -------------------------------------------------
    _t("searchsploit", "exploits", "local", "Search Exploit-DB offline by product/version, e.g. ['apache 2.4.49'].", "exploitdb", needs_target=False, timeout=60),
    _t("hashid", "crypto", "local", "Identify a hash type, e.g. ['-m', '<hash>'].", "hashid", needs_target=False, timeout=30),
    # --- recon -------------------------------------------------------------
    _t("nmap", "network", "recon", "Port/service identification: ['-sV','--max-rate','50','<ip>']. Full ports elevate risk; named reviewed NSE scripts require confirmation.", "nmap", timeout=3600),
    _t("ping", "network", "recon", "Check if a host is up: ['-c','2','<ip>'].", "iputils-ping", timeout=30),
    _t("dig", "dns", "recon", "DNS queries, zone transfer: ['axfr','@<dns-ip>','domain.htb'].", "dnsutils", timeout=60),
    _t("host", "dns", "recon", "Simple DNS lookup.", "bind9-host", timeout=60),
    _t("nslookup", "dns", "recon", "DNS lookup.", "dnsutils", timeout=60),
    _t("whois", "dns", "recon", "WHOIS lookup of a domain/IP.", "whois", timeout=60),
    _t("whatweb", "web", "recon", "Fingerprint web technologies: ['-a','1','http://<host>'].", "whatweb", timeout=300),
    _t("wafw00f", "web", "recon", "Detect a WAF in front of a site.", "wafw00f", timeout=300),
    _t("curl", "web", "recon", "Raw HTTP requests. Use ['-sik','http://...'] to see headers.", "curl", timeout=120),
    _t("httpx", "web", "recon", "Probe web servers for title/status/tech (projectdiscovery httpx).", "httpx-toolkit", binaries=("httpx-toolkit",), timeout=600),
    _t("sslscan", "web", "recon", "TLS/SSL configuration check.", "sslscan", timeout=300),
    _t("testssl", "web", "recon", "Detailed TLS/SSL testing.", "testssl.sh", binaries=("testssl", "testssl.sh"), timeout=1800),
    _t("subfinder", "dns", "recon", "Passive subdomain discovery from public sources: ['-d','example.com'].", "subfinder", timeout=900),
    # --- active ------------------------------------------------------------
    _t("ffuf", "web", "active", "Fuzz paths/params/vhosts. ['-u','http://<host>/FUZZ','-w','<wordlist>','-ac'].", "ffuf", timeout=3600),
    _t("gobuster", "web", "active", "Directory / vhost / DNS brute forcing: ['dir','-u','http://<host>','-w','<wordlist>'].", "gobuster", timeout=3600),
    _t("feroxbuster", "web", "active", "Recursive content discovery: ['-u','http://<host>','-w','<wordlist>','--no-state'].", "feroxbuster", timeout=3600),
    _t("dirsearch", "web", "active", "Web path discovery: ['-u','http://<host>'].", "dirsearch", timeout=3600),
    _t("nikto", "web", "active", "Web server misconfiguration scanner: ['-h','http://<host>'].", "nikto", timeout=3600),
    _t("nuclei", "web", "active", "Template-based vulnerability scanner: ['-u','http://<host>'].", "nuclei", timeout=3600),
    _t("wpscan", "web", "active", "WordPress scanner: ['--url','http://<host>','-e','vp,vt,u'].", "wpscan", timeout=3600),
    _t("katana", "web", "active", "Crawl a site for endpoints/JS: ['-u','http://<host>'].", "katana", timeout=1800),
    _t("arjun", "web", "active", "Discover hidden HTTP parameters: ['-u','http://<host>/page'].", "arjun", timeout=1800),
    _t("dnsrecon", "dns", "active", "DNS enumeration incl. zone transfer: ['-d','domain.htb','-n','<dns-ip>'].", "dnsrecon", timeout=900),
    _t("enum4linux-ng", "smb/ad", "active", "SMB/RPC/LDAP enumeration: ['-A','<ip>'].", "enum4linux-ng", timeout=1800),
    _t("smbclient", "smb/ad", "active", "List/access SMB shares: ['-N','-L','//<ip>'] (use -N for null session).", "smbclient", timeout=300),
    _t("smbmap", "smb/ad", "active", "Show SMB share permissions: ['-H','<ip>'].", "smbmap", timeout=600),
    _t("rpcclient", "smb/ad", "active", "RPC queries: ['-U','','-N','<ip>','-c','enumdomusers'].", "smbclient", timeout=300),
    _t("netexec", "smb/ad", "active", "Swiss-army knife for SMB/WinRM/LDAP/MSSQL: ['smb','<ip>','-u','','-p','','--shares'].", "netexec", binaries=("netexec", "nxc"), timeout=1800),
    _t("ldapsearch", "smb/ad", "active", "LDAP queries: ['-x','-H','ldap://<ip>','-s','base','namingcontexts'].", "ldap-utils", timeout=300),
    _t("impacket-GetNPUsers", "smb/ad", "active", "AS-REP roasting: ['domain.htb/','-usersfile','users.txt','-dc-ip','<ip>','-no-pass'].", "impacket-scripts", timeout=900),
    _t("impacket-GetUserSPNs", "smb/ad", "active", "Kerberoasting (needs creds): ['domain.htb/user:pass','-dc-ip','<ip>','-request'].", "impacket-scripts", timeout=900),
    _t("impacket-lookupsid", "smb/ad", "active", "Enumerate users via SID brute: ['guest@<ip>','-no-pass'].", "impacket-scripts", timeout=900),
    _t("snmpwalk", "network", "active", "Read SNMP data: ['-v2c','-c','public','<ip>'].", "snmp", timeout=900),
    _t("onesixtyone", "network", "active", "Brute-force SNMP community strings: ['-c','<wordlist>','<ip>'].", "onesixtyone", timeout=900),
    # --- intrusive ---------------------------------------------------------
    _t("sqlmap", "web", "intrusive", "Exploit SQL injection: ['-u','http://<host>/page?id=1','--batch'].", "sqlmap", timeout=3600),
    _t("hydra", "auth", "intrusive", "Online password brute force (only if the user asked).", "hydra", timeout=3600),
]}

REGISTRY.update({t.name: t for t in [
    _t('amass', 'dns', 'active', 'Attack surface mapping; explicit domain, review version-specific enum options.', 'amass', timeout=1800),
    _t('dnsx', 'dns', 'active', 'DNS probing; explicit -d domain and -w wordlist, -rl controls rate.', 'dnsx', timeout=900),
    _t('tshark', 'analysis', 'local', 'Offline packet inspection only: -r an imported capture; no live capture.', 'tshark', needs_target=False, timeout=120),
]})

# nmap scripts in these categories make a scan intrusive
NMAP_INTRUSIVE = re.compile(r"(vuln|exploit|brute|dos|intrusive|malware|fuzzer)", re.I)


def risk_for(tool, args):
    """Base risk of the tool, raised by dangerous arguments."""
    risk = tool.risk
    joined = " ".join(args)
    if tool.name == 'nmap' and any(a in args for a in ('-sC', '-A')):
        risk = 'intrusive'
    elif tool.name == 'nmap' and any(a in args for a in ('-p-', '-sU')):
        risk = 'active'
    if tool.name == "nmap":
        for i, a in enumerate(args):
            if a.startswith("--script"):
                value = a.split("=", 1)[1] if "=" in a else (args[i + 1] if i + 1 < len(args) else "")
                if NMAP_INTRUSIVE.search(value):
                    risk = "intrusive"
                elif risk == "recon":
                    risk = "active"
    if tool.name == "netexec" and ("--rid-brute" in args or "-x" in args or "-X" in args):
        risk = "intrusive"
    if tool.name == "netexec":                     # a file for -u/-p = password spraying
        for i, a in enumerate(args[:-1]):
            if a in ("-u", "-p", "-H") and os.path.isfile(args[i + 1]):
                risk = "intrusive"
    if tool.name == "wpscan" and ("--passwords" in joined or "-P " in joined):
        risk = "intrusive"
    if tool.name == 'curl' and any(a == flag or a.startswith(flag + '=') for a in args
            for flag in ('-T', '--upload-file', '-X', '--request', '-d', '--data', '--data-raw', '--data-binary', '-F', '--form')):
        risk = 'intrusive'
    if tool.name in ('nuclei', 'impacket-GetNPUsers', 'impacket-GetUserSPNs', 'onesixtyone'):
        risk = 'intrusive'
    if tool.name in ('rpcclient', 'smbclient', 'netexec'):
        risk = 'intrusive'  # these clients can change state or execute operations
    return risk


# ----------------------------------------------------------------------------
# Running commands
# ----------------------------------------------------------------------------
ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07]*\x07")
NOISE_RE = re.compile(r"^\s*(:: Progress:|Progress:|\[#+|\[\s*\d+/\d+\]\s*\[)", re.I)


def clean_output(text):
    """Remove colors, progress bars and repeated lines so the model gets less noise."""
    out, last = [], None
    for line in text.splitlines():
        line = ANSI_RE.sub("", line)
        if "\r" in line:
            line = line.rsplit("\r", 1)[-1]
        line = line.rstrip()
        if NOISE_RE.match(line) or line == last:
            continue
        out.append(line)
        last = line
    return "\n".join(out).strip()


def shorten(text, limit):
    if len(text) <= limit:
        return text
    half = limit // 2
    return text[:half] + f"\n\n[... {len(text) - limit} characters cut, see the saved file ...]\n\n" + text[-half:]


def prepare_args(tool, args, outdir, stamp):
    """Add helpful flags. For nmap we also save XML so we can parse it."""
    args = list(args)
    xml_path = None
    if tool.name == "nmap" and not any(a in ("-oX", "-oA") or a.startswith("-oX") or a.startswith("-oA") for a in args):
        xml_path = outdir / f"nmap_{stamp}.xml"
        args += ["-oX", str(xml_path)]
    return args, xml_path


# ----------------------------------------------------------------------------
# nmap XML -> short summary (saves a lot of tokens)
# ----------------------------------------------------------------------------
def parse_nmap_xml(path):
    try:
        root = ET.parse(path).getroot()
    except (ET.ParseError, OSError):
        return ""
    lines = []
    for host in root.findall("host"):
        addr = host.find("address[@addrtype='ipv4']")   # (Elements are falsy, so no "or" here)
        if addr is None:
            addr = host.find("address")
        ip = addr.get("addr") if addr is not None else "?"
        names = [h.get("name") for h in host.findall("hostnames/hostname") if h.get("name")]
        status = host.find("status")
        state = status.get("state") if status is not None else "?"
        lines.append(f"Host {ip}{' (' + ', '.join(names) + ')' if names else ''} - {state}")
        for port in host.findall("ports/port"):
            st = port.find("state")
            if st is None or st.get("state") not in ("open", "open|filtered"):
                continue
            svc = port.find("service")
            desc = ""
            if svc is not None:
                desc = " ".join(x for x in (svc.get("name"), svc.get("product"), svc.get("version"),
                                            svc.get("extrainfo")) if x)
            lines.append(f"  {port.get('portid')}/{port.get('protocol')} {st.get('state')}  {desc}")
            for script in port.findall("script"):
                out = re.sub(r"\s+", " ", script.get("output", "")).strip()
                lines.append(f"      [{script.get('id')}] {out[:400]}")
        for script in host.findall("hostscript/script"):
            out = re.sub(r"\s+", " ", script.get("output", "")).strip()
            lines.append(f"  [host:{script.get('id')}] {out[:400]}")
        os_match = host.find("os/osmatch")
        if os_match is not None:
            lines.append(f"  OS guess: {os_match.get('name')} ({os_match.get('accuracy')}%)")
    return "\n".join(lines)
