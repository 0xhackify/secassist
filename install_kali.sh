#!/usr/bin/env bash
# Installs the Kali packages SecAssist can use.
#   sudo ./install_kali.sh                 # tools only
#   sudo ./install_kali.sh --with-seclists # + SecLists wordlists (large download)
set -euo pipefail

MODE="${1:---core}"
if [[ "$MODE" != '--core' && "$MODE" != '--all' && "$MODE" != '--with-seclists' ]]; then
  echo 'Usage: sudo ./install_kali.sh [--core|--all|--with-seclists]'
  exit 2
fi

if [ "$(id -u)" -ne 0 ]; then
  echo "Run with sudo: sudo ./install_kali.sh"
  exit 1
fi

PKGS=(
  python3 tmux nmap iputils-ping dnsutils bind9-host whois curl
  whatweb wafw00f httpx-toolkit sslscan testssl.sh subfinder
  ffuf gobuster feroxbuster dirsearch nikto nuclei wpscan katana arjun dnsrecon
  enum4linux-ng smbclient smbmap netexec ldap-utils impacket-scripts snmp onesixtyone
  sqlmap hydra exploitdb hashid wordlists amass dnsx tshark
)
if [[ "$MODE" == '--core' ]]; then
  PKGS=(python3 tmux nmap curl dnsutils whatweb sslscan ffuf wordlists)
fi
[ "${1:-}" = "--with-seclists" ] && PKGS+=(seclists)

echo "[*] Updating package lists..."
apt-get update -qq

AVAILABLE=()
for p in "${PKGS[@]}"; do
  if apt-cache show "$p" >/dev/null 2>&1; then
    AVAILABLE+=("$p")
  else
    echo "[!] Package not found in your repos, skipping: $p"
  fi
done

echo "[*] Installing ${#AVAILABLE[@]} packages..."
apt-get install -y "${AVAILABLE[@]}"

# rockyou comes compressed on Kali
if [ -f /usr/share/wordlists/rockyou.txt.gz ] && [ ! -f /usr/share/wordlists/rockyou.txt ]; then
  echo "[*] Unpacking rockyou.txt"
  gunzip -k /usr/share/wordlists/rockyou.txt.gz
fi

echo
echo "[+] Done. Update nuclei templates as your normal user with:  nuclei -update-templates"
echo "[+] Then start SecAssist:  ./secassist --panes"
