"""
Recon Agent — AI-powered reconnaissance tool for CTF/pentesting.
Uses the Anthropic API (Claude) and runs nmap, gobuster, nikto,
subfinder, dig/nslookup, curl, whois, and SSL checks against a target.

Usage:
    python recon_agent.py <target_ip_or_domain>
    python recon_agent.py 10.10.10.1
    python recon_agent.py scanme.nmap.org

Requires:
    - ANTHROPIC_API_KEY env var (or .env file)
    - anthropic pip package
    - Optional: nmap, gobuster, nikto, subfinder on PATH
"""

import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
from datetime import datetime, timezone

import anthropic

# Fix Windows terminal encoding for Unicode output (emojis, etc.)
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
sys.stderr.reconfigure(encoding='utf-8', errors='replace')

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

from agents.base import get_model

MODEL = get_model()  # single source of truth (honors RECON_MODEL)

# Add local tools and nmap to PATH
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
TOOLS_DIR = os.path.join(SCRIPT_DIR, "tools")
NMAP_DIR = os.path.join(os.environ.get("ProgramFiles(x86)", ""), "Nmap")
PERLLIB_DIR = os.path.join(TOOLS_DIR, "perllib")

for d in [TOOLS_DIR, NMAP_DIR]:
    if os.path.isdir(d) and d not in os.environ.get("PATH", ""):
        os.environ["PATH"] = d + os.pathsep + os.environ.get("PATH", "")

if os.path.isdir(PERLLIB_DIR):
    os.environ["PERL5LIB"] = PERLLIB_DIR + os.pathsep + os.environ.get("PERL5LIB", "")

# Load API key from env or .env file
def load_api_key():
    key = os.getenv("ANTHROPIC_API_KEY")
    if key:
        return key
    env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
    if os.path.exists(env_path):
        with open(env_path) as f:
            for line in f:
                line = line.strip()
                if line.startswith("ANTHROPIC_API_KEY="):
                    return line.split("=", 1)[1].strip().strip("\"'")
    print("ERROR: Set ANTHROPIC_API_KEY as an env var or in a .env file")
    sys.exit(1)


# ---------------------------------------------------------------------------
# Tool implementations
# ---------------------------------------------------------------------------

def run_cmd(cmd: list[str], timeout: int = 60, label: str = "") -> str:
    """Run a subprocess command, stream output live, and return full result."""
    import threading

    prefix = f"     [{label}] " if label else "     | "

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        stdout_lines = []
        stderr_lines = []

        def read_stream(stream, lines, is_stderr=False):
            for line in stream:
                stripped = line.rstrip("\n\r")
                lines.append(stripped)
                tag = f"{prefix}[err] " if is_stderr else prefix
                print(f"{tag}{stripped}", flush=True)

        t_out = threading.Thread(target=read_stream, args=(proc.stdout, stdout_lines, False))
        t_err = threading.Thread(target=read_stream, args=(proc.stderr, stderr_lines, True))
        t_out.start()
        t_err.start()

        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
            t_out.join(timeout=2)
            t_err.join(timeout=2)
            return f"ERROR: Command timed out after {timeout}s."

        t_out.join(timeout=5)
        t_err.join(timeout=5)

        output = "\n".join(stdout_lines)
        if stderr_lines:
            output += "\n[stderr]\n" + "\n".join(stderr_lines)
        return output.strip() or "(no output)"

    except FileNotFoundError:
        msg = f"ERROR: '{cmd[0]}' is not installed or not on PATH."
        print(f"{prefix}{msg}", flush=True)
        return msg
    except Exception as e:
        msg = f"ERROR: {e}"
        print(f"{prefix}{msg}", flush=True)
        return msg


def tool_nmap(target: str, ports: str = "", scan_type: str = "default") -> str:
    """Run an nmap scan against the target."""
    if not shutil.which("nmap"):
        return "ERROR: nmap is not installed. Install it from https://nmap.org/download.html"

    cmd = ["nmap"]
    if scan_type == "service":
        cmd += ["-sV"]
    elif scan_type == "os":
        cmd += ["-O"]
    elif scan_type == "aggressive":
        cmd += ["-A"]
    elif scan_type == "quick":
        cmd += ["-T4", "-F"]
    elif scan_type == "udp":
        cmd += ["-sU", "--top-ports", "20"]

    if ports:
        cmd += ["-p", ports]

    cmd.append(target)
    return run_cmd(cmd, timeout=120, label="nmap")


def tool_dns_lookup(target: str, record_type: str = "A") -> str:
    """Perform DNS lookup using nslookup or dig."""
    if shutil.which("dig"):
        cmd = ["dig", target, record_type, "+short"]
    else:
        cmd = ["nslookup"]
        if record_type != "A":
            cmd += ["-type=" + record_type]
        cmd.append(target)
    return run_cmd(cmd, timeout=15, label=f"dns:{record_type}")


def tool_reverse_dns(ip: str) -> str:
    """Perform reverse DNS lookup."""
    if shutil.which("dig"):
        cmd = ["dig", "-x", ip, "+short"]
        return run_cmd(cmd, timeout=15, label="rdns")

    # Fallback: Python socket
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return f"Reverse DNS: {hostname}"
    except socket.herror:
        return "No reverse DNS record found."
    except Exception as e:
        return f"ERROR: {e}"


def tool_curl(url: str, method: str = "GET", headers_only: bool = False,
              follow_redirects: bool = True, custom_headers: list[str] | None = None) -> str:
    """Make an HTTP request using curl."""
    cmd = ["curl", "-s", "-S", "--max-time", "15"]

    if headers_only:
        cmd.append("-I")
    else:
        cmd += ["-i"]  # include response headers

    if follow_redirects:
        cmd += ["-L", "--max-redirs", "5"]

    if method != "GET":
        cmd += ["-X", method]

    if custom_headers:
        for h in custom_headers:
            cmd += ["-H", h]

    cmd.append(url)
    output = run_cmd(cmd, timeout=20, label="curl")

    # Truncate very large responses
    if len(output) > 8000:
        output = output[:8000] + "\n\n[...truncated, response too large...]"
    return output


def tool_whois(target: str) -> str:
    """Run whois lookup."""
    if shutil.which("whois"):
        return run_cmd(["whois", target], timeout=15)

    # Resolve hostname to IP if needed (ARIN API only accepts IPs)
    query = target
    try:
        socket.inet_aton(target)
    except OSError:
        try:
            query = socket.gethostbyname(target)
        except socket.gaierror:
            pass  # keep original target

    # Fallback: use curl against a whois API
    try:
        result = subprocess.run(
            ["curl", "-s", "--max-time", "10",
             "-H", "Accept: text/plain",
             f"https://whois.arin.net/rest/ip/{query}"],
            capture_output=True, text=True, timeout=15,
        )
        output = result.stdout.strip()
        if not output or "<html" in output.lower():
            # Try rdap as second fallback
            result = subprocess.run(
                ["curl", "-s", "--max-time", "10",
                 f"https://rdap.arin.net/registry/ip/{query}"],
                capture_output=True, text=True, timeout=15,
            )
            try:
                data = json.loads(result.stdout)
                lines = [f"Name: {data.get('name', 'N/A')}"]
                lines.append(f"Handle: {data.get('handle', 'N/A')}")
                for entity in data.get("entities", []):
                    vcard = entity.get("vcardArray", [None, []])[1]
                    for field in vcard:
                        if field[0] == "fn":
                            lines.append(f"Organization: {field[3]}")
                lines.append(f"CIDR: {data.get('cidr0_cidrs', 'N/A')}")
                lines.append(f"Start: {data.get('startAddress', 'N/A')}")
                lines.append(f"End: {data.get('endAddress', 'N/A')}")
                return "\n".join(lines)
            except (json.JSONDecodeError, KeyError):
                return result.stdout.strip() or "No WHOIS data returned."
        return output
    except Exception as e:
        return f"ERROR: {e}"


def tool_ssl_check(host: str, port: int = 443) -> str:
    """Check SSL/TLS certificate details."""
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=host) as s:
            s.settimeout(10)
            s.connect((host, port))
            cert = s.getpeercert()

        lines = [f"SSL Certificate for {host}:{port}"]
        lines.append(f"  Subject: {dict(x[0] for x in cert.get('subject', []))}")
        lines.append(f"  Issuer:  {dict(x[0] for x in cert.get('issuer', []))}")
        lines.append(f"  Valid from: {cert.get('notBefore')}")
        lines.append(f"  Valid until: {cert.get('notAfter')}")

        san = cert.get("subjectAltName", [])
        if san:
            lines.append(f"  SANs: {', '.join(v for _, v in san)}")

        return "\n".join(lines)
    except ssl.SSLCertVerificationError as e:
        return f"SSL verification error: {e}"
    except ConnectionRefusedError:
        return f"Connection refused on {host}:{port}"
    except socket.timeout:
        return f"Connection timed out to {host}:{port}"
    except Exception as e:
        return f"ERROR: {e}"


def tool_ping(target: str, count: int = 4) -> str:
    """Ping a target to check if it's alive."""
    # Windows uses -n, Unix uses -c
    flag = "-n" if sys.platform == "win32" else "-c"
    return run_cmd(["ping", flag, str(count), target], timeout=30, label="ping")


def tool_gobuster(url: str, mode: str = "dir", wordlist: str = "",
                  extensions: str = "", threads: int = 20,
                  status_codes: str = "", extra_flags: str = "") -> str:
    """Run gobuster for directory/file/vhost/dns brute-forcing."""
    if not shutil.which("gobuster"):
        return "ERROR: gobuster is not installed. Install from https://github.com/OJ/gobuster/releases"

    # Find a wordlist if none specified or resolve relative names
    if wordlist and not os.path.isabs(wordlist) and not os.path.isfile(wordlist):
        # Try resolving against bundled wordlists dir
        candidate = os.path.join(SCRIPT_DIR, "wordlists", wordlist)
        if os.path.isfile(candidate):
            wordlist = candidate

    if not wordlist or not os.path.isfile(wordlist):
        search_paths = [
            # Bundled wordlists next to this script (check first)
            os.path.join(SCRIPT_DIR, "wordlists", "common.txt"),
            # Common SecLists locations
            os.path.expanduser("~/SecLists/Discovery/Web-Content/common.txt"),
            os.path.expanduser("~/wordlists/common.txt"),
            "/usr/share/wordlists/dirb/common.txt",
            "/usr/share/seclists/Discovery/Web-Content/common.txt",
        ]
        for p in search_paths:
            if os.path.isfile(p):
                wordlist = p
                break
        if not wordlist or not os.path.isfile(wordlist):
            return ("ERROR: No wordlist specified and no default wordlist found. "
                    "Provide a wordlist path or install SecLists: "
                    "git clone https://github.com/danielmiessler/SecLists ~/SecLists")

    cmd = ["gobuster", mode, "-u", url, "-w", wordlist, "-t", str(threads), "--no-color"]

    if extensions and mode == "dir":
        cmd += ["-x", extensions]

    if status_codes and mode == "dir":
        cmd += ["-s", status_codes]

    if extra_flags:
        cmd += extra_flags.split()

    output = run_cmd(cmd, timeout=600, label="gobuster")

    # Truncate very large output
    if len(output) > 10000:
        output = output[:10000] + "\n\n[...truncated, output too large...]"
    return output


def tool_nikto(target: str, port: int = 80, ssl: bool = False,
               tuning: str = "", extra_flags: str = "") -> str:
    """Run nikto web vulnerability scanner against a target."""
    # Find nikto: check PATH, then local tools dir (bash wrapper or perl script)
    nikto_bin = shutil.which("nikto") or shutil.which("nikto.pl")
    if not nikto_bin:
        local_wrapper = os.path.join(TOOLS_DIR, "nikto")
        local_pl = os.path.join(TOOLS_DIR, "nikto2", "program", "nikto.pl")
        if os.path.isfile(local_wrapper):
            nikto_bin = local_wrapper
        elif os.path.isfile(local_pl):
            nikto_bin = local_pl
    if not nikto_bin:
        return "ERROR: nikto is not installed. Install from https://github.com/sullo/nikto"

    # If it's a bash wrapper or perl script, run via bash/perl
    if nikto_bin.endswith(".pl"):
        cmd = ["perl", nikto_bin, "-h", target, "-p", str(port), "-nointeractive", "-C", "all"]
    elif not nikto_bin.endswith(".exe"):
        cmd = ["bash", nikto_bin, "-h", target, "-p", str(port), "-nointeractive", "-C", "all"]
    else:
        cmd = [nikto_bin, "-h", target, "-p", str(port), "-nointeractive", "-C", "all"]

    if ssl:
        cmd += ["-ssl"]

    if tuning:
        cmd += ["-Tuning", tuning]

    if extra_flags:
        cmd += extra_flags.split()

    output = run_cmd(cmd, timeout=120, label="nikto")

    if len(output) > 12000:
        output = output[:12000] + "\n\n[...truncated, output too large...]"
    return output


def tool_subfinder(domain: str, recursive: bool = False,
                   extra_flags: str = "") -> str:
    """Run subfinder to enumerate subdomains of a domain."""
    if not shutil.which("subfinder"):
        return "ERROR: subfinder is not installed. Install from https://github.com/projectdiscovery/subfinder/releases"

    cmd = ["subfinder", "-d", domain, "-silent"]

    if recursive:
        cmd += ["-recursive"]

    if extra_flags:
        cmd += extra_flags.split()

    output = run_cmd(cmd, timeout=120, label="subfinder")

    if len(output) > 10000:
        output = output[:10000] + "\n\n[...truncated, output too large...]"
    return output


# ---------------------------------------------------------------------------
# Tool definitions (Anthropic function-calling format)
# ---------------------------------------------------------------------------

TOOLS = [
    {
        "name": "nmap_scan",
        "description": "Run an nmap scan to discover open ports and services on the target. Supports various scan types.",
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "IP address or hostname to scan"},
                "ports": {"type": "string", "description": "Port specification (e.g. '80,443', '1-1000', '-' for all). Leave empty for nmap defaults."},
                "scan_type": {
                    "type": "string",
                    "enum": ["default", "quick", "service", "os", "aggressive", "udp"],
                    "description": "Type of scan: default, quick (-F), service (-sV), os (-O), aggressive (-A), or udp"
                },
            },
            "required": ["target"],
        },
    },
    {
        "name": "dns_lookup",
        "description": "Perform a DNS lookup for the target. Supports different record types (A, AAAA, MX, NS, TXT, CNAME, SOA, etc).",
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Domain name or IP to look up"},
                "record_type": {"type": "string", "description": "DNS record type: A, AAAA, MX, NS, TXT, CNAME, SOA, PTR, etc.", "default": "A"},
            },
            "required": ["target"],
        },
    },
    {
        "name": "reverse_dns",
        "description": "Perform a reverse DNS lookup to find hostnames associated with an IP address.",
        "input_schema": {
            "type": "object",
            "properties": {
                "ip": {"type": "string", "description": "IP address for reverse lookup"},
            },
            "required": ["ip"],
        },
    },
    {
        "name": "curl_request",
        "description": "Make an HTTP/HTTPS request to a URL. Useful for grabbing banners, checking HTTP headers, inspecting web servers, and probing services.",
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Full URL to request (e.g. http://10.10.10.1, https://example.com:8443/api)"},
                "method": {"type": "string", "enum": ["GET", "HEAD", "POST", "PUT", "OPTIONS"], "description": "HTTP method", "default": "GET"},
                "headers_only": {"type": "boolean", "description": "If true, only fetch response headers (-I flag)", "default": False},
                "follow_redirects": {"type": "boolean", "description": "Follow HTTP redirects", "default": True},
                "custom_headers": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Custom headers to send (e.g. ['User-Agent: Mozilla/5.0', 'Authorization: Bearer token'])"
                },
            },
            "required": ["url"],
        },
    },
    {
        "name": "whois_lookup",
        "description": "Perform a WHOIS lookup to get registration and ownership information for an IP or domain.",
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "IP address or domain to look up"},
            },
            "required": ["target"],
        },
    },
    {
        "name": "ssl_check",
        "description": "Check the SSL/TLS certificate of a host. Returns subject, issuer, validity dates, and SANs.",
        "input_schema": {
            "type": "object",
            "properties": {
                "host": {"type": "string", "description": "Hostname or IP to check"},
                "port": {"type": "integer", "description": "Port number (default 443)", "default": 443},
            },
            "required": ["host"],
        },
    },
    {
        "name": "ping_target",
        "description": "Ping a target to check if it is reachable/alive.",
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "IP address or hostname to ping"},
                "count": {"type": "integer", "description": "Number of ping packets (default 4)", "default": 4},
            },
            "required": ["target"],
        },
    },
    {
        "name": "gobuster_scan",
        "description": "Run gobuster to brute-force directories, files, vhosts, or DNS subdomains on a web server. Requires a wordlist. Use after discovering HTTP/HTTPS ports to find hidden paths and files.",
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target URL including scheme (e.g. http://10.10.10.1, https://example.com:8443)"},
                "mode": {
                    "type": "string",
                    "enum": ["dir", "dns", "vhost"],
                    "description": "Brute-force mode: dir (directories/files), dns (subdomains), vhost (virtual hosts)",
                    "default": "dir",
                },
                "wordlist": {"type": "string", "description": "Path to wordlist file. Leave empty to auto-detect a default wordlist."},
                "extensions": {"type": "string", "description": "File extensions to search for in dir mode, comma-separated (e.g. 'php,html,txt,bak')"},
                "threads": {"type": "integer", "description": "Number of threads (default 20)", "default": 20},
                "status_codes": {"type": "string", "description": "Comma-separated status codes to match (e.g. '200,204,301,302,307,401,403')"},
                "extra_flags": {"type": "string", "description": "Additional gobuster flags as a string (e.g. '--follow-redirect --timeout 10s')"},
            },
            "required": ["url"],
        },
    },
    {
        "name": "nikto_scan",
        "description": "Run nikto web vulnerability scanner to identify dangerous files, outdated software, misconfigurations, and known vulnerabilities on a web server. Use after discovering HTTP/HTTPS ports.",
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target hostname or IP address"},
                "port": {"type": "integer", "description": "Target port (default 80)", "default": 80},
                "ssl": {"type": "boolean", "description": "Use SSL/HTTPS (default false)", "default": False},
                "tuning": {
                    "type": "string",
                    "description": "Nikto scan tuning options: 1=interesting files, 2=misconfiguration, 3=information disclosure, 4=injection (XSS/Script/HTML), 5=remote file retrieval, 6=denial of service, 7=remote file retrieval (server-wide), 8=command execution, 9=SQL injection, 0=file upload, a=authentication bypass, b=software identification, c=remote source inclusion, x=reverse tuning (exclude). Combine like '123' or 'x6' to exclude DoS.",
                },
                "extra_flags": {"type": "string", "description": "Additional nikto flags as a string"},
            },
            "required": ["target"],
        },
    },
    {
        "name": "subfinder_enum",
        "description": "Run subfinder to passively enumerate subdomains of a domain using OSINT sources (search engines, certificate transparency logs, DNS datasets, etc). Use early in recon to discover the target's subdomain attack surface.",
        "input_schema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Root domain to enumerate subdomains for (e.g. 'example.com', 'nmap.org')"},
                "recursive": {"type": "boolean", "description": "Recursively enumerate subdomains of discovered subdomains", "default": False},
                "extra_flags": {"type": "string", "description": "Additional subfinder flags as a string"},
            },
            "required": ["domain"],
        },
    },
]

# Map tool names to functions
TOOL_DISPATCH = {
    "nmap_scan": lambda **kw: tool_nmap(**kw),
    "dns_lookup": lambda **kw: tool_dns_lookup(**kw),
    "reverse_dns": lambda **kw: tool_reverse_dns(**kw),
    "curl_request": lambda **kw: tool_curl(**kw),
    "whois_lookup": lambda **kw: tool_whois(**kw),
    "ssl_check": lambda **kw: tool_ssl_check(**kw),
    "ping_target": lambda **kw: tool_ping(**kw),
    "gobuster_scan": lambda **kw: tool_gobuster(**kw),
    "nikto_scan": lambda **kw: tool_nikto(**kw),
    "subfinder_enum": lambda **kw: tool_subfinder(**kw),
}


# ---------------------------------------------------------------------------
# Agent loop
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """You are a reconnaissance agent for authorized security testing and CTF challenges.
Your job is to gather as much useful information as possible about the given target using the available tools.

Strategy:
1. Start with a ping to check if the target is alive.
2. Run DNS lookups (A, AAAA, MX, NS, TXT records) and reverse DNS.
3. Run subfinder to enumerate subdomains of the target domain.
4. Run an nmap scan to find open ports (start with a quick scan, then do service detection on discovered ports).
5. For any HTTP/HTTPS ports found:
   a. Use curl to grab headers and inspect the web server.
   b. Run gobuster to brute-force directories and files (try extensions like php,html,txt,bak,js,json).
   c. Run nikto to scan for known web vulnerabilities and misconfigurations.
6. Check SSL certificates on any HTTPS services.
7. Run a WHOIS lookup for ownership info.
8. Based on findings, do deeper investigation — probe discovered paths with curl, check interesting subdomains, etc.

After gathering information, provide a structured recon report with:
- Target summary (IP, hostname, location/owner info)
- Subdomains discovered
- Open ports and services
- Web server details and discovered paths/files (if applicable)
- Web vulnerabilities found by nikto (if applicable)
- DNS records
- SSL/TLS certificate info
- WHOIS summary
- Notable findings or potential attack surface

Be thorough but efficient. Use parallel tool calls when possible.
Only scan the specified target — never expand scope without authorization."""


def run_agent(target: str, output_file: str = ""):
    api_key = load_api_key()
    client = anthropic.Anthropic(api_key=api_key)

    print(f"{'='*60}")
    print(f"  RECON AGENT")
    print(f"  Target: {target}")
    print(f"  Model:  {MODEL}")
    print(f"  Time:   {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print(f"{'='*60}\n")

    messages = [
        {"role": "user", "content": f"Run a full reconnaissance scan on target: {target}"},
    ]

    iteration = 0
    max_iterations = 20  # safety limit

    while iteration < max_iterations:
        iteration += 1
        print(f"[Agent] Iteration {iteration} — thinking...")

        try:
            response = client.messages.create(
                model=MODEL,
                system=SYSTEM_PROMPT,
                messages=messages,
                tools=TOOLS,
                max_tokens=4096,
            )
        except Exception as e:
            print(f"\n[ERROR] API call failed: {e}")
            sys.exit(1)

        # Append assistant message to history
        messages.append({"role": "assistant", "content": response.content})

        # If the model is done (no tool calls), print final response and exit
        if response.stop_reason == "end_turn":
            report_text = ""
            for block in response.content:
                if block.type == "text":
                    report_text += block.text

            print(f"\n{'='*60}")
            print("  RECON REPORT")
            print(f"{'='*60}\n")
            print(report_text)

            # Save report to file if --output was specified
            if output_file:
                with open(output_file, "w", encoding="utf-8") as f:
                    f.write(report_text)
                print(f"\n[+] Report saved to: {output_file}")
            break

        # Execute each tool call
        tool_results = []
        for block in response.content:
            if block.type == "tool_use":
                fn_name = block.name
                fn_args = block.input

                print(f"  -> Running: {fn_name}({', '.join(f'{k}={v!r}' for k, v in fn_args.items())})")

                if fn_name in TOOL_DISPATCH:
                    result = TOOL_DISPATCH[fn_name](**fn_args)
                else:
                    result = f"Unknown tool: {fn_name}"
                print()  # blank line after tool output

                tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": block.id,
                    "content": result,
                })

        # Send tool results back as a user message
        if tool_results:
            messages.append({"role": "user", "content": tool_results})
    else:
        print("\n[WARNING] Reached maximum iterations. Stopping.")

    print(f"\n{'='*60}")
    print(f"  Scan complete. {iteration} iteration(s).")
    print(f"{'='*60}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="AI-powered reconnaissance tool for CTF/pentesting.",
        epilog="Example: python recon_agent.py scanme.nmap.org -o report.md",
    )
    parser.add_argument("target", help="Target IP address or domain to scan")
    parser.add_argument("-o", "--output", default="", metavar="FILE",
                        help="Save the recon report to a file (e.g. report.md)")

    args = parser.parse_args()

    # Basic input validation — only allow IPs, domains, and CIDR notation
    target = args.target.strip()
    if not re.match(r'^[a-zA-Z0-9._:\-/]+$', target):
        print(f"ERROR: Invalid target format: {target}")
        sys.exit(1)

    run_agent(target, output_file=args.output)
