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
from pathlib import Path
from typing import Any, Iterable


APP_NAME = "Bird Scan Internal"
APP_VERSION = "0.1.0"
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
    "/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt",
    "/usr/share/seclists/Usernames/Names/names.txt",
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
    "impacket-mssqlclient",
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
]

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
    "impacket-mssqlclient": "impacket-scripts",
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
        "nmap_scripts": [],
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


def command_timeout(base_timeout: int, args: argparse.Namespace, multiplier: float = 1.0) -> int:
    return max(1, int(base_timeout * multiplier))


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
        proc = subprocess.run(
            command,
            cwd=str(cwd) if cwd else None,
            input=input_text,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout,
            check=False,
            env=env,
        )
        stdout = proc.stdout or ""
        stderr = proc.stderr or ""
        returncode = proc.returncode
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout if isinstance(exc.stdout, str) else (exc.stdout or b"").decode(errors="replace")
        stderr = exc.stderr if isinstance(exc.stderr, str) else (exc.stderr or b"").decode(errors="replace")
        stderr += f"\n[TIMEOUT after {timeout}s]"
        returncode = 124
    duration = time.monotonic() - start
    stored_file = None
    if output_file:
        output_file.parent.mkdir(parents=True, exist_ok=True)
        output_file.write_text(
            f"$ {shell_join(redacted)}\n\n"
            f"Return code: {returncode}\n"
            f"Duration: {duration:.2f}s\n\n"
            f"--- STDOUT ---\n{stdout}\n\n"
            f"--- STDERR ---\n{stderr}\n",
            encoding="utf-8",
            errors="replace",
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
              sudo nmap --open -Pn -p- -sC -sV --script vuln -oA <prefix> <targets>

            Examples:
              python3 Bird-Scan-internal.py --target 192.168.1.10
              python3 Bird-Scan-internal.py --target 192.168.1.0/24 --profile safe
              python3 Bird-Scan-internal.py --targets-file targets.txt --threads-level 3
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
            """
        ),
    )
    target_group = parser.add_argument_group("targets")
    target_group.add_argument("--target", "-t", action="append", help="IP, CIDR, hostname, or comma-separated list.")
    target_group.add_argument("--targets-file", help="File with IPs, CIDRs, hostnames, or comma-separated values.")
    target_group.add_argument("--from-nmap", action="append", nargs="+", help="Import one or more Nmap XML, normal, gnmap outputs, directories, prefixes, or glob patterns.")
    target_group.add_argument("--from-ip-port", action="append", help="Import simple IP:PORT or host:port file.")

    scan_group = parser.add_argument_group("scan behavior")
    scan_group.add_argument("--profile", choices=sorted(PROFILE_DEFAULTS), default="safe", help="Operational profile.")
    scan_group.add_argument("--threads-level", type=int, choices=sorted(THREAD_LEVELS), default=2, help="Global aggressiveness 1..5.")
    scan_group.add_argument("--ports", help="Nmap ports, e.g. 80,443,445 or 1-1000. Overrides the default -p-.") 
    scan_group.add_argument("--full-portscan", action="store_true", help="Keep -p- during Nmap discovery. This is already the default.")
    scan_group.add_argument("--udp-top-ports", type=int, default=0, help="Optional UDP discovery with top N UDP ports. Disabled by default.")
    scan_group.add_argument("--skip-nmap", action="store_true", help="Do not run Nmap; use imported targets/services only.")
    scan_group.add_argument("--web-only", action="store_true", help="Only perform web catalog after importing/running discovery.")
    scan_group.add_argument("--service-enum-only", action="store_true", help="Only perform service enum after importing/running discovery.")
    scan_group.add_argument("--skip-web", action="store_true", help="Skip HTTP/HTTPS probing.")
    scan_group.add_argument("--skip-service-enum", action="store_true", help="Skip SMB/AD/RDP/SSH/FTP/DB/generic service enum.")
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
    auth_group.add_argument("--ntlm-hash", help="Single NTLM hash for authenticated enumeration.")
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
        if not re.search(r"([A-Za-z0-9_.:-]+):(\d{1,5})(?:/(tcp|udp))?", text, flags=re.I):
            raise BirdScanUsageError(f"Arquivo IP:PORT não contém entradas válidas no formato IP:PORT: {ip_port_file}")
    if args.resume and not (Path(args.resume) / "state.json").is_file():
        raise BirdScanUsageError(f"Diretório de resume inválido: não encontrei {Path(args.resume) / 'state.json'}")
    if args.web_wordlist and not Path(args.web_wordlist).is_file():
        raise BirdScanUsageError(f"Wordlist web inválida ou inexistente: {args.web_wordlist}")
    if args.user_enum_wordlist and not Path(args.user_enum_wordlist).is_file():
        raise BirdScanUsageError(f"Wordlist de usuários inválida ou inexistente: {args.user_enum_wordlist}")
    if getattr(args, "username_file", None) and not Path(args.username_file).is_file():
        raise BirdScanUsageError(f"Lista de usuários inválida ou inexistente: {args.username_file}")
    if getattr(args, "password_file", None) and not Path(args.password_file).is_file():
        raise BirdScanUsageError(f"Lista de senhas inválida ou inexistente: {args.password_file}")
    validate_credential_attack_args(args)


def validate_credential_attack_args(args: argparse.Namespace) -> None:
    mode = getattr(args, "auth_attack_mode", "pitchfork") or "pitchfork"
    if mode in {"single-user", "single-pass"}:
        users = collect_credential_usernames(args)
        passwords = collect_credential_passwords(args)
        if not users or not passwords:
            raise BirdScanUsageError(
                f"Modo {mode} exige ao menos um usuário e uma senha via -u/-p ou arquivos de lista."
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
    parts: list[str] = []
    for raw in re.split(r"[\s,]+", value):
        token = normalize_target_token(raw)
        if token:
            parts.append(token)
    return parts


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
    data = json.loads(path.read_text(encoding="utf-8"))
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
    (output_dir / "state.json").write_text(
        json.dumps(state_to_dict(state), indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


def write_json_export(state: ScanState) -> Path:
    path = Path(state.output_dir) / "results.json"
    path.write_text(json.dumps(state_to_dict(state), indent=2, ensure_ascii=False), encoding="utf-8")
    return path


def write_csv_export(state: ScanState) -> Path:
    path = Path(state.output_dir) / "services.csv"
    with path.open("w", encoding="utf-8", newline="") as handle:
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
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def check_dependencies(state: ScanState, logger: Logger) -> dict[str, bool]:
    deps = {tool: has_tool(tool) for tool in DEPENDENCIES}
    state.dependencies = deps
    missing = [tool for tool, present in deps.items() if not present]
    logger.info("Dependency check:")
    for tool, present in deps.items():
        marker = "OK" if present else "missing"
        logger.info(f"  {tool}: {marker}")
    if missing:
        logger.warn("Missing optional/required tools: " + ", ".join(missing))
    return deps


def install_missing_dependencies(state: ScanState, deps: dict[str, bool], logger: Logger) -> dict[str, bool]:
    missing_tools = [tool for tool, present in deps.items() if not present]
    if not missing_tools:
        return deps
    if not has_tool("apt-get"):
        logger.warn("apt-get não encontrado; não foi possível instalar dependências automaticamente.")
        return deps
    packages = sorted({DEPENDENCY_PACKAGES.get(tool, tool) for tool in missing_tools})
    command: list[str] = []
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        if not has_tool("sudo"):
            logger.warn("sudo não encontrado; não foi possível instalar dependências automaticamente.")
            return deps
        command.append("sudo")
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
        logger.warn("apt-get update falhou; mantendo dependências ausentes sem instalação automática.")
        return deps
    install_command = command[:-1] + ["install", "-y", *packages]
    logger.info("Installing missing tools: " + ", ".join(packages))
    install_result = run_command(
        install_command,
        timeout=3600,
        output_file=raw_dir / "apt-install.command.txt",
        logger=logger,
    )
    if install_result.returncode != 0:
        logger.warn("apt-get install falhou; algumas ferramentas podem continuar ausentes.")
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
        matches = re.findall(r"([A-Za-z0-9_.:-]+):(\d{1,5})(?:/(tcp|udp))?", stripped, flags=re.I)
        if not matches:
            continue
        for host, port_text, proto in matches:
            try:
                port = int(port_text)
            except ValueError:
                continue
            if not 1 <= port <= 65535:
                continue
            ip = host.strip("[]")
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


def parse_nmap_file(path: Path, state: ScanState, logger: Logger) -> None:
    if not path.exists():
        raise BirdScanError(f"Nmap file not found: {path}")
    text = path.read_text(encoding="utf-8", errors="replace")
    if looks_like_xml(text):
        logger.info(f"Importing Nmap XML from {path}")
        parse_nmap_xml(text, state, source=path.name, raw_file=relpath(path, state.output_dir))
    elif looks_like_gnmap(text):
        logger.info(f"Importing Nmap greppable data from {path}")
        parse_nmap_gnmap(text, state, source=path.name)
    else:
        logger.info(f"Importing Nmap normal output from {path}")
        parse_nmap_normal(text, state, source=path.name)


def looks_like_xml(text: str) -> bool:
    sample = text.lstrip()[:300]
    return sample.startswith("<?xml") or sample.startswith("<nmaprun")


def looks_like_gnmap(text: str) -> bool:
    for line in text.splitlines():
        if line.startswith("Host:") and ("Status:" in line or "Ports:" in line):
            return True
    return False


def parse_nmap_xml(text: str, state: ScanState, source: str, raw_file: str = "") -> None:
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        raise BirdScanUsageError(f"XML Nmap inválido: {exc}") from exc
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
    command: list[str] = []
    if args.sudo_nmap:
        command.append("sudo")
    command.extend(["nmap", "--open", "-Pn"])
    if args.ports:
        command.extend(["-p", args.ports])
    else:
        command.append("-p-")
    command.extend(["-sC", "-sV", "--script", "vuln", f"-{thread_conf['nmap_timing']}", "-oA", str(output_prefix)])
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
    command.extend(targets)
    return command


def split_nmap_extra(value: str) -> list[str]:
    # Keep this intentionally simple: --nmap-extra is repeatable and should
    # normally receive one flag/value per use. If spaces are supplied, split.
    return [part for part in value.split(" ") if part]


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
    if result.returncode not in {0, 1}:
        logger.warn(f"Nmap returned code {result.returncode}; attempting to parse whatever was written")
    xml_path = output_prefix.with_suffix(".xml")
    normal_path = output_prefix.with_suffix(".nmap")
    gnmap_path = output_prefix.with_suffix(".gnmap")
    for candidate in [xml_path, normal_path, gnmap_path]:
        if candidate.exists() and candidate.stat().st_size > 0:
            parse_nmap_file(candidate, state, logger)
            break
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
        if udp_result.returncode not in {0, 1}:
            logger.warn(f"UDP Nmap returned code {udp_result.returncode}; attempting to parse whatever was written")
        for candidate in [udp_prefix.with_suffix(".xml"), udp_prefix.with_suffix(".nmap"), udp_prefix.with_suffix(".gnmap")]:
            if candidate.exists() and candidate.stat().st_size > 0:
                parse_nmap_file(candidate, state, logger)
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
        command: list[str] = []
        if args.sudo_nmap:
            command.append("sudo")
        command.extend(
            [
                "nmap",
                "-Pn",
                "-sV",
                "-sC",
                "--script",
                "vuln",
                "--open",
                f"-{THREAD_LEVELS[args.threads_level]['nmap_timing']}",
                "-p",
                port_list,
                "-oA",
                str(output_prefix),
                host,
            ]
        )
        for extra in args.nmap_extra:
            command.extend(split_nmap_extra(extra))
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
            return False
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
        future_map = {
            executor.submit(probe_web_endpoint, args, state, service, scheme, path, timeout, logger): (service, scheme, path)
            for service, scheme, path in jobs
        }
        for future in concurrent.futures.as_completed(future_map):
            endpoint = future.result()
            if endpoint and has_http_response(endpoint):
                update_service_from_web_endpoint(state, endpoint)
                endpoints.append(endpoint)
                add_web_endpoint(state, endpoint)
                maybe_add_web_evidence(endpoint, state)
            delay = thread_conf["rate_delay"]
            if delay:
                time.sleep(delay)
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
    wordlist.write_text("\n".join(dedupe_text(values)) + "\n", encoding="utf-8")
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
    if not args.no_follow_redirects:
        command.extend(["--location", "--max-redirs", "5"])
    if args.proxy:
        command.extend(["--proxy", args.proxy])
    command.append(url)
    
    # User requested a 3s wait to allow complete data to load (best effort for curl/servers)
    time.sleep(3)
    
    result = run_command(
        command,
        timeout=timeout + 3,
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
            "--location",
            "--max-redirs",
            "3",
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
        
        time.sleep(3)
        result = run_command(command, timeout=timeout + 3, output_file=meta_file, logger=logger)
        meta = parse_curl_meta(result.stdout)
        status_code = int(meta.get("status_code", 0) or 0)
        content_type = str(meta.get("content_type", ""))
        if (
            result.returncode == 0
            and 200 <= status_code <= 399
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
    return dedupe_text([url for url in candidates if is_valid_web_url(url)])


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
    url_file.write_text("\n".join(urls) + "\n", encoding="utf-8")
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
    run_kerbrute_user_enum(args, state, logger)
    run_credential_auth_enumeration(args, state, logger)
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


def credential_args(args: argparse.Namespace, tool: str = "nxc") -> tuple[list[str], list[str]]:
    command_args: list[str] = []
    secrets: list[str] = []
    if args.domain:
        if tool in {"nxc", "crackmapexec"}:
            command_args.extend(["-d", args.domain])
        else:
            command_args.append(args.domain)
    if args.username:
        if tool in {"nxc", "crackmapexec"}:
            command_args.extend(["-u", args.username])
        else:
            command_args.append(args.username)
    if args.password:
        if tool in {"nxc", "crackmapexec"}:
            command_args.extend(["-p", args.password])
        else:
            command_args.append(args.password)
    if args.ntlm_hash:
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


def load_credential_list_file(path: str | None) -> list[str]:
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
        if "#" in token:
            token = token.split("#", 1)[0].strip()
        if token:
            entries.append(token)
    return entries


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
    passwords.extend(load_credential_list_file(getattr(args, "password_file", None)))
    return passwords


def resolve_auth_attack_mode(args: argparse.Namespace) -> str:
    mode = getattr(args, "auth_attack_mode", "pitchfork") or "pitchfork"
    if mode != "auto":
        return mode
    has_user_file = bool(getattr(args, "username_file", None))
    has_pass_file = bool(getattr(args, "password_file", None))
    users = collect_credential_usernames(args)
    passwords = collect_credential_passwords(args)
    if has_user_file and has_pass_file:
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


def build_credential_pairs(args: argparse.Namespace) -> tuple[list[CredentialPair], str]:
    mode = resolve_auth_attack_mode(args)
    users = collect_credential_usernames(args)
    passwords = collect_credential_passwords(args)
    if args.ntlm_hash and not passwords:
        if not users:
            users = [""]
        return [CredentialPair(user, "") for user in users], mode
    if not users or not passwords:
        return [], mode
    pairs: list[CredentialPair] = []
    if mode == "pitchfork":
        for username, password in zip(users, passwords):
            pairs.append(CredentialPair(username, password))
    elif mode == "clusterbomb":
        for username in users:
            for password in passwords:
                pairs.append(CredentialPair(username, password))
    elif mode == "single-user":
        username = users[0]
        for password in passwords:
            pairs.append(CredentialPair(username, password))
    elif mode == "single-pass":
        password = passwords[0]
        for username in users:
            pairs.append(CredentialPair(username, password))
    return pairs, mode


def has_automated_credential_spray(args: argparse.Namespace) -> bool:
    pairs, _ = build_credential_pairs(args)
    return bool(pairs)


def credential_args_for_attempt(
    args: argparse.Namespace,
    tool: str = "nxc",
    *,
    username: str = "",
    password: str = "",
) -> tuple[list[str], list[str]]:
    command_args: list[str] = []
    secrets: list[str] = []
    if args.domain:
        if tool in {"nxc", "crackmapexec"}:
            command_args.extend(["-d", args.domain])
        else:
            command_args.append(args.domain)
    if username:
        if tool in {"nxc", "crackmapexec"}:
            command_args.extend(["-u", username])
        else:
            command_args.append(username)
    if password:
        if tool in {"nxc", "crackmapexec"}:
            command_args.extend(["-p", password])
        else:
            command_args.append(password)
    if args.ntlm_hash:
        if tool in {"nxc", "crackmapexec"}:
            command_args.extend(["-H", args.ntlm_hash])
        else:
            command_args.append(args.ntlm_hash)
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
    username_display = pair.username or "(anonymous)"
    severity = "high" if protocol in {"smb", "rdp", "winrm", "mssql"} else "medium"
    auth_method = "ntlm-hash" if uses_hash and not pair.password else "password"
    description = (
        f"{tool} authentication accepted for {username_display} on "
        f"{service.protocol.upper()}/{service.port} (mode={mode}, method={auth_method})."
    )
    state.add_evidence(
        Evidence(
            category=category,
            ip=service.ip,
            port=service.port,
            service=protocol,
            title=f"Auth accepted: {username_display} ({protocol})",
            description=description,
            command=command,
            raw_output_file=raw_output_file,
            severity=severity,
            data={
                "auth_result": "accepted",
                "auth_mode": mode,
                "auth_method": auth_method,
                "username": pair.username,
                "password": pair.password,
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
    return sorted_services_unique(services)


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
    cred_args, secrets = credential_args_for_attempt(args, "nxc", username=pair.username, password=pair.password)
    if not cred_args and not uses_hash:
        return
    command = ["nxc", protocol, service.ip, "--port", str(service.port)] + cred_args
    slug = safe_filename(f"{pair.username}_{pair.password or 'hash'}")
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
    cred_args, secrets = credential_args_for_attempt(args, "crackmapexec", username=pair.username, password=pair.password)
    if not cred_args and not uses_hash:
        return
    command = ["crackmapexec", "smb", service.ip, "--port", str(service.port)] + cred_args
    slug = safe_filename(f"{pair.username}_{pair.password or 'hash'}")
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
        "-c",
        "\\q",
    ]
    slug = safe_filename(f"{pair.username}_{pair.password}")
    output_file = raw_dir / f"psql_{safe_filename(service.ip)}_{service.port}_{slug}.txt"
    result = run_command(
        command,
        timeout=command_timeout(THREAD_LEVELS[args.threads_level]["timeout"], args, multiplier=3.0),
        output_file=output_file,
        logger=logger,
        secrets=secrets,
        env=env,
    )
    combined = result.stdout + result.stderr
    lower = combined.lower()
    success = result.returncode == 0 and "authentication failed" not in lower and "password authentication failed" not in lower
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
    pairs, mode = build_credential_pairs(args)
    uses_hash = bool(args.ntlm_hash and not collect_credential_passwords(args))
    if not pairs:
        return
    users = collect_credential_usernames(args)
    passwords = collect_credential_passwords(args)
    warn_credential_list_size_mismatch(args, mode, users, passwords, logger, state)
    services = auth_capable_services(state)
    if not services:
        logger.info("No auth-capable services found for credential attempts")
        return
    state.metadata["credential_spray_mode"] = mode
    state.metadata["credential_spray_pairs"] = len(pairs)
    state.metadata["credential_lists_execute_automated_spray"] = True
    logger.info(
        f"Running credential attempts mode={mode} with {len(pairs)} pair(s) across "
        f"{len(services)} auth-capable service target(s)"
    )
    raw_dir = Path(state.output_dir) / RAW_DIR / "services" / "auth"
    raw_dir.mkdir(parents=True, exist_ok=True)
    for service in services:
        for pair in pairs:
            for protocol, tool in auth_protocols_for_service(service):
                if tool == "nxc":
                    run_nxc_auth_attempt(args, state, logger, raw_dir, service, protocol, pair, mode, uses_hash)
                elif tool == "crackmapexec":
                    run_crackmapexec_auth_attempt(args, state, logger, raw_dir, service, pair, mode, uses_hash)
                elif tool == "psql":
                    run_postgres_auth_attempt(args, state, logger, raw_dir, service, pair, mode)


def run_smb_ad_enum(args: argparse.Namespace, state: ScanState, logger: Logger) -> None:
    services = services_for_group(state, "SMB", {"tcp"})
    if not services:
        return
    raw_dir = Path(state.output_dir) / RAW_DIR / "services" / "smb"
    raw_dir.mkdir(parents=True, exist_ok=True)
    for service in services:
        ip = service.ip
        port = service.port
        if has_tool("nxc"):
            cred_args, secrets = credential_args(args, "nxc")
            command = ["nxc", "smb", ip, "--port", str(port)] + cred_args
            result = run_service_command(command, raw_dir / f"nxc_smb_{safe_filename(ip)}_{port}.txt", args, logger, secrets)
            add_tool_evidence(state, "smb", ip, port, "nxc smb", result, parse_smb_keywords(result.stdout + result.stderr))
            update_host_from_smb_text(state, ip, result.stdout + result.stderr)
            if args.username or args.password or args.ntlm_hash:
                shares_command = ["nxc", "smb", ip, "--port", str(port)] + cred_args + ["--shares"]
                shares_result = run_service_command(shares_command, raw_dir / f"nxc_smb_shares_{safe_filename(ip)}_{port}.txt", args, logger, secrets)
                add_tool_evidence(state, "smb", ip, port, "nxc smb shares", shares_result, parse_smb_keywords(shares_result.stdout + shares_result.stderr))
        if has_tool("crackmapexec"):
            cred_args, secrets = credential_args(args, "crackmapexec")
            command = ["crackmapexec", "smb", ip, "--port", str(port)] + cred_args
            result = run_service_command(command, raw_dir / f"cme_smb_{safe_filename(ip)}_{port}.txt", args, logger, secrets)
            add_tool_evidence(state, "smb", ip, port, "crackmapexec smb", result, parse_smb_keywords(result.stdout + result.stderr))
            update_host_from_smb_text(state, ip, result.stdout + result.stderr)
        if has_tool("smbclient"):
            command = ["smbclient", "-L", f"//{ip}", "-N", "-p", str(port)]
            result = run_service_command(command, raw_dir / f"smbclient_list_{safe_filename(ip)}_{port}.txt", args, logger, [])
            add_tool_evidence(state, "smb", ip, port, "smbclient anonymous list", result, parse_smb_keywords(result.stdout + result.stderr))
            if "Disk|" in result.stdout or "Sharename" in result.stdout:
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
                    )
                )
        if has_tool("impacket-smbclient"):
            impacket_input = raw_dir / f"impacket_smbclient_{safe_filename(ip)}_{port}.commands"
            impacket_input.write_text("shares\nexit\n", encoding="utf-8")
            command, secrets = build_impacket_smbclient_command(args, ip, port, impacket_input)
            result = run_service_command(command, raw_dir / f"impacket_smbclient_{safe_filename(ip)}_{port}.txt", args, logger, secrets)
            add_tool_evidence(state, "smb", ip, port, "impacket-smbclient shares", result, parse_smb_keywords(result.stdout + result.stderr))
        if has_tool("rpcclient"):
            command = ["rpcclient", "-U", "", "-N", ip, "-p", str(port), "-c", "srvinfo"]
            result = run_service_command(command, raw_dir / f"rpcclient_srvinfo_{safe_filename(ip)}_{port}.txt", args, logger, [])
            add_tool_evidence(state, "rpc", ip, port, "rpcclient srvinfo", result, parse_smb_keywords(result.stdout + result.stderr))
            update_host_from_smb_text(state, ip, result.stdout + result.stderr)
    run_ad_discovery_helpers(args, state, logger)


def build_impacket_smbclient_command(args: argparse.Namespace, ip: str, port: int, input_file: Path) -> tuple[list[str], list[str]]:
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
    if args.domain and args.username:
        target = f"{args.domain}/{args.username}"
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
            cred_args, secrets = credential_args(args, "nxc")
            command = ["nxc", "ldap", dc_ip, "--port", str(port)] + cred_args
            result = run_service_command(command, raw_dir / f"nxc_ldap_{safe_filename(dc_ip)}_{port}.txt", args, logger, secrets)
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
            cred_args, secrets = credential_args(args, "nxc")
            command = ["nxc", "rdp", ip, "--port", str(port)] + cred_args
            result = run_service_command(command, raw_dir / f"nxc_rdp_{safe_filename(ip)}_{port}.txt", args, logger, secrets)
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
        run_ftp_auth_attempts(args, state, logger, raw_dir, service)
        if has_tool("nxc"):
            cred_args, secrets = credential_args(args, "nxc")
            command = ["nxc", "ftp", ip, "--port", str(port)] + cred_args
            result = run_service_command(command, raw_dir / f"nxc_ftp_{safe_filename(ip)}_{port}.txt", args, logger, secrets)
            add_tool_evidence(state, "ftp", ip, port, "nxc ftp", result, parse_generic_keywords(result.stdout + result.stderr))


def run_ftp_auth_attempts(
    args: argparse.Namespace,
    state: ScanState,
    logger: Logger,
    raw_dir: Path,
    service: ServiceRecord,
) -> None:
    pairs, mode = build_credential_pairs(args)
    attempts: list[tuple[str, str, str]] = [
        ("anonymous", "anonymous@", "anonymous"),
        ("ftp", "ftp", "anonymous"),
    ]
    seen = {(username, password) for username, password, _ in attempts}
    for pair in pairs:
        key = (pair.username, pair.password)
        if key not in seen:
            attempts.append((pair.username, pair.password, mode))
            seen.add(key)
    timeout = THREAD_LEVELS[args.threads_level]["timeout"]
    for username, password, attempt_mode in attempts:
        success, transcript = try_ftp_login(service.ip, service.port, username, password, timeout)
        raw_file = raw_dir / f"ftp_auth_{safe_filename(service.ip)}_{service.port}_{safe_filename(username)}.txt"
        raw_file.write_text(transcript, encoding="utf-8", errors="replace")
        if not success:
            logger.debug(f"FTP auth rejected for {service.ip}:{service.port} with {username}")
        record_auth_attempt_evidence(
            state,
            service,
            category="ftp",
            protocol="ftp",
            tool="ftp",
            pair=CredentialPair(username, password),
            mode=attempt_mode,
            success=success,
            command=f"ftp {service.ip} {service.port} # user={username}",
            raw_output_file=relpath(raw_file, state.output_dir),
            transcript=transcript,
        )


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
                cred_args, secrets = credential_args(args, "nxc")
                command = ["nxc", "mssql", service.ip, "--port", str(service.port)] + cred_args
                result = run_service_command(command, raw_dir / f"nxc_mssql_{safe_filename(service.ip)}_{service.port}.txt", args, logger, secrets)
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
    if not args.kerberos_realm:
        logger.warn("--enable-user-enum requires --kerberos-realm; skipping Kerberos user enum")
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
    script_args = [f"krb5-enum-users.realm={args.kerberos_realm}"]
    if args.user_enum_wordlist:
        script_args.append(f"userdb={args.user_enum_wordlist}")
    for service in services:
        ip = service.ip
        port = service.port
        command = [
            "nmap",
            "-Pn",
            "-p",
            str(port),
            "--script",
            "krb5-enum-users",
            "--script-args",
            ",".join(script_args),
            ip,
        ]
        result = run_service_command(command, raw_dir / f"nmap_krb5_enum_users_{safe_filename(ip)}_{port}.txt", args, logger, [])
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
    realm = resolve_kerberos_realm(args, state)
    if not realm:
        logger.warn("No Kerberos realm available (use --kerberos-realm or ensure domain is discovered); skipping kerbrute")
        return
    wordlist = resolve_kerbrute_wordlist(args)
    if not wordlist:
        logger.warn("No kerbrute user wordlist found in SecLists paths; skipping kerbrute userenum")
        return
    raw_dir = Path(state.output_dir) / RAW_DIR / "services" / "kerberos"
    raw_dir.mkdir(parents=True, exist_ok=True)
    logger.info(f"Running kerbrute userenum against {len(services)} Kerberos target(s) with realm {realm}")
    seen_ips: set[str] = set()
    for service in services:
        ip = service.ip
        if ip in seen_ips:
            continue
        seen_ips.add(ip)
        port = service.port
        command = ["kerbrute", "userenum", "--dc", f"{ip}:{port}", "-d", realm, str(wordlist)]
        result = run_service_command(command, raw_dir / f"kerbrute_userenum_{safe_filename(ip)}_{port}.txt", args, logger, [])
        parsed = parse_kerbrute_results(result.stdout + result.stderr)
        add_tool_evidence(state, "kerberos", ip, port, "kerbrute userenum", result, parsed)


def resolve_kerberos_realm(args: argparse.Namespace, state: ScanState) -> str:
    """Determine Kerberos realm: explicit CLI > discovered domain from hosts."""
    if getattr(args, "kerberos_realm", None):
        return args.kerberos_realm
    hosts = list(state.hosts.values())
    domains = discovered_local_domains(hosts)
    if domains:
        return domains[0].upper()
    for host in hosts:
        if host.domain:
            return host.domain.strip().strip(".").upper()
    return ""


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
    command_str = shell_join(result.command)
    if "description" in parsed:
        description = parsed.pop("description")
    else:
        description = f"Comando manual: `{command_str}`"
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
            command=shell_join(result.command),
            raw_output_file=relpath(result.output_file or "", state.output_dir),
            severity=severity,
            data=parsed,
        )
    )


def parse_smb_keywords(text: str) -> dict[str, Any]:
    parsed: dict[str, Any] = {}
    lower = text.lower()
    if "signing: false" in lower or "smb signing disabled" in lower or "message signing disabled" in lower:
        parsed["severity"] = "medium"
        parsed["description"] = "SMB signing appears disabled or not required."
        parsed["smb_signing"] = "disabled_or_not_required"
    elif "signing:" in lower:
        parsed["smb_signing"] = extract_after(text, "signing:")
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
    hostname = extract_regex(text, r"(?:name|hostname|computer name)[:=]\s*([A-Za-z0-9_.-]+)")
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
    hosts = sorted(state.hosts.values(), key=lambda item: ip_sort_key(item.ip))
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
      {overview_panel(hosts, services, web_endpoints, evidence)}
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
      {table_section("Hosts", hosts_table(hosts), len(hosts))}
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
    report_path.write_text(html_text, encoding="utf-8")
    return report_path


def h(value: Any) -> str:
    return html.escape(str(value if value is not None else ""), quote=True)


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
        <div class="panel">
          <h2>Mapa Rápido</h2>
          <div class="kv-grid">
            <div class="kv"><span>Domínios locais</span><div>{domain_summary_html(local_domains)}</div></div>
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


def domain_summary_html(domains: list[str]) -> str:
    if not domains:
        return h("-")
    shown = domains[:8]
    extra = len(domains) - len(shown)
    extra_html = f'<span class="pill">+{h(extra)}</span>' if extra > 0 else ""
    return pill_list(shown) + extra_html


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
        hosts = sorted({service.ip for service in group_services}, key=ip_sort_key)
        group_endpoints = [
            endpoint
            for service in group_services
            for endpoint in endpoints_by_host_port.get((service.ip, service.port), [])
        ]
        group_evidence = [
            item
            for host in hosts
            for item in evidence_by_host.get(host, [])
            if evidence_matches_service_group(item, group_name, group_services)
        ]
        group_enum_evidence = [item for item in group_evidence if not is_group_enum_noise_evidence(item)]
        filter_text = row_filter(
            group_name,
            hosts,
            [service.service for service in group_services],
            [service.port for service in group_services],
            [endpoint.url for endpoint in group_endpoints],
        )
        rows.append(
            f'<details class="group-item" data-filter="{filter_text}" data-service="{h(group_name)}">'
            "<summary>"
            f'<span class="summary-title"><strong>{h(group_name)}</strong></span>'
            '<span class="summary-pills">'
            f'{metric_pill("hosts", len(hosts))}'
            f'{metric_pill("serviços", len(group_services))}'
            f'{metric_pill("web", len(group_endpoints))}'
            f'{metric_pill("evidências", len(group_enum_evidence))}'
            "</span>"
            "</summary>"
            '<div class="group-body">'
            f"{service_group_actions(group_name, group_services)}"
            f"{service_group_body(group_name, group_services, group_endpoints, endpoints_by_host_port, state)}"
            f"{grouped_enumeration_details_block(group_enum_evidence, state, title='Informações de Enumeração do Grupo')}"
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
        return smb_service_group_table(services, endpoints_by_host_port, state)
    return service_group_table(services, endpoints_by_host_port, state)


def service_group_actions(group_name: str, services: list[ServiceRecord]) -> str:
    targets = service_group_targets(services)
    if not targets:
        return ""
    command_buttons = service_group_command_buttons(services)
    return (
        '<div class="service-group-actions">'
        f'<span class="muted">{h(group_name)}: {h(len(targets))} alvo(s) ativo(s)</span>'
        f'<div class="copy-actions">{copy_commands_button("Copiar IP:porta", targets)}{copy_commands_button("Copiar IPs", service_group_ips(services))}{command_buttons}</div>'
        "</div>"
    )


def service_group_command_buttons(services: list[ServiceRecord]) -> str:
    sorted_services = sorted_services_unique(services)
    commands_by_tool: dict[str, list[tuple[ServiceRecord, list[str]]]] = {}
    for service in sorted_services:
        for tool, commands in service_primary_commands_by_tool(service).items():
            commands_by_tool.setdefault(tool, []).append((service, commands))
    buttons: list[str] = []
    for tool, entries in commands_by_tool.items():
        tool_services = [service for service, commands in entries if commands]
        if len(tool_services) > 1:
            loop_command = service_tool_loop_command(tool, tool_services)
            if loop_command:
                buttons.append(copy_commands_button(tool, [loop_command]))
                continue
        commands: list[str] = []
        for _, service_commands in entries:
            commands.extend(service_commands)
        buttons.append(copy_commands_button(tool, dedupe_text(commands), loop_multiple=True))
    return "".join(buttons)


def service_group_targets(services: list[ServiceRecord]) -> list[str]:
    values = [
        host_port_value(service.ip, service.port)
        for service in sorted(services, key=lambda item: (ip_sort_key(item.ip), item.port, item.protocol))
    ]
    return dedupe_text(values)


def service_group_ips(services: list[ServiceRecord]) -> list[str]:
    return dedupe_text(service.ip for service in sorted(services, key=lambda item: (ip_sort_key(item.ip), item.port, item.protocol)))


def service_tool_loop_command(tool: str, services: list[ServiceRecord]) -> str:
    unique_services = sorted_services_unique(services)
    specs = " ".join(shlex_quote(service_loop_spec(tool, service)) for service in unique_services)
    if not specs:
        return ""
    body = service_tool_loop_body(tool)
    if not body:
        return ""
    log_file = f"birdscan-{safe_filename(tool.lower())}-all-targets.txt"
    setup = 'IFS="|" read -r ip port proto extra <<< "$spec"; host="$ip"; case "$host" in *:*) host="[$host]";; esac'
    return f'for spec in {specs}; do {setup}; {body}; done 2>&1 | tee -a {shlex_quote(log_file)}'


def service_loop_spec(tool: str, service: ServiceRecord) -> str:
    parts = [service.ip, str(service.port), service.protocol, ""]
    if tool == "Nmap NSE":
        parts[-1] = service_nmap_scripts(service)
    return "|".join(parts)


def h_shell_label(value: str) -> str:
    return value.replace('"', "'")


def service_tool_loop_body(tool: str) -> str:
    bodies = {
        "Nmap Versão": 'udp=""; case "$proto" in udp) udp="-sU";; esac; nmap $udp -sV --version-all --reason -Pn -p "$port" "$ip"',
        "Nmap NSE": 'udp=""; case "$proto" in udp) udp="-sU";; esac; nmap $udp -sV -Pn -p "$port" --script "$extra" "$ip"',
        "NetCat": 'nc -nv "$ip" "$port"',
        "CURL": 'scheme="http"; case "$port" in 443|8443|9443|5986|2376) scheme="https";; esac; curl -k -i -L --max-time 10 -A Mozilla/5.0 "${scheme}://${host}:${port}/"',
        "WhatWeb": 'scheme="http"; case "$port" in 443|8443|9443|5986|2376) scheme="https";; esac; whatweb --no-errors "${scheme}://${host}:${port}/"',
        "SMBClient": 'smbclient -L "//$ip" -N -p "$port"',
        "NXC": 'nxc smb "$ip" --port "$port" --shares',
        "CrackMapExec": 'crackmapexec smb "$ip" --port "$port" --shares',
        "RPCClient": 'rpcclient -U "" -N "$ip" -p "$port" -c srvinfo',
        "Impacket": 'printf "shares\\nexit\\n" | impacket-smbclient -port "$port" -no-pass "$ip"',
        "XFreeRDP": 'xfreerdp /v:"$ip:$port" /cert:ignore /dynamic-resolution',
        "RDesktop": 'rdesktop "$ip:$port"',
        "NXC RDP": 'nxc rdp "$ip" --port "$port"',
        "SSH": 'ssh -p "$port" "user@$ip"',
        "FTP anonymous": 'printf "anonymous\\nanonymous\\npwd\\nls\\nbye\\n" | ftp -inv -p "$ip" "$port"',
        "FTP ftp": 'printf "ftp\\nftp\\npwd\\nls\\nbye\\n" | ftp -inv -p "$ip" "$port"',
        "LFTP anon": 'lftp -u anonymous,anonymous -p "$port" "$ip" -e "pwd; ls; bye"',
        "LFTP ftp": 'lftp -u ftp,ftp -p "$port" "$ip" -e "pwd; ls; bye"',
        "NXC FTP": 'nxc ftp "$ip" --port "$port"',
        "LDAPSearch": 'scheme="ldap"; case "$port" in 636|3269) scheme="ldaps";; esac; ldapsearch -x -H "${scheme}://${host}:${port}" -s base',
        "NXC LDAP": 'nxc ldap "$ip" --port "$port"',
        "KRB5 info": 'nmap -sV -Pn -p "$port" --script krb5-info "$ip"',
        "Kerbrute userenum": 'kerbrute userenum --dc "$ip:$port" -d "$extra" /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt',
        "Kerbrute passwordspray": 'kerbrute passwordspray --dc "$ip:$port" -d "$extra" /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt Senha123!',
        "Impacket GetNPUsers": 'impacket-GetNPUsers "$extra"/ -no-pass -usersfile lista-de-user-valido.txt -format hashcat -outputfile hashes-found.txt -dc-ip "$ip"',
        "MySQL": 'mysql -h "$ip" -P "$port" -u root -p',
        "Postgres": 'psql -h "$ip" -p "$port" -U postgres',
        "MSSQL": 'impacket-mssqlclient -port "$port" user:pass@"$ip"; nxc mssql "$ip" --port "$port"',
        "NXC MSSQL": 'nxc mssql "$ip" --port "$port"',
        "Redis": 'redis-cli -h "$ip" -p "$port" INFO',
        "Mongo": 'mongosh --host "$ip" --port "$port"',
        "Elastic": 'curl -s "http://${host}:${port}/_cluster/health?pretty"',
        "Evil-WinRM": 'evil-winrm -i "$ip" -P "$port" -u user -p password',
        "NXC WinRM": 'nxc winrm "$ip" --port "$port"',
        "Showmount": 'showmount -e "$ip"',
        "RPCInfo": 'rpcinfo -p "$ip"',
        "SNMPWalk": 'snmpwalk -v2c -c public "udp:${ip}:${port}"',
        "VNCViewer": 'vncviewer "$ip::$port"',
        "CURL HTTPS": 'curl -k -i "https://${host}:${port}/version"',
        "CURL HTTP": 'curl -i "http://${host}:${port}/version"',
        "Telnet": 'telnet "$ip" "$port"',
        "Swaks": 'swaks --server "$ip" --port "$port" --quit-after HELO',
        "OpenSSL": 'openssl s_client -connect "$ip:$port" -servername "$ip"',
        "DIG version": 'dig @"$ip" -p "$port" version.bind chaos txt',
        "DIG AXFR": 'dig @"$ip" -p "$port" axfr domain.local',
    }
    return bodies.get(tool, "")


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
            f"<td>{service_interaction_buttons(service)}</td>"
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
            f'<div class="kv"><span>Interação</span><div>{service_interaction_buttons(service)}</div></div>'
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
    rows = [
        '<div class="table-wrap"><table><thead><tr><th>Host</th><th>Porta</th><th>Serviço</th><th>Produto</th><th>Web</th><th>Interação</th></tr></thead><tbody>'
    ]
    for service in sorted(services, key=lambda item: (ip_sort_key(item.ip), item.port)):
        host = state.hosts.get(service.ip, HostRecord(ip=service.ip))
        hostname = host.hostname or host.fqdn
        service_endpoints = endpoints_by_host_port.get((service.ip, service.port), [])
        endpoint_links = " ".join(endpoint.url for endpoint in service_endpoints)
        endpoint_links_html = web_dropdown_for_service(service_endpoints, state)
        rows.append(
            f'<tr data-filter="{row_filter(service.ip, hostname, service.port, service.protocol, service.service, service.product, service.version, endpoint_links)}" '
            f'data-service="{h(service.service or service_group_name(service))}">'
            f'<td><span class="mono">{h(service.ip)}</span><br><span class="muted">{h(hostname)}</span></td>'
            f'<td class="mono nowrap">{h(service.port)}/{h(service.protocol)}</td>'
            f"<td>{h(service.service or service_group_name(service))}</td>"
            f"<td>{h(service_descriptor(service) or '-')}</td>"
            f"<td>{endpoint_links_html}</td>"
            f"<td>{service_interaction_buttons(service)}</td>"
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
    auth_status = detect_smb_auth_status_from_evidence(state)
    shares_status = detect_smb_shares_from_evidence(state)
    rows = [
        '<div class="table-wrap"><table><thead><tr><th>Host</th><th>Porta</th><th>Serviço</th><th>Produto</th><th>SMBv1</th><th>Auth</th><th>Shares</th><th>Web</th><th>Interação</th></tr></thead><tbody>'
    ]
    for service in sorted(services, key=lambda item: (ip_sort_key(item.ip), item.port)):
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
        auth_label = auth_status.get(smbv1_key, "")
        if auth_label:
            auth_html = f'<span class="sev-medium" style="font-weight:800">✓ {h(auth_label)}</span>'
        else:
            auth_html = '<span class="muted">-</span>'
        shares_found = shares_status.get(smbv1_key, False)
        if shares_found:
            shares_anchor = f"shares-{safe_filename(service.ip)}-{service.port}"
            shares_html = f'<a href="#{h(shares_anchor)}" class="sev-medium" style="font-weight:800">✓ Shares</a>'
        else:
            shares_html = '<span class="muted">-</span>'
        rows.append(
            f'<tr data-filter="{row_filter(service.ip, hostname, service.port, service.protocol, service.service, service.product, service.version, endpoint_links, "smbv1" if smbv1_enabled else "", auth_label, "shares" if shares_found else "")}" '
            f'data-service="{h(service.service or service_group_name(service))}">'
            f'<td><span class="mono">{h(service.ip)}</span><br><span class="muted">{h(hostname)}</span></td>'
            f'<td class="mono nowrap">{h(service.port)}/{h(service.protocol)}</td>'
            f"<td>{h(service.service or service_group_name(service))}</td>"
            f"<td>{h(service_descriptor(service) or '-')}</td>"
            f"<td>{smbv1_html}</td>"
            f"<td>{auth_html}</td>"
            f"<td>{shares_html}</td>"
            f"<td>{endpoint_links_html}</td>"
            f"<td>{service_interaction_buttons(service)}</td>"
            "</tr>"
        )
    rows.append("</tbody></table></div>")
    return "\n".join(rows)


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


def detect_smb_auth_status_from_evidence(state: ScanState) -> dict[tuple[str, int], str]:
    """Return auth status label per SMB IP:port from evidence data."""
    result: dict[tuple[str, int], str] = {}
    for item in state.evidence:
        if item.port is None:
            continue
        key = (item.ip, item.port)
        if key in result:
            continue
        # Check for successful auth evidence
        if item.data.get("auth_result") == "accepted" and item.data.get("protocol") in {"smb", "smb/shares"}:
            username = item.data.get("username", "")
            if not username or username in {"", "anonymous", "guest"}:
                result[key] = "anonymous"
            else:
                password = item.data.get("password", "")
                if password:
                    result[key] = f"{username}:{password}"
                else:
                    result[key] = username
            continue
        # Check for anonymous/null session in parsed SMB data
        if item.category == "smb" and item.data.get("anonymous_or_null_session"):
            result[key] = "anonymous/null"
    return result


def detect_smb_shares_from_evidence(state: ScanState) -> dict[tuple[str, int], bool]:
    """Return True per SMB IP:port if shares were discovered."""
    result: dict[tuple[str, int], bool] = {}
    for item in state.evidence:
        if item.category != "smb" or item.port is None:
            continue
        key = (item.ip, item.port)
        if key in result:
            continue
        title_lower = item.title.lower()
        desc_lower = item.description.lower()
        if "shares" in title_lower and ("visible" in title_lower or "listing" in desc_lower or "share" in desc_lower):
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
        grouped.setdefault(item.title or item.service or item.category, []).append(item)
    rows = [
        '<details class="enum-details">',
        f'<summary>{h(title)} <span class="metric"><strong>{h(len(grouped))}</strong>grupos</span></summary>',
        '<div class="enum-list">',
    ]
    for group_title, group_items in sorted(grouped.items(), key=lambda entry: (severity_rank(group_severity(entry[1])), entry[0])):
        sorted_items = sorted(group_items, key=lambda entry: (ip_sort_key(entry.ip), entry.port or 0, entry.category, entry.service))
        hosts = sorted({item.ip for item in sorted_items}, key=ip_sort_key)
        ports = sorted({item.port for item in sorted_items if item.port})
        categories = sorted({item.category for item in sorted_items if item.category})
        raw = grouped_raw_details(group_title, sorted_items, state)
        descriptions = grouped_evidence_descriptions(sorted_items)
        rows.append(
            '<details class="enum-item">'
            "<summary>"
            f'<span><strong>{h(group_title)}</strong><br><span class="muted mono">{h(", ".join(categories) or "-")} · {h(len(hosts))} host(s) · {h(len(ports))} porta(s)</span></span>'
            f'<span class="metric"><strong>{h(group_severity(sorted_items))}</strong>nível</span>'
            "</summary>"
            '<div class="enum-body">'
            f'{descriptions}'
            f'{raw}'
            "</div>"
            "</details>"
        )
    rows.append("</div></details>")
    return "\n".join(rows)


def group_severity(items: list[Evidence]) -> str:
    if not items:
        return "info"
    return sorted({item.severity for item in items}, key=severity_rank)[0]


def grouped_evidence_descriptions(items: list[Evidence]) -> str:
    rows = ['<div class="enum-target-list">']
    for item in items:
        target = item.ip + (f":{item.port}" if item.port else "")
        rows.append(
            f'<div class="enum-target-row"><span class="mono">{h(target)}</span>'
            f'<span class="pill sev-{h(item.severity)}">{h(item.severity)}</span>'
            f'<span>{h(item.description or item.service or item.category)}</span></div>'
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
    command_text = evidence_group_command_text(title, items)
    return raw_details_html("RAW agregado", "\n".join(chunks).rstrip() + "\n", command=command_text, meta=title)


def evidence_group_command_text(title: str, items: list[Evidence]) -> str:
    services = [
        ServiceRecord(ip=item.ip, port=int(item.port), protocol="tcp", service=item.service or item.category)
        for item in items
        if item.port
    ]
    tool = evidence_title_tool_label(title)
    if tool and len(services) > 1:
        loop_command = service_tool_loop_command(tool, services)
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
        return candidate.read_text(encoding="utf-8", errors="replace")
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
            f'count=0; for url in {target_values}; do count=$((count+1)); '
            f'gobuster dir -u "$url" -w {shlex_quote(gobuster_wordlist)} -k -t {thread_count} -e --no-error -r '
            f'-o "fuzz-gobuster-$count.txt" -a Mozilla/5.0 --exclude-length 123456 -x {DASHBOARD_EXTENSIONS_CSV}; '
            "done 2>&1 | tee -a fuzzing-gobuster-all-web.txt"
        ),
        "Feroxbuster": (
            f'count=0; for url in {target_values}; do count=$((count+1)); '
            f'feroxbuster --insecure --url "$url" --methods GET,POST -r -A -w {shlex_quote(DASHBOARD_BIG_WORDLIST)} '
            f'-o "fuzz-feroxbuster-$count.txt" -x {DASHBOARD_EXTENSIONS_SPACE}; '
            "done 2>&1 | tee -a fuzzing-feroxbuster-all-web.txt"
        ),
        "Dirsearch": (
            f'count=0; for url in {target_values}; do count=$((count+1)); '
            f'dirsearch -u "$url" --crawl --full-url -t {thread_count} --user-agent Mozilla/5.0 '
            f'-e {DASHBOARD_EXTENSIONS_CSV} -o "fuzz-dirsearch-$count.txt"; '
            "done 2>&1 | tee -a fuzzing-dirsearch-all-web.txt"
        ),
        "FFUF": (
            f'count=0; for url in {target_values}; do count=$((count+1)); fuzz_url="${{url%/}}/FUZZ"; '
            f'ffuf -u "$fuzz_url" -w {shlex_quote(DASHBOARD_BIG_WORDLIST)} -c -t 100 -e {DASHBOARD_EXTENSIONS_DOT} '
            f'-o "output-$count.html" -of html; '
            "done 2>&1 | tee -a fuzzing-ffuf-all-web.txt"
        ),
        "Dirb": (
            f'count=0; for url in {target_values}; do count=$((count+1)); '
            f'dirb "$url" {shlex_quote(DASHBOARD_SECLISTS_BIG_WORDLIST)} -a Mozilla/5.0 -X {DASHBOARD_EXTENSIONS_DOT} '
            f'-o "dirb-$count.txt"; '
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


def service_interaction_buttons(service: ServiceRecord) -> str:
    by_tool = service_primary_commands_by_tool(service)
    buttons: list[str] = []
    if service_group_name(service) == "WEB":
        buttons.append(open_url_button("Abrir", build_url(preferred_scheme_for_service(service), service.ip, service.port, "/")))
    buttons.extend(copy_commands_button(label, commands, loop_multiple=True) for label, commands in by_tool.items())
    return '<div class="copy-actions">' + "".join(buttons) + "</div>"


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


def service_primary_commands_by_tool(service: ServiceRecord) -> dict[str, list[str]]:
    ip = service.ip
    port = service.port
    group = service_group_name(service)
    netcat = f"nc -nv {shlex_quote(ip)} {port}"
    commands: dict[str, list[str]] = {
        "Nmap Versão": [service_nmap_command(service)],
        "Nmap NSE": [service_nmap_script_command(service)],
    }
    if service.protocol == "tcp":
        commands["NetCat"] = [netcat]
    if group == "WEB":
        scheme = preferred_scheme_for_service(service)
        url = build_url(scheme, ip, port, "/")
        commands.update({
            "CURL": [f"curl -k -i -L --max-time 10 -A Mozilla/5.0 {shlex_quote(url)}"],
            "WhatWeb": [f"whatweb --no-errors {shlex_quote(url)}"],
        })
        return commands
    if group == "SMB":
        commands.update({
            "SMBClient": [f"smbclient -L //{shlex_quote(ip)} -N -p {port}"],
            "NXC": [f"nxc smb {shlex_quote(ip)} --port {port} --shares"],
            "CrackMapExec": [f"crackmapexec smb {shlex_quote(ip)} --port {port} --shares"],
            "RPCClient": [f"rpcclient -U '' -N {shlex_quote(ip)} -p {port} -c srvinfo"],
            "Impacket": [f"printf 'shares\\nexit\\n' | impacket-smbclient -port {port} -no-pass {shlex_quote(ip)}"],
        })
        return commands
    if group == "RDP":
        commands.update({
            "XFreeRDP": [f"xfreerdp /v:{ip}:{port} /cert:ignore /dynamic-resolution"],
            "RDesktop": [f"rdesktop {ip}:{port}"],
            "NXC RDP": [f"nxc rdp {shlex_quote(ip)} --port {port}"],
        })
        return commands
    if group == "SSH":
        commands["SSH"] = [f"ssh -p {port} user@{shlex_quote(ip)}"]
        return commands
    if group == "FTP":
        commands.update({
            "FTP anonymous": [f"printf 'anonymous\\nanonymous\\npwd\\nls\\nbye\\n' | ftp -inv -p {shlex_quote(ip)} {port}"],
            "FTP ftp": [f"printf 'ftp\\nftp\\npwd\\nls\\nbye\\n' | ftp -inv -p {shlex_quote(ip)} {port}"],
            "LFTP anon": [f"lftp -u anonymous,anonymous -p {port} {shlex_quote(ip)} -e 'pwd; ls; bye'"],
            "LFTP ftp": [f"lftp -u ftp,ftp -p {port} {shlex_quote(ip)} -e 'pwd; ls; bye'"],
            "NXC FTP": [f"nxc ftp {shlex_quote(ip)} --port {port}"],
        })
        return commands
    if group == "LDAP/AD":
        ldap_scheme = "ldaps" if port in {636, 3269} else "ldap"
        commands.update({
            "LDAPSearch": [f"ldapsearch -x -H {ldap_scheme}://{ip}:{port} -s base"],
            "NXC LDAP": [f"nxc ldap {shlex_quote(ip)} --port {port}"],
        })
        return commands
    if group == "KERBEROS":
        commands["KRB5 info"] = [f"nmap -sV -Pn -p {port} --script krb5-info {shlex_quote(ip)}"]
        realm = "DOMAIN.LOCAL"
        kerbrute_wordlist = "/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt"
        bruteuser_wordlist = "/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt"
        commands["Kerbrute userenum"] = [f"kerbrute userenum --dc {shlex_quote(ip)}:{port} -d {realm} {shlex_quote(kerbrute_wordlist)}"]
        commands["Kerbrute passwordspray"] = [f"kerbrute passwordspray --dc {shlex_quote(ip)}:{port} -d {realm} {shlex_quote(kerbrute_wordlist)} Senha123!"]
        commands["Impacket GetNPUsers"] = [f"impacket-GetNPUsers {realm}/ -no-pass -usersfile lista-de-user-valido.txt -format hashcat -outputfile hashes-found.txt -dc-ip {shlex_quote(ip)}"]
        return commands
    if group == "DATABASE/DATA":
        service_name = (service.service or "").lower()
        if port in MYSQL_PORTS or "mysql" in service_name:
            commands["MySQL"] = [f"mysql -h {shlex_quote(ip)} -P {port} -u root -p"]
        if port in POSTGRES_PORTS or "postgres" in service_name:
            commands["Postgres"] = [f"psql -h {shlex_quote(ip)} -p {port} -U postgres"]
        if port in MSSQL_PORTS or "ms-sql" in service_name or "mssql" in service_name:
            commands["MSSQL"] = [f"impacket-mssqlclient -port {port} user:pass@{shlex_quote(ip)}", f"nxc mssql {shlex_quote(ip)} --port {port}"]
        if port in REDIS_PORTS or "redis" in service_name:
            commands["Redis"] = [f"redis-cli -h {shlex_quote(ip)} -p {port} INFO"]
        if port in MONGO_PORTS or "mongo" in service_name:
            commands["Mongo"] = [f"mongosh --host {shlex_quote(ip)} --port {port}"]
        if port in ELASTIC_PORTS or "elastic" in service_name:
            commands["Elastic"] = [f"curl -s {shlex_quote(build_url('http', ip, port, '/_cluster/health?pretty'))}"]
        return commands
    if group == "WINRM":
        commands.update({
            "Evil-WinRM": [f"evil-winrm -i {shlex_quote(ip)} -P {port} -u user -p 'password'"],
            "NXC WinRM": [f"nxc winrm {shlex_quote(ip)} --port {port}"],
            "CURL": [f"curl -k -i --max-time 10 {shlex_quote(build_url('https' if port == 5986 else 'http', ip, port, '/wsman'))}"],
        })
        return commands
    if group == "NFS/RPC":
        commands.update({
            "Showmount": [f"showmount -e {shlex_quote(ip)}"],
            "RPCInfo": [f"rpcinfo -p {shlex_quote(ip)}"],
        })
        return commands
    if group == "SNMP":
        commands["SNMPWalk"] = [f"snmpwalk -v2c -c public udp:{shlex_quote(ip)}:{port}"]
        return commands
    if group == "VNC":
        commands["VNCViewer"] = [f"vncviewer {ip}::{port}"]
        return commands
    if group == "CONTAINER":
        commands.update({
            "CURL HTTPS": [f"curl -k -i {shlex_quote(build_url('https', ip, port, '/version'))}"],
            "CURL HTTP": [f"curl -i {shlex_quote(build_url('http', ip, port, '/version'))}"],
        })
        return commands
    if group == "TELNET":
        commands["Telnet"] = [f"telnet {shlex_quote(ip)} {port}"]
        return commands
    if group == "MAIL":
        commands.update({
            "Swaks": [f"swaks --server {shlex_quote(ip)} --port {port} --quit-after HELO"],
            "OpenSSL": [f"openssl s_client -connect {ip}:{port} -servername {ip}"],
        })
        return commands
    if group == "DNS":
        commands.update({
            "DIG version": [f"dig @{shlex_quote(ip)} -p {port} version.bind chaos txt"],
            "DIG AXFR": [f"dig @{shlex_quote(ip)} -p {port} axfr domain.local"],
        })
        return commands
    commands["NetCat"] = [netcat]
    return commands


def dedupe_text(values: Iterable[str]) -> list[str]:
    result: list[str] = []
    for value in values:
        if value and value not in result:
            result.append(value)
    return result


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
        return (0, ipaddress.ip_address(value))
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
            f"<td>{h(service.version)}</td><td>{service_interaction_buttons(service)}</td></tr>"
        )
    rows.append("</tbody></table>")
    return "\n".join(rows)


def hosts_table(hosts: list[HostRecord]) -> str:
    rows = [
        "<table><thead><tr><th>IP</th><th>Hostname</th><th>Aliases</th><th>FQDN</th><th>Domínio</th><th>OS Guess</th><th>Tags</th><th>Ações</th></tr></thead><tbody>"
    ]
    for host in hosts:
        aliases = " ".join(f'<span class="pill">{h(item)}</span>' for item in host.aliases)
        tags = " ".join(f'<span class="pill">{h(item)}</span>' for item in host.tags)
        hostnames = "\n".join(item for item in [host.hostname, host.fqdn, *host.aliases] if item)
        actions = copy_value_button("Copiar IP", host.ip) + copy_value_button("Copiar hostnames", hostnames)
        rows.append(
            f'<tr data-filter="{row_filter(host.ip, host.hostname, host.aliases, host.fqdn, host.domain, host.os_guess, host.tags, host.sources)}">'
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
    gobuster_commands = fuzz_commands_by_tool("http://10.10.10.50:8080/").get("Gobuster", [])
    ftp_commands = service_primary_commands_by_tool(ServiceRecord(ip="10.10.10.50", port=21, service="ftp"))
    smb_commands = service_primary_commands_by_tool(ServiceRecord(ip="10.10.10.60", port=139, service="netbios-ssn"))
    rdp_commands = service_primary_commands_by_tool(ServiceRecord(ip="10.10.10.30", port=3390, service="ms-wbt-server"))
    ssh_commands = service_primary_commands_by_tool(ServiceRecord(ip="10.10.10.50", port=2222, service="ssh"))
    ldap_commands = service_primary_commands_by_tool(ServiceRecord(ip="10.10.10.40", port=636, service="ldaps"))
    kerberos_commands = service_primary_commands_by_tool(ServiceRecord(ip="10.10.10.40", port=88, service="kerberos"))
    mssql_commands = service_primary_commands_by_tool(ServiceRecord(ip="10.10.10.20", port=1444, service="ms-sql-s"))
    winrm_commands = service_primary_commands_by_tool(ServiceRecord(ip="10.10.10.70", port=5986, service="wsmans"))
    generic_nmap_commands = service_primary_commands_by_tool(ServiceRecord(ip="10.10.10.93", port=12345, service="unknown"))
    group_action_html = service_group_actions(
        "RDP",
        [
            ServiceRecord(ip="10.10.10.30", port=3390, service="ms-wbt-server"),
            ServiceRecord(ip="10.10.10.31", port=3391, service="ms-wbt-server"),
        ],
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
    rdp_grouped_html = grouped_enumeration_details_block(rdp_filtered_evidence, state, title="Informações de Enumeração do Grupo")
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

    checks = [
        ("hosts", len(state.hosts) == 5, f"expected 5 hosts, got {len(state.hosts)}"),
        ("services", len(state.services) == 7, f"expected 7 services, got {len(state.services)}"),
        ("default-nmap", default_nmap_command[:9] == ["sudo", "nmap", "--open", "-Pn", "-p-", "-sC", "-sV", "--script", "vuln"], "default Nmap command changed unexpectedly"),
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
        ("group-enum-aggregates-title", rdp_grouped_html.count('<details class="enum-item">') == 1 and "RDP output one" in rdp_grouped_html and "RDP output two" in rdp_grouped_html and "RAW agregado" in rdp_grouped_html, "service group enumeration should aggregate outputs by title/tool"),
        ("group-raw-copy-tool-loop", "for spec in" in rdp_grouped_html and "for cmd in" not in rdp_grouped_html and "birdscan-nmap_nse-all-targets.txt" in rdp_grouped_html, "aggregated RAW copy action should use a tool target loop"),
        ("raw-inline", "raw-details" in rdp_raw_inline_html and "RDP output one" in rdp_raw_inline_html and "Copiar comando" in rdp_raw_inline_html, "RAW output should render inline with command copy action"),
        ("gobuster-single-command", len(gobuster_commands) == 1, "Gobuster copy button should contain one command"),
        ("ftp-copy-commands", any("ftp -inv -p 10.10.10.50 21" in command for command in ftp_commands.get("FTP anonymous", [])), "FTP anonymous command not generated as expected"),
        ("smb-port-commands", " -p 139" in " ".join(smb_commands.get("SMBClient", [])) and "-g" not in " ".join(smb_commands.get("SMBClient", [])) and "--port 139" in " ".join(smb_commands.get("NXC", [])) and "-port 139" in " ".join(smb_commands.get("Impacket", [])), "SMB commands do not carry the detected port or still have -g flag"),
        ("rdp-port-commands", "/v:10.10.10.30:3390" in " ".join(rdp_commands.get("XFreeRDP", [])) and "--port 3390" in " ".join(rdp_commands.get("NXC RDP", [])), "RDP commands do not carry the detected port"),
        ("ssh-port-command", "ssh -p 2222" in " ".join(ssh_commands.get("SSH", [])), "SSH command does not carry the detected port"),
        ("ldap-port-command", "ldaps://10.10.10.40:636" in " ".join(ldap_commands.get("LDAPSearch", [])) and "--port 636" in " ".join(ldap_commands.get("NXC LDAP", [])), "LDAP commands do not carry the detected port"),
        ("kerberos-not-ldap", "LDAPSearch" not in kerberos_commands and "krb5-info" in " ".join(kerberos_commands.get("KRB5 info", [])), "Kerberos commands should not render LDAP search commands"),
        ("mssql-port-command", "-port 1444" in " ".join(mssql_commands.get("MSSQL", [])) and "--port 1444" in " ".join(mssql_commands.get("MSSQL", [])), "MSSQL commands do not carry the detected port"),
        ("winrm-port-command", "-P 5986" in " ".join(winrm_commands.get("Evil-WinRM", [])) and "--port 5986" in " ".join(winrm_commands.get("NXC WinRM", [])), "WinRM commands do not carry the detected port"),
        ("group-actions-all-services", "10.10.10.30:3390" in group_action_html and "10.10.10.31:3391" in group_action_html and "XFreeRDP" in group_action_html, "service group actions do not include commands for every host:port"),
        ("generic-command-loop", "for cmd in" in generic_loop_text and 'sh -c "$cmd"' in generic_loop_text and "tee -a birdscan-commands-all.txt" in generic_loop_text and "echo" not in generic_loop_text, "multiple commands should be copied as a clean shell for-loop without echo decorations"),
        ("service-group-command-loop", "for spec in" in group_action_html and "for cmd in" not in group_action_html and 'nxc rdp &quot;$ip&quot; --port &quot;$port&quot;' in group_action_html and "tee -a birdscan-nxc_rdp-all-targets.txt" in group_action_html and 'echo' not in service_tool_loop_command("NXC RDP", rdp_group_services), "service group multi-target commands should render as clean tool target loops"),
        ("service-group-loop-no-bad-bracket-pattern", '${ip#[}' not in group_action_html and '[ &quot;$proto&quot;' not in group_action_html, "service group loop should not render shell patterns that break on '['"),
        ("copy-ips-action", "Copiar IPs" in group_action_html and "10.10.10.30\n10.10.10.31" in group_action_html, "service group should include copy-only-IPs action"),
        ("gobuster-url-loop", "for url in" in gobuster_loop_command and 'gobuster dir -u "$url"' in gobuster_loop_command and gobuster_loop_command.count("gobuster dir -u") == 1 and "tee -a fuzzing-gobuster-all-web.txt" in gobuster_loop_command and "http://10.10.10.50:8080/" in gobuster_loop_command and "https://10.10.10.40/" in gobuster_loop_command and "echo" not in gobuster_loop_command, "global Gobuster command should loop over WEB roots without echo decorations"),
        ("fuzz-loop-simple-counter", "sed " not in gobuster_loop_command and "$slug" not in gobuster_loop_command and "count=$((count+1))" in gobuster_loop_command, "global fuzzing loop should use a simple counter instead of slug parsing"),
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
        ("nxc-auth-success-parse", nxc_auth_success("SMB 10.0.0.1 445 HOST [-] user bad\nSMB 10.0.0.1 445 HOST [+] user:pass") and not nxc_auth_success("SMB 10.0.0.1 445 HOST [-] user bad"), "nxc auth success parser failed"),
        ("smbv1-detect-nxc", detect_smbv1_enabled("SMB 10.0.0.1 445 HOST SMBv1:True"), "detect_smbv1_enabled should detect nxc SMBv1:True"),
        ("smbv1-detect-nmap", detect_smbv1_enabled("smb-protocols:\n  NT LM 0.12\n  2.0.2\n  3.0.2"), "detect_smbv1_enabled should detect NT LM 0.12 dialect"),
        ("smbv1-detect-false", not detect_smbv1_enabled("SMB 10.0.0.1 445 HOST SMBv1:False signing:True"), "detect_smbv1_enabled should return False when SMBv1 is disabled"),
        ("smbv1-parse-keywords", parse_smb_keywords("SMBv1:True signing: false")["smbv1_enabled"] is True and parse_smb_keywords("SMBv1:True signing: false")["severity"] == "high", "parse_smb_keywords should flag SMBv1 as high severity"),
        ("impacket-no-inputfile", all("-inputfile" not in cmd for cmd in smb_commands.get("Impacket", [])) and "printf" in " ".join(smb_commands.get("Impacket", [])) and "|" in " ".join(smb_commands.get("Impacket", [])), "Impacket copy command should use pipe instead of inputfile"),
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
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    logger = Logger(verbose=args.verbose, quiet=args.quiet)
    try:
        validate_required_cli_input(args)
        validate_cli_file_paths(args)
        if args.self_test:
            return run_self_test(args, logger)
        state = setup_run(args, logger)
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
                ),
                "username_file": args.username_file or "",
                "password_file": args.password_file or "",
                "auth_attack_mode": getattr(args, "auth_attack_mode", "pitchfork") or "pitchfork",
                "credential_lists_execute_automated_spray": has_automated_credential_spray(args),
                "user_enum_enabled": bool(args.enable_user_enum),
            }
        )
        deps = check_dependencies(state, logger)
        if not args.no_auto_install:
            deps = install_missing_dependencies(state, deps, logger)
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
        run_nmap_discovery(args, state, targets, logger)
        if args.web_only:
            run_web_catalog(args, state, logger)
        elif args.service_enum_only:
            run_service_enumeration(args, state, logger)
        else:
            run_web_catalog(args, state, logger)
            run_service_enumeration(args, state, logger)
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
    if "/" in target:
        return False
    return True


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
