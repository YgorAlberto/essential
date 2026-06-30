#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Bird Final Findings - verificações leves e relatório HTML para pentests autorizados.

O scanner trabalha somente com requisições HTTP de leitura, OPTIONS, consultas DNS,
handshakes TLS e RDAP. Ele não envia PUT/DELETE/TRACE, não tenta reivindicar serviços
e não altera o estado dos alvos.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import html
import io
import ipaddress
import os
import re
import shlex
import shutil
import socket
import ssl
import subprocess
import sys
import textwrap
import threading
import time
import warnings
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

try:
    import requests
    import urllib3
    from requests.adapters import HTTPAdapter
except ImportError:
    print("[ERRO] Dependência ausente. Execute: pip install requests", file=sys.stderr)
    raise SystemExit(2)

try:
    import dns.exception
    import dns.resolver
except ImportError:
    print("[ERRO] Dependência ausente. Execute: pip install dnspython", file=sys.stderr)
    raise SystemExit(2)

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
except ImportError:
    print("[ERRO] Dependência ausente. Execute: pip install cryptography", file=sys.stderr)
    raise SystemExit(2)

try:
    from PIL import Image, ImageDraw, ImageFont
except ImportError:
    print("[ERRO] Dependência ausente. Execute: pip install Pillow", file=sys.stderr)
    raise SystemExit(2)

try:
    from ipwhois import IPWhois
except ImportError:
    IPWhois = None

try:
    from playwright.sync_api import sync_playwright
except ImportError:
    sync_playwright = None


VERSION = "1.2.0"
DEFAULT_USER_AGENT = f"Bird-Final-Findings/{VERSION} (authorized-security-assessment)"
MAX_BODY_BYTES = 2 * 1024 * 1024
MAX_EVIDENCE_CHARS = 12_000
TEST_ORIGIN = "https://xploitops.invalid"
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEVERITY_LABEL = {
    "critical": "Crítico", "high": "Alto", "medium": "Médio",
    "low": "Baixo", "info": "Informativo",
}
CONFIDENCE_LABEL = {"high": "Alta", "medium": "Média", "low": "Baixa"}

SENSITIVE_QUERY_KEYS = re.compile(
    r"(?:pass(?:word)?|pwd|secret|token|key|auth|session|jwt|code|credential)", re.I
)
SECRET_LINE_RE = re.compile(
    r"(?im)^([A-Z][A-Z0-9_]{2,}\s*=\s*)([^\r\n]+)$"
)
JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_.+/=-]*\b")
BEARER_RE = re.compile(r"(?i)(authorization\s*:\s*bearer\s+)[^\s]+")
COOKIE_VALUE_RE = re.compile(r"(?im)^(set-cookie\s*:\s*[^=;\r\n]+)=([^;\r\n]*)")

SECURITY_HEADERS = {
    "strict-transport-security": {
        "label": "Strict-Transport-Security (HSTS)",
        "severity": "medium",
        "description": "O navegador não recebeu uma política HSTS para forçar conexões HTTPS futuras.",
        "impact": "Um primeiro acesso por HTTP pode ficar exposto a downgrade ou interceptação em redes hostis.",
        "recommendation": "Envie Strict-Transport-Security em respostas HTTPS, com max-age adequado; avalie includeSubDomains e preload após validar toda a zona.",
    },
    "content-security-policy": {
        "label": "Content-Security-Policy (CSP)",
        "severity": "medium",
        "description": "A resposta HTML não definiu uma política CSP efetiva por cabeçalho.",
        "impact": "A ausência reduz a contenção de XSS, injeção de conteúdo e carregamento de recursos não confiáveis.",
        "recommendation": "Defina uma CSP restritiva baseada em allowlist, começando em Report-Only e removendo unsafe-inline/unsafe-eval quando possível.",
    },
    "x-frame-options": {
        "label": "Proteção contra framing",
        "severity": "medium",
        "description": "A resposta não definiu X-Frame-Options nem frame-ancestors em CSP.",
        "impact": "A página pode ser incorporada por terceiros e ficar sujeita a clickjacking.",
        "recommendation": "Use CSP frame-ancestors 'none' ou uma allowlist explícita; X-Frame-Options DENY/SAMEORIGIN pode ser mantido para clientes legados.",
    },
    "x-content-type-options": {
        "label": "X-Content-Type-Options",
        "severity": "low",
        "description": "A resposta não enviou X-Content-Type-Options: nosniff.",
        "impact": "Alguns clientes podem tentar interpretar conteúdo com um tipo diferente do declarado.",
        "recommendation": "Envie X-Content-Type-Options: nosniff e mantenha Content-Type correto para todos os recursos.",
    },
}

DISCLOSURE_HEADERS = {
    "server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version",
    "x-generator", "x-runtime", "x-version", "x-drupal-cache", "x-php-version",
}

TAKEOVER_PROVIDERS = [
    {
        "name": "GitHub Pages",
        "suffixes": ("github.io",),
        "fingerprints": ("there isn't a github pages site here",),
    },
    {
        "name": "Heroku",
        "suffixes": ("herokudns.com", "herokuapp.com"),
        "fingerprints": ("no such app", "there's nothing here, yet"),
    },
    {
        "name": "AWS S3",
        "suffixes": ("s3.amazonaws.com", "s3-website",),
        "fingerprints": ("nosuchbucket", "the specified bucket does not exist"),
    },
    {
        "name": "Azure",
        "suffixes": ("azurewebsites.net", "cloudapp.net", "trafficmanager.net", "azurefd.net"),
        "fingerprints": ("404 web site not found", "the resource you are looking for has been removed"),
    },
    {
        "name": "Fastly",
        "suffixes": ("fastly.net", "fastlylb.net"),
        "fingerprints": ("fastly error: unknown domain",),
    },
    {
        "name": "Netlify",
        "suffixes": ("netlify.app", "netlify.com"),
        "fingerprints": ("not found - request id",),
    },
    {
        "name": "Vercel",
        "suffixes": ("vercel.app", "now.sh"),
        "fingerprints": ("deployment_not_found", "the deployment could not be found"),
    },
    {
        "name": "Pantheon",
        "suffixes": ("pantheonsite.io",),
        "fingerprints": ("the gods are wise", "unknown site"),
    },
    {
        "name": "Shopify",
        "suffixes": ("myshopify.com",),
        "fingerprints": ("sorry, this shop is currently unavailable",),
    },
]

TECH_RULES = [
    ("Next.js", (r"/_next/", r"__NEXT_DATA__", r"x-powered-by:\s*next\.js")),
    ("React", (r"data-reactroot", r"react(?:\.production)?\.min\.js", r"__REACT_DEVTOOLS_GLOBAL_HOOK__")),
    ("Vue.js", (r"data-v-[0-9a-f]{6,}", r"vue(?:\.runtime)?(?:\.global)?(?:\.prod)?\.js", r"__VUE__")),
    ("Angular", (r"ng-version=", r"angular(?:\.min)?\.js", r"<app-root")),
    ("Svelte", (r"svelte-[a-z0-9]+", r"__svelte")),
    ("WordPress", (r"/wp-content/", r"/wp-includes/", r"generator[^>]+wordpress")),
    ("Drupal", (r"drupal-settings-json", r"/sites/default/files/", r"x-drupal-cache:")),
    ("Joomla", (r"generator[^>]+joomla", r"/media/system/js/")),
    ("Shopify", (r"cdn\.shopify\.com", r"shopify\.theme", r"x-shopid:")),
    ("jQuery", (r"jquery(?:-[0-9.]+)?(?:\.min)?\.js",)),
    ("Bootstrap", (r"bootstrap(?:\.bundle)?(?:\.min)?\.(?:css|js)",)),
    ("Tailwind CSS", (r"tailwind(?:\.min)?\.css", r"--tw-[a-z-]+:")),
    ("Nginx", (r"server:\s*nginx",)),
    ("Apache HTTP Server", (r"server:\s*apache",)),
    ("Microsoft IIS", (r"server:\s*microsoft-iis", r"x-aspnet-version:")),
    ("Express", (r"x-powered-by:\s*express", r"connect\.sid")),
    ("ASP.NET", (r"x-powered-by:\s*asp\.net", r"asp\.net_sessionid", r"__viewstate")),
    ("PHP", (r"x-powered-by:\s*php", r"phpsessid")),
    ("Laravel", (r"laravel_session", r"x-xsrf-token")),
    ("Django", (r"csrftoken", r"__admin_media_prefix__")),
    ("Ruby on Rails", (r"x-runtime:", r"_rails_session", r"csrf-param")),
    ("Spring", (r"jsessionid", r"whitelabel error page")),
    ("Cloudflare", (r"server:\s*cloudflare", r"cf-ray:")),
]

WAF_CDN_RULES = [
    ("Cloudflare", ("cf-ray", "cf-cache-status"), ("cloudflare",)),
    ("AWS CloudFront", ("x-amz-cf-id", "x-amz-cf-pop"), ("cloudfront.net",)),
    ("Akamai", ("x-akamai-transformed", "akamai-grn"), ("akamaiedge.net", "edgesuite.net")),
    ("Fastly", ("x-served-by", "x-fastly-request-id"), ("fastly.net",)),
    ("Sucuri", ("x-sucuri-id", "x-sucuri-cache"), ("sucuri.net",)),
    ("Imperva/Incapsula", ("x-iinfo",), ("incapdns.net",)),
    ("Azure Front Door", ("x-azure-ref", "x-fd-int-roxy-purgeid"), ("azurefd.net",)),
    ("Vercel", ("x-vercel-id", "x-vercel-cache"), ("vercel-dns.com", "vercel.app")),
    ("Netlify", ("x-nf-request-id",), ("netlify.app",)),
]

CLOUD_ORG_RULES = [
    ("AWS", ("amazon", "amazon.com", "aws")),
    ("Google Cloud", ("google", "google cloud")),
    ("Microsoft Azure", ("microsoft", "azure")),
    ("Cloudflare", ("cloudflare",)),
    ("Oracle Cloud", ("oracle",)),
    ("DigitalOcean", ("digitalocean",)),
    ("Akamai/Linode", ("akamai", "linode")),
    ("OVHcloud", ("ovh",)),
    ("Hostinger", ("hostinger",)),
    ("Hetzner", ("hetzner",)),
]


@dataclass
class HttpSnapshot:
    requested_url: str
    final_url: str = ""
    status: int = 0
    reason: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    set_cookies: list[str] = field(default_factory=list)
    body: bytes = b""
    history: list[tuple[int, str, str]] = field(default_factory=list)
    elapsed: float = 0.0
    truncated: bool = False
    error: str = ""

    @property
    def text(self) -> str:
        if not self.body:
            return ""
        content_type = self.headers.get("content-type", "")
        match = re.search(r"charset=([\w.-]+)", content_type, re.I)
        encoding = match.group(1) if match else "utf-8"
        try:
            return self.body.decode(encoding, errors="replace")
        except LookupError:
            return self.body.decode("utf-8", errors="replace")

    @property
    def content_type(self) -> str:
        return self.headers.get("content-type", "").lower()


@dataclass
class Finding:
    merge_key: str
    code: str
    title: str
    category: str
    severity: str
    confidence: str
    target: str
    description: str
    impact: str
    recommendation: str
    evidence: str
    reproduce: str
    urls: set[str] = field(default_factory=set)
    cli_transcript: str = ""


class FindingCollector:
    def __init__(self) -> None:
        self._items: dict[str, Finding] = {}
        self._lock = threading.Lock()

    def add(self, finding: Finding, url: str | None = None) -> None:
        if finding.severity not in SEVERITY_ORDER:
            finding.severity = "info"
        if url:
            finding.urls.add(url)
        with self._lock:
            existing = self._items.get(finding.merge_key)
            if existing:
                existing.urls.update(finding.urls)
                if SEVERITY_ORDER[finding.severity] < SEVERITY_ORDER[existing.severity]:
                    existing.severity = finding.severity
                return
            self._items[finding.merge_key] = finding

    def sorted(self) -> list[Finding]:
        return sorted(
            self._items.values(),
            key=lambda item: (SEVERITY_ORDER[item.severity], item.category, item.title, item.target),
        )


def sanitize_url(url: str) -> str:
    parsed = urlparse(url)
    query = []
    for key, value in parse_qsl(parsed.query, keep_blank_values=True):
        query.append((key, "[REDACTED]" if SENSITIVE_QUERY_KEYS.search(key) else value))
    clean_netloc = parsed.hostname or ""
    if parsed.port:
        clean_netloc += f":{parsed.port}"
    return urlunparse((parsed.scheme, clean_netloc, parsed.path, parsed.params, urlencode(query), ""))


def redact_evidence(value: str) -> str:
    value = value[:MAX_EVIDENCE_CHARS]
    value = BEARER_RE.sub(r"\1[REDACTED]", value)
    value = JWT_RE.sub("[JWT REDACTED]", value)
    value = COOKIE_VALUE_RE.sub(r"\1=[REDACTED]", value)
    value = SECRET_LINE_RE.sub(r"\1[REDACTED]", value)
    value = re.sub(
        r"(?i)([?&](?:password|passwd|pwd|secret|token|api[_-]?key|session|jwt)=)[^&\s]+",
        r"\1[REDACTED]",
        value,
    )
    return value


def normalize_url(raw: str) -> str | None:
    raw = raw.strip().lstrip("\ufeff")
    if not raw or raw.startswith("#"):
        return None
    if "://" not in raw:
        raw = "https://" + raw
    try:
        parsed = urlparse(raw)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            return None
        if parsed.username or parsed.password:
            return None
        host = parsed.hostname.encode("idna").decode("ascii").lower()
        netloc = host
        if parsed.port:
            netloc += f":{parsed.port}"
        path = parsed.path or "/"
        return urlunparse((parsed.scheme.lower(), netloc, path, parsed.params, parsed.query, ""))
    except (ValueError, UnicodeError):
        return None


def origin_for(url: str) -> str:
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def shell_url(url: str) -> str:
    return shlex.quote(sanitize_url(url))


def highest_severity(values: Iterable[str]) -> str:
    values = list(values)
    return min(values, key=lambda item: SEVERITY_ORDER.get(item, 99)) if values else "info"


def run_reproduction_command(command: str, timeout: float) -> str:
    """Executa o comando exibido no relatório e devolve seu transcript real."""
    if not command.strip():
        return ""
    env = os.environ.copy()
    env.update({"LC_ALL": "C", "LANG": "C"})
    started = time.monotonic()
    try:
        result = subprocess.run(
            ["bash", "-o", "pipefail", "-c", command],
            capture_output=True,
            text=True,
            errors="replace",
            timeout=max(5.0, timeout),
            env=env,
            check=False,
        )
        output = (result.stdout or "") + (result.stderr or "")
        footer = f"\n[exit={result.returncode} · duração={time.monotonic() - started:.2f}s]"
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout.decode(errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        stderr = exc.stderr.decode(errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        output = stdout + stderr
        footer = f"\n[timeout após {max(5.0, timeout):.1f}s]"
    except OSError as exc:
        output = f"Não foi possível executar: {type(exc).__name__}: {exc}"
        footer = "\n[execução indisponível]"
    return redact_evidence(f"$ {command}\n{output.rstrip()}{footer}")


class BrowserVerifier:
    """Confirma a navegação real com Chromium, sem gerar capturas no relatório."""

    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self._playwright = None
        self._browser = None

    def __enter__(self) -> "BrowserVerifier":
        if sync_playwright is None:
            raise RuntimeError("Playwright não está instalado")
        self._playwright = sync_playwright().start()
        executable = (
            os.environ.get("PLAYWRIGHT_CHROMIUM_EXECUTABLE")
            or shutil.which("chromium")
            or shutil.which("chromium-browser")
            or shutil.which("google-chrome")
        )
        launch_options: dict[str, Any] = {"headless": True, "args": ["--no-sandbox"]}
        if executable:
            launch_options["executable_path"] = executable
        if self.args.proxy:
            launch_options["proxy"] = {"server": self.args.proxy}
        self._browser = self._playwright.chromium.launch(**launch_options)
        return self

    def __exit__(self, _exc_type, _exc, _traceback) -> None:
        if self._browser is not None:
            self._browser.close()
        if self._playwright is not None:
            self._playwright.stop()

    def navigate(self, url: str) -> dict[str, Any]:
        if self._browser is None:
            raise RuntimeError("Navegador Playwright não foi iniciado")
        context = self._browser.new_context(
            ignore_https_errors=not self.args.verify_tls,
            viewport={"width": 1365, "height": 768},
            user_agent=self.args.user_agent,
        )
        page = context.new_page()
        page.on("dialog", lambda dialog: dialog.dismiss())
        result: dict[str, Any] = {
            "requested_url": url,
            "final_url": "",
            "status": 0,
            "error": "",
        }
        try:
            response = page.goto(
                url,
                wait_until="domcontentloaded",
                timeout=int(max(5.0, self.args.timeout) * 1000),
            )
            page.wait_for_timeout(900)
            result["final_url"] = page.url
            if response is not None:
                result["status"] = response.status
        except Exception as exc:
            result["final_url"] = page.url
            result["error"] = f"{type(exc).__name__}: {exc}"
        finally:
            context.close()
        return result


class Scanner:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.findings = FindingCollector()
        self.snapshots: dict[str, HttpSnapshot] = {}
        self.diagnostics: list[dict[str, Any]] = []
        self._diag_lock = threading.Lock()
        self._thread_local = threading.local()
        self._dns_cache: dict[str, dict[str, Any]] = {}
        self._dns_lock = threading.Lock()
        self._asn_cache: dict[str, dict[str, str]] = {}
        self._asn_lock = threading.Lock()
        self._missing_headers: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
        self._header_samples: dict[str, tuple[str, HttpSnapshot, int]] = {}
        self._header_lock = threading.Lock()
        self._redirect_candidates: list[dict[str, Any]] = []
        self._redirect_lock = threading.Lock()

    def session(self) -> requests.Session:
        session = getattr(self._thread_local, "session", None)
        if session is not None:
            return session
        session = requests.Session()
        session.headers.update({"User-Agent": self.args.user_agent, "Accept": "*/*"})
        adapter = HTTPAdapter(pool_connections=self.args.workers, pool_maxsize=self.args.workers)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        if self.args.proxy:
            session.proxies.update({"http": self.args.proxy, "https": self.args.proxy})
        self._thread_local.session = session
        return session

    def fetch(
        self,
        url: str,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        allow_redirects: bool = True,
        max_bytes: int = MAX_BODY_BYTES,
    ) -> HttpSnapshot:
        started = time.monotonic()
        snapshot = HttpSnapshot(requested_url=url)
        try:
            response = self.session().request(
                method,
                url,
                headers=headers,
                timeout=(self.args.connect_timeout, self.args.timeout),
                allow_redirects=allow_redirects,
                verify=self.args.verify_tls,
                stream=True,
            )
            data = bytearray()
            for chunk in response.iter_content(chunk_size=32_768):
                if not chunk:
                    continue
                remaining = max_bytes - len(data)
                if remaining <= 0:
                    snapshot.truncated = True
                    break
                data.extend(chunk[:remaining])
                if len(chunk) > remaining or len(data) >= max_bytes:
                    snapshot.truncated = True
                    break
            raw_headers = response.raw.headers
            if hasattr(raw_headers, "getlist"):
                set_cookies = list(raw_headers.getlist("Set-Cookie"))
            elif hasattr(raw_headers, "get_all"):
                set_cookies = list(raw_headers.get_all("Set-Cookie") or [])
            else:
                set_cookies = []
            snapshot.final_url = response.url
            snapshot.status = response.status_code
            snapshot.reason = response.reason or ""
            snapshot.headers = {str(k).lower(): str(v) for k, v in response.headers.items()}
            snapshot.set_cookies = set_cookies
            snapshot.body = bytes(data)
            snapshot.history = [
                (item.status_code, item.url, item.headers.get("Location", ""))
                for item in response.history
            ]
            response.close()
        except requests.RequestException as exc:
            snapshot.error = f"{type(exc).__name__}: {exc}"
        except Exception as exc:  # Mantém um alvo problemático isolado dos demais.
            snapshot.error = f"{type(exc).__name__}: {exc}"
        snapshot.elapsed = time.monotonic() - started
        if self.args.delay > 0:
            time.sleep(self.args.delay)
        return snapshot

    def add_diagnostic(self, url: str, snapshot: HttpSnapshot) -> None:
        row = {
            "url": sanitize_url(url),
            "status": snapshot.status,
            "final_url": sanitize_url(snapshot.final_url) if snapshot.final_url else "",
            "elapsed": round(snapshot.elapsed, 3),
            "bytes": len(snapshot.body),
            "error": redact_evidence(snapshot.error),
        }
        with self._diag_lock:
            self.diagnostics.append(row)

    def scan_page(self, url: str) -> HttpSnapshot:
        snapshot = self.fetch(url)
        self.snapshots[url] = snapshot
        self.add_diagnostic(url, snapshot)
        if snapshot.error:
            return snapshot
        self.analyze_security_headers(url, snapshot)
        self.analyze_disclosure_headers(url, snapshot)
        self.analyze_cookies(url, snapshot)
        self.analyze_http_methods(url)
        self.analyze_csrf(url, snapshot)
        self.analyze_technologies(url, snapshot)
        if not self.args.no_cors:
            self.analyze_cors(url)
        return snapshot

    def analyze_security_headers(self, url: str, snapshot: HttpSnapshot) -> None:
        if not (200 <= snapshot.status < 400):
            return
        is_html = "text/html" in snapshot.content_type or snapshot.text.lstrip().lower().startswith("<!doctype html")
        parsed = urlparse(snapshot.final_url or url)
        missing: list[str] = []
        for name in SECURITY_HEADERS:
            if name == "strict-transport-security" and parsed.scheme != "https":
                continue
            if name in {"content-security-policy", "x-frame-options"} and not is_html:
                continue
            if name == "x-frame-options":
                csp = snapshot.headers.get("content-security-policy", "").lower()
                if "frame-ancestors" in csp:
                    continue
            if name not in snapshot.headers:
                missing.append(name)
        if not missing:
            return
        origin = origin_for(url)
        with self._header_lock:
            for name in missing:
                self._missing_headers[origin][name].add(url)
            current = self._header_samples.get(origin)
            if current is None or len(missing) > current[2]:
                self._header_samples[origin] = (url, snapshot, len(missing))

    def finalize_security_headers(self) -> None:
        """Cria um único achado de headers por origem, detalhando cada impacto."""
        for origin, header_urls in sorted(self._missing_headers.items()):
            names = sorted(header_urls, key=lambda name: SEVERITY_ORDER[SECURITY_HEADERS[name]["severity"]])
            if not names:
                continue
            sample_url, sample, _count = self._header_samples[origin]
            all_urls: set[str] = set()
            description_lines = ["Cabeçalhos ausentes em uma ou mais respostas avaliadas:"]
            impact_lines = []
            recommendation_lines = []
            evidence_lines = [f"Amostra: {sanitize_url(sample_url)}", f"HTTP: {sample.status}"]
            for name in names:
                data = SECURITY_HEADERS[name]
                affected = header_urls[name]
                all_urls.update(affected)
                description_lines.append(f"• {data['label']} ({len(affected)} URL(s)): {data['description']}")
                impact_lines.append(f"• {data['label']}: {data['impact']}")
                recommendation_lines.append(f"• {data['label']}: {data['recommendation']}")
                evidence_lines.append(f"AUSENTE: {data['label']} · {len(affected)} ocorrência(s)")
            present = [
                name for name in SECURITY_HEADERS
                if name in sample.headers
            ]
            evidence_lines.append(f"Presentes na amostra: {', '.join(present) if present else 'nenhum dos cabeçalhos avaliados'}")
            finding = Finding(
                merge_key=f"security-headers|{origin}",
                code="SEC-HEADERS",
                title=f"Cabeçalhos de segurança ausentes ({len(names)})",
                category="Security Headers",
                severity=highest_severity(SECURITY_HEADERS[name]["severity"] for name in names),
                confidence="high",
                target=origin,
                description="\n".join(description_lines),
                impact="\n".join(impact_lines),
                recommendation="\n".join(recommendation_lines),
                evidence="\n".join(evidence_lines),
                reproduce=f"curl --silent --show-error --insecure --dump-header - --output /dev/null {shell_url(sample_url)}",
                urls=all_urls,
            )
            self.findings.add(finding)

    def analyze_disclosure_headers(self, url: str, snapshot: HttpSnapshot) -> None:
        exposed = {name: snapshot.headers[name] for name in DISCLOSURE_HEADERS if name in snapshot.headers}
        if not exposed:
            return
        origin = origin_for(url)
        details = "\n".join(f"{name}: {value}" for name, value in sorted(exposed.items()))
        has_version = any(re.search(r"\d+\.\d+", value) for value in exposed.values())
        severity = "low" if has_version or any(name != "server" for name in exposed) else "info"
        finding = Finding(
            merge_key=f"disclosure|{origin}|{hashlib.sha1(details.encode()).hexdigest()[:10]}",
            code="INFO-HEADERS",
            title="Information disclosure em cabeçalhos HTTP",
            category="Information Disclosure",
            severity=severity,
            confidence="high",
            target=origin,
            description="A resposta expõe identificadores de servidor, framework ou runtime nos cabeçalhos HTTP.",
            impact="Versões e tecnologias facilitam a seleção de ataques e a correlação com vulnerabilidades conhecidas; valores genéricos têm impacto apenas informativo.",
            recommendation="Remova cabeçalhos desnecessários e evite divulgar versões detalhadas, sem depender dessa ocultação como controle primário.",
            evidence=redact_evidence(f"URL: {sanitize_url(url)}\n{details}"),
            reproduce=f"curl -sk -D - -o /dev/null {shell_url(url)}",
        )
        self.findings.add(finding, url)

    def analyze_cookies(self, url: str, snapshot: HttpSnapshot) -> None:
        if not snapshot.set_cookies:
            return
        origin = origin_for(url)
        for raw_cookie in snapshot.set_cookies:
            parts = [part.strip() for part in raw_cookie.split(";") if part.strip()]
            if not parts or "=" not in parts[0]:
                continue
            cookie_name = parts[0].split("=", 1)[0].strip()
            attrs = {part.split("=", 1)[0].strip().lower(): part.split("=", 1)[1].strip() if "=" in part else True for part in parts[1:]}
            missing = []
            if "httponly" not in attrs:
                missing.append("HttpOnly")
            if urlparse(snapshot.final_url or url).scheme == "https" and "secure" not in attrs:
                missing.append("Secure")
            if "samesite" not in attrs:
                missing.append("SameSite")
            same_site = str(attrs.get("samesite", "")).lower()
            if same_site == "none" and "secure" not in attrs:
                missing.append("Secure obrigatório com SameSite=None")
            if not missing:
                continue
            session_like = bool(re.search(r"session|sess|auth|token|jwt|sid", cookie_name, re.I))
            severity = "medium" if session_like and ("HttpOnly" in missing or "Secure" in missing) else "low"
            evidence = (
                f"URL: {sanitize_url(url)}\nCookie: {cookie_name}=[REDACTED]\n"
                f"Atributos observados: {', '.join(sorted(attrs)) or 'nenhum'}\n"
                f"Flags ausentes/inconsistentes: {', '.join(missing)}"
            )
            finding = Finding(
                merge_key=f"cookie|{origin}|{cookie_name.lower()}|{'-'.join(sorted(missing))}",
                code="COOKIE-FLAGS",
                title=f"Cookie sem flags recomendadas: {cookie_name}",
                category="Cookies e Sessão",
                severity=severity,
                confidence="medium" if not session_like else "high",
                target=origin,
                description=f"O cookie {cookie_name} foi emitido sem: {', '.join(missing)}.",
                impact="Cookies de sessão sem essas proteções podem ficar mais expostos a JavaScript malicioso, transporte inseguro ou requisições cross-site. Cookies estritamente funcionais podem ter requisitos diferentes.",
                recommendation="Classifique a finalidade do cookie e, para cookies de autenticação/sessão, use HttpOnly, Secure e SameSite=Lax/Strict (ou None; Secure quando o fluxo cross-site for necessário).",
                evidence=evidence,
                reproduce=f"curl -sk -D - -o /dev/null {shell_url(url)}",
            )
            self.findings.add(finding, url)

    def analyze_http_methods(self, url: str) -> None:
        snapshot = self.fetch(url, method="OPTIONS", max_bytes=64 * 1024)
        if snapshot.error:
            return
        allow = snapshot.headers.get("allow", "")
        methods = {item.strip().upper() for item in allow.split(",") if item.strip()}
        dangerous = sorted(methods.intersection({"PUT", "DELETE", "TRACE"}))
        if not dangerous:
            return
        severity = "high" if "TRACE" in dangerous else "medium"
        origin = origin_for(url)
        finding = Finding(
            merge_key=f"methods|{origin}|{'-'.join(dangerous)}",
            code="HTTP-METHODS",
            title=f"Métodos HTTP potencialmente perigosos anunciados: {', '.join(dangerous)}",
            category="Métodos HTTP",
            severity=severity,
            confidence="medium",
            target=origin,
            description="A resposta OPTIONS anunciou métodos que podem alterar recursos ou, no caso de TRACE, refletir dados da requisição.",
            impact="Se não houver autenticação e autorização adequadas, PUT/DELETE podem permitir alteração de estado. TRACE pode ampliar cenários legados de exposição de cabeçalhos.",
            recommendation="Desabilite métodos não utilizados no proxy e na aplicação. Para métodos necessários, aplique autenticação, autorização por recurso, CSRF e validação de conteúdo.",
            evidence=f"URL: {sanitize_url(url)}\nHTTP: {snapshot.status}\nAllow: {allow}",
            reproduce=f"curl -sk -i -X OPTIONS {shell_url(url)}",
        )
        self.findings.add(finding, url)

    def analyze_cors(self, url: str) -> None:
        snapshot = self.fetch(url, headers={"Origin": TEST_ORIGIN}, max_bytes=128 * 1024)
        if snapshot.error:
            return
        acao = snapshot.headers.get("access-control-allow-origin", "").strip()
        acac = snapshot.headers.get("access-control-allow-credentials", "").strip().lower()
        if not acao:
            return
        reflected = acao.rstrip("/") == TEST_ORIGIN.rstrip("/")
        wildcard = acao == "*"
        if not (reflected or wildcard or acao.lower() == "null"):
            return
        if reflected and acac == "true":
            severity, confidence = "high", "high"
            title = "CORS reflete origem arbitrária com credenciais"
            impact = "Um site controlado por atacante pode realizar requisições autenticadas e ler respostas no navegador da vítima, conforme os cookies e controles do endpoint."
        elif reflected:
            severity, confidence = "medium", "high"
            title = "CORS reflete origem arbitrária"
            impact = "Respostas acessíveis sem cookies podem ser lidas por origens não confiáveis; o impacto depende dos demais mecanismos de autenticação."
        elif acao.lower() == "null" and acac == "true":
            severity, confidence = "medium", "medium"
            title = "CORS permite origem null com credenciais"
            impact = "Contextos sandboxados podem emitir Origin: null; o impacto depende de os cookies serem enviados e de o endpoint expor dados sensíveis."
        else:
            severity, confidence = "info", "high"
            title = "CORS permite qualquer origem"
            impact = "Qualquer site pode ler respostas sem credenciais. Isso pode ser intencional em APIs públicas; confirme a classificação dos dados. O navegador bloqueia credenciais com ACAO '*'."
        origin = origin_for(url)
        finding = Finding(
            merge_key=f"cors|{origin}|{acao}|{acac}",
            code="CORS",
            title=title,
            category="CSRF e CORS",
            severity=severity,
            confidence=confidence,
            target=origin,
            description=f"Com Origin de teste {TEST_ORIGIN}, o servidor respondeu Access-Control-Allow-Origin: {acao} e credenciais: {acac or 'não'}.",
            impact=impact,
            recommendation="Use uma allowlist exata de origens confiáveis, não reflita Origin sem validação e habilite credenciais apenas nos endpoints que realmente dependem delas. Inclua Vary: Origin em respostas dinâmicas.",
            evidence=(
                f"GET {sanitize_url(url)}\nOrigin: {TEST_ORIGIN}\nHTTP: {snapshot.status}\n"
                f"Access-Control-Allow-Origin: {acao}\n"
                f"Access-Control-Allow-Credentials: {acac or '(ausente)'}\n"
                f"Vary: {snapshot.headers.get('vary', '(ausente)')}"
            ),
            reproduce=f"curl -sk -i -H {shlex.quote('Origin: ' + TEST_ORIGIN)} {shell_url(url)}",
        )
        self.findings.add(finding, url)

    def analyze_csrf(self, url: str, snapshot: HttpSnapshot) -> None:
        if "html" not in snapshot.content_type and "<form" not in snapshot.text.lower():
            return
        forms = re.findall(r"(?is)<form\b([^>]*)>(.*?)</form\s*>", snapshot.text)
        suspicious = []
        for attrs, body in forms:
            method_match = re.search(r"(?i)\bmethod\s*=\s*['\"]?([a-z]+)", attrs)
            method = method_match.group(1).upper() if method_match else "GET"
            if method not in {"POST", "PUT", "PATCH", "DELETE"}:
                continue
            token_pattern = r"(?i)(?:csrf|xsrf|authenticity[_-]?token|request[_-]?verification[_-]?token)"
            if not re.search(token_pattern, body + attrs):
                action_match = re.search(r"(?i)\baction\s*=\s*['\"]([^'\"]+)", attrs)
                suspicious.append((method, action_match.group(1) if action_match else "(URL atual)"))
        if not suspicious:
            return
        origin = origin_for(url)
        evidence_lines = [f"URL: {sanitize_url(url)}", f"Formulários sem token visível: {len(suspicious)}"]
        evidence_lines.extend(f"- {method} {action}" for method, action in suspicious[:10])
        finding = Finding(
            merge_key=f"csrf-form|{origin}|{hashlib.sha1(str(suspicious).encode()).hexdigest()[:10]}",
            code="CSRF-HEURISTIC",
            title="Formulário de alteração sem token CSRF visível",
            category="CSRF e CORS",
            severity="low",
            confidence="low",
            target=origin,
            description="Foi identificado formulário com método de alteração de estado sem campo de token CSRF reconhecível no HTML.",
            impact="Se a aplicação autentica por cookies e não valida Origin/Referer ou token fora do HTML, outro site pode induzir ações no contexto da vítima.",
            recommendation="Valide o fluxo autenticado manualmente. Use tokens anti-CSRF por sessão/requisição, cookies SameSite adequados e validação de Origin/Referer como defesa adicional.",
            evidence="\n".join(evidence_lines),
            reproduce=f"curl -sk {shell_url(url)}",
        )
        self.findings.add(finding, url)

    def analyze_technologies(self, url: str, snapshot: HttpSnapshot) -> None:
        combined = "\n".join(f"{key}: {value}" for key, value in snapshot.headers.items()) + "\n" + snapshot.text[:1_000_000]
        detected = []
        matches = []
        for technology, patterns in TECH_RULES:
            for pattern in patterns:
                match = re.search(pattern, combined, re.I)
                if match:
                    detected.append(technology)
                    matches.append(f"{technology}: {match.group(0)[:160]}")
                    break
        meta_generator = re.search(
            r"(?is)<meta[^>]+name\s*=\s*['\"]generator['\"][^>]+content\s*=\s*['\"]([^'\"]+)",
            snapshot.text,
        )
        if meta_generator:
            value = re.sub(r"\s+", " ", meta_generator.group(1)).strip()
            detected.append(value)
            matches.append(f"Meta generator: {value}")
        detected = list(dict.fromkeys(detected))
        if not detected:
            return
        origin = origin_for(url)
        signature = hashlib.sha1("|".join(sorted(detected)).encode()).hexdigest()[:10]
        finding = Finding(
            merge_key=f"technology|{origin}|{signature}",
            code="TECH-FINGERPRINT",
            title=f"Tecnologias identificadas: {', '.join(detected)}",
            category="Tecnologias",
            severity="info",
            confidence="medium",
            target=origin,
            description="Assinaturas em cabeçalhos, cookies ou conteúdo indicam as tecnologias listadas.",
            impact="O inventário ajuda a direcionar validações de versão, hardening e componentes vulneráveis; a assinatura não confirma a versão nem uma vulnerabilidade.",
            recommendation="Mantenha componentes suportados e atualizados, remova assinaturas desnecessárias e confirme versões no inventário interno.",
            evidence=redact_evidence(f"URL: {sanitize_url(url)}\n" + "\n".join(matches)),
            reproduce=f"curl -sk -D - {shell_url(url)}",
        )
        self.findings.add(finding, url)

    def resolve_dns(self, host: str) -> dict[str, Any]:
        with self._dns_lock:
            cached = self._dns_cache.get(host)
        if cached is not None:
            return cached
        result: dict[str, Any] = {"cname": "", "ips": [], "cname_resolves": None, "error": ""}
        resolver = dns.resolver.Resolver()
        resolver.timeout = min(self.args.timeout, 5)
        resolver.lifetime = min(self.args.timeout, 8)
        try:
            try:
                answers = resolver.resolve(host, "CNAME", search=False)
                result["cname"] = str(answers[0].target).rstrip(".").lower()
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                pass
            for record_type in ("A", "AAAA"):
                try:
                    answers = resolver.resolve(host, record_type, search=False)
                    result["ips"].extend(str(answer) for answer in answers)
                except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout, dns.resolver.NoNameservers):
                    pass
            if result["cname"]:
                try:
                    resolver.resolve(result["cname"], "A", search=False)
                    result["cname_resolves"] = True
                except (dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
                    result["cname_resolves"] = False
                except (dns.resolver.NoAnswer, dns.exception.Timeout):
                    result["cname_resolves"] = None
        except Exception as exc:
            result["error"] = f"{type(exc).__name__}: {exc}"
        result["ips"] = sorted(set(result["ips"]))
        with self._dns_lock:
            self._dns_cache[host] = result
        return result

    def lookup_asn(self, ip: str) -> dict[str, str]:
        with self._asn_lock:
            cached = self._asn_cache.get(ip)
        if cached is not None:
            return cached
        result = {"asn": "", "asn_description": "", "network": "", "country": ""}
        try:
            address = ipaddress.ip_address(ip)
            if address.is_private or address.is_loopback or address.is_link_local or IPWhois is None:
                return result
            data = IPWhois(ip, timeout=min(self.args.timeout, 8)).lookup_rdap(depth=0, retry_count=0)
            result = {
                "asn": str(data.get("asn") or ""),
                "asn_description": str(data.get("asn_description") or ""),
                "network": str((data.get("network") or {}).get("name") or ""),
                "country": str(data.get("asn_country_code") or ""),
            }
        except Exception:
            pass
        with self._asn_lock:
            self._asn_cache[ip] = result
        return result

    def analyze_origin(self, origin: str, sample_url: str) -> None:
        parsed = urlparse(origin)
        host = parsed.hostname or ""
        dns_data = self.resolve_dns(host)
        snapshot = self.snapshots.get(sample_url)
        self.analyze_infrastructure(origin, sample_url, dns_data, snapshot)
        self.analyze_takeover(origin, sample_url, dns_data, snapshot)
        if parsed.scheme == "https":
            self.analyze_certificate_and_tls(origin, sample_url)
            self.analyze_http_redirect(origin, sample_url)
        if not self.args.no_sensitive_files:
            self.analyze_sensitive_files(origin)

    def analyze_infrastructure(
        self,
        origin: str,
        sample_url: str,
        dns_data: dict[str, Any],
        snapshot: HttpSnapshot | None,
    ) -> None:
        header_names = set(snapshot.headers) if snapshot and not snapshot.error else set()
        cname = dns_data.get("cname", "")
        layers = []
        for name, headers, suffixes in WAF_CDN_RULES:
            if header_names.intersection(headers) or any(suffix in cname for suffix in suffixes):
                layers.append(name)
        asn_rows = []
        cloud = []
        if not self.args.no_asn:
            for ip in dns_data.get("ips", [])[:4]:
                info = self.lookup_asn(ip)
                asn_rows.append((ip, info))
                searchable = f"{info.get('asn_description', '')} {info.get('network', '')}".lower()
                for provider, markers in CLOUD_ORG_RULES:
                    if any(marker in searchable for marker in markers):
                        cloud.append(provider)
        cloud = list(dict.fromkeys(cloud))
        layers = list(dict.fromkeys(layers))
        evidence_lines = [f"Origem: {origin}", f"IPs: {', '.join(dns_data.get('ips', [])) or '(não resolvido)'}"]
        if cname:
            evidence_lines.append(f"CNAME: {cname}")
        for ip, info in asn_rows:
            if info.get("asn") or info.get("asn_description"):
                evidence_lines.append(
                    f"{ip}: AS{info.get('asn') or '?'} {info.get('asn_description') or info.get('network') or ''} {info.get('country') or ''}".strip()
                )
        evidence_lines.append(f"Cloud/provider provável: {', '.join(cloud) or 'não identificado'}")
        evidence_lines.append(f"WAF/CDN/edge provável: {', '.join(layers) or 'não identificado'}")
        title_bits = []
        if cloud:
            title_bits.append("Cloud: " + ", ".join(cloud))
        if layers:
            title_bits.append("Edge/WAF: " + ", ".join(layers))
        if not title_bits:
            title_bits.append("Mapeamento de infraestrutura")
        finding = Finding(
            merge_key=f"infra|{origin}",
            code="INFRA-MAP",
            title=" | ".join(title_bits),
            category="Infraestrutura",
            severity="info",
            confidence="medium",
            target=origin,
            description="O provedor e as camadas de borda foram inferidos por DNS, ASN/RDAP e assinaturas de cabeçalhos.",
            impact="Este inventário ajuda a entender a superfície, os limites de responsabilidade e a presença de CDN/WAF. A detecção é heurística.",
            recommendation="Confirme o inventário com a equipe de infraestrutura e aplique hardening tanto na origem quanto nas camadas de borda.",
            evidence="\n".join(evidence_lines),
            reproduce=f"dig +short {shlex.quote(hostname_from_origin(origin))} A; dig +short {shlex.quote(hostname_from_origin(origin))} CNAME",
        )
        self.findings.add(finding, sample_url)

    def analyze_takeover(
        self,
        origin: str,
        sample_url: str,
        dns_data: dict[str, Any],
        snapshot: HttpSnapshot | None,
    ) -> None:
        cname = dns_data.get("cname", "")
        if not cname:
            return
        provider = next(
            (item for item in TAKEOVER_PROVIDERS if any(suffix in cname for suffix in item["suffixes"])),
            None,
        )
        body = snapshot.text.lower() if snapshot and not snapshot.error else ""
        fingerprint = ""
        if provider:
            fingerprint = next((item for item in provider["fingerprints"] if item in body), "")
        dangling = dns_data.get("cname_resolves") is False
        if not fingerprint and not dangling:
            return
        provider_name = provider["name"] if provider else "serviço externo"
        severity = "high" if fingerprint and dangling else "medium"
        confidence = "high" if fingerprint and dangling else "medium"
        evidence = [f"Host: {hostname_from_origin(origin)}", f"CNAME: {cname}", f"Provedor provável: {provider_name}"]
        evidence.append(f"Destino CNAME resolve: {'não' if dangling else 'indeterminado/sim'}")
        if fingerprint:
            evidence.append(f"Assinatura HTTP encontrada: {fingerprint}")
        finding = Finding(
            merge_key=f"takeover|{origin}|{cname}",
            code="TAKEOVER-SIGNAL",
            title=f"Indício de subdomain takeover ({provider_name})",
            category="Roteamento e Takeover",
            severity=severity,
            confidence=confidence,
            target=origin,
            description="O host aponta para um serviço de terceiro com sinal de recurso inexistente ou DNS pendente. Isso é um indício, não uma confirmação de que o nome pode ser reivindicado.",
            impact="Se o provedor permitir vincular o identificador abandonado, um terceiro pode servir conteúdo sob o subdomínio confiável.",
            recommendation="Confirme a propriedade no painel do provedor sem tentar reivindicar o recurso fora do procedimento autorizado. Remova o CNAME órfão ou associe-o a um recurso controlado.",
            evidence="\n".join(evidence),
            reproduce=f"dig +noall +answer {shlex.quote(hostname_from_origin(origin))} CNAME; curl -sk -i {shell_url(sample_url)}",
        )
        self.findings.add(finding, sample_url)

    def analyze_http_redirect(self, origin: str, sample_url: str) -> None:
        parsed = urlparse(origin)
        if parsed.port not in (None, 443):
            return
        http_url = f"http://{parsed.hostname}/"
        snapshot = self.fetch(http_url, allow_redirects=False, max_bytes=64 * 1024)
        if snapshot.error:
            return
        location = snapshot.headers.get("location", "")
        valid_redirect = snapshot.status in {301, 302, 303, 307, 308} and urlparse(urljoin(http_url, location)).scheme == "https"
        if valid_redirect:
            return
        candidate = {
            "origin": origin,
            "sample_url": sample_url,
            "http_url": http_url,
            "status": snapshot.status,
            "location": location,
            "evidence": f"GET {http_url}\nHTTP: {snapshot.status}\nLocation: {location or '(ausente)'}",
        }
        with self._redirect_lock:
            self._redirect_candidates.append(candidate)

    def verify_redirects_with_browser(self) -> None:
        """Só reporta redirect HTTP quebrado quando o Chromium headless também confirma."""
        with self._redirect_lock:
            candidates = list(self._redirect_candidates)
        if not candidates:
            return
        if getattr(self.args, "no_browser_evidence", False) or sync_playwright is None:
            if not self.args.quiet:
                print("    [aviso] Redirect HTTP não será reportado sem confirmação Playwright.")
            return
        try:
            with BrowserVerifier(self.args) as browser:
                for item in candidates:
                    proof = browser.navigate(item["http_url"])
                    final_url = proof.get("final_url") or ""
                    parsed_final = urlparse(final_url)
                    if parsed_final.scheme == "https":
                        continue
                    if proof.get("error"):
                        continue
                    finding = Finding(
                        merge_key=f"http-redirect|{item['origin']}",
                        code="HTTP-REDIRECT",
                        title="HTTP não redireciona para HTTPS também no navegador",
                        category="Roteamento e Takeover",
                        severity="medium",
                        confidence="high",
                        target=item["origin"],
                        description=(
                            f"A raiz HTTP respondeu {item['status']} sem redirecionamento inequívoco para HTTPS, "
                            "e o Chromium headless permaneceu em HTTP."
                        ),
                        impact="Usuários que iniciam a navegação por HTTP podem permanecer em transporte sem criptografia ou receber conteúdo diferente.",
                        recommendation="Configure redirecionamento permanente na primeira camada que recebe HTTP e combine-o com HSTS na resposta HTTPS.",
                        evidence=item["evidence"],
                        reproduce=f"curl --silent --show-error --head {shell_url(item['http_url'])}",
                        urls={item["sample_url"], item["http_url"]},
                    )
                    self.findings.add(finding, item["sample_url"])
        except Exception as exc:
            if not self.args.quiet:
                print(f"    [aviso] Confirmação Playwright de redirect indisponível: {exc}", file=sys.stderr)

    def enrich_evidence(self, findings: list[Finding]) -> None:
        """Executa os comandos de reprodução usados nas evidências CLI."""
        if not findings:
            return
        command_timeout = max(self.args.timeout + self.args.connect_timeout + 8.0, 12.0)
        for finding in findings:
            if finding.reproduce and not finding.cli_transcript:
                finding.cli_transcript = run_reproduction_command(finding.reproduce, command_timeout)

    def analyze_certificate_and_tls(self, origin: str, sample_url: str) -> None:
        parsed = urlparse(origin)
        host = parsed.hostname or ""
        port = parsed.port or 443
        cert_error = ""
        cert = None
        chain_error = verify_certificate_chain(host, port, self.args.timeout)
        try:
            raw = fetch_certificate_der(host, port, self.args.timeout)
            cert = x509.load_der_x509_certificate(raw)
        except Exception as exc:
            cert_error = f"{type(exc).__name__}: {exc}"
        if cert is not None:
            now = datetime.now(timezone.utc)
            not_after = cert.not_valid_after_utc
            not_before = cert.not_valid_before_utc
            days = int((not_after - now).total_seconds() // 86400)
            try:
                sans = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
            except x509.ExtensionNotFound:
                sans = []
            try:
                fingerprint = cert.fingerprint(hashes.SHA256()).hex(":")
            except Exception:
                fingerprint = ""
            if days < 0:
                severity, title = "critical", "Certificado TLS expirado"
            elif days <= 14:
                severity, title = "high", "Certificado TLS próximo da expiração"
            elif days <= 45:
                severity, title = "medium", "Certificado TLS próximo da expiração"
            else:
                severity, title = "info", "Inventário do certificado TLS"
            if chain_error:
                severity = highest_severity((severity, "high"))
                title = "Falha na validação do certificado TLS"
            evidence_lines = [
                f"Host: {host}:{port}",
                f"Válido de: {not_before.isoformat()}",
                f"Expira em: {not_after.isoformat()}",
                f"Dias restantes: {days}",
                f"Emissor: {cert.issuer.rfc4514_string()}",
                f"Sujeito: {cert.subject.rfc4514_string()}",
                f"SANs ({len(sans)}): {', '.join(sans) if sans else '(ausente)'}",
                f"SHA-256: {fingerprint}",
                f"Cadeia e hostname: {'FALHA - ' + chain_error if chain_error else 'válidos para o trust store local'}",
            ]
            finding = Finding(
                merge_key=f"certificate|{host}|{port}",
                code="TLS-CERT",
                title=title,
                category="SSL/TLS",
                severity=severity,
                confidence="high",
                target=origin,
                description=f"O certificado possui {days} dia(s) restante(s), emitido por {cert.issuer.rfc4514_string()}." + (f" A validação local falhou: {chain_error}." if chain_error else " A cadeia e o hostname foram validados localmente."),
                impact="Certificados expirados, não confiáveis ou próximos da expiração podem causar indisponibilidade, alertas de navegador e falhas de integração.",
                recommendation="Automatize renovação e monitoramento. Confirme que SANs cobrem apenas nomes necessários e que a cadeia completa e confiável é entregue pelo servidor.",
                evidence="\n".join(evidence_lines),
                reproduce=f"openssl s_client -connect {shlex.quote(host + ':' + str(port))} -servername {shlex.quote(host)} </dev/null 2>/dev/null | openssl x509 -noout -dates -issuer -subject -ext subjectAltName",
            )
            self.findings.add(finding, sample_url)
        elif cert_error:
            finding = Finding(
                merge_key=f"certificate-error|{host}|{port}",
                code="TLS-CERT-ERROR",
                title="Não foi possível obter o certificado TLS",
                category="SSL/TLS",
                severity="low",
                confidence="medium",
                target=origin,
                description="O handshake para extrair o certificado falhou.",
                impact="A falha pode indicar indisponibilidade, incompatibilidade TLS ou configuração incorreta.",
                recommendation="Valide conectividade, SNI, cadeia e configuração TLS manualmente.",
                evidence=f"Host: {host}:{port}\nErro: {cert_error}",
                reproduce=f"openssl s_client -connect {shlex.quote(host + ':' + str(port))} -servername {shlex.quote(host)}",
            )
            self.findings.add(finding, sample_url)

        protocols = test_tls_protocols(host, port, self.args.timeout)
        obsolete = [name for name in ("SSLv3", "TLS 1.0", "TLS 1.1") if protocols.get(name) is True]
        accepted = [name for name, value in protocols.items() if value is True]
        evidence = "\n".join(f"{name}: {format_protocol_status(value)}" for name, value in protocols.items())
        severity = "high" if obsolete else "info"
        title = f"Protocolos TLS obsoletos aceitos: {', '.join(obsolete)}" if obsolete else "Inventário de versões TLS"
        openssl_flags = {
            "SSLv3": "-ssl3",
            "TLS 1.0": "-tls1",
            "TLS 1.1": "-tls1_1",
            "TLS 1.2": "-tls1_2",
            "TLS 1.3": "-tls1_3",
        }
        probe_versions = obsolete or accepted or ["TLS 1.2"]
        tls_reproduce = "\n".join(
            (
                f"openssl s_client -connect {shlex.quote(host + ':' + str(port))} "
                f"-servername {shlex.quote(host)} {openssl_flags[name]} "
                "-cipher 'ALL:@SECLEVEL=0' -brief </dev/null"
            )
            for name in probe_versions
            if name in openssl_flags
        )
        if not tls_reproduce:
            tls_reproduce = f"openssl s_client -connect {shlex.quote(host + ':' + str(port))} -servername {shlex.quote(host)} -brief </dev/null"
        finding = Finding(
            merge_key=f"tls-protocols|{host}|{port}",
            code="TLS-PROTOCOLS",
            title=title,
            category="SSL/TLS",
            severity=severity,
            confidence="high",
            target=origin,
            description=f"Versões aceitas pelo handshake: {', '.join(accepted) if accepted else 'nenhuma confirmada'}.",
            impact="TLS 1.0/1.1 e SSLv3 não atendem práticas modernas e podem habilitar ataques conhecidos ou impedir conformidade.",
            recommendation="Desabilite SSLv3, TLS 1.0 e TLS 1.1; mantenha TLS 1.2 com cifras fortes e TLS 1.3 sempre que suportado.",
            evidence=f"Host: {host}:{port}\n{evidence}",
            reproduce=tls_reproduce,
        )
        self.findings.add(finding, sample_url)

    def analyze_sensitive_files(self, origin: str) -> None:
        random_path = f"/.bird-not-found-{hashlib.sha1(origin.encode()).hexdigest()[:12]}"
        baseline = self.fetch(origin + random_path, allow_redirects=False, max_bytes=128 * 1024)
        baseline_hash = normalized_body_hash(baseline.text) if baseline.status == 200 else ""
        checks = [
            ("/.git/config", "git"),
            ("/.env", "env"),
        ]
        for path, kind in checks:
            url = origin + path
            snapshot = self.fetch(url, allow_redirects=False, max_bytes=256 * 1024)
            if snapshot.error or snapshot.status != 200 or not snapshot.body:
                continue
            body = snapshot.text
            soft_404 = bool(baseline_hash and baseline_hash == normalized_body_hash(body))
            if soft_404:
                continue
            looks_html = "text/html" in snapshot.content_type or bool(re.search(r"(?i)<(?:html|body|head)\b", body[:2000]))
            if kind == "git":
                confirmed = bool(re.search(r"(?im)^\s*\[core\]\s*$", body) and re.search(r"(?im)^\s*repositoryformatversion\s*=", body))
                if not confirmed and looks_html:
                    continue
                severity = "high" if confirmed else "medium"
                confidence = "high" if confirmed else "low"
                title = "Arquivo .git/config exposto" if confirmed else "Possível exposição de .git/config"
                finding = Finding(
                    merge_key=f"git-config|{origin}",
                    code="SENSITIVE-GIT",
                    title=title,
                    category="Arquivos Sensíveis",
                    severity=severity,
                    confidence=confidence,
                    target=origin,
                    description="O caminho /.git/config retornou conteúdo compatível com configuração de repositório." if confirmed else "O caminho /.git/config retornou 200 com conteúdo não HTML, mas a assinatura não foi conclusiva.",
                    impact="Metadados Git podem revelar URLs de repositório e, se outros objetos estiverem acessíveis, permitir reconstrução de código-fonte e histórico.",
                    recommendation="Bloqueie diretórios .git no servidor/proxy, remova metadados do artefato publicado e avalie se segredos históricos precisam ser rotacionados.",
                    evidence=redact_evidence(f"GET {url}\nHTTP 200\nContent-Type: {snapshot.content_type}\n\n{body[:5000]}"),
                    reproduce=f"curl -sk -i {shell_url(url)}",
                )
                self.findings.add(finding, url)
                continue
            env_lines = re.findall(r"(?m)^\s*([A-Za-z_][A-Za-z0-9_.-]{1,})\s*=\s*([^\r\n]*)$", body)
            confirmed = len(env_lines) >= 2 and not looks_html
            if not confirmed:
                continue
            names = [name for name, _ in env_lines[:30]]
            safe_preview = "\n".join(f"{name}=[REDACTED]" for name in names)
            finding = Finding(
                merge_key=f"env|{origin}",
                code="SENSITIVE-ENV",
                title="Arquivo .env exposto",
                category="Arquivos Sensíveis",
                severity="critical" if any(re.search(r"secret|pass|token|key", name, re.I) for name in names) else "high",
                confidence="high",
                target=origin,
                description=f"O caminho /.env retornou {len(env_lines)} variável(is) no formato de arquivo de ambiente. Valores foram removidos da evidência.",
                impact="Arquivos de ambiente podem conter credenciais, chaves de API, endpoints internos e configurações que facilitam comprometimento adicional.",
                recommendation="Remova o arquivo da raiz pública, bloqueie dotfiles, rotacione todos os segredos potencialmente expostos e revise logs/cache/CDN.",
                evidence=f"GET {url}\nHTTP 200\nContent-Type: {snapshot.content_type}\n\n{safe_preview}",
                reproduce=f"curl -sk -i {shell_url(url)}",
            )
            self.findings.add(finding, url)


def hostname_from_origin(origin: str) -> str:
    return urlparse(origin).hostname or ""


def normalized_body_hash(body: str) -> str:
    normalized = re.sub(r"[0-9a-f]{8,}", "<dynamic>", body.lower())
    normalized = re.sub(r"\s+", " ", normalized).strip()[:50_000]
    return hashlib.sha256(normalized.encode("utf-8", errors="ignore")).hexdigest()


def fetch_certificate_der(host: str, port: int, timeout: float) -> bytes:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as raw_socket:
        with context.wrap_socket(raw_socket, server_hostname=host) as tls_socket:
            return tls_socket.getpeercert(binary_form=True)


def verify_certificate_chain(host: str, port: int, timeout: float) -> str:
    """Retorna vazio quando cadeia/hostname são válidos, ou o erro resumido."""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as raw_socket:
            with context.wrap_socket(raw_socket, server_hostname=host):
                return ""
    except Exception as exc:
        return redact_evidence(f"{type(exc).__name__}: {exc}")[:500]


def test_tls_version(host: str, port: int, version: ssl.TLSVersion, timeout: float) -> bool | None:
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.minimum_version = version
        context.maximum_version = version
        try:
            context.set_ciphers("ALL:@SECLEVEL=0")
        except ssl.SSLError:
            pass
        with socket.create_connection((host, port), timeout=timeout) as raw_socket:
            with context.wrap_socket(raw_socket, server_hostname=host):
                return True
    except ssl.SSLError:
        return False
    except (OSError, TimeoutError):
        return None


def test_tls_protocols(host: str, port: int, timeout: float) -> dict[str, bool | None]:
    results: dict[str, bool | None] = {"SSLv3": None}
    versions = [
        ("TLS 1.0", getattr(ssl.TLSVersion, "TLSv1", None)),
        ("TLS 1.1", getattr(ssl.TLSVersion, "TLSv1_1", None)),
        ("TLS 1.2", getattr(ssl.TLSVersion, "TLSv1_2", None)),
        ("TLS 1.3", getattr(ssl.TLSVersion, "TLSv1_3", None)),
    ]
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        for name, version in versions:
            results[name] = test_tls_version(host, port, version, timeout) if version is not None else None
    return results


def format_protocol_status(value: bool | None) -> str:
    if value is True:
        return "ACEITO"
    if value is False:
        return "recusado"
    return "inconclusivo/não suportado pelo cliente local"


def font_path(bold: bool = False) -> str | None:
    candidates = [
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf" if bold else "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
        "/usr/share/fonts/truetype/liberation2/LiberationMono-Bold.ttf" if bold else "/usr/share/fonts/truetype/liberation2/LiberationMono-Regular.ttf",
    ]
    return next((path for path in candidates if os.path.exists(path)), None)


def load_font(size: int, bold: bool = False) -> ImageFont.ImageFont:
    path = font_path(bold)
    if path:
        return ImageFont.truetype(path, size)
    return ImageFont.load_default()


def evidence_png_data_uri(title: str, evidence: str) -> str:
    evidence = redact_evidence(evidence)
    wrapper = textwrap.TextWrapper(width=112, replace_whitespace=False, drop_whitespace=False)
    lines = []
    for raw_line in evidence.splitlines() or ["(sem evidência textual)"]:
        wrapped = wrapper.wrap(raw_line) or [""]
        lines.extend(wrapped)
    omitted = max(0, len(lines) - 34)
    lines = lines[:34]
    if omitted:
        lines.append(f"... {omitted} linha(s) omitida(s) nesta captura; texto completo disponível abaixo.")
    title_font = load_font(25, bold=True)
    body_font = load_font(18)
    small_font = load_font(15)
    width = 1440
    line_height = 28
    height = 124 + max(5, len(lines)) * line_height + 42
    image = Image.new("RGB", (width, height), "#020617")
    draw = ImageDraw.Draw(image)
    draw.rectangle((0, 0, width, 70), fill="#0f172a")
    draw.ellipse((24, 25, 38, 39), fill="#ef4444")
    draw.ellipse((48, 25, 62, 39), fill="#fbbf24")
    draw.ellipse((72, 25, 86, 39), fill="#10b981")
    draw.text((112, 20), title[:80], font=title_font, fill="#ffffff")
    draw.line((0, 69, width, 69), fill="#38bdf8", width=2)
    y = 92
    for index, line in enumerate(lines, start=1):
        draw.text((26, y), f"{index:02d}", font=small_font, fill="#64748b")
        color = "#f87171" if any(token in line.upper() for token in ("AUSENTE", "ERRO", "ACEITO", "EXPOSTO")) else "#cbd5e1"
        draw.text((74, y - 2), line, font=body_font, fill=color)
        y += line_height
    buffer = io.BytesIO()
    image.save(buffer, format="PNG", optimize=True)
    return "data:image/png;base64," + base64.b64encode(buffer.getvalue()).decode("ascii")


def html_text(value: Any) -> str:
    return html.escape(str(value), quote=True)


def render_report_legacy(
    output: Path,
    findings: list[Finding],
    diagnostics: list[dict[str, Any]],
    input_file: Path,
    started_at: datetime,
    duration: float,
    valid_urls: int,
    invalid_lines: int,
    args: argparse.Namespace,
) -> None:
    counts = Counter(item.severity for item in findings)
    categories = Counter(item.category for item in findings)
    origins = sorted({origin_for(url) for item in findings for url in item.urls if urlparse(url).scheme in {"http", "https"}})
    cards = []
    for index, finding in enumerate(findings, start=1):
        urls = sorted(finding.urls) or [finding.target]
        url_links = "".join(
            f'<li><a href="{html_text(sanitize_url(url))}" target="_blank" rel="noreferrer">{html_text(sanitize_url(url))}</a></li>'
            for url in urls[:30]
        )
        if len(urls) > 30:
            url_links += f"<li>+ {len(urls) - 30} URL(s) adicional(is) consolidadas</li>"
        evidence_text = redact_evidence(finding.evidence)
        evidence_image = evidence_png_data_uri(finding.title, evidence_text)
        cards.append(f"""
        <article class="finding" data-severity="{finding.severity}" data-category="{html_text(finding.category)}" data-search="{html_text((finding.title + ' ' + finding.target + ' ' + finding.code).lower())}">
          <div class="finding-top">
            <div><span class="finding-id">#{index:03d} · {html_text(finding.code)}</span><h3>{html_text(finding.title)}</h3></div>
            <span class="badge severity-{finding.severity}">{SEVERITY_LABEL[finding.severity]}</span>
          </div>
          <div class="meta-row">
            <span>Categoria: <strong>{html_text(finding.category)}</strong></span>
            <span>Confiança: <strong>{CONFIDENCE_LABEL.get(finding.confidence, finding.confidence)}</strong></span>
            <span>Ocorrências: <strong>{len(urls)}</strong></span>
          </div>
          <div class="finding-grid">
            <section><h4>Descrição</h4><p>{html_text(finding.description)}</p></section>
            <section><h4>Impacto</h4><p>{html_text(finding.impact)}</p></section>
            <section><h4>Recomendação</h4><p>{html_text(finding.recommendation)}</p></section>
          </div>
          <details class="urls"><summary>URLs afetadas ({len(urls)})</summary><ul>{url_links}</ul></details>
          <details open class="evidence"><summary>Evidência · captura técnica</summary>
            <img loading="lazy" src="{evidence_image}" alt="Captura técnica do achado {index}">
            <pre>{html_text(evidence_text)}</pre>
          </details>
          <details class="reproduce"><summary>Como reproduzir</summary>
            <div class="command"><code>{html_text(finding.reproduce)}</code><button type="button" onclick="copyCommand(this)">copiar</button></div>
          </details>
        </article>""")
    category_options = "".join(f'<option value="{html_text(name)}">{html_text(name)} ({count})</option>' for name, count in sorted(categories.items()))
    diagnostic_rows = []
    for row in sorted(diagnostics, key=lambda item: item["url"]):
        state = row["error"] or (f"HTTP {row['status']}" if row["status"] else "sem resposta")
        diagnostic_rows.append(
            f"<tr><td><a href=\"{html_text(row['url'])}\" target=\"_blank\" rel=\"noreferrer\">{html_text(row['url'])}</a></td>"
            f"<td>{html_text(state)}</td><td>{row['elapsed']:.3f}s</td><td>{row['bytes']}</td></tr>"
        )
    max_count = max(counts.values(), default=1)
    chart = "".join(
        f'<div class="bar-row"><span>{SEVERITY_LABEL[severity]}</span><div class="bar-track"><i class="bar severity-{severity}" style="width:{(counts[severity] / max_count) * 100:.1f}%"></i></div><b>{counts[severity]}</b></div>'
        for severity in ("critical", "high", "medium", "low", "info")
    )
    generated = datetime.now().astimezone()
    report = f"""<!doctype html>
<html lang="pt-BR">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>XPLOIT OPS · Achados finais</title>
<style>
:root{{--bg:#0f172a;--deep:#020617;--panel:rgba(30,41,59,.68);--line:rgba(255,255,255,.11);--text:#fff;--muted:#94a3b8;--soft:#cbd5e1;--red:#ef4444;--blue:#38bdf8;--green:#10b981;--amber:#fbbf24}}
*{{box-sizing:border-box}}html{{scroll-behavior:smooth}}body{{margin:0;background:var(--bg);color:var(--text);font:15px/1.65 Inter,system-ui,sans-serif}}
body:before{{content:"";position:fixed;inset:0;background-image:linear-gradient(rgba(255,255,255,.025) 1px,transparent 1px),linear-gradient(90deg,rgba(255,255,255,.025) 1px,transparent 1px);background-size:50px 50px;pointer-events:none}}
a{{color:var(--blue);word-break:break-all}}.wrap{{width:min(1320px,calc(100% - 36px));margin:auto;position:relative}}header{{border-bottom:1px solid var(--line);background:rgba(15,23,42,.88);backdrop-filter:blur(12px);position:sticky;top:0;z-index:20}}
.nav{{height:72px;display:flex;align-items:center;justify-content:space-between;gap:20px}}.logo{{display:flex;align-items:center;gap:12px;font:900 21px Urbanist,system-ui;letter-spacing:2px}}.sig{{font:900 25px ui-monospace,monospace;color:var(--red)}}.logo small{{font-size:15px;color:var(--soft)}}
button,.btn{{border:1px solid var(--line);background:transparent;color:var(--text);border-radius:4px;padding:10px 14px;font:700 12px ui-monospace,monospace;text-transform:uppercase;cursor:pointer}}button:hover,.btn:hover{{border-color:var(--blue);color:var(--blue)}}
.hero{{padding:72px 0 36px}}.eyebrow,.finding-id{{color:var(--red);font:700 12px ui-monospace,monospace;text-transform:uppercase;letter-spacing:.12em}}h1{{font:800 clamp(34px,6vw,68px)/1.05 Urbanist,system-ui;margin:14px 0}}h1 em{{color:var(--red);font-style:normal}}.lead{{max-width:850px;color:var(--soft);font:15px/1.8 ui-monospace,monospace}}
.summary{{display:grid;grid-template-columns:repeat(5,1fr);gap:14px;margin:28px 0}}.stat,.panel{{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:20px;backdrop-filter:blur(4px)}}.stat b{{display:block;font:900 32px Urbanist,system-ui}}.stat span{{color:var(--muted);font:12px ui-monospace,monospace;text-transform:uppercase}}.stat.alert b{{color:var(--red)}}
.overview{{display:grid;grid-template-columns:1.1fr .9fr;gap:18px;margin:18px 0 36px}}h2{{font:800 28px Urbanist,system-ui}}.bar-row{{display:grid;grid-template-columns:95px 1fr 35px;align-items:center;gap:12px;margin:11px 0;font:12px ui-monospace,monospace}}.bar-track{{height:9px;background:var(--deep);border-radius:10px;overflow:hidden}}.bar{{display:block;height:100%;min-width:2px}}
.severity-critical{{background:#991b1b!important;color:#fecaca!important}}.severity-high{{background:#dc2626!important;color:#fff!important}}.severity-medium{{background:#d97706!important;color:#fff!important}}.severity-low{{background:#2563eb!important;color:#fff!important}}.severity-info{{background:#334155!important;color:#cbd5e1!important}}
.scope p,.scope li{{color:var(--soft)}}.scope code,code,pre{{font-family:"JetBrains Mono",ui-monospace,monospace}}.filters{{display:grid;grid-template-columns:1fr 220px 220px;gap:12px;position:sticky;top:12px;z-index:10;background:rgba(15,23,42,.94);padding:12px;border:1px solid var(--line);border-radius:8px;margin-bottom:20px}}input,select{{width:100%;background:var(--deep);border:1px solid var(--line);border-radius:4px;color:var(--text);padding:12px}}
.finding{{background:var(--panel);border:1px solid var(--line);border-left:3px solid var(--red);border-radius:8px;padding:24px;margin:16px 0;box-shadow:0 14px 45px rgba(0,0,0,.12)}}.finding-top{{display:flex;justify-content:space-between;gap:18px;align-items:flex-start}}.finding h3{{font:750 23px Urbanist,system-ui;margin:5px 0 8px}}.badge{{padding:7px 10px;border-radius:3px;font:800 11px ui-monospace,monospace;text-transform:uppercase;white-space:nowrap}}
.meta-row{{display:flex;flex-wrap:wrap;gap:18px;color:var(--muted);font-size:12px;border-top:1px solid var(--line);border-bottom:1px solid var(--line);padding:10px 0;margin:10px 0 18px}}.finding-grid{{display:grid;grid-template-columns:repeat(3,1fr);gap:16px}}.finding-grid section{{background:rgba(2,6,23,.5);padding:15px;border-radius:5px}}h4{{margin:0 0 6px;font:750 13px ui-monospace,monospace;color:var(--blue);text-transform:uppercase}}p{{margin:0}}details{{border-top:1px solid var(--line);padding-top:12px;margin-top:14px}}summary{{cursor:pointer;font:700 12px ui-monospace,monospace;text-transform:uppercase;color:var(--soft)}}.evidence img{{display:block;width:100%;height:auto;margin:14px 0;border:1px solid rgba(56,189,248,.25);border-radius:5px;background:var(--deep)}}pre{{white-space:pre-wrap;word-break:break-word;background:var(--deep);color:var(--soft);padding:16px;border-radius:4px;max-height:430px;overflow:auto}}.command{{display:flex;gap:10px;align-items:center;margin-top:12px;background:var(--deep);padding:12px}}.command code{{flex:1;word-break:break-all;color:#a7f3d0}}
.empty{{display:none;text-align:center;padding:40px;color:var(--muted)}}table{{width:100%;border-collapse:collapse;font-size:12px}}th,td{{text-align:left;padding:10px;border-bottom:1px solid var(--line);vertical-align:top}}th{{color:var(--blue);font-family:ui-monospace,monospace}}.diagnostics{{overflow:auto;max-height:520px}}footer{{padding:44px 0;color:var(--muted);border-top:1px solid var(--line);margin-top:50px}}
@media(max-width:900px){{.summary{{grid-template-columns:repeat(2,1fr)}}.overview,.finding-grid{{grid-template-columns:1fr}}.filters{{grid-template-columns:1fr;position:relative;top:0}}header{{position:relative}}}}@media print{{header,.filters,.no-print{{display:none!important}}body{{background:#fff;color:#111}}body:before{{display:none}}.finding,.panel,.stat{{break-inside:avoid;background:#fff;color:#111;box-shadow:none}}.evidence{{display:block}}details:not([open])>*:not(summary){{display:block}}a{{color:#111}}}}
</style>
</head>
<body>
<button class="menu-toggle no-print" type="button" aria-label="Abrir menu de navegação" aria-controls="sidebar" aria-expanded="false" onclick="toggleMenu()">☰ menu</button>
<aside id="sidebar" class="sidebar no-print">
  <div class="sidebar-head"><div class="logo"><span class="sig">&gt;X&lt;</span><span>XPLOIT <small>OPS</small></span></div><span class="sidebar-kicker">Bird Final Findings · v{VERSION}</span></div>
  <nav class="side-nav" aria-label="Navegação do relatório">
    <a href="#resumo">Visão geral</a>
    <a href="#achados">[01] Achados ({len(actionable)})</a>
    <details open><summary>Ir para um achado</summary>{nav_findings_markup}</details>
    <a href="#inventario">[02] Inventário ({len(inventory)})</a>
    <details><summary>Itens do inventário</summary>{nav_inventory_markup}</details>
    <a href="#cobertura">[03] Cobertura</a>
    <a href="#diagnostico">[04] Diagnóstico</a>
  </nav>
  <div class="sidebar-actions"><button type="button" onclick="window.print()">Exportar PDF / imprimir</button></div>
</aside>
<div class="menu-backdrop no-print" onclick="closeMenu()"></div>
<div class="page">
<main class="wrap">
  <section id="resumo" class="hero"><div class="eyebrow">&gt;_ modo_operacional: relatório_final</div><h1>Achados de <em>Segurança</em></h1><p class="lead">Relatório técnico gerado pelo Bird Final Findings. Evidências, impacto, recomendações e comandos de reprodução permanecem no próprio arquivo HTML — sem dependências externas.</p></section>
  <section class="summary">
    <div class="stat"><b>{valid_urls}</b><span>URLs analisadas</span></div>
    <div class="stat"><b>{len(origins)}</b><span>Origens com achados</span></div>
    <div class="stat alert"><b>{counts['critical'] + counts['high']}</b><span>Críticos + altos</span></div>
    <div class="stat"><b>{len(findings)}</b><span>Achados consolidados</span></div>
    <div class="stat"><b>{duration:.1f}s</b><span>Duração</span></div>
  </section>
  <section class="overview">
    <div class="panel"><h2>Distribuição por severidade</h2>{chart}</div>
    <div class="panel scope"><h2>Escopo e confiança</h2><p><strong>Insumo:</strong> {html_text(str(input_file))}</p><p><strong>Início:</strong> {html_text(started_at.astimezone().isoformat())}<br><strong>Geração:</strong> {html_text(generated.isoformat())}<br><strong>Linhas inválidas/ignoradas:</strong> {invalid_lines}</p><p>O scanner fez apenas leituras HTTP, OPTIONS, DNS, RDAP e handshakes TLS. Indícios de takeover, CORS, CSRF e métodos anunciados exigem confirmação manual e contextual.</p></div>
  </section>
  <section><h2>[01] Achados</h2>
    <div class="filters no-print"><input id="search" type="search" placeholder="Buscar título, código ou alvo..." oninput="applyFilters()"><select id="severity" onchange="applyFilters()"><option value="">Todas as severidades</option><option value="critical">Crítico ({counts['critical']})</option><option value="high">Alto ({counts['high']})</option><option value="medium">Médio ({counts['medium']})</option><option value="low">Baixo ({counts['low']})</option><option value="info">Informativo ({counts['info']})</option></select><select id="category" onchange="applyFilters()"><option value="">Todas as categorias</option>{category_options}</select></div>
    <div id="finding-list">{''.join(cards)}</div><div id="empty" class="empty">Nenhum achado corresponde aos filtros.</div>
  </section>
  <section><h2>[02] Cobertura e limitações</h2><div class="panel scope"><ul><li>Ausência de header foi avaliada sobre a resposta observada; políticas podem variar por rota, autenticação, proxy ou status.</li><li>OPTIONS informa capacidades anunciadas, mas não prova que PUT/DELETE/TRACE sejam executáveis sem autorização.</li><li>CSRF por análise de formulário é heurístico: frameworks podem usar tokens em headers ou validação server-side não visível.</li><li>CORS com <code>*</code> é informativo quando os dados são públicos; navegadores não aceitam credenciais junto de wildcard.</li><li>Takeover não é explorado nem reivindicado. CNAME pendente e fingerprints são sinais para validação no provedor.</li><li>O scanner limita corpos a {MAX_BODY_BYTES // (1024 * 1024)} MiB e não executa JavaScript. Tecnologias e WAF/CDN são inferências por assinatura.</li></ul></div></section>
  <section><h2>[03] Diagnóstico das URLs</h2><div class="panel diagnostics"><table><thead><tr><th>URL</th><th>Resultado</th><th>Tempo</th><th>Bytes lidos</th></tr></thead><tbody>{''.join(diagnostic_rows)}</tbody></table></div></section>
</main>
<footer><div class="wrap"><div class="logo"><span class="sig">&gt;X&lt;</span><span>XPLOIT <small>OPS</small></span></div><p>Use somente em ativos com autorização explícita. Bird Final Findings v{VERSION}.</p></div></footer>
<script>
function applyFilters(){{const q=document.getElementById('search').value.toLowerCase().trim(),s=document.getElementById('severity').value,c=document.getElementById('category').value;let visible=0;document.querySelectorAll('.finding').forEach(el=>{{const ok=(!q||el.dataset.search.includes(q))&&(!s||el.dataset.severity===s)&&(!c||el.dataset.category===c);el.style.display=ok?'block':'none';if(ok)visible++}});document.getElementById('empty').style.display=visible?'none':'block'}}
function copyCommand(button){{const value=button.parentElement.querySelector('code').textContent;navigator.clipboard.writeText(value).then(()=>{{const old=button.textContent;button.textContent='copiado';setTimeout(()=>button.textContent=old,1300)}})}}
function toggleMenu(){{const open=document.body.classList.toggle('menu-open');document.querySelector('.menu-toggle').setAttribute('aria-expanded',String(open))}}
function closeMenu(){{document.body.classList.remove('menu-open');document.querySelector('.menu-toggle').setAttribute('aria-expanded','false')}}
document.querySelectorAll('.side-nav a').forEach(link=>link.addEventListener('click',closeMenu));
document.addEventListener('keydown',event=>{{if(event.key==='Escape')closeMenu()}});
const navLinks=[...document.querySelectorAll('.side-nav a[href^="#"]')];
const navTargets=navLinks.map(link=>document.querySelector(link.getAttribute('href'))).filter(Boolean);
if('IntersectionObserver' in window){{const observer=new IntersectionObserver(entries=>{{const visible=entries.filter(entry=>entry.isIntersecting).sort((a,b)=>b.intersectionRatio-a.intersectionRatio)[0];if(!visible)return;navLinks.forEach(link=>link.classList.toggle('active',link.getAttribute('href')==='#'+visible.target.id))}},{{rootMargin:'-12% 0px -70% 0px',threshold:[0,.1,.4]}});navTargets.forEach(target=>observer.observe(target))}}
</script>
</body></html>"""
    temporary = output.with_suffix(output.suffix + ".tmp")
    temporary.write_text(report, encoding="utf-8")
    temporary.replace(output)


def render_report(
    output: Path,
    findings: list[Finding],
    diagnostics: list[dict[str, Any]],
    input_file: Path,
    started_at: datetime,
    duration: float,
    valid_urls: int,
    invalid_lines: int,
    args: argparse.Namespace,
) -> None:
    inventory_categories = {"Infraestrutura", "Tecnologias"}
    actionable = [item for item in findings if item.category not in inventory_categories]
    inventory = [item for item in findings if item.category in inventory_categories]
    counts = Counter(item.severity for item in actionable)
    categories = Counter(item.category for item in actionable)
    origins = sorted({origin_for(url) for item in findings for url in item.urls if urlparse(url).scheme in {"http", "https"}})
    nav_finding_links: list[str] = []
    nav_inventory_links: list[str] = []

    def url_links_for(urls: list[str]) -> str:
        links = "".join(
            f'<li><a href="{html_text(sanitize_url(url))}" target="_blank" rel="noreferrer">{html_text(sanitize_url(url))}</a></li>'
            for url in urls[:30]
        )
        if len(urls) > 30:
            links += f"<li>+ {len(urls) - 30} URL(s) adicional(is) consolidadas</li>"
        return links

    def evidence_html(finding: Finding, index: int, open_cli: bool = True) -> str:
        evidence_text = redact_evidence(finding.evidence)
        cli_text = finding.cli_transcript or (
            f"$ {finding.reproduce}\n\n{evidence_text}" if finding.reproduce else evidence_text
        )
        cli_image = evidence_png_data_uri(f"CLI real · {finding.title}", cli_text)
        open_attr = " open" if open_cli else ""
        analysis_block = ""
        if evidence_text.strip():
            analysis_block = f"""
          <details class="evidence-note"><summary>Análise resumida do achado</summary>
            <pre>{html_text(evidence_text)}</pre>
          </details>"""
        return f"""
          <details{open_attr} class="evidence"><summary>Evidência · comando executado no CLI</summary>
            <img loading="lazy" src="{cli_image}" alt="Screenshot CLI do achado {index}">
            <pre>{html_text(cli_text)}</pre>
          </details>
          {analysis_block}
          <details class="reproduce"><summary>Como reproduzir</summary>
            <div class="command"><code>{html_text(finding.reproduce)}</code><button type="button" onclick="copyCommand(this)">copiar</button></div>
          </details>"""

    cards = []
    for index, finding in enumerate(actionable, start=1):
        urls = sorted(finding.urls) or [finding.target]
        finding_id = f"achado-{index:03d}"
        nav_finding_links.append(
            f'<a href="#{finding_id}" title="{html_text(finding.title)}">'
            f'<i class="nav-dot severity-{finding.severity}"></i>'
            f'<span><b>#{index:03d} · {html_text(finding.code)}</b>{html_text(finding.title)}</span></a>'
        )
        cards.append(f"""
        <article id="{finding_id}" class="finding" data-severity="{finding.severity}" data-category="{html_text(finding.category)}" data-search="{html_text((finding.title + ' ' + finding.target + ' ' + finding.code).lower())}">
          <div class="finding-top">
            <div><span class="finding-id">#{index:03d} · {html_text(finding.code)}</span><h3>{html_text(finding.title)}</h3></div>
            <span class="badge severity-{finding.severity}">{SEVERITY_LABEL[finding.severity]}</span>
          </div>
          <div class="meta-row">
            <span>Categoria: <strong>{html_text(finding.category)}</strong></span>
            <span>Confiança: <strong>{CONFIDENCE_LABEL.get(finding.confidence, finding.confidence)}</strong></span>
            <span>Ocorrências: <strong>{len(urls)}</strong></span>
          </div>
          <div class="finding-grid">
            <section><h4>Descrição</h4><p>{html_text(finding.description)}</p></section>
            <section><h4>Impacto</h4><p>{html_text(finding.impact)}</p></section>
            <section><h4>Recomendação</h4><p>{html_text(finding.recommendation)}</p></section>
          </div>
          <details class="urls"><summary>URLs afetadas ({len(urls)})</summary><ul>{url_links_for(urls)}</ul></details>
          {evidence_html(finding, index, open_cli=True)}
        </article>""")

    inventory_rows = []
    for index, finding in enumerate(inventory, start=1):
        urls = sorted(finding.urls) or [finding.target]
        inventory_id = f"inventario-{index:03d}"
        nav_inventory_links.append(
            f'<a href="#{inventory_id}" title="{html_text(finding.title)}">'
            f'<i class="nav-dot severity-{finding.severity}"></i>'
            f'<span><b>{html_text(finding.category)}</b>{html_text(finding.title)}</span></a>'
        )
        inventory_rows.append(f"""
          <tr id="{inventory_id}">
            <td>{html_text(finding.category)}</td>
            <td><a href="{html_text(sanitize_url(finding.target))}" target="_blank" rel="noreferrer">{html_text(sanitize_url(finding.target))}</a></td>
            <td><span class="badge severity-{finding.severity}">{SEVERITY_LABEL[finding.severity]}</span></td>
            <td>
              <details class="inventory-detail">
                <summary>{html_text(finding.title)}</summary>
                <div class="finding-grid compact">
                  <section><h4>Descrição</h4><p>{html_text(finding.description)}</p></section>
                  <section><h4>Impacto</h4><p>{html_text(finding.impact)}</p></section>
                  <section><h4>Recomendação</h4><p>{html_text(finding.recommendation)}</p></section>
                </div>
                <details class="urls"><summary>URLs relacionadas ({len(urls)})</summary><ul>{url_links_for(urls)}</ul></details>
                {evidence_html(finding, index + len(actionable), open_cli=False)}
              </details>
            </td>
          </tr>""")
    if not inventory_rows:
        inventory_rows.append('<tr><td colspan="4">Nenhum item de inventário técnico identificado.</td></tr>')

    diagnostic_rows = []
    for row in sorted(diagnostics, key=lambda item: item["url"]):
        state = row["error"] or (f"HTTP {row['status']}" if row["status"] else "sem resposta")
        diagnostic_rows.append(
            f"<tr><td><a href=\"{html_text(row['url'])}\" target=\"_blank\" rel=\"noreferrer\">{html_text(row['url'])}</a></td>"
            f"<td>{html_text(state)}</td><td>{row['elapsed']:.3f}s</td><td>{row['bytes']}</td></tr>"
        )

    category_options = "".join(f'<option value="{html_text(name)}">{html_text(name)} ({count})</option>' for name, count in sorted(categories.items()))
    max_count = max(counts.values(), default=1)
    chart = "".join(
        f'<div class="bar-row"><span>{SEVERITY_LABEL[severity]}</span><div class="bar-track"><i class="bar severity-{severity}" style="width:{(counts[severity] / max_count) * 100:.1f}%"></i></div><b>{counts[severity]}</b></div>'
        for severity in ("critical", "high", "medium", "low", "info")
    )
    cards_markup = "".join(cards) or '<div class="empty" style="display:block">Nenhum achado acionável foi identificado; confira o inventário técnico e o diagnóstico das URLs.</div>'
    nav_findings_markup = "".join(nav_finding_links) or '<span class="nav-empty">Nenhum achado acionável</span>'
    nav_inventory_markup = "".join(nav_inventory_links) or '<span class="nav-empty">Nenhum item identificado</span>'
    generated = datetime.now().astimezone()
    report = f"""<!doctype html>
<html lang="pt-BR">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>XPLOIT OPS · Achados finais</title>
<style>
:root{{--bg:#0f172a;--deep:#020617;--panel:rgba(30,41,59,.68);--line:rgba(255,255,255,.11);--text:#fff;--muted:#94a3b8;--soft:#cbd5e1;--red:#ef4444;--blue:#38bdf8;--green:#10b981;--amber:#fbbf24}}
*{{box-sizing:border-box}}html{{scroll-behavior:smooth}}body{{margin:0;background:var(--bg);color:var(--text);font:15px/1.65 Inter,system-ui,sans-serif}}
body:before{{content:"";position:fixed;inset:0;background-image:linear-gradient(rgba(255,255,255,.025) 1px,transparent 1px),linear-gradient(90deg,rgba(255,255,255,.025) 1px,transparent 1px);background-size:50px 50px;pointer-events:none}}
a{{color:var(--blue);word-break:break-all}}.wrap{{width:min(1240px,calc(100% - 44px));margin:auto;position:relative}}.page{{margin-left:300px;min-width:0;transition:margin .2s ease}}
.sidebar{{position:fixed;inset:0 auto 0 0;width:300px;z-index:40;display:flex;flex-direction:column;background:rgba(2,6,23,.97);border-right:1px solid var(--line);box-shadow:18px 0 55px rgba(0,0,0,.2)}}.sidebar-head{{padding:24px 20px 18px;border-bottom:1px solid var(--line)}}.logo{{display:flex;align-items:center;gap:12px;font:900 21px Urbanist,system-ui;letter-spacing:2px}}.sig{{font:900 25px ui-monospace,monospace;color:var(--red)}}.logo small{{font-size:15px;color:var(--soft)}}.sidebar-kicker{{display:block;margin-top:7px;color:var(--muted);font:10px ui-monospace,monospace;text-transform:uppercase;letter-spacing:.12em}}
.side-nav{{padding:12px;overflow-y:auto;overscroll-behavior:contain;flex:1}}.side-nav>a,.side-nav details a{{display:flex;align-items:flex-start;gap:9px;padding:9px 10px;margin:2px 0;border-radius:5px;color:var(--soft);text-decoration:none;font:12px/1.35 ui-monospace,monospace;word-break:normal}}.side-nav>a{{font-weight:800;text-transform:uppercase;letter-spacing:.04em}}.side-nav a:hover,.side-nav a.active{{background:rgba(56,189,248,.11);color:#fff}}.side-nav details{{border:0;padding:0;margin:5px 0}}.side-nav details>summary{{padding:9px 10px;color:var(--blue);list-style:none}}.side-nav details>summary::-webkit-details-marker{{display:none}}.side-nav details>summary:before{{content:"›";display:inline-block;margin-right:8px;transition:transform .15s}}.side-nav details[open]>summary:before{{transform:rotate(90deg)}}.side-nav details a span{{min-width:0;display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}.side-nav details a b{{display:block;color:var(--muted);font-size:9px;text-transform:uppercase}}.nav-dot{{width:8px;height:8px;min-width:8px;border-radius:50%;margin-top:4px;padding:0!important}}.nav-empty{{display:block;padding:8px 10px;color:var(--muted);font:11px ui-monospace,monospace}}.sidebar-actions{{padding:14px 18px 20px;border-top:1px solid var(--line)}}
button,.btn{{border:1px solid var(--line);background:transparent;color:var(--text);border-radius:4px;padding:10px 14px;font:700 12px ui-monospace,monospace;text-transform:uppercase;cursor:pointer}}button:hover,.btn:hover{{border-color:var(--blue);color:var(--blue)}}.sidebar-actions button{{width:100%}}.menu-toggle{{display:none;position:fixed;top:14px;left:14px;z-index:60;background:var(--deep)}}.menu-backdrop{{display:none;position:fixed;inset:0;background:rgba(2,6,23,.72);z-index:35}}
.hero{{padding:58px 0 30px}}.eyebrow,.finding-id{{color:var(--red);font:700 12px ui-monospace,monospace;text-transform:uppercase;letter-spacing:.12em}}h1{{font:800 clamp(34px,6vw,68px)/1.05 Urbanist,system-ui;margin:14px 0}}h1 em{{color:var(--red);font-style:normal}}.lead{{max-width:850px;color:var(--soft);font:15px/1.8 ui-monospace,monospace}}section[id],article[id],tr[id]{{scroll-margin-top:20px}}
.summary{{display:grid;grid-template-columns:repeat(6,1fr);gap:14px;margin:28px 0}}.stat,.panel{{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:20px;backdrop-filter:blur(4px)}}.stat b{{display:block;font:900 32px Urbanist,system-ui}}.stat span{{color:var(--muted);font:12px ui-monospace,monospace;text-transform:uppercase}}.stat.alert b{{color:var(--red)}}
.overview{{display:grid;grid-template-columns:1.1fr .9fr;gap:18px;margin:18px 0 36px}}h2{{font:800 28px Urbanist,system-ui}}.bar-row{{display:grid;grid-template-columns:95px 1fr 35px;align-items:center;gap:12px;margin:11px 0;font:12px ui-monospace,monospace}}.bar-track{{height:9px;background:var(--deep);border-radius:10px;overflow:hidden}}.bar{{display:block;height:100%;min-width:2px}}
.severity-critical{{background:#991b1b!important;color:#fecaca!important}}.severity-high{{background:#dc2626!important;color:#fff!important}}.severity-medium{{background:#d97706!important;color:#fff!important}}.severity-low{{background:#2563eb!important;color:#fff!important}}.severity-info{{background:#334155!important;color:#cbd5e1!important}}
.scope p,.scope li{{color:var(--soft)}}.scope code,code,pre{{font-family:"JetBrains Mono",ui-monospace,monospace}}.filters{{display:grid;grid-template-columns:1fr 220px 220px;gap:12px;position:sticky;top:84px;z-index:10;background:rgba(15,23,42,.94);padding:12px;border:1px solid var(--line);border-radius:8px;margin-bottom:20px}}input,select{{width:100%;background:var(--deep);border:1px solid var(--line);border-radius:4px;color:var(--text);padding:12px}}
.finding{{background:var(--panel);border:1px solid var(--line);border-left:3px solid var(--red);border-radius:8px;padding:24px;margin:16px 0;box-shadow:0 14px 45px rgba(0,0,0,.12)}}.finding-top{{display:flex;justify-content:space-between;gap:18px;align-items:flex-start}}.finding h3{{font:750 23px Urbanist,system-ui;margin:5px 0 8px}}.badge{{padding:7px 10px;border-radius:3px;font:800 11px ui-monospace,monospace;text-transform:uppercase;white-space:nowrap}}
.meta-row{{display:flex;flex-wrap:wrap;gap:18px;color:var(--muted);font-size:12px;border-top:1px solid var(--line);border-bottom:1px solid var(--line);padding:10px 0;margin:10px 0 18px}}.finding-grid{{display:grid;grid-template-columns:repeat(3,1fr);gap:16px}}.finding-grid.compact{{margin-top:14px}}.finding-grid section{{background:rgba(2,6,23,.5);padding:15px;border-radius:5px}}h4{{margin:0 0 6px;font:750 13px ui-monospace,monospace;color:var(--blue);text-transform:uppercase}}p{{margin:0;white-space:pre-line}}details{{border-top:1px solid var(--line);padding-top:12px;margin-top:14px}}summary{{cursor:pointer;font:700 12px ui-monospace,monospace;text-transform:uppercase;color:var(--soft)}}.evidence img{{display:block;width:100%;height:auto;margin:14px 0;border:1px solid rgba(56,189,248,.25);border-radius:5px;background:var(--deep)}}pre{{white-space:pre-wrap;word-break:break-word;background:var(--deep);color:var(--soft);padding:16px;border-radius:4px;max-height:430px;overflow:auto}}.command{{display:flex;gap:10px;align-items:center;margin-top:12px;background:var(--deep);padding:12px}}.command code{{flex:1;word-break:break-word;white-space:pre-wrap;color:#a7f3d0}}
.empty{{display:none;text-align:center;padding:40px;color:var(--muted)}}table{{width:100%;border-collapse:collapse;font-size:12px}}th,td{{text-align:left;padding:10px;border-bottom:1px solid var(--line);vertical-align:top}}th{{color:var(--blue);font-family:ui-monospace,monospace}}.diagnostics{{overflow:auto;max-height:520px}}footer{{padding:44px 0;color:var(--muted);border-top:1px solid var(--line);margin-top:50px}}
.inventory-table details{{border-top:0;padding-top:0;margin-top:0}}.inventory-table summary{{color:#fff}}.inventory-table .finding-grid{{grid-template-columns:repeat(3,1fr)}}.section-gap{{margin-top:34px}}
@media(max-width:1100px){{.page{{margin-left:0}}.sidebar{{transform:translateX(-102%);transition:transform .2s ease}}body.menu-open .sidebar{{transform:translateX(0)}}.sidebar-head{{padding-top:68px}}.menu-toggle{{display:block}}body.menu-open .menu-backdrop{{display:block}}.hero{{padding-top:82px}}}}@media(max-width:900px){{.summary{{grid-template-columns:repeat(2,1fr)}}.overview,.finding-grid,.inventory-table .finding-grid{{grid-template-columns:1fr}}.filters{{grid-template-columns:1fr;position:relative;top:0}}}}@media(max-width:540px){{.wrap{{width:min(100% - 24px,1240px)}}.sidebar{{width:min(88vw,320px)}}.finding{{padding:17px}}.finding-top{{display:block}}.badge{{display:inline-block;margin-top:8px}}}}@media print{{.sidebar,.menu-toggle,.menu-backdrop,.filters,.no-print{{display:none!important}}.page{{margin-left:0}}body{{background:#fff;color:#111}}body:before{{display:none}}.finding,.panel,.stat{{break-inside:avoid;background:#fff;color:#111;box-shadow:none}}.evidence{{display:block}}details:not([open])>*:not(summary){{display:block}}a{{color:#111}}}}
</style>
</head>
<body>
<button class="menu-toggle no-print" type="button" aria-label="Abrir menu de navegação" aria-controls="sidebar" aria-expanded="false" onclick="toggleMenu()">☰ menu</button>
<aside id="sidebar" class="sidebar no-print">
  <div class="sidebar-head"><div class="logo"><span class="sig">&gt;X&lt;</span><span>XPLOIT <small>OPS</small></span></div><span class="sidebar-kicker">Bird Final Findings · v{VERSION}</span></div>
  <nav class="side-nav" aria-label="Navegação do relatório">
    <a href="#resumo">Visão geral</a>
    <a href="#achados">[01] Achados ({len(actionable)})</a>
    <details open><summary>Ir para um achado</summary>{nav_findings_markup}</details>
    <a href="#inventario">[02] Inventário ({len(inventory)})</a>
    <details><summary>Itens do inventário</summary>{nav_inventory_markup}</details>
    <a href="#cobertura">[03] Cobertura</a>
    <a href="#diagnostico">[04] Diagnóstico</a>
  </nav>
  <div class="sidebar-actions"><button type="button" onclick="window.print()">Exportar PDF / imprimir</button></div>
</aside>
<div class="menu-backdrop no-print" onclick="closeMenu()"></div>
<div class="page">
<main class="wrap">
  <section id="resumo" class="hero"><div class="eyebrow">&gt;_ modo_operacional: relatório_final</div><h1>Achados de <em>Segurança</em></h1><p class="lead">Relatório técnico gerado pelo Bird Final Findings. Evidências, impacto, recomendações e comandos de reprodução permanecem no próprio arquivo HTML — sem dependências externas.</p></section>
  <section class="summary">
    <div class="stat"><b>{valid_urls}</b><span>URLs analisadas</span></div>
    <div class="stat"><b>{len(origins)}</b><span>Origens com achados</span></div>
    <div class="stat alert"><b>{counts['critical'] + counts['high']}</b><span>Críticos + altos</span></div>
    <div class="stat"><b>{len(actionable)}</b><span>Achados acionáveis</span></div>
    <div class="stat"><b>{len(inventory)}</b><span>Inventário técnico</span></div>
    <div class="stat"><b>{duration:.1f}s</b><span>Duração</span></div>
  </section>
  <section class="overview">
    <div class="panel"><h2>Distribuição por severidade</h2>{chart}</div>
    <div class="panel scope"><h2>Escopo e confiança</h2><p><strong>Insumo:</strong> {html_text(str(input_file))}</p><p><strong>Início:</strong> {html_text(started_at.astimezone().isoformat())}<br><strong>Geração:</strong> {html_text(generated.isoformat())}<br><strong>Linhas inválidas/ignoradas:</strong> {invalid_lines}</p><p>O scanner fez leituras HTTP, OPTIONS, DNS, RDAP e handshakes TLS. Os comandos de reprodução foram executados para gerar as evidências CLI. Um navegador headless é usado somente como validação interna de redirecionamento HTTP, sem capturas no relatório.</p></div>
  </section>
  <section id="achados"><h2>[01] Achados</h2>
    <div class="filters no-print"><input id="search" type="search" placeholder="Buscar título, código ou alvo..." oninput="applyFilters()"><select id="severity" onchange="applyFilters()"><option value="">Todas as severidades</option><option value="critical">Crítico ({counts['critical']})</option><option value="high">Alto ({counts['high']})</option><option value="medium">Médio ({counts['medium']})</option><option value="low">Baixo ({counts['low']})</option><option value="info">Informativo ({counts['info']})</option></select><select id="category" onchange="applyFilters()"><option value="">Todas as categorias</option>{category_options}</select></div>
    <div id="finding-list">{cards_markup}</div><div id="empty" class="empty">Nenhum achado corresponde aos filtros.</div>
  </section>
  <section id="inventario" class="section-gap"><h2>[02] Inventário técnico</h2><div class="panel diagnostics inventory-table"><table><thead><tr><th>Categoria</th><th>Alvo</th><th>Severidade</th><th>Achado clicável / evidências</th></tr></thead><tbody>{''.join(inventory_rows)}</tbody></table></div></section>
  <section id="cobertura"><h2>[03] Cobertura e limitações</h2><div class="panel scope"><ul><li>Cabeçalhos faltantes foram consolidados em um achado por origem e avaliados sobre as respostas observadas; políticas podem variar por rota, autenticação, proxy ou status.</li><li>OPTIONS informa capacidades anunciadas, mas não prova que PUT/DELETE/TRACE sejam executáveis sem autorização.</li><li>CSRF por análise de formulário é heurístico: frameworks podem usar tokens em headers ou validação server-side não visível.</li><li>CORS com <code>*</code> é informativo quando os dados são públicos; navegadores não aceitam credenciais junto de wildcard.</li><li>Takeover não é explorado nem reivindicado. CNAME pendente e fingerprints são sinais para validação no provedor.</li><li>O scanner limita corpos a {MAX_BODY_BYTES // (1024 * 1024)} MiB. Tecnologias e WAF/CDN são inferências por assinatura; o navegador headless é usado somente para confirmar redirecionamento HTTP, sem gerar evidências visuais.</li></ul></div></section>
  <section id="diagnostico"><h2>[04] Diagnóstico das URLs</h2><div class="panel diagnostics"><table><thead><tr><th>URL</th><th>Resultado</th><th>Tempo</th><th>Bytes lidos</th></tr></thead><tbody>{''.join(diagnostic_rows)}</tbody></table></div></section>
</main>
<footer><div class="wrap"><div class="logo"><span class="sig">&gt;X&lt;</span><span>XPLOIT <small>OPS</small></span></div><p>Use somente em ativos com autorização explícita. Bird Final Findings v{VERSION}.</p></div></footer>
</div>
<script>
function applyFilters(){{const q=document.getElementById('search').value.toLowerCase().trim(),s=document.getElementById('severity').value,c=document.getElementById('category').value;let visible=0;document.querySelectorAll('.finding').forEach(el=>{{const ok=(!q||el.dataset.search.includes(q))&&(!s||el.dataset.severity===s)&&(!c||el.dataset.category===c);el.style.display=ok?'block':'none';if(ok)visible++}});document.getElementById('empty').style.display=visible?'none':'block'}}
function copyCommand(button){{const value=button.parentElement.querySelector('code').textContent;navigator.clipboard.writeText(value).then(()=>{{const old=button.textContent;button.textContent='copiado';setTimeout(()=>button.textContent=old,1300)}})}}
function toggleMenu(){{const open=document.body.classList.toggle('menu-open'),button=document.querySelector('.menu-toggle');button.setAttribute('aria-expanded',String(open));button.textContent=open?'× fechar':'☰ menu'}}
function closeMenu(){{const button=document.querySelector('.menu-toggle');document.body.classList.remove('menu-open');button.setAttribute('aria-expanded','false');button.textContent='☰ menu'}}
document.querySelectorAll('.side-nav a').forEach(link=>link.addEventListener('click',closeMenu));
document.addEventListener('keydown',event=>{{if(event.key==='Escape')closeMenu()}});
const navLinks=[...document.querySelectorAll('.side-nav a[href^="#"]')];
const navTargets=navLinks.map(link=>document.querySelector(link.getAttribute('href'))).filter(Boolean);
if('IntersectionObserver' in window){{const observer=new IntersectionObserver(entries=>{{const visible=entries.filter(entry=>entry.isIntersecting).sort((a,b)=>b.intersectionRatio-a.intersectionRatio)[0];if(!visible)return;navLinks.forEach(link=>link.classList.toggle('active',link.getAttribute('href')==='#'+visible.target.id))}},{{rootMargin:'-12% 0px -70% 0px',threshold:[0,.1,.4]}});navTargets.forEach(target=>observer.observe(target))}}
</script>
</body></html>"""
    temporary = output.with_suffix(output.suffix + ".tmp")
    temporary.write_text(report, encoding="utf-8")
    temporary.replace(output)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="bird-final-findings.py",
        description="Analisa URLs de um pentest autorizado e gera dashboard HTML autocontido.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("-f", "--file", required=True, help="arquivo com uma URL http(s) por linha")
    parser.add_argument("-o", "--output", help="caminho do relatório HTML (padrão: diretório atual)")
    parser.add_argument("--workers", type=int, default=8, help="requisições concorrentes")
    parser.add_argument("--timeout", type=float, default=12.0, help="timeout de leitura/handshake em segundos")
    parser.add_argument("--connect-timeout", type=float, default=5.0, help="timeout de conexão em segundos")
    parser.add_argument("--delay", type=float, default=0.0, help="pausa por requisição em cada worker")
    parser.add_argument("--max-urls", type=int, default=0, help="limita URLs após deduplicação; 0 processa todas")
    parser.add_argument("--proxy", help="proxy HTTP(S), por exemplo http://127.0.0.1:8080")
    parser.add_argument("--user-agent", default=DEFAULT_USER_AGENT, help="User-Agent das requisições")
    parser.add_argument("--verify-tls", action="store_true", help="valida a cadeia TLS também nas requisições HTTP")
    parser.add_argument("--no-cors", action="store_true", help="desativa a requisição adicional com Origin de teste")
    parser.add_argument("--no-sensitive-files", action="store_true", help="não consulta .git/config e .env")
    parser.add_argument("--no-asn", action="store_true", help="não executa consultas RDAP para ASN/provider")
    parser.add_argument(
        "--no-browser-verification", "--no-browser-evidence",
        dest="no_browser_evidence", action="store_true",
        help="não usa Playwright/Chromium para confirmar redirecionamento HTTP",
    )
    parser.add_argument("-q", "--quiet", action="store_true", help="omite o progresso individual de cada URL")
    parser.add_argument("--dry-run", action="store_true", help="valida e deduplica o arquivo, sem acessar a rede")
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    args = parser.parse_args(argv)
    if not 1 <= args.workers <= 64:
        parser.error("--workers deve estar entre 1 e 64")
    if args.timeout <= 0 or args.connect_timeout <= 0 or args.delay < 0:
        parser.error("timeouts devem ser positivos e delay não pode ser negativo")
    return args


def load_urls(path: Path, max_urls: int) -> tuple[list[str], int, int]:
    seen = set()
    urls = []
    invalid = 0
    duplicates = 0
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        normalized = normalize_url(raw)
        if normalized is None:
            invalid += 1
            continue
        if normalized in seen:
            duplicates += 1
            continue
        seen.add(normalized)
        urls.append(normalized)
        if max_urls and len(urls) >= max_urls:
            break
    return urls, invalid, duplicates


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    input_file = Path(args.file).expanduser()
    if not input_file.is_file():
        print(f"[ERRO] Arquivo não encontrado: {input_file}", file=sys.stderr)
        return 2
    try:
        urls, invalid, duplicates = load_urls(input_file, args.max_urls)
    except OSError as exc:
        print(f"[ERRO] Não foi possível ler {input_file}: {exc}", file=sys.stderr)
        return 2
    if not urls:
        print("[ERRO] Nenhuma URL HTTP(S) válida foi encontrada.", file=sys.stderr)
        return 2
    print(f"[+] Bird Final Findings v{VERSION}")
    print("[!] Use somente em ativos com autorização explícita.")
    print(f"[+] {len(urls)} URL(s) única(s); {duplicates} duplicada(s); {invalid} inválida(s).")
    if args.dry_run:
        for url in urls:
            print(url)
        return 0
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    started_at = datetime.now().astimezone()
    started = time.monotonic()
    scanner = Scanner(args)
    print(f"[+] Fase 1/3: HTTP, headers, cookies, métodos, CORS/CSRF e tecnologias ({args.workers} workers)")
    completed = 0
    with ThreadPoolExecutor(max_workers=args.workers, thread_name_prefix="bird-page") as executor:
        futures = {executor.submit(scanner.scan_page, url): url for url in urls}
        for future in as_completed(futures):
            completed += 1
            url = futures[future]
            try:
                snapshot = future.result()
                state = f"HTTP {snapshot.status}" if snapshot.status else "falha"
            except Exception as exc:
                state = f"erro: {exc}"
            if not args.quiet:
                print(f"    [{completed}/{len(urls)}] {state} {sanitize_url(url)}")
    scanner.finalize_security_headers()
    origins: dict[str, str] = {}
    for url in urls:
        origins.setdefault(origin_for(url), url)
    print(f"[+] Fase 2/3: DNS, takeover, TLS, redirect, arquivos sensíveis e infraestrutura ({len(origins)} origem(ns))")
    with ThreadPoolExecutor(max_workers=min(args.workers, max(1, len(origins))), thread_name_prefix="bird-origin") as executor:
        futures = {executor.submit(scanner.analyze_origin, origin, sample): origin for origin, sample in origins.items()}
        for future in as_completed(futures):
            origin = futures[future]
            try:
                future.result()
                if not args.quiet:
                    print(f"    [ok] {origin}")
            except Exception as exc:
                print(f"    [aviso] {origin}: {exc}", file=sys.stderr)
    scanner.verify_redirects_with_browser()
    findings = scanner.findings.sorted()
    print(f"[+] Fase 3/3: evidências CLI reais ({len(findings)} achado(s))")
    scanner.enrich_evidence(findings)
    duration = time.monotonic() - started
    if args.output:
        output = Path(args.output).expanduser()
        if not output.is_absolute():
            output = Path.cwd() / output
    else:
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        output = Path.cwd() / f"xploitops-achados-{stamp}.html"
    if output.suffix.lower() != ".html":
        output = output.with_suffix(".html")
    try:
        output.parent.mkdir(parents=True, exist_ok=True)
        render_report(output, findings, scanner.diagnostics, input_file, started_at, duration, len(urls), invalid, args)
    except OSError as exc:
        print(f"[ERRO] Não foi possível gravar o relatório: {exc}", file=sys.stderr)
        return 2
    counts = Counter(item.severity for item in findings)
    print(
        f"[+] Concluído em {duration:.1f}s: {len(findings)} achado(s) consolidado(s) "
        f"(crítico={counts['critical']}, alto={counts['high']}, médio={counts['medium']}, baixo={counts['low']}, info={counts['info']})."
    )
    print(f"[+] Relatório: {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
