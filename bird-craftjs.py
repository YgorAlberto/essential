#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Bird-CraftJS: análise estática de páginas, bundles JavaScript e source maps."""

import argparse
import ipaddress
import json
import random
import re
import shlex
import stat
import sys
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from urllib.parse import unquote, urljoin, urlparse, urlunparse

try:
    import requests
    import urllib3
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError:
    print("[ERRO] Instale a dependência: pip install requests", file=sys.stderr)
    raise SystemExit(1)

try:
    from bs4 import BeautifulSoup
except ImportError:
    print("[ERRO] Instale a dependência: pip install beautifulsoup4", file=sys.stderr)
    raise SystemExit(1)

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
except ImportError:
    class _NoColor:
        def __getattr__(self, _name):
            return ""
    Fore = Style = _NoColor()


TOOL_VERSION = "3.1"
DEFAULT_OUTPUT = "output-craftjs.txt"
DEFAULT_MAX_BYTES = 5 * 1024 * 1024
BACKTICK = chr(96)
HTTP_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
STATIC_EXTENSIONS = {
    ".avif", ".bmp", ".css", ".eot", ".gif", ".ico", ".jpeg", ".jpg", ".mp3",
    ".mp4", ".pdf", ".png", ".svg", ".ttf", ".webp", ".woff", ".woff2",
}
API_PREFIXES = (
    "/api", "/rest", "/graphql", "/gql", "/rpc", "/oauth", "/auth",
    "/openid", "/.well-known", "/swagger", "/actuator", "/v1/", "/v2/",
    "/v3/", "/internal/", "/admin/api",
)
CONFIDENCE_RANK = {"low": 1, "medium": 2, "high": 3}
FINDING_GUIDANCE = {
    "AWS Access Key": "Confirme o proprietário e valide identidade/permissões somente no ambiente autorizado; depois rotacione a chave.",
    "Google API Key": "Verifique restrições de origem, APIs habilitadas e cotas; rotacione se a chave não deveria ser pública.",
    "GitHub Token": "Valide o escopo do token de forma autorizada e revogue-o imediatamente se estiver ativo.",
    "Slack Token": "Confirme workspace e escopos sem enviar mensagens; revogue o token exposto.",
    "Stripe Secret Key": "Não realize transações; confirme ambiente e rotacione a credencial no painel autorizado.",
    "Database URI": "Não conecte sem autorização explícita; remova a URI do cliente e rotacione as credenciais.",
    "JDBC Connection": "Revise host, usuário e segredo expostos; valide conectividade apenas no escopo autorizado.",
    "Webhook": "Evite publicar mensagens de teste; confirme o destino e revogue o webhook exposto.",
    "Generic Credential": "Identifique o serviço consumidor, valide o escopo e rotacione o segredo.",
    "Bearer Token": "Decodifique localmente quando aplicável, confira expiração/escopos e não reutilize fora do teste autorizado.",
    "Private Key": "Trate como comprometida, remova do bundle e substitua o par de chaves.",
    "Cloud Storage": "Verifique políticas de leitura/listagem sem alterar ou enviar objetos.",
    "Admin/Debug Route": "Teste acesso e exposição de metadados sem executar ações administrativas.",
    "Debug Parameter": "Compare a resposta com e sem o parâmetro e procure informações sensíveis adicionais.",
    "CI/CD Config": "Revise o arquivo e o histórico em busca de variáveis, tokens e permissões excessivas.",
    "Filesystem Path": "Use somente como evidência de exposição; não tente acessar o caminho fora do escopo.",
    "Subdomínio relacionado": "Valide resolução, propriedade e superfície exposta do hostname.",
}
PLACEHOLDER_MARKERS = {
    "xxx", "your_", "example", "sample", "placeholder", "change_me", "changeme",
    "replace_me", "todo", "undefined", "dummy", "fake",
}
COMMON_CLIENT_RE = re.compile(
    r"^(?:api|apiClient|client|http|httpClient|request|requester|service|sdk|restClient)[A-Za-z0-9_$]*$",
    re.IGNORECASE,
)

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
]

FINDING_PATTERNS = [
    ("AWS Access Key", re.compile(r"\b(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b"), "critical", "Possível identificador de credencial AWS exposto.", True),
    ("Google API Key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), "high", "Possível chave de API Google exposta.", True),
    ("GitHub Token", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{36,}\b"), "critical", "Possível token GitHub exposto.", True),
    ("Slack Token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{20,}\b"), "high", "Possível token Slack exposto.", True),
    ("Stripe Secret Key", re.compile(r"\bsk_(?:live|test)_[0-9A-Za-z]{24,}\b"), "critical", "Possível chave secreta Stripe exposta.", True),
    ("SendGrid Key", re.compile(r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b"), "critical", "Possível chave SendGrid exposta.", True),
    ("Twilio Key", re.compile(r"\bSK[0-9a-fA-F]{32}\b"), "high", "Possível chave de API Twilio exposta.", True),
    ("Telegram Bot Token", re.compile(r"\b[0-9]{8,10}:[A-Za-z0-9_-]{35}\b"), "high", "Possível token de bot Telegram exposto.", True),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_.+/=-]*\b"), "high", "Token JWT encontrado no cliente.", True),
    ("Private Key", re.compile(r"-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----"), "critical", "Marcador de chave privada encontrado.", True),
    ("Database URI", re.compile(r"\b(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|mssql|sqlserver)://[^\s\"'<>]+", re.I), "critical", "String de conexão de banco de dados encontrada.", True),
    ("JDBC Connection", re.compile(r"\bjdbc:[a-z0-9]+:[^\s\"'<>]+", re.I), "high", "String de conexão JDBC encontrada.", True),
    ("Webhook", re.compile(r"https://(?:hooks\.slack\.com|discord(?:app)?\.com/api/webhooks|outlook\.office\.com/webhook)/?[^\s\"'<>]*", re.I), "high", "Webhook potencialmente utilizável encontrado.", True),
    ("Cloud Storage", re.compile(r"(?:https?://)?(?:[a-z0-9.-]+\.s3[.-][a-z0-9.-]*\.amazonaws\.com|[a-z0-9.-]+\.blob\.core\.windows\.net|[a-z0-9.-]+\.storage\.googleapis\.com)", re.I), "medium", "Endpoint de armazenamento em nuvem encontrado.", False),
    ("Generic Credential", re.compile(r"""(?ix)\b(?:password|passwd|secret|client_secret|api[_-]?key|auth[_-]?token)[\"']?\s*[:=]\s*[\"'](?P<value>[^\"'\r\n]{6,})[\"']"""), "high", "Valor semelhante a segredo hardcoded encontrado.", True),
    ("Bearer Token", re.compile(r"""(?ix)\bAuthorization[\"']?\s*[:=]\s*[\"']Bearer\s+(?P<value>[^\"'\s]{8,})"""), "high", "Bearer token hardcoded encontrado.", True),
    ("CI/CD Config", re.compile(r"(?:\.gitlab-ci\.ya?ml|Jenkinsfile|\.github/workflows/[A-Za-z0-9_.-]+\.ya?ml|bitbucket-pipelines\.ya?ml)", re.I), "medium", "Referência a arquivo de pipeline encontrada.", False),
    ("Admin/Debug Route", re.compile(r"(?:/actuator(?:/[^\"'\s]*)?|/server-status|/console|/swagger-ui(?:/[^\"'\s]*)?|/graphql|/phpinfo\.php|/env)\b", re.I), "medium", "Rota administrativa, de documentação ou debug encontrada.", False),
    ("Debug Parameter", re.compile(r"[?&](?:debug=true|test=1|admin=1|show_errors=true)\b", re.I), "medium", "Parâmetro que pode alterar o fluxo ou habilitar debug.", False),
    ("Filesystem Path", re.compile(r"(?:/(?:var/www|home|usr/local)/[A-Za-z0-9_./-]+|[C-Z]:\\[A-Za-z0-9_ .\\-]+)"), "low", "Possível caminho absoluto do sistema de arquivos encontrado.", False),
    ("Email", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), "info", "Endereço de e-mail encontrado.", False),
    ("IPv4", re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"), "info", "Endereço IPv4 encontrado.", False),
]


@dataclass
class ScanItem:
    locator: str
    context_url: str | None = None
    depth: int = 0
    local: bool = False


@dataclass
class Endpoint:
    method: str
    url: str
    raw: str
    kind: str
    confidence: str
    source: str
    body_fields: tuple[str, ...] = ()
    auth_hint: bool = False
    dynamic: bool = False
    sources: set[str] = field(default_factory=set)

    def __post_init__(self):
        if not self.sources:
            self.sources.add(self.source)


@dataclass
class Finding:
    category: str
    value: str
    severity: str
    description: str
    secret: bool
    sources: set[str] = field(default_factory=set)


@dataclass
class FetchResult:
    text: str
    status: int
    final_url: str
    content_type: str
    truncated: bool
    size: int


@dataclass
class ScanTiming:
    source: str
    status: str
    download_seconds: float = 0.0
    analysis_seconds: float = 0.0
    discovery_seconds: float = 0.0
    total_seconds: float = 0.0
    size: int = 0


def clean_whitespace(value):
    return re.sub(r"\s+", " ", value or "").strip()


def is_placeholder(value):
    lowered = value.lower()
    return (
        any(marker in lowered for marker in PLACEHOLDER_MARKERS)
        or len(set(value)) < 3
        or value in {"null", "true", "false"}
    )


def mask_secret(value):
    if len(value) <= 10:
        return value[:2] + "…" + value[-2:] if len(value) > 4 else "••••"
    return value[:5] + "…" + value[-4:]


def decode_js_string(value):
    value = re.sub(r"\\+/", "/", value)
    value = re.sub(r"\\x([0-9a-fA-F]{2})", lambda m: chr(int(m.group(1), 16)), value)
    value = re.sub(r"\\u([0-9a-fA-F]{4})", lambda m: chr(int(m.group(1), 16)), value)
    replacements = {
        r"\n": "\n", r"\r": "\r", r"\t": "\t", r"\'": "'", r'\"': '"',
        "\\\\" + BACKTICK: BACKTICK, r"\\": "\\",
    }
    for escaped, decoded in replacements.items():
        value = value.replace(escaped, decoded)
    return value


def extract_balanced(text, open_index, opener="(", closer=")"):
    if open_index >= len(text) or text[open_index] != opener:
        return None, open_index
    depth = 0
    quote = None
    escaped = False
    index = open_index
    while index < len(text):
        char = text[index]
        next_char = text[index + 1] if index + 1 < len(text) else ""
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif quote == BACKTICK and char == "$" and next_char == "{":
                nested, end = extract_balanced(text, index + 1, "{", "}")
                if nested is None:
                    return None, index
                index = end
                continue
            elif char == quote:
                quote = None
            index += 1
            continue
        if char in ('"', "'", BACKTICK):
            quote = char
        elif char == "/" and next_char == "/":
            newline = text.find("\n", index + 2)
            index = len(text) if newline == -1 else newline
            continue
        elif char == "/" and next_char == "*":
            end_comment = text.find("*/", index + 2)
            index = len(text) if end_comment == -1 else end_comment + 2
            continue
        elif char == opener:
            depth += 1
        elif char == closer:
            depth -= 1
            if depth == 0:
                return text[open_index + 1:index], index + 1
        index += 1
    return None, index


def split_top_level(text, delimiter=","):
    parts, stack = [], []
    start = index = 0
    quote = None
    escaped = False
    pairs = {"(": ")", "[": "]", "{": "}"}
    while index < len(text):
        char = text[index]
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            index += 1
            continue
        if char in ('"', "'", BACKTICK):
            quote = char
        elif char in pairs:
            stack.append(pairs[char])
        elif stack and char == stack[-1]:
            stack.pop()
        elif not stack and text.startswith(delimiter, index):
            parts.append(text[start:index].strip())
            index += len(delimiter)
            start = index
            continue
        index += 1
    parts.append(text[start:].strip())
    return parts


def read_expression(text, start, delimiters=(";", "\n", ","), max_chars=8192):
    stack = []
    quote = None
    escaped = False
    pairs = {"(": ")", "[": "]", "{": "}"}
    index = start
    limit = min(len(text), start + max_chars)
    while index < limit:
        char = text[index]
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            index += 1
            continue
        if char in ('"', "'", BACKTICK):
            quote = char
        elif char in pairs:
            stack.append(pairs[char])
        elif stack and char == stack[-1]:
            stack.pop()
        elif not stack and char in ")}]":
            break
        elif not stack and char in delimiters:
            break
        index += 1
    return text[start:index].strip(), index


def iter_js_strings(text, max_length=2048):
    """Itera strings JS em tempo linear, evitando backtracking em bundles grandes."""
    index, text_length = 0, len(text)
    while index < text_length:
        quote = text[index]
        if quote not in ('"', "'", BACKTICK):
            index += 1
            continue
        start = index + 1
        index = start
        escaped = False
        while index < text_length:
            char = text[index]
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                if index - start <= max_length:
                    yield quote, text[start:index]
                index += 1
                break
            elif char in "\r\n" and quote != BACKTICK:
                # Não é uma string válida; retome após a quebra para não
                # engolir o restante do bundle.
                index += 1
                break
            index += 1


def strip_wrapping_parentheses(expression):
    expression = expression.strip()
    while expression.startswith("(") and expression.endswith(")"):
        inner, end = extract_balanced(expression, 0)
        if inner is None or end != len(expression):
            break
        expression = inner.strip()
    return expression


def template_value(template, constants, origin):
    def replace(match):
        expression = match.group(1).strip()
        resolved = evaluate_expression(expression, constants, origin, allow_placeholder=False)
        if resolved is not None:
            return resolved
        name = re.sub(r"[^A-Za-z0-9_.-]+", "_", expression).strip("_") or "value"
        return "{" + name + "}"
    return re.sub(r"\$\{(.*?)\}", replace, template, flags=re.DOTALL)


def evaluate_expression(expression, constants, origin, allow_placeholder=True):
    expression = strip_wrapping_parentheses(clean_whitespace(expression))
    if not expression:
        return None
    fallback_parts = split_top_level(expression, "||")
    if len(fallback_parts) > 1:
        for part in fallback_parts:
            resolved = evaluate_expression(part, constants, origin, allow_placeholder=False)
            if resolved and not resolved.startswith("{"):
                return resolved
        return evaluate_expression(fallback_parts[-1], constants, origin, allow_placeholder)
    if len(expression) >= 2 and expression[0] in ('"', "'", BACKTICK) and expression[-1] == expression[0]:
        body = decode_js_string(expression[1:-1])
        return template_value(body, constants, origin) if expression[0] == BACKTICK else body
    if re.match(r"^new\s+URL\s*\(", expression):
        open_index = expression.find("(")
        arguments_text, end = extract_balanced(expression, open_index)
        if arguments_text is not None and not expression[end:].strip():
            arguments = split_top_level(arguments_text)
            route = evaluate_expression(arguments[0], constants, origin) if arguments else None
            base = evaluate_expression(arguments[1], constants, origin) if len(arguments) > 1 else origin
            if route and base:
                return urljoin(base.rstrip("/") + "/", route)
    concat_match = re.fullmatch(r"(.+)\.concat\((.*)\)", expression, re.DOTALL)
    if concat_match:
        base_value = evaluate_expression(concat_match.group(1), constants, origin, True)
        arguments = [
            evaluate_expression(part, constants, origin, True)
            for part in split_top_level(concat_match.group(2))
        ]
        if base_value is not None and all(value is not None for value in arguments):
            return base_value + "".join(arguments)
    join_match = re.fullmatch(r"\[(.*)\]\.join\(\s*([\"'])(.*?)\2\s*\)", expression, re.DOTALL)
    if join_match:
        values = [evaluate_expression(part, constants, origin) for part in split_top_level(join_match.group(1))]
        if all(value is not None for value in values):
            return join_match.group(3).join(values)
    plus_parts = split_top_level(expression, "+")
    if len(plus_parts) > 1:
        values = [evaluate_expression(part, constants, origin, True) for part in plus_parts]
        return "".join(values) if all(value is not None for value in values) else None
    if expression in {"window.location.origin", "location.origin", "document.location.origin"}:
        return origin
    if expression in constants:
        return constants[expression]
    if re.fullmatch(r"[A-Za-z_$][\w$]*", expression):
        return "{" + expression + "}" if allow_placeholder else None
    if re.fullmatch(r"[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+", expression):
        if any(marker in expression for marker in ("process.env", "import.meta.env", "window.__ENV")):
            return None
        leaf = expression.rsplit(".", 1)[-1]
        return "{" + leaf + "}" if allow_placeholder else None
    return None


def extract_constants(content, origin):
    assignments = []
    for match in re.finditer(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=", content):
        expression, _ = read_expression(content, match.end(), delimiters=(";", "\n"))
        if expression:
            assignments.append((match.group(1), expression))
    constants = {}
    for _ in range(5):
        changed = False
        for name, expression in assignments:
            value = evaluate_expression(expression, constants, origin, False)
            if value is not None and constants.get(name) != value:
                constants[name] = value
                changed = True
        if not changed:
            break
    for match in re.finditer(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*\{", content):
        open_index = content.find("{", match.start())
        body, _ = extract_balanced(content, open_index, "{", "}")
        if body is None:
            continue
        for part in split_top_level(body):
            prop = re.match(r"\s*([A-Za-z_$][\w$]*)\s*:\s*(.*)", part, re.DOTALL)
            if prop:
                value = evaluate_expression(prop.group(2), constants, origin, False)
                if value is not None:
                    constants[f"{match.group(1)}.{prop.group(1)}"] = value
    return constants


def object_property(expression, names):
    expression = expression.strip()
    if expression.startswith("{"):
        object_body, end = extract_balanced(expression, 0, "{", "}")
        if object_body is not None and not expression[end:].strip():
            expression = object_body
    wanted = {name.lower() for name in names}
    for part in split_top_level(expression):
        match = re.match(r"\s*[\"']?([A-Za-z_$][\w$-]*)[\"']?\s*:\s*(.*)", part, re.DOTALL)
        if match and match.group(1).lower() in wanted:
            return match.group(2).strip()
    return None


def extract_object_body(expression):
    expression = expression.strip()
    if re.match(r"(?:JSON\.)?stringify\s*\(", expression):
        body, _ = extract_balanced(expression, expression.find("("))
        expression = body or expression
    open_index = expression.find("{")
    if open_index == -1:
        return ()
    body, _ = extract_balanced(expression, open_index, "{", "}")
    if body is None:
        return ()
    fields, ignored = [], {"headers", "method", "url", "params", "signal", "credentials", "mode"}
    for part in split_top_level(body):
        match = re.match(r"\s*[\"']?([A-Za-z_$][\w$-]*)[\"']?\s*(?::|,|$)", part)
        if match and match.group(1).lower() not in ignored:
            fields.append(match.group(1))
    return tuple(dict.fromkeys(fields[:15]))


def looks_like_api(candidate, contextual=False):
    value = candidate.strip()
    if not value or len(value) > 2048:
        return False
    lowered = value.lower()
    if lowered.startswith(("data:", "javascript:", "mailto:", "tel:", "#")):
        return False
    probe = value if "://" in value else "http://placeholder" + (value if value.startswith("/") else "/" + value)
    parsed = urlparse(probe)
    extension = Path(parsed.path).suffix.lower()
    if extension in STATIC_EXTENSIONS and extension != ".json":
        return False
    if contextual:
        return bool(re.match(r"^(?:https?|wss?)://", value, re.I)) or bool(
            re.match(r"^(?:\.{0,2}/)?[A-Za-z0-9_{}:@.-]+(?:/[A-Za-z0-9_{}:@?&=+%.,~-]*)*$", value)
        )
    return (
        bool(re.match(r"^(?:https?|wss?)://", value, re.I))
        and any(prefix in parsed.path.lower() for prefix in API_PREFIXES)
    ) or any(
        lowered.startswith(prefix) or prefix in parsed.path.lower()
        for prefix in API_PREFIXES
    )


def resolve_endpoint(candidate, document_url, api_base=None):
    candidate = clean_whitespace(decode_js_string(candidate)).strip("\"' " + BACKTICK)
    candidate = candidate.replace("$" + "{", "{")
    candidate = re.sub(r"\{([^{}]+)\}", lambda m: "{" + (re.sub(r"\W+", "_", m.group(1)).strip("_") or "value") + "}", candidate)
    if not candidate:
        return None
    combined = api_base.rstrip("/") + "/" + candidate.lstrip("/") if api_base and not re.match(r"^(?:https?|wss?)://", candidate, re.I) else candidate
    if combined.startswith("//"):
        scheme = urlparse(document_url or "https://placeholder").scheme or "https"
        combined = scheme + ":" + combined
    elif not re.match(r"^(?:https?|wss?)://", combined, re.I):
        if not document_url:
            return combined
        combined = urljoin(document_url, combined)
    parsed = urlparse(combined)
    if parsed.scheme.lower() not in {"http", "https", "ws", "wss"}:
        return None
    return urlunparse((parsed.scheme.lower(), parsed.netloc, parsed.path or "/", "", parsed.query, ""))


class JavaScriptExtractor:
    CALL_PATTERN = re.compile(
        r"""(?ix)(?P<callee>
            fetch |
            axios(?:\.(?:get|post|put|patch|delete|head|options|request))? |
            ky(?:\.(?:get|post|put|patch|delete|head))? |
            (?:this\.)?\$?http\.(?:get|post|put|patch|delete|head|options) |
            request |
            [A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*\??\.(?:get|post|put|patch|delete|head|options)
        )\s*\("""
    )
    ROUTER_PATTERN = re.compile(
        r"\b(?P<router>app|router|server|fastify)\.(?P<method>get|post|put|patch|delete|head|options|all)\s*\(",
        re.I,
    )
    XHR_PATTERN = re.compile(r"\.open\s*\(", re.I)
    AJAX_PATTERN = re.compile(r"(?:\$\.ajax|jQuery\.ajax)\s*\(", re.I)
    STREAM_PATTERN = re.compile(r"new\s+(?P<kind>WebSocket|EventSource)\s*\(", re.I)
    def extract(self, content, source_url, document_url=None):
        document_url = document_url or source_url
        origin = self._origin(document_url)
        constants = extract_constants(content, origin)
        clients, bases = self._extract_clients(content, constants, origin)
        endpoints = []
        endpoints.extend(self._extract_calls(content, source_url, document_url, constants, clients, bases))
        endpoints.extend(self._extract_routers(content, source_url, document_url, constants))
        endpoints.extend(self._extract_xhr(content, source_url, document_url, constants))
        endpoints.extend(self._extract_ajax(content, source_url, document_url, constants))
        endpoints.extend(self._extract_streams(content, source_url, document_url, constants))
        endpoints.extend(self._extract_configured_routes(content, source_url, document_url, constants, bases))
        endpoints.extend(self._extract_route_literals(content, source_url, document_url, constants, bases))
        findings = self._extract_findings(content, source_url, document_url)
        return self._dedup_endpoints(endpoints), self._dedup_findings(findings)

    @staticmethod
    def _origin(url):
        if url and re.match(r"^https?://", url):
            parsed = urlparse(url)
            return f"{parsed.scheme}://{parsed.netloc}"
        return ""

    def _extract_clients(self, content, constants, origin):
        clients, bases = {}, []
        for match in re.finditer(r"\bbaseURL\s*[:=]\s*", content, re.I):
            expression, _ = read_expression(content, match.end())
            value = evaluate_expression(expression, constants, origin, False)
            if value and looks_like_api(value, True):
                bases.append(value)

        create_re = re.compile(
            r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*axios\.create\s*\(",
            re.I,
        )
        for match in create_re.finditer(content):
            body, _ = extract_balanced(content, content.find("(", match.start()))
            if body is None:
                continue
            object_body = body.strip()
            if object_body.startswith("{"):
                object_body, _ = extract_balanced(object_body, 0, "{", "}")
            expression = object_property(object_body or "", {"baseURL", "baseUrl", "base"})
            value = evaluate_expression(expression or "", constants, origin, False)
            if value:
                clients[match.group(1)] = value
                bases.append(value)
        return clients, list(dict.fromkeys(bases))

    @staticmethod
    def _semantic_placeholders(candidate, content, call_position):
        """Recupera nomes de aliases minificados no escopo próximo da chamada."""
        placeholders = set(re.findall(r"\{([A-Za-z_$][\w$]*)\}", candidate))
        if not placeholders:
            return candidate
        nearby = content[max(0, call_position - 3000):call_position]
        destructurings = list(
            re.finditer(r"\b(?:const|let|var)\s*\{([^{}]{1,1000})\}\s*=", nearby)
        )
        for variable_name in placeholders:
            property_name = None
            for destructuring in reversed(destructurings):
                for part in split_top_level(destructuring.group(1)):
                    alias = re.match(
                        r"\s*[\"']?([A-Za-z_$][\w$-]*)[\"']?\s*"
                        r"(?::\s*([A-Za-z_$][\w$]*))?",
                        part,
                    )
                    if alias and (alias.group(2) or alias.group(1)) == variable_name:
                        property_name = alias.group(1)
                        break
                if property_name:
                    break
            if property_name:
                candidate = candidate.replace("{" + variable_name + "}", "{" + property_name + "}")
        return candidate

    def _extract_calls(self, content, source, document_url, constants, clients, bases):
        endpoints = []
        origin = self._origin(document_url)
        for match in self.CALL_PATTERN.finditer(content):
            callee = match.group("callee")
            body, _ = extract_balanced(content, content.find("(", match.start()))
            if body is None:
                continue
            arguments = split_top_level(body)
            if not arguments:
                continue

            lowered = callee.lower()
            method, route_expression, options = "GET", arguments[0], ""
            api_base, body_fields = None, ()
            call_confidence = "high"
            auth_hint = any(word in body.lower() for word in ("authorization", "x-api-key", "apikey"))

            if "." in callee:
                client_name, method_name = callee.rsplit(".", 1)
                if method_name.upper() in HTTP_METHODS:
                    method = method_name.upper()
                api_base = clients.get(client_name)
                if api_base is None and client_name.lower() == "axios" and len(bases) == 1:
                    api_base = bases[0]
                if api_base is None and COMMON_CLIENT_RE.match(client_name) and len(bases) == 1:
                    api_base = bases[0]
                known_clients = {"axios", "ky", "http", "$http", "this.http"}
                if (
                    client_name.lower() not in known_clients
                    and not COMMON_CLIENT_RE.match(client_name)
                    and client_name not in clients
                ):
                    call_confidence = "medium"
            elif lowered in {"axios", "request", "fetch", "ky"}:
                options = arguments[1] if len(arguments) > 1 else ""

            if lowered.endswith(".request") or lowered in {"axios", "request"}:
                if arguments[0].strip().startswith("{"):
                    object_body, _ = extract_balanced(arguments[0], arguments[0].find("{"), "{", "}")
                    route_expression = object_property(object_body or "", {"url", "endpoint", "path"}) or ""
                    options = object_body or ""

            method_expression = object_property(options, {"method", "type"}) if options else None
            method_value = evaluate_expression(method_expression or "", constants, origin, False)
            if method_value and method_value.upper() in HTTP_METHODS:
                method = method_value.upper()

            if method in {"POST", "PUT", "PATCH"}:
                if lowered == "fetch":
                    payload = object_property(options, {"body", "data"}) or ""
                    body_fields = extract_object_body(payload)
                elif "." in callee and len(arguments) > 1:
                    body_fields = extract_object_body(arguments[1])
                else:
                    payload = object_property(options, {"body", "data"}) or ""
                    body_fields = extract_object_body(payload)

            candidate = evaluate_expression(route_expression, constants, origin)
            if not candidate or not looks_like_api(candidate, True):
                continue
            candidate = self._semantic_placeholders(candidate, content, match.start())
            if api_base:
                api_base = resolve_endpoint(api_base, document_url) or api_base
            url = resolve_endpoint(candidate, document_url, api_base)
            if url:
                endpoints.append(
                    Endpoint(
                        method, url, candidate, "request-call", call_confidence, source,
                        body_fields, auth_hint, "{" in candidate,
                    )
                )
        return endpoints

    def _extract_routers(self, content, source, document_url, constants):
        endpoints, origin = [], self._origin(document_url)
        for match in self.ROUTER_PATTERN.finditer(content):
            body, _ = extract_balanced(content, content.find("(", match.start()))
            arguments = split_top_level(body or "")
            candidate = evaluate_expression(arguments[0], constants, origin) if arguments else None
            if not candidate or not looks_like_api(candidate, True):
                continue
            method = match.group("method").upper()
            method = "GET" if method == "ALL" else method
            url = resolve_endpoint(candidate, document_url)
            if url:
                endpoints.append(Endpoint(method, url, candidate, "server-route", "high", source, dynamic="{" in candidate))
        return endpoints

    def _extract_xhr(self, content, source, document_url, constants):
        endpoints, origin = [], self._origin(document_url)
        for match in self.XHR_PATTERN.finditer(content):
            body, _ = extract_balanced(content, content.find("(", match.start()))
            arguments = split_top_level(body or "")
            if len(arguments) < 2:
                continue
            method = (evaluate_expression(arguments[0], constants, origin, False) or "GET").upper()
            if method not in HTTP_METHODS:
                method = "GET"
            candidate = evaluate_expression(arguments[1], constants, origin)
            if not candidate or not looks_like_api(candidate, True):
                continue
            url = resolve_endpoint(candidate, document_url)
            if url:
                endpoints.append(Endpoint(method, url, candidate, "xml-http-request", "high", source, dynamic="{" in candidate))
        return endpoints

    def _extract_ajax(self, content, source, document_url, constants):
        endpoints, origin = [], self._origin(document_url)
        for match in self.AJAX_PATTERN.finditer(content):
            body, _ = extract_balanced(content, content.find("(", match.start()))
            if body is None:
                continue
            object_body = body.strip()
            if object_body.startswith("{"):
                object_body, _ = extract_balanced(object_body, 0, "{", "}")
            route_expression = object_property(object_body or "", {"url", "endpoint"})
            candidate = evaluate_expression(route_expression or "", constants, origin)
            if not candidate or not looks_like_api(candidate, True):
                continue
            method_expression = object_property(object_body or "", {"method", "type"})
            method = (evaluate_expression(method_expression or "", constants, origin, False) or "GET").upper()
            if method not in HTTP_METHODS:
                method = "GET"
            payload = object_property(object_body or "", {"data", "body"}) or ""
            url = resolve_endpoint(candidate, document_url)
            if url:
                endpoints.append(
                    Endpoint(
                        method, url, candidate, "jquery-ajax", "high", source,
                        extract_object_body(payload),
                        "authorization" in (object_body or "").lower(),
                        "{" in candidate,
                    )
                )
        return endpoints

    def _extract_streams(self, content, source, document_url, constants):
        endpoints, origin = [], self._origin(document_url)
        for match in self.STREAM_PATTERN.finditer(content):
            body, _ = extract_balanced(content, content.find("(", match.start()))
            arguments = split_top_level(body or "")
            candidate = evaluate_expression(arguments[0], constants, origin) if arguments else None
            if not candidate or not looks_like_api(candidate, True):
                continue
            url = resolve_endpoint(candidate, document_url)
            if url:
                method = "WS" if match.group("kind").lower() == "websocket" else "GET"
                endpoints.append(
                    Endpoint(method, url, candidate, match.group("kind").lower(), "high", source, dynamic="{" in candidate)
                )
        return endpoints

    def _extract_configured_routes(self, content, source, document_url, constants, bases):
        endpoints, origin = [], self._origin(document_url)
        for match in re.finditer(r"\b(?:url|uri|endpoint|apiEndpoint|apiUrl)\s*:\s*", content, re.I):
            expression, _ = read_expression(content, match.end())
            candidate = evaluate_expression(expression, constants, origin)
            if not candidate or not looks_like_api(candidate, True):
                continue
            nearby = content[match.start():match.end() + 280]
            method_match = re.search(
                r"\b(?:method|type)\s*:\s*[\"'](GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)[\"']",
                nearby,
                re.I,
            )
            method = method_match.group(1).upper() if method_match else "GET"
            api_base = resolve_endpoint(bases[0], document_url) if len(bases) == 1 else None
            url = resolve_endpoint(candidate, document_url, api_base)
            if url:
                endpoints.append(Endpoint(method, url, candidate, "endpoint-config", "medium", source, dynamic="{" in candidate))
        return endpoints

    def _extract_route_literals(self, content, source, document_url, constants, bases):
        endpoints = []
        for quote, raw_body in iter_js_strings(content):
            body = decode_js_string(raw_body)
            candidate = template_value(body, constants, "") if quote == BACKTICK else body
            if not looks_like_api(candidate, False):
                continue
            url = resolve_endpoint(candidate, document_url)
            if url:
                resolved_bases = {
                    resolve_endpoint(base, document_url).rstrip("/")
                    for base in bases
                    if resolve_endpoint(base, document_url)
                }
                if url.rstrip("/") in resolved_bases:
                    continue
                endpoints.append(Endpoint("GET", url, candidate, "route-literal", "low", source, dynamic="{" in candidate))
        return endpoints

    def _extract_findings(self, content, source, document_url):
        findings = []
        for category, regex, severity, description, secret in FINDING_PATTERNS:
            for match in regex.finditer(content):
                value = match.groupdict().get("value") or match.group(0)
                value = clean_whitespace(decode_js_string(value)).rstrip(".,;)")
                if not value or (secret and is_placeholder(value)):
                    continue
                current_category, current_description = category, description
                if category == "Email" and any(domain in value.lower() for domain in ("example.com", "test.com", "domain.com")):
                    continue
                if category == "IPv4":
                    try:
                        address = ipaddress.ip_address(value)
                    except ValueError:
                        continue
                    scope = "privado/reservado" if not address.is_global else "público"
                    current_category = f"IPv4 {scope.title()}"
                    current_description = f"Endereço IPv4 {scope} encontrado no conteúdo."
                findings.append(Finding(current_category, value[:2048], severity, current_description, secret, {source}))

        source_host = urlparse(document_url or source).hostname or ""
        parts = source_host.split(".")
        base = ".".join(parts[-2:]) if len(parts) >= 2 else source_host
        if base:
            domain_re = re.compile(r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}\b")
            for match in domain_re.finditer(content):
                domain = match.group(0).lower()
                if domain.endswith("." + base) and domain != source_host:
                    findings.append(Finding("Subdomínio relacionado", domain, "info", "Hostname relacionado ao escopo encontrado.", False, {source}))
        return findings

    @staticmethod
    def _dedup_endpoints(endpoints):
        strong_urls = {
            endpoint.url for endpoint in endpoints if endpoint.confidence != "low"
        }
        unique = {}
        for endpoint in endpoints:
            if endpoint.confidence == "low" and endpoint.url in strong_urls:
                continue
            if endpoint.confidence == "low" and any(
                strong.startswith(endpoint.url.rstrip("/") + "/")
                for strong in strong_urls
            ):
                continue
            key = (endpoint.method, endpoint.url)
            existing = unique.get(key)
            if existing is None:
                unique[key] = endpoint
                continue
            existing.sources.update(endpoint.sources)
            if CONFIDENCE_RANK[endpoint.confidence] > CONFIDENCE_RANK[existing.confidence]:
                existing.confidence, existing.kind, existing.raw = endpoint.confidence, endpoint.kind, endpoint.raw
            existing.body_fields = tuple(dict.fromkeys(existing.body_fields + endpoint.body_fields))
            existing.auth_hint = existing.auth_hint or endpoint.auth_hint
            existing.dynamic = existing.dynamic or endpoint.dynamic
        return list(unique.values())

    @staticmethod
    def _dedup_findings(findings):
        unique = {}
        for finding in findings:
            key = (finding.category, finding.value)
            if key in unique:
                unique[key].sources.update(finding.sources)
            else:
                unique[key] = finding
        return list(unique.values())


class HTTPClient:
    def __init__(self, timeout, retries, max_bytes, verify_tls, delay):
        self.timeout = timeout
        self.retries = retries
        self.max_bytes = max_bytes
        self.verify_tls = verify_tls
        self.delay = delay
        self.local = threading.local()

    def _session(self):
        if not hasattr(self.local, "session"):
            session = requests.Session()
            retry = Retry(
                total=self.retries,
                connect=self.retries,
                read=self.retries,
                status=self.retries,
                backoff_factor=0.5,
                status_forcelist=(429, 500, 502, 503, 504),
                allowed_methods=frozenset({"GET"}),
                raise_on_status=False,
            )
            adapter = HTTPAdapter(max_retries=retry, pool_connections=20, pool_maxsize=20)
            session.mount("http://", adapter)
            session.mount("https://", adapter)
            self.local.session = session
        return self.local.session

    @staticmethod
    def _headers():
        return {
            "User-Agent": random.choice(USER_AGENTS),
            "Accept": "text/html,application/javascript,text/javascript,application/json,"
                      "application/source-map,*/*;q=0.5",
            "Accept-Language": "pt-BR,pt;q=0.9,en;q=0.7",
            "DNT": "1",
        }

    def fetch(self, url):
        if self.delay:
            time.sleep(random.uniform(0, self.delay))
        started = time.monotonic()
        response = self._session().get(
            url,
            headers=self._headers(),
            timeout=(min(5.0, self.timeout), self.timeout),
            allow_redirects=True,
            verify=self.verify_tls,
            stream=True,
        )
        chunks, size, truncated = [], 0, False
        try:
            for chunk in response.iter_content(chunk_size=65536):
                if time.monotonic() - started > self.timeout:
                    truncated = True
                    break
                if not chunk:
                    continue
                remaining = self.max_bytes - size
                if remaining <= 0:
                    truncated = True
                    break
                chunks.append(chunk[:remaining])
                size += min(len(chunk), remaining)
                if len(chunk) > remaining or size >= self.max_bytes:
                    truncated = True
                    break
            raw = b"".join(chunks)
            encoding = response.encoding or "utf-8"
            text = raw.decode(encoding, errors="replace")
            return FetchResult(
                text=text,
                status=response.status_code,
                final_url=response.url,
                content_type=response.headers.get("Content-Type", "").lower(),
                truncated=truncated,
                size=size,
            )
        finally:
            response.close()


class Scanner:
    def __init__(
        self,
        threads=10,
        timeout=8,
        retries=0,
        max_bytes=DEFAULT_MAX_BYTES,
        verify_tls=False,
        delay=0.3,
        depth=2,
        max_assets=500,
        include_external=False,
        include_subdomains=False,
        base_url=None,
        scan_timeout=180,
        include_static_inputs=False,
        follow_chunks=False,
    ):
        self.threads = threads
        self.depth = depth
        self.max_assets = max_assets
        self.include_external = include_external
        self.include_subdomains = include_subdomains
        self.base_url = base_url
        self.scan_timeout = scan_timeout
        self.include_static_inputs = include_static_inputs
        self.follow_chunks = follow_chunks
        self.verify_tls = verify_tls
        self.max_bytes = max_bytes
        self.client = HTTPClient(timeout, retries, max_bytes, verify_tls, delay)
        self.extractor = JavaScriptExtractor()
        self.lock = threading.Lock()
        self.print_lock = threading.Lock()
        self.allowed_hosts = set()
        self.visited = set()
        self.endpoints = {}
        self.findings = {}
        self.timings = []
        self.stats = Counter(
            loaded=0, processed=0, remote_ok=0, errors=0, local_ok=0,
            bytes=0, truncated=0, assets_discovered=0, source_maps=0,
            deadline_reached=0, skipped=0, input_skipped=0,
            invalid_input=0, scan_seconds=0,
        )

    def _log(self, message):
        with self.print_lock:
            print(message, flush=True)

    def _record_timing(self, timing):
        with self.lock:
            self.timings.append(timing)

    @staticmethod
    def _normalize_url(value, default_scheme="https"):
        value = value.strip()
        main_part = value.split("?", 1)[0].split("#", 1)[0]
        if len(re.findall(r"https?://", main_part, re.I)) > 1:
            raise ValueError(f"duas URLs parecem estar concatenadas: {value}")
        if not re.match(r"^https?://", value, re.I):
            value = f"{default_scheme}://{value}"
        parsed = urlparse(value)
        if not parsed.hostname:
            raise ValueError(f"URL inválida: {value}")
        return urlunparse((parsed.scheme.lower(), parsed.netloc, parsed.path or "/", "", parsed.query, ""))

    def _document_context(self, url):
        if self.base_url:
            return self.base_url
        parsed = urlparse(url)
        next_marker = parsed.path.find("/_next/")
        if next_marker != -1:
            base_path = parsed.path[:next_marker].rstrip("/") + "/"
            return urlunparse((parsed.scheme, parsed.netloc, base_path, "", "", ""))
        if Path(parsed.path).suffix.lower() in {".js", ".mjs", ".cjs", ".map"}:
            return urlunparse((parsed.scheme, parsed.netloc, "/", "", "", ""))
        return url

    def load_items(self, input_value, default_scheme="https"):
        source = Path(input_value).expanduser()
        items = []
        static_examples = []

        if source.is_file() and source.suffix.lower() in {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".html", ".htm", ".map"}:
            items.append(ScanItem(str(source.resolve()), self.base_url, 0, True))
        elif source.is_file():
            base_dir = source.resolve().parent
            with source.open("r", encoding="utf-8", errors="replace") as target_file:
                for line_number, line in enumerate(target_file, start=1):
                    value = line.strip()
                    if not value or value.startswith("#"):
                        continue
                    local_candidate = (base_dir / value).resolve()
                    if local_candidate.is_file():
                        items.append(ScanItem(str(local_candidate), self.base_url, 0, True))
                        continue
                    try:
                        url = self._normalize_url(value, default_scheme)
                    except ValueError as error:
                        self._log(f"{Fore.YELLOW}[!] Linha {line_number} ignorada: {error}")
                        self.stats["invalid_input"] += 1
                        continue
                    suffix = Path(urlparse(url).path).suffix.lower()
                    if suffix in STATIC_EXTENSIONS and not self.include_static_inputs:
                        if len(static_examples) < 3:
                            static_examples.append(f"linha {line_number}: {url}")
                        self.stats["input_skipped"] += 1
                        continue
                    items.append(ScanItem(url, self._document_context(url), 0, False))
                    self.allowed_hosts.add(urlparse(url).hostname or "")
        elif re.match(r"^https?://", input_value, re.I) or (
            source.suffix.lower() not in {
                ".txt", ".list", ".csv", ".js", ".mjs", ".cjs", ".jsx",
                ".ts", ".tsx", ".html", ".htm", ".map",
            }
            and re.match(
                r"^(?:localhost|[A-Za-z0-9.-]+|\[[0-9A-Fa-f:]+\])(?::\d+)?(?:/|$)",
                input_value,
            )
        ):
            url = self._normalize_url(input_value, default_scheme)
            items.append(ScanItem(url, self._document_context(url), 0, False))
            self.allowed_hosts.add(urlparse(url).hostname or "")
        else:
            raise FileNotFoundError(input_value)

        dedup = {}
        for item in items:
            key = ("local:" if item.local else "url:") + item.locator
            dedup[key] = item
        self.stats["loaded"] = len(dedup)
        if self.stats["input_skipped"]:
            examples = " | ".join(static_examples)
            self._log(
                f"{Fore.YELLOW}[!] {self.stats['input_skipped']} entrada(s) de CSS/imagem/"
                f"fonte/mídia ignorada(s). Exemplos: {examples}. "
                f"Use --include-static-assets para incluí-las."
            )
        return list(dedup.values())

    def _in_scope(self, url):
        if self.include_external:
            return True
        hostname = urlparse(url).hostname or ""
        if hostname in self.allowed_hosts:
            return True
        return self.include_subdomains and any(
            hostname.endswith("." + allowed) for allowed in self.allowed_hosts if allowed
        )

    def _canonical(self, item):
        if item.local:
            return "file:" + str(Path(item.locator).resolve())
        parsed = urlparse(item.locator)
        return urlunparse((parsed.scheme.lower(), parsed.netloc.lower(), parsed.path or "/", "", parsed.query, ""))

    def _claim(self, item):
        canonical = self._canonical(item)
        with self.lock:
            if canonical in self.visited or len(self.visited) >= self.max_assets:
                return False
            self.visited.add(canonical)
            if item.depth > 0:
                self.stats["assets_discovered"] += 1
            return True

    def _add_endpoint(self, endpoint):
        key = (endpoint.method, endpoint.url)
        with self.lock:
            existing = self.endpoints.get(key)
            if existing is None:
                self.endpoints[key] = endpoint
                return
            existing.sources.update(endpoint.sources)
            if CONFIDENCE_RANK[endpoint.confidence] > CONFIDENCE_RANK[existing.confidence]:
                existing.confidence = endpoint.confidence
                existing.kind = endpoint.kind
                existing.raw = endpoint.raw
            existing.body_fields = tuple(dict.fromkeys(existing.body_fields + endpoint.body_fields))
            existing.auth_hint = existing.auth_hint or endpoint.auth_hint
            existing.dynamic = existing.dynamic or endpoint.dynamic

    def _add_finding(self, finding):
        key = (finding.category, finding.value)
        with self.lock:
            if key in self.findings:
                self.findings[key].sources.update(finding.sources)
            else:
                self.findings[key] = finding

    def _analyze(self, text, source, context_url):
        endpoints, findings = self.extractor.extract(text, source, context_url)
        for endpoint in endpoints:
            self._add_endpoint(endpoint)
        for finding in findings:
            self._add_finding(finding)

    def _analyze_source_map(self, text, source, context_url):
        try:
            source_map = json.loads(text)
        except (json.JSONDecodeError, TypeError):
            return
        if not isinstance(source_map, dict):
            return
        sources = source_map.get("sources") or []
        contents = source_map.get("sourcesContent") or []
        if not isinstance(contents, list):
            return
        with self.lock:
            self.stats["source_maps"] += 1
        for index, source_content in enumerate(contents):
            if not isinstance(source_content, str):
                continue
            source_name = sources[index] if index < len(sources) else f"source-{index}"
            self._analyze(source_content, f"{source}#{source_name}", context_url)

    def _discover_assets(self, text, source_url, context_url, content_type, depth):
        if depth >= self.depth:
            return []
        candidates = set()

        if "html" in content_type or re.search(r"<(?:html|script|head|body)\b", text[:5000], re.I):
            try:
                soup = BeautifulSoup(text, "html.parser")
                base_tag = soup.find("base", href=True)
                asset_base = source_url if urlparse(source_url).scheme == "file" else context_url
                resolution_base = urljoin(asset_base, base_tag["href"]) if base_tag else asset_base
                for tag in soup.find_all("script", src=True):
                    candidates.add(urljoin(resolution_base, tag["src"]))
                for tag in soup.find_all("link", href=True):
                    rel = {str(value).lower() for value in (tag.get("rel") or [])}
                    as_value = str(tag.get("as") or "").lower()
                    if "modulepreload" in rel or ("preload" in rel and as_value == "script"):
                        candidates.add(urljoin(resolution_base, tag["href"]))
            except Exception:
                pass

        for match in re.finditer(r"(?://[#@]\s*sourceMappingURL=)([^\s\"']+)", text):
            candidates.add(urljoin(source_url, decode_js_string(match.group(1))))

        if self.follow_chunks:
            for match in re.finditer(
                r"""[\"']([^\"']+\.(?:js|mjs|cjs|map)(?:\?[^\"']*)?)[\"']""",
                text,
                re.I,
            ):
                value = decode_js_string(match.group(1))
                if len(value) < 1024:
                    candidates.add(urljoin(source_url, value))

        discovered = []
        for candidate in sorted(candidates):
            parsed = urlparse(candidate)
            if parsed.scheme == "file":
                local_path = Path(unquote(parsed.path))
                if local_path.is_file():
                    discovered.append(ScanItem(str(local_path.resolve()), context_url, depth + 1, True))
                continue
            if parsed.scheme not in {"http", "https"} or not parsed.hostname:
                continue
            if not self._in_scope(candidate):
                continue
            discovered.append(ScanItem(candidate, context_url, depth + 1, False))

        return discovered

    def _read_local(self, path):
        raw = Path(path).read_bytes()
        truncated = len(raw) > self.max_bytes
        raw = raw[:self.max_bytes]
        return raw.decode("utf-8", errors="replace"), truncated, len(raw)

    def _process(self, item):
        item_started = time.monotonic()
        download_seconds = 0.0
        if item.local:
            self._log(f"{Fore.YELLOW}[>] LEITURA: {item.locator}")
            download_started = time.monotonic()
            try:
                text, truncated, size = self._read_local(item.locator)
            except OSError as error:
                elapsed = time.monotonic() - item_started
                self._log(f"{Fore.RED}[-] Falha na LEITURA após {elapsed:.2f}s: {item.locator}: {error}")
                with self.lock:
                    self.stats["errors"] += 1
                self._record_timing(ScanTiming(item.locator, "erro-leitura", total_seconds=elapsed))
                return []
            download_seconds = time.monotonic() - download_started
            source = Path(item.locator).resolve().as_uri()
            context = item.context_url or self.base_url
            lowered_path = item.locator.lower()
            if lowered_path.endswith((".html", ".htm")):
                content_type = "text/html"
            elif lowered_path.endswith(".map"):
                content_type = "application/source-map+json"
            else:
                content_type = "application/javascript"
            status_label = "local"
            with self.lock:
                self.stats["local_ok"] += 1
        else:
            self._log(f"{Fore.YELLOW}[>] DOWNLOAD: {item.locator}")
            download_started = time.monotonic()
            try:
                result = self.client.fetch(item.locator)
            except requests.RequestException as error:
                download_seconds = time.monotonic() - download_started
                self._log(
                    f"{Fore.RED}[-] Falha no DOWNLOAD após {download_seconds:.2f}s: "
                    f"{item.locator}: {error}"
                )
                with self.lock:
                    self.stats["errors"] += 1
                self._record_timing(
                    ScanTiming(
                        item.locator, "erro-download", download_seconds=download_seconds,
                        total_seconds=time.monotonic() - item_started,
                    )
                )
                return []
            download_seconds = time.monotonic() - download_started
            text, truncated, size = result.text, result.truncated, result.size
            source, content_type = result.final_url, result.content_type
            context = item.context_url or result.final_url
            status_label = str(result.status)
            final_host = urlparse(result.final_url).hostname
            if final_host and urlparse(item.locator).hostname in self.allowed_hosts:
                with self.lock:
                    self.allowed_hosts.add(final_host)
            with self.lock:
                self.stats["remote_ok"] += 1

        self._log(
            f"{Fore.BLUE}[>] ANÁLISE (download {download_seconds:.2f}s, "
            f"{size} bytes): {source}"
        )
        analysis_started = time.monotonic()
        is_source_map = source.lower().split("?", 1)[0].endswith(".map") or "source-map" in content_type
        if is_source_map:
            self._analyze_source_map(text, source, context)
        else:
            self._analyze(text, source, context)
        analysis_seconds = time.monotonic() - analysis_started

        discovery_started = time.monotonic()
        discovered = self._discover_assets(text, source, context or source, content_type, item.depth)
        discovery_seconds = time.monotonic() - discovery_started
        total_seconds = time.monotonic() - item_started

        with self.lock:
            self.stats["processed"] += 1
            self.stats["bytes"] += size
            self.stats["truncated"] += int(truncated)
        suffix = " [truncado]" if truncated else ""
        self._record_timing(
            ScanTiming(
                source, "concluído", download_seconds, analysis_seconds,
                discovery_seconds, total_seconds, size,
            )
        )
        self._log(
            f"{Fore.GREEN}[+] CONCLUÍDO ({status_label}) "
            f"[download {download_seconds:.2f}s | análise {analysis_seconds:.2f}s | "
            f"descoberta {discovery_seconds:.2f}s | total {total_seconds:.2f}s]: "
            f"{source}{suffix}"
        )
        return discovered

    def run(self, initial_items):
        pending = list(initial_items)
        started = time.monotonic()
        while pending and len(self.visited) < self.max_assets:
            if self.scan_timeout and time.monotonic() - started >= self.scan_timeout:
                self.stats["deadline_reached"] = 1
                self.stats["skipped"] += len(pending)
                self._log(f"{Fore.YELLOW}[!] Prazo global atingido; {len(pending)} item(ns) não processado(s).")
                break

            batch = []
            while pending and len(batch) < self.threads:
                item = pending.pop(0)
                if self._claim(item):
                    batch.append(item)
            if not batch:
                continue

            discovered = []
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                future_map = {executor.submit(self._process, item): item for item in batch}
                for future in as_completed(future_map):
                    try:
                        discovered.extend(future.result())
                    except Exception as error:
                        item = future_map[future]
                        self._log(f"{Fore.RED}[!] Erro inesperado em {item.locator}: {error}")
                        with self.lock:
                            self.stats["errors"] += 1
            pending.extend(discovered)

        if pending and len(self.visited) >= self.max_assets:
            self.stats["skipped"] += len(pending)
            self._log(f"{Fore.YELLOW}[!] Limite de {self.max_assets} assets atingido; fila restante descartada.")

        self.stats["scan_seconds"] = round(time.monotonic() - started, 3)

        print(
            f"\n{Fore.CYAN}[*] Processados: {self.stats['processed']} | "
            f"Endpoints: {len(self.endpoints)} | Achados complementares: {len(self.findings)} | "
            f"Tempo: {self.stats['scan_seconds']:.2f}s"
        )


def build_curl(endpoint, insecure=True, timeout=15):
    method = endpoint.method.upper()
    command = ["curl", "--globoff", "-i", "-sS", "--max-time", str(timeout)]
    if insecure and endpoint.url.startswith("https://"):
        command.append("-k")

    if method == "WS":
        command.extend(["-N", endpoint.url])
        return shlex.join(command)

    if method == "HEAD":
        command.append("-I")
    else:
        command.extend(["-X", method])
    command.extend(["-H", "Accept: application/json"])

    if endpoint.auth_hint:
        command.extend(["-H", "Authorization: Bearer <TOKEN>"])

    if method in {"POST", "PUT", "PATCH"}:
        command.extend(["-H", "Content-Type: application/json"])
        payload = {
            field_name: f"<{field_name}>"
            for field_name in endpoint.body_fields
        }
        command.extend([
            "--data",
            json.dumps(payload, ensure_ascii=False) if payload else "<PAYLOAD_JSON>",
        ])

    command.append(endpoint.url)
    return shlex.join(command)


def endpoint_to_dict(endpoint, insecure=True, timeout=15):
    return {
        "method": endpoint.method,
        "url": endpoint.url,
        "raw": endpoint.raw,
        "kind": endpoint.kind,
        "confidence": endpoint.confidence,
        "dynamic": endpoint.dynamic,
        "body_fields": list(endpoint.body_fields),
        "auth_hint": endpoint.auth_hint,
        "sources": sorted(endpoint.sources),
        "curl": build_curl(endpoint, insecure, timeout),
    }


def finding_to_dict(finding, redact=False):
    return {
        "category": finding.category,
        "value": mask_secret(finding.value) if redact and finding.secret else finding.value,
        "severity": finding.severity,
        "description": finding.description,
        "recommendation": finding_guidance(finding.category),
        "secret": finding.secret,
        "sources": sorted(finding.sources),
    }


def finding_guidance(category):
    if category.startswith("IPv4"):
        return "Correlacione o endereço com o escopo e verifique se revela infraestrutura interna ou serviço público inesperado."
    if category == "Email":
        return "Confirme se o contato deveria estar público e evite qualquer uso fora da avaliação autorizada."
    return FINDING_GUIDANCE.get(category, "Valide o contexto e o impacto manualmente antes de classificar o achado.")


def write_private_text(path, content):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as output:
        output.write(content)
    try:
        path.chmod(stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass


def generate_report(scanner, output_file, redact_secrets=False, timeout=15):
    endpoints = sorted(
        scanner.endpoints.values(),
        key=lambda endpoint: (endpoint.url, endpoint.method),
    )
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings = sorted(
        scanner.findings.values(),
        key=lambda finding: (severity_order.get(finding.severity, 9), finding.category, finding.value),
    )

    lines = [
        "BIRD-CRAFTJS — RELATÓRIO UNIFICADO",
        f"Versão: {TOOL_VERSION}",
        f"Gerado em: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "=" * 88,
        "",
        "RESUMO",
        f"  Alvos carregados: {scanner.stats['loaded']}",
        f"  Entradas estáticas ignoradas: {scanner.stats['input_skipped']}",
        f"  Entradas inválidas ignoradas: {scanner.stats['invalid_input']}",
        f"  Documentos/assets processados: {scanner.stats['processed']}",
        f"  Assets descobertos: {scanner.stats['assets_discovered']}",
        f"  Source maps analisados: {scanner.stats['source_maps']}",
        f"  Falhas de leitura/rede: {scanner.stats['errors']}",
        f"  Itens não processados: {scanner.stats['skipped']}",
        f"  Prazo global atingido: {'sim' if scanner.stats['deadline_reached'] else 'não'}",
        f"  Conteúdo analisado: {scanner.stats['bytes']} bytes",
        f"  Respostas truncadas no limite: {scanner.stats['truncated']}",
        f"  Endpoints de API únicos: {len(endpoints)}",
        f"  Outros achados únicos: {len(findings)}",
        f"  Tempo total do scan: {scanner.stats['scan_seconds']:.2f} segundos",
        "",
        "NOTA DE USO",
        "  Execute os curls somente em ativos autorizados. Substitua valores entre <...> e",
        "  placeholders entre {...}. Para operações POST/PUT/PATCH, revise o JSON antes do teste.",
        "",
        "=" * 88,
        "ENDPOINTS DE API E COMO TESTAR",
        "=" * 88,
    ]

    if not endpoints:
        lines.append("\nNenhum endpoint de API foi reconstruído.")
    for index, endpoint in enumerate(endpoints, start=1):
        lines.extend(
            [
                "",
                f"[{index}] {endpoint.method} {endpoint.url}",
                f"    Confiança: {endpoint.confidence} | Origem da detecção: {endpoint.kind}",
                f"    Expressão/rota original: {endpoint.raw}",
                f"    Dinâmico: {'sim' if endpoint.dynamic else 'não'}",
                f"    Campos de corpo inferidos: {', '.join(endpoint.body_fields) if endpoint.body_fields else 'nenhum'}",
                f"    Autenticação observada: {'sim' if endpoint.auth_hint else 'não/inconclusivo'}",
                "    Encontrado em:",
            ]
        )
        lines.extend(f"      - {source}" for source in sorted(endpoint.sources))
        lines.extend(
            [
                "    CURL PARA TESTE:",
                f"      {build_curl(endpoint, not scanner.verify_tls, timeout)}",
                "-" * 88,
            ]
        )

    slowest = sorted(scanner.timings, key=lambda timing: timing.total_seconds, reverse=True)[:15]
    lines.extend(["", "=" * 88, "DIAGNÓSTICO DE DESEMPENHO", "=" * 88])
    if not slowest:
        lines.append("\nNenhuma medição de desempenho disponível.")
    for index, timing in enumerate(slowest, start=1):
        lines.extend(
            [
                "",
                f"[{index}] {timing.source}",
                f"    Status: {timing.status} | Tamanho: {timing.size} bytes",
                f"    Download/leitura: {timing.download_seconds:.2f}s | "
                f"Análise: {timing.analysis_seconds:.2f}s | "
                f"Descoberta: {timing.discovery_seconds:.2f}s | "
                f"Total: {timing.total_seconds:.2f}s",
            ]
        )

    lines.extend(["", "=" * 88, "ACHADOS COMPLEMENTARES", "=" * 88])
    if not findings:
        lines.append("\nNenhum segredo, infraestrutura ou indicador complementar encontrado.")
    for index, finding in enumerate(findings, start=1):
        value = mask_secret(finding.value) if redact_secrets and finding.secret else finding.value
        lines.extend(
            [
                "",
                f"[{index}] {finding.category} [{finding.severity.upper()}]",
                f"    Valor: {value}",
                f"    Descrição: {finding.description}",
                f"    Validação sugerida: {finding_guidance(finding.category)}",
                "    Encontrado em:",
            ]
        )
        lines.extend(f"      - {source}" for source in sorted(finding.sources))
        lines.append("-" * 88)

    write_private_text(output_file, "\n".join(lines) + "\n")
    print(f"{Fore.GREEN}[OK] Relatório salvo: {output_file}")


def generate_json_report(scanner, output_file, redact_secrets=False, timeout=15):
    payload = {
        "tool": "Bird-CraftJS",
        "version": TOOL_VERSION,
        "generated_at": datetime.now().astimezone().isoformat(),
        "stats": dict(scanner.stats),
        "timings": [timing.__dict__ for timing in scanner.timings],
        "endpoints": [
            endpoint_to_dict(endpoint, not scanner.verify_tls, timeout)
            for endpoint in sorted(scanner.endpoints.values(), key=lambda item: (item.url, item.method))
        ],
        "findings": [
            finding_to_dict(finding, redact_secrets)
            for finding in scanner.findings.values()
        ],
    }
    write_private_text(output_file, json.dumps(payload, ensure_ascii=False, indent=2) + "\n")
    print(f"{Fore.GREEN}[OK] JSON salvo: {output_file}")


def build_parser():
    parser = argparse.ArgumentParser(
        description="Analisa páginas, JavaScript e source maps para reconstruir endpoints de API."
    )
    parser.add_argument("input", nargs="?", help="arquivo de alvos, arquivo JS/HTML/map ou URL")
    parser.add_argument("-f", "--file", dest="input_file", help="compatibilidade: arquivo de alvos ou fonte")
    parser.add_argument("-t", "--threads", type=int, default=10, help="threads simultâneas (padrão: 10)")
    parser.add_argument("-o", "--output", default=DEFAULT_OUTPUT, help=f"relatório TXT (padrão: {DEFAULT_OUTPUT})")
    parser.add_argument("--json-output", help="salva também um relatório JSON estruturado")
    parser.add_argument(
        "--depth", type=int,
        help="profundidade de assets (automática: 0 para listas/JS, 2 para uma página)",
    )
    parser.add_argument("--max-assets", type=int, default=500, help="limite global de documentos/assets (padrão: 500)")
    parser.add_argument("--max-mb", type=float, default=5.0, help="máximo baixado por asset em MiB (padrão: 5)")
    parser.add_argument("--timeout", type=float, default=8, help="timeout HTTP por tentativa em segundos (padrão: 8)")
    parser.add_argument("--retries", type=int, default=0, help="repetições para erros transitórios (padrão: 0)")
    parser.add_argument("--delay", type=float, default=0.3, help="atraso aleatório máximo por request")
    parser.add_argument(
        "--scan-timeout", type=float, default=180,
        help="prazo global do scan em segundos; 0 desativa (padrão: 180)",
    )
    parser.add_argument("--default-scheme", choices=("https", "http"), default="https")
    parser.add_argument("--base-url", help="URL base para resolver rotas de arquivos JS locais")
    parser.add_argument("--verify-tls", action="store_true", help="valida certificados TLS (modo antigo era inseguro)")
    parser.add_argument("--include-external-assets", action="store_true", help="baixa scripts de hosts externos")
    parser.add_argument("--include-subdomains", action="store_true", help="permite assets em subdomínios dos alvos")
    parser.add_argument(
        "--include-static-assets", action="store_true",
        help="inclui CSS, imagens, fontes e mídia quando aparecem no arquivo de alvos",
    )
    chunk_group = parser.add_mutually_exclusive_group()
    chunk_group.add_argument(
        "--follow-chunks", dest="follow_chunks", action="store_true",
        help="segue referências literais a outros chunks JS/map",
    )
    chunk_group.add_argument(
        "--no-follow-chunks", dest="follow_chunks", action="store_false",
        help="não expande referências literais a chunks (sourceMappingURL ainda é seguido)",
    )
    parser.set_defaults(follow_chunks=None)
    parser.add_argument("--redact-secrets", action="store_true", help="mascara segredos nos relatórios")
    return parser


def infer_default_depth(items):
    """Evita explosão de fila quando a entrada já é uma lista de assets."""
    asset_suffixes = {".js", ".mjs", ".cjs", ".map"}
    only_assets = all(
        Path(urlparse(item.locator).path if not item.local else item.locator).suffix.lower()
        in asset_suffixes
        for item in items
    )
    return 0 if len(items) > 1 or only_assets else 2


def main(argv=None):
    args = build_parser().parse_args(argv)
    input_value = args.input_file or args.input
    if not input_value:
        build_parser().error("informe INPUT ou use -f/--file")
    if args.input_file and args.input and args.input_file != args.input:
        build_parser().error("informe a entrada uma única vez")
    if not 1 <= args.threads <= 100:
        build_parser().error("--threads deve estar entre 1 e 100")
    if args.depth is not None and not 0 <= args.depth <= 5:
        build_parser().error("--depth deve estar entre 0 e 5")
    if args.max_assets < 1 or args.max_mb <= 0 or args.timeout <= 0 or args.retries < 0 or args.delay < 0 or args.scan_timeout < 0:
        build_parser().error("limites, timeout, retries e delay devem usar valores válidos")

    if not args.verify_tls:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    scanner = Scanner(
        threads=args.threads,
        timeout=args.timeout,
        retries=args.retries,
        max_bytes=int(args.max_mb * 1024 * 1024),
        verify_tls=args.verify_tls,
        delay=args.delay,
        depth=args.depth if args.depth is not None else 0,
        max_assets=args.max_assets,
        include_external=args.include_external_assets,
        include_subdomains=args.include_subdomains,
        base_url=args.base_url,
        scan_timeout=args.scan_timeout,
        include_static_inputs=args.include_static_assets,
        follow_chunks=False,
    )

    try:
        items = scanner.load_items(input_value, args.default_scheme)
    except (FileNotFoundError, OSError) as error:
        print(f"{Fore.RED}[ERRO] Entrada não encontrada ou ilegível: {error}", file=sys.stderr)
        return 1
    if not items:
        print(f"{Fore.RED}[ERRO] Nenhum alvo válido encontrado.", file=sys.stderr)
        return 1

    if args.depth is None:
        scanner.depth = infer_default_depth(items)
    scanner.follow_chunks = args.follow_chunks if args.follow_chunks is not None else len(items) == 1

    print(f"\n{Fore.CYAN}BIRD-CRAFTJS v{TOOL_VERSION} — scanner unificado")
    depth_mode = f"{scanner.depth} ({'automática' if args.depth is None else 'manual'})"
    chunks_mode = "sim" if scanner.follow_chunks else "não (lista protegida contra expansão)"
    print(
        f"{Fore.BLUE}[*] Alvos iniciais: {len(items)} | threads: {args.threads} | "
        f"profundidade: {depth_mode} | seguir chunks: {chunks_mode}"
    )
    scanner.run(items)
    generate_report(scanner, args.output, args.redact_secrets, int(args.timeout))
    if args.json_output:
        generate_json_report(scanner, args.json_output, args.redact_secrets, int(args.timeout))
    if scanner.stats["processed"] == 0:
        print(f"{Fore.RED}[ERRO] Nenhum documento pôde ser analisado.", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
