#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Bird Leak Cleaner - Robust ULP (URL, Login, Password) Parser

Este script faz parsing de dados vazados que não seguem um padrão fixo,
com múltiplos separadores e ordens variáveis.

Autor: Bird Leak Cleaner
Data: 2026-01-20
"""

import argparse
import csv
import os
import re
import sys
from typing import Optional, Tuple, Dict, List, Set
from dataclasses import dataclass
from urllib.parse import urlparse
import logging

# Configuração de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@dataclass
class ParsedLine:
    """Estrutura para armazenar dados parseados de uma linha."""
    url: Optional[str] = None
    login: Optional[str] = None
    password: Optional[str] = None
    original_line: str = ""
    parse_success: bool = False
    parse_method: str = ""


class DataValidator:
    """Validadores para diferentes tipos de dados."""
    
    # Padrões de URL - mais permissivos para capturar variações
    URL_PROTOCOLS = ('http://', 'https://')
    
    # Regex para email
    EMAIL_PATTERN = re.compile(
        r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$',
        re.IGNORECASE
    )
    
    # Regex para CPF (com ou sem pontuação)
    CPF_PATTERN = re.compile(r'^\d{3}\.?\d{3}\.?\d{3}-?\d{2}$')
    
    # Regex para CNPJ (com ou sem pontuação)
    CNPJ_PATTERN = re.compile(r'^\d{2}\.?\d{3}\.?\d{3}/?\d{4}-?\d{2}$')
    
    # Regex para telefone brasileiro
    TELEFONE_PATTERN = re.compile(
        r'^(\+?55)?[\s-]?\(?\d{2}\)?[\s-]?\d{4,5}[\s-]?\d{4}$'
    )
    
    # Regex para detectar domínio válido (sem protocolo)
    # Deve ter pelo menos 2 partes (subdomínio.domínio) e TLD válido
    DOMAIN_PATTERN = re.compile(
        r'^([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}(:\d+)?(/[^\s|;:@]*)?$',
        re.IGNORECASE
    )
    
    # TLDs comuns para validação mais rigorosa
    COMMON_TLDS = {'com', 'br', 'net', 'org', 'io', 'tv', 'chat', 'php', 'jsp', 'html'}
    
    @classmethod
    def is_url(cls, text: str) -> bool:
        """Verifica se o texto é uma URL válida."""
        if not text:
            return False
        
        text = text.strip()
        
        # Rejeitar textos muito curtos ou que parecem logins
        if len(text) < 5:
            return False
        
        # Rejeitar se termina com : (provavelmente URL incompleta ou tem credenciais)
        if text.endswith(':'):
            return False
        
        # Rejeitar se contém espaço (URL inválida)
        if ' ' in text:
            return False
        
        # Rejeitar URLs que contêm credenciais (@ após o host)
        # Ex: https://site.com:user@email.com é URL + credenciais misturadas
        if text.lower().startswith(cls.URL_PROTOCOLS):
            try:
                parsed = urlparse(text)
                if not parsed.netloc:
                    return False
                
                # Verificar se o netloc contém credenciais embutidas
                if '@' in parsed.netloc:
                    # URLs com auth (user:pass@host) são válidas mas raras
                    # Se o que vem antes do @ parece email, então é URL + credenciais
                    before_at = parsed.netloc.split('@')[0]
                    if '.' in before_at and ':' in before_at:
                        # Parece ter email:senha antes do @, não é URL válida isolada
                        return False
                
                # Verificar se @ aparece depois do netloc (no path)
                if '@' in text:
                    netloc_end = text.find(parsed.netloc) + len(parsed.netloc)
                    if '@' in text[netloc_end:]:
                        # @ no path indica credenciais misturadas
                        return False
                
                return True
            except Exception:
                return False
        
        # Verificar se é um domínio válido sem protocolo
        # Mas também verificar se não contém credenciais
        if cls.DOMAIN_PATTERN.match(text):
            # Se contém @ após o domínio base, provavelmente tem credenciais
            if '@' in text:
                return False
            
            # Verificar se o texto tem um TLD válido
            # Evita confundir logins como "afonso.junior" com domínios
            parts = text.split('/')
            domain_part = parts[0].split(':')[0]  # Remover porta e path
            domain_parts = domain_part.split('.')
            
            if len(domain_parts) >= 2:
                tld = domain_parts[-1].lower()
                # TLDs de um único caractere não são válidos
                if len(tld) < 2:
                    return False
                # Verificar se é algo que parece um TLD real
                # (não "junior", "senior", etc.)
                if tld in ['junior', 'senior', 'admin', 'user', 'root', 'teste', 'test']:
                    return False
            else:
                return False
            
            return True
        
        return False
    
    @classmethod
    def is_email(cls, text: str) -> bool:
        """Verifica se o texto é um email válido."""
        if not text:
            return False
        return bool(cls.EMAIL_PATTERN.match(text.strip()))
    
    @classmethod
    def is_cpf(cls, text: str) -> bool:
        """Verifica se o texto é um CPF válido."""
        if not text:
            return False
        return bool(cls.CPF_PATTERN.match(text.strip()))
    
    @classmethod
    def is_cnpj(cls, text: str) -> bool:
        """Verifica se o texto é um CNPJ válido."""
        if not text:
            return False
        return bool(cls.CNPJ_PATTERN.match(text.strip()))
    
    @classmethod
    def is_telefone(cls, text: str) -> bool:
        """Verifica se o texto é um telefone válido."""
        if not text:
            return False
        return bool(cls.TELEFONE_PATTERN.match(text.strip()))
    
    @classmethod
    def is_login(cls, text: str) -> bool:
        """
        Verifica se o texto pode ser um login.
        Login pode ser: email, CPF, CNPJ, telefone, ou username genérico.
        """
        if not text or len(text.strip()) < 2:
            return False
        
        text = text.strip()
        
        # Email é sempre login
        if cls.is_email(text):
            return True
        
        # CPF/CNPJ/Telefone podem ser login
        if cls.is_cpf(text) or cls.is_cnpj(text) or cls.is_telefone(text):
            return True
        
        # Username genérico (não contém espaços, tem tamanho razoável)
        if ' ' not in text and 2 <= len(text) <= 100:
            return True
        
        return False
    
    @classmethod
    def looks_like_password(cls, text: str) -> bool:
        """
        Heurística para verificar se texto parece uma senha.
        Senhas geralmente são strings sem espaços (a menos que sejam senhas complexas).
        """
        if not text:
            return False
        
        text = text.strip()
        
        # Tamanho mínimo de senha
        if len(text) < 1:
            return False
        
        # Não pode ser URL nem email claramente identificável
        if cls.is_url(text):
            return False
        
        return True


class URLExtractor:
    """Extrator especializado de URLs de linhas complexas."""
    
    # Regex para extrair URL do início da linha
    URL_START_PATTERN = re.compile(
        r'^(https?://[^\s|;]+)',
        re.IGNORECASE
    )
    
    # Regex para extrair URL no meio/fim da linha (após espaço)
    URL_ANYWHERE_PATTERN = re.compile(
        r'(https?://[^\s|;]+)',
        re.IGNORECASE
    )
    
    # Regex para domínio no início (sem protocolo)
    DOMAIN_START_PATTERN = re.compile(
        r'^([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}(:\d+)?(/[^\s|;:]*)?',
        re.IGNORECASE
    )
    
    @classmethod
    def extract_url_from_start(cls, line: str) -> Tuple[Optional[str], str]:
        """
        Extrai URL do início da linha.
        Retorna (url, restante_da_linha) ou (None, linha_original).
        """
        line = line.strip()
        
        # Tentar com protocolo primeiro
        if line.lower().startswith(('http://', 'https://')):
            return cls._extract_url_with_protocol(line)
        
        # Tentar domínio sem protocolo
        match = cls.DOMAIN_START_PATTERN.match(line)
        if match:
            url = match.group(0)
            remaining = line[len(url):].strip()
            # Remover separador inicial do restante
            remaining = cls._clean_remaining(remaining)
            return url, remaining
        
        return None, line
    
    @classmethod
    def _extract_url_with_protocol(cls, line: str) -> Tuple[Optional[str], str]:
        """Extrai URL que começa com http:// ou https://."""
        # Encontrar onde a URL termina
        # A URL pode conter : para porta, então precisamos ser cuidadosos
        
        # Primeiro, identificar o host e porta
        try:
            # Estratégia: encontrar o próximo separador que NÃO é parte da URL
            # Separadores válidos: | ; espaço (quando não faz parte do path)
            
            # Para URLs com porta (ex: http://site:3000/path), 
            # o : após o número é separador
            
            url_end = len(line)
            
            # Verificar separadores óbvios
            for sep in ['|', ';']:
                pos = line.find(sep)
                if pos > 0:
                    url_end = min(url_end, pos)
            
            # Para : precisamos verificar se é porta ou separador
            # Procurar : que vem após / (indicando fim do path)
            url_part = line[:url_end]
            
            # Encontrar onde a URL realmente termina antes de :login:senha
            # Estratégia: após o host/porta e path, o próximo : é separador
            parsed = urlparse(url_part)
            
            if parsed.netloc:
                # Reconstruir URL válida
                base_url = f"{parsed.scheme}://{parsed.netloc}"
                
                # Verificar se há path
                if parsed.path:
                    # Verificar se o path contém credenciais (: após path sem /)
                    path_end = cls._find_path_end(line, len(base_url))
                    full_url = line[:path_end]
                else:
                    full_url = base_url
                    # Verificar se há mais na URL (path)
                    remaining_start = len(base_url)
                    if remaining_start < len(line):
                        next_char = line[remaining_start]
                        if next_char == '/':
                            # Há path, encontrar fim
                            path_end = cls._find_path_end(line, remaining_start)
                            full_url = line[:path_end]
                
                remaining = line[len(full_url):].strip()
                remaining = cls._clean_remaining(remaining)
                return full_url, remaining
                
        except Exception:
            pass
        
        return None, line
    
    @classmethod
    def _find_path_end(cls, line: str, start: int) -> int:
        """Encontra onde o path da URL termina e começam as credenciais."""
        # Procurar por separadores que indicam fim da URL
        # | ; são separadores claros
        # espaço seguido de texto que parece login/senha
        # : seguido de texto que NÃO parece ser parte do path
        
        pos = start
        while pos < len(line):
            char = line[pos]
            
            if char in '|;':
                return pos
            
            if char == ' ':
                # Espaço pode ser fim da URL
                return pos
            
            if char == ':':
                # Verificar se é porta ou separador
                remaining = line[pos+1:]
                # Se o que vem depois não parece porta (4-5 dígitos seguidos de / ou fim)
                # então é separador
                if remaining:
                    # Verificar se é porta
                    port_match = re.match(r'^(\d{1,5})([/\s|;:]|$)', remaining)
                    if port_match:
                        # É porta, continuar
                        pos += 1 + len(port_match.group(1))
                        continue
                    else:
                        # Não é porta, é separador
                        return pos
            
            pos += 1
        
        return pos
    
    @classmethod
    def _clean_remaining(cls, remaining: str) -> str:
        """Remove separadores iniciais do texto restante."""
        remaining = remaining.strip()
        while remaining and remaining[0] in ':;| ':
            remaining = remaining[1:].strip()
        return remaining
    
    @classmethod
    def extract_url_from_anywhere(cls, line: str) -> Tuple[Optional[str], str]:
        """
        Extrai URL de qualquer posição na linha.
        Para casos onde login:senha vem antes da URL.
        """
        match = cls.URL_ANYWHERE_PATTERN.search(line)
        if match:
            url = match.group(1)
            # Remover URL e limpar
            before = line[:match.start()].strip()
            after = line[match.end():].strip()
            remaining = f"{before} {after}".strip()
            remaining = cls._clean_remaining(remaining)
            return url, remaining
        
        return None, line


class CredentialParser:
    """Parser para extrair login e senha de uma string."""
    
    @classmethod
    def parse_credentials(cls, text: str) -> Tuple[Optional[str], Optional[str]]:
        """
        Extrai login e senha de uma string.
        Formato esperado: login:senha ou login|senha ou login;senha
        """
        if not text or not text.strip():
            return None, None
        
        text = text.strip()
        
        # Tentar diferentes separadores em ordem de prioridade
        for sep in ['|', ';']:
            if sep in text:
                parts = text.split(sep, 1)
                if len(parts) == 2:
                    login = parts[0].strip()
                    password = parts[1].strip()
                    # Limpar trailing colons da senha
                    password = cls._clean_password(password)
                    if login and password:
                        # Validar que não são fragmentos de URL
                        if not cls._is_url_fragment(login) and not cls._is_url_fragment(password):
                            return login, password
        
        # Para : é mais complexo porque pode estar na senha
        if ':' in text:
            return cls._parse_with_colon(text)
        
        # Sem separador identificável
        return None, None
    
    @classmethod
    def _clean_password(cls, password: str) -> str:
        """Remove trailing colons e limpa senha."""
        if password:
            password = password.strip()
            # Remover trailing : (pode ser erro de parsing)
            while password.endswith(':'):
                password = password[:-1].strip()
        return password
    
    @classmethod
    def _is_url_fragment(cls, text: str) -> bool:
        """Verifica se texto parece um fragmento de URL."""
        if not text:
            return False
        # Padrões que indicam URL
        url_indicators = ['//', 'http', 'https', '.com/', '.br/', '.net/']
        text_lower = text.lower()
        for indicator in url_indicators:
            if indicator in text_lower:
                return True
        return False
    
    @classmethod
    def _parse_with_colon(cls, text: str) -> Tuple[Optional[str], Optional[str]]:
        """Parse especial para separador : que pode estar na senha."""
        # Estratégia: identificar email/login que contenha @
        # O @ ajuda a identificar onde termina o login
        
        if '@' in text:
            # Pode ser email:senha ou algo como user@domain:senha
            # Encontrar o @ e construir o email
            at_pos = text.find('@')
            
            # Encontrar início do email (antes do @)
            email_start = 0
            for i in range(at_pos - 1, -1, -1):
                if text[i] in ':;| ':
                    email_start = i + 1
                    break
            
            # Encontrar fim do email (depois do @, até próximo :)
            # O domínio não contém : então o próximo : é separador
            email_end = len(text)
            domain_start = at_pos + 1
            
            # Procurar : após o domínio
            for i in range(domain_start, len(text)):
                if text[i] == ':':
                    # Verificar se já temos um domínio válido
                    potential_email = text[email_start:i]
                    if DataValidator.is_email(potential_email):
                        email_end = i
                        break
                elif text[i] in ' |;':
                    email_end = i
                    break
            
            email = text[email_start:email_end].strip()
            
            # O resto é senha
            password_part = text[email_end:].strip()
            if password_part.startswith(':'):
                password_part = password_part[1:].strip()
            
            # Limpar trailing colons e validar
            password_part = cls._clean_password(password_part)
            
            if email and password_part:
                # Verificar se senha não é fragmento de URL
                if not cls._is_url_fragment(password_part):
                    return email, password_part
        
        # Sem @ - usar primeira ocorrência de : como separador
        colon_pos = text.find(':')
        if colon_pos > 0:
            login = text[:colon_pos].strip()
            password = text[colon_pos + 1:].strip()
            password = cls._clean_password(password)
            if login and password:
                # Verificar se não são fragmentos de URL
                if not cls._is_url_fragment(login) and not cls._is_url_fragment(password):
                    return login, password
        
        return None, None


class LeakParser:
    """Parser principal para linhas de leak."""
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.stats = {
            'total_lines': 0,
            'parsed_ulp': 0,
            'parsed_lp': 0,
            'parsed_ul': 0,
            'parsed_url_only': 0,
            'parsed_login_only': 0,
            'out_of_pattern': 0,
            'empty_lines': 0,
            'duplicates': 0
        }
        self.seen_combinations: Set[str] = set()
    
    def parse_line(self, line: str) -> ParsedLine:
        """
        Faz parsing de uma linha tentando extrair URL, Login e Senha.
        Usa múltiplas estratégias para maximizar a taxa de sucesso.
        """
        original_line = line
        line = self._normalize_line(line)
        
        if not line:
            return ParsedLine(
                original_line=original_line,
                parse_success=False,
                parse_method="empty_line"
            )
        
        # Estratégia 1: URL no início (mais comum)
        result = self._try_url_first(line)
        if result.parse_success:
            result.original_line = original_line
            return result
        
        # Estratégia 2: URL no fim (login:senha URL)
        result = self._try_url_last(line)
        if result.parse_success:
            result.original_line = original_line
            return result
        
        # Estratégia 3: Apenas login:senha (sem URL)
        result = self._try_login_password_only(line)
        if result.parse_success:
            result.original_line = original_line
            return result
        
        # Estratégia 4: Apenas URL (sem credenciais)
        result = self._try_url_only(line)
        if result.parse_success:
            result.original_line = original_line
            return result
        
        # Estratégia 5: Padrões especiais (URL:porta:login sem senha)
        result = self._try_special_patterns(line)
        if result.parse_success:
            result.original_line = original_line
            return result
        
        # Nenhuma estratégia funcionou
        return ParsedLine(
            original_line=original_line,
            parse_success=False,
            parse_method="no_pattern_matched"
        )
    
    def _normalize_line(self, line: str) -> str:
        """Normaliza a linha removendo caracteres problemáticos."""
        if not line:
            return ""
        
        # Remover espaços extras e caracteres de controle
        line = line.strip()
        line = line.replace('\r', '').replace('\n', '')
        
        # Normalizar múltiplos espaços
        line = re.sub(r'\s+', ' ', line)
        
        return line
    
    def _try_url_first(self, line: str) -> ParsedLine:
        """Tenta parsing assumindo URL no início."""
        url, remaining = URLExtractor.extract_url_from_start(line)
        
        if url:
            # Validar que a URL extraída não contém credenciais embutidas
            if '@' in url and not url.startswith('mailto:'):
                # Verificar se parece URL com credenciais misturadas
                # Se sim, re-parsear
                pass  # Continuar com o parsing normal
            
            if remaining:
                login, password = CredentialParser.parse_credentials(remaining)
                if login and password:
                    return ParsedLine(
                        url=url,
                        login=login,
                        password=password,
                        parse_success=True,
                        parse_method="url_first_full"
                    )
                elif login:
                    # Só login, sem senha clara - verificar se é válido
                    # Para casos como URL:login onde falta senha
                    if DataValidator.is_login(login):
                        return ParsedLine(
                            url=url,
                            login=login,
                            parse_success=True,
                            parse_method="url_first_login_only"
                        )
            else:
                # Só URL - verificar se não tem credenciais
                if not ('@' in url and ':' in url.split('@')[0]):
                    return ParsedLine(
                        url=url,
                        parse_success=True,
                        parse_method="url_only"
                    )
        
        return ParsedLine(parse_success=False)
    
    def _try_url_last(self, line: str) -> ParsedLine:
        """Tenta parsing assumindo URL no fim (login:senha URL)."""
        url, remaining = URLExtractor.extract_url_from_anywhere(line)
        
        if url and remaining:
            login, password = CredentialParser.parse_credentials(remaining)
            if login and password:
                return ParsedLine(
                    url=url,
                    login=login,
                    password=password,
                    parse_success=True,
                    parse_method="url_last_full"
                )
            elif login:
                return ParsedLine(
                    url=url,
                    login=login,
                    parse_success=True,
                    parse_method="url_last_login_only"
                )
        
        return ParsedLine(parse_success=False)
    
    def _try_login_password_only(self, line: str) -> ParsedLine:
        """Tenta parsing de linha que contém apenas login:senha."""
        # Verificar se definitivamente não há URL
        if DataValidator.is_url(line.split()[0] if ' ' in line else line.split(':')[0] if ':' in line else line):
            return ParsedLine(parse_success=False)
        
        login, password = CredentialParser.parse_credentials(line)
        
        if login and password:
            # Validar que login parece login (email, username, etc.)
            if DataValidator.is_login(login):
                return ParsedLine(
                    login=login,
                    password=password,
                    parse_success=True,
                    parse_method="login_password_only"
                )
        
        return ParsedLine(parse_success=False)
    
    def _try_url_only(self, line: str) -> ParsedLine:
        """Tenta parsing de linha que contém apenas URL."""
        if DataValidator.is_url(line):
            return ParsedLine(
                url=line,
                parse_success=True,
                parse_method="url_only_direct"
            )
        
        return ParsedLine(parse_success=False)
    
    def _try_special_patterns(self, line: str) -> ParsedLine:
        """
        Tenta parsing de padrões especiais que não se encaixam nos padrões normais.
        Ex: URL:porta:login (sem senha), email:, etc.
        """
        # Padrão 1: domain.com:porta:login (sem senha)
        # Ex: 10013.onu.ipv7.com.br:9090:suporte29@ibitelecom.com.br
        colon_count = line.count(':')
        if colon_count >= 2:
            parts = line.split(':')
            # Verificar se primeiro elemento parece domínio e segundo parece porta
            if len(parts) >= 3:
                first_part = parts[0]
                second_part = parts[1]
                
                # Verificar se parece domínio:porta:login
                if '.' in first_part and second_part.isdigit():
                    # Primeiro parece domínio, segundo é porta
                    url = f"{first_part}:{second_part}"
                    # O resto é login (pode ter : no email se tiver mais partes)
                    remaining = ':'.join(parts[2:])
                    
                    if remaining and DataValidator.is_login(remaining):
                        return ParsedLine(
                            url=url,
                            login=remaining,
                            parse_success=True,
                            parse_method="special_url_port_login"
                        )
        
        # Padrão 2: email: ou login: (com : no final, sem senha)
        # Tratar como linha incompleta - marcar como login apenas
        if line.endswith(':'):
            potential_login = line[:-1].strip()
            if potential_login and DataValidator.is_login(potential_login):
                # Linha incompleta com apenas login
                return ParsedLine(
                    login=potential_login,
                    parse_success=True,
                    parse_method="special_login_only_incomplete"
                )
        
        # Padrão 3: email:senha:URL (ordem LPU - Login Password URL)
        # Ex: amanda@ipv7.com.br:@Ipv7tecnologia:accounts.autodesk.com/Authentication/LogOn
        if colon_count >= 2 and '@' in line:
            # Tentar extrair email primeiro
            at_pos = line.find('@')
            if at_pos > 0:
                # Encontrar fim do email
                email_end = at_pos + 1
                while email_end < len(line) and line[email_end] not in ':;| ':
                    email_end += 1
                
                potential_email = line[:email_end]
                if DataValidator.is_email(potential_email):
                    remaining = line[email_end:]
                    if remaining.startswith(':'):
                        remaining = remaining[1:]
                    
                    # Verificar se o resto tem formato senha:URL
                    if ':' in remaining:
                        parts = remaining.split(':')
                        # Última parte pode ser URL
                        for i in range(len(parts) - 1, 0, -1):
                            potential_url = ':'.join(parts[i:])
                            if '.' in potential_url and '/' in potential_url:
                                # Parece URL
                                password = ':'.join(parts[:i])
                                password = CredentialParser._clean_password(password)
                                if password:
                                    return ParsedLine(
                                        url=potential_url,
                                        login=potential_email,
                                        password=password,
                                        parse_success=True,
                                        parse_method="special_lpu_order"
                                    )
        
        # Padrão 4: URL:login:senha onde login não é email
        # Ex: https://23021.vision.ipv7.com.br:sac-glfibra:GL@Fibr#s
        if line.lower().startswith(('http://', 'https://')):
            # Extrair URL base
            try:
                parsed = urlparse(line.split(':')[0] + '://' + line.split('://')[1].split(':')[0])
                if parsed.netloc:
                    base_url = f"{parsed.scheme}://{parsed.netloc}"
                    if parsed.path:
                        base_url += parsed.path
                    
                    remaining = line[len(base_url):]
                    if remaining.startswith(':'):
                        remaining = remaining[1:]
                    
                    if ':' in remaining:
                        parts = remaining.split(':', 1)
                        login = parts[0].strip()
                        password = CredentialParser._clean_password(parts[1].strip())
                        
                        if login and password:
                            return ParsedLine(
                                url=base_url,
                                login=login,
                                password=password,
                                parse_success=True,
                                parse_method="special_url_username_password"
                            )
            except Exception:
                pass
        
        return ParsedLine(parse_success=False)
    
    
    def process_file(
        self, 
        input_path: str, 
        output_dir: str,
        deduplicate: bool = True
    ) -> Dict[str, int]:
        """
        Processa arquivo de entrada e gera arquivos de saída.
        
        Workflow:
        1. Parseia todas as linhas e gera ulp_combined.csv
        2. A partir do ulp_combined.csv, extrai os demais arquivos
        
        Args:
            input_path: Caminho do arquivo de entrada
            output_dir: Diretório para arquivos de saída
            deduplicate: Se True, remove duplicatas
        
        Returns:
            Estatísticas do processamento
        """
        # Criar diretório de saída se não existir
        os.makedirs(output_dir, exist_ok=True)
        
        # Definir caminhos de saída
        combined_path = os.path.join(output_dir, 'ulp_combined.csv')
        out_of_pattern_path = os.path.join(output_dir, 'out-of-pattern.txt')
        
        # Sets para deduplicação
        seen_combined: Set[str] = set()
        
        # Listas para armazenar dados
        combined: List[Tuple[str, str, str]] = []
        out_of_pattern: List[str] = []
        
        # Processar arquivo
        logger.info(f"Processando arquivo: {input_path}")
        
        try:
            # Tentar diferentes encodings
            encodings = ['utf-8', 'latin-1', 'cp1252', 'iso-8859-1']
            content = None
            
            for encoding in encodings:
                try:
                    with open(input_path, 'r', encoding=encoding) as f:
                        content = f.readlines()
                    logger.info(f"Arquivo lido com encoding: {encoding}")
                    break
                except UnicodeDecodeError:
                    continue
            
            if content is None:
                # Fallback: ler como bytes e ignorar erros
                with open(input_path, 'rb') as f:
                    content = f.read().decode('utf-8', errors='ignore').splitlines()
                logger.warning("Arquivo lido com encoding fallback (UTF-8 ignore errors)")
            
            # PASSO 1: Parsear todas as linhas e gerar ULP combinado
            for line in content:
                self.stats['total_lines'] += 1
                
                # Pular linhas vazias
                if not line.strip():
                    self.stats['empty_lines'] += 1
                    continue
                
                # Fazer parsing
                result = self.parse_line(line)
                
                if result.parse_success:
                    # Extrair dados
                    url = result.url or ""
                    login = result.login or ""
                    password = result.password or ""
                    
                    # Verificar duplicatas se necessário
                    combined_key = f"{url}|{login}|{password}"
                    if deduplicate and combined_key in seen_combined:
                        self.stats['duplicates'] += 1
                        continue
                    seen_combined.add(combined_key)
                    
                    # Adicionar ao combinado se tiver pelo menos 2 componentes
                    if (url and login) or (url and password) or (login and password):
                        combined.append((url, login, password))
                        
                        if url and login and password:
                            self.stats['parsed_ulp'] += 1
                        elif login and password:
                            self.stats['parsed_lp'] += 1
                        elif url and login:
                            self.stats['parsed_ul'] += 1
                        else:
                            self.stats['parsed_url_only'] += 1
                    elif url:
                        self.stats['parsed_url_only'] += 1
                    elif login:
                        self.stats['parsed_login_only'] += 1
                else:
                    # Não conseguiu parsear
                    out_of_pattern.append(line.strip())
                    self.stats['out_of_pattern'] += 1
            
            # Escrever ULP combinado e out-of-pattern
            self._write_csv_combined(combined_path, combined)
            self._write_text(out_of_pattern_path, out_of_pattern)
            
            logger.info(f"Processamento concluído!")
            logger.info(f"  Total de linhas: {self.stats['total_lines']}")
            logger.info(f"  Linhas vazias: {self.stats['empty_lines']}")
            logger.info(f"  Parsed ULP completo: {self.stats['parsed_ulp']}")
            logger.info(f"  Parsed LP apenas: {self.stats['parsed_lp']}")
            logger.info(f"  Parsed UL apenas: {self.stats['parsed_ul']}")
            logger.info(f"  Parsed URL apenas: {self.stats['parsed_url_only']}")
            logger.info(f"  Parsed Login apenas: {self.stats['parsed_login_only']}")
            logger.info(f"  Out of pattern: {self.stats['out_of_pattern']}")
            logger.info(f"  Duplicatas removidas: {self.stats['duplicates']}")
            
            return self.stats
            
        except Exception as e:
            logger.error(f"Erro ao processar arquivo: {e}")
            raise
    
    def _write_csv_combined(
        self, 
        path: str, 
        data: List[Tuple[str, str, str]]
    ) -> None:
        """Escreve CSV combinado com URL, Login, Password."""
        with open(path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['url', 'login', 'password'])
            for url, login, password in data:
                writer.writerow([url, login, password])
        logger.info(f"  Escrito: {path} ({len(data)} registros)")
    
    def _write_text(self, path: str, data: List[str]) -> None:
        """Escreve arquivo de texto com linhas não parseadas."""
        with open(path, 'w', encoding='utf-8') as f:
            for line in data:
                f.write(f"{line}\n")
        logger.info(f"  Escrito: {path} ({len(data)} registros)")


def main():
    """Função principal."""
    parser = argparse.ArgumentParser(
        description='Bird Leak Cleaner - Parser robusto para dados vazados ULP',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos de uso:
  %(prog)s --input leak --output ./output
  %(prog)s -i dados.txt -o ./resultado --no-dedup
  %(prog)s -i leak -o ./output --verbose
        """
    )
    
    parser.add_argument(
        '-i', '--input',
        required=True,
        help='Arquivo de entrada com dados de leak'
    )
    
    parser.add_argument(
        '-o', '--output',
        required=True,
        help='Diretório de saída para os arquivos CSV'
    )
    
    parser.add_argument(
        '--no-dedup',
        action='store_true',
        help='Não remover duplicatas'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Modo verbose com mais informações'
    )
    
    args = parser.parse_args()
    
    # Verificar arquivo de entrada
    if not os.path.exists(args.input):
        logger.error(f"Arquivo não encontrado: {args.input}")
        sys.exit(1)
    
    # Configurar logging verbose
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Processar
    leak_parser = LeakParser(verbose=args.verbose)
    
    try:
        stats = leak_parser.process_file(
            input_path=args.input,
            output_dir=args.output,
            deduplicate=not args.no_dedup
        )
        
        # Verificar se o processamento foi bem-sucedido
        total_processed = (
            stats['parsed_ulp'] + 
            stats['parsed_lp'] + 
            stats['parsed_ul'] +
            stats['parsed_url_only'] + 
            stats['parsed_login_only'] +
            stats['out_of_pattern'] +
            stats['empty_lines'] +
            stats['duplicates']
        )
        
        if total_processed == stats['total_lines']:
            logger.info("✅ Validação: Todas as linhas foram processadas corretamente!")
        else:
            logger.warning(
                f"⚠️ Validação: Discrepância detectada! "
                f"Total: {stats['total_lines']}, Processado: {total_processed}"
            )
        
        # Mostrar resumo final
        print("\n" + "="*60)
        print("RESUMO DO PROCESSAMENTO")
        print("="*60)
        print(f"Linhas totais:        {stats['total_lines']}")
        print(f"Linhas vazias:        {stats['empty_lines']}")
        print(f"Duplicatas removidas: {stats['duplicates']}")
        print(f"ULP completo:         {stats['parsed_ulp']}")
        print(f"URL+Login apenas:     {stats['parsed_ul']}")
        print(f"Login+Senha apenas:   {stats['parsed_lp']}")
        print(f"URL apenas:           {stats['parsed_url_only']}")
        print(f"Login apenas:         {stats['parsed_login_only']}")
        print(f"Fora do padrão:       {stats['out_of_pattern']}")
        print("="*60)
        print(f"\nArquivos salvos em: {os.path.abspath(args.output)}/")
        
    except Exception as e:
        logger.error(f"Erro fatal: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
