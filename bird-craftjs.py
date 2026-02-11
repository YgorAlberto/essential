#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import re
import argparse
import sys
import threading
import time
import random
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Style, init

# Inicializa cores para terminal
init(autoreset=True)

# --- CONFIGURAÇÕES GLOBAIS & PATTERNS ---

# User-Agents para simular navegação legítima
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:90.0) Gecko/20100101 Firefox/90.0"
]

# Dicionário de Regex categorizado (O "Cérebro" da ferramenta)
PATTERNS = {
    # INFRAESTRUTURA & CONECTIVIDADE
    "Connection String": {
        "regex": r"(?:jdbc:[a-z:]+|mysql:\/\/|postgres:\/\/|mongodb:\/\/|redis:\/\/|sqlserver:\/\/)[^\s\"']+",
        "desc": "String de conexão de banco de dados completa.",
        "exploit": "Permite acesso direto ao banco de dados se a porta estiver exposta ou via SSRF. Verifique credenciais."
    },
    "Cloud Bucket/Blob": {
        "regex": r"(?:[a-z0-9\.\-]+\.s3\.amazonaws\.com|[a-z0-9\.\-]+\.blob\.core\.windows\.net|[a-z0-9\.\-]+\.storage\.googleapis\.com)",
        "desc": "URL de Bucket S3, Azure Blob ou Google Storage.",
        "exploit": "Teste a listagem pública (ls) e upload (cp) usando CLI do provedor (aws s3 ls...). Risco de Data Leak."
    },
    "Internal IP": {
        "regex": r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3})\b",
        "desc": "Endereço IP Privado (RFC 1918).",
        "exploit": "Revela topologia interna. Útil para SSRF ou Pivoting se obtiver acesso à rede."
    },
    "Webhook URL": {
        "regex": r"https:\/\/(?:hooks\.slack\.com|discord\.com\/api\/webhooks|outlook\.office\.com\/webhook)[^\s\"']+",
        "desc": "URL de Webhook (Slack, Discord, Teams).",
        "exploit": "Permite enviar mensagens falsas (Phishing interno) ou exfiltrar dados para canais da empresa."
    },
    "CI/CD Config": {
        "regex": r"(?:\.gitlab-ci\.yml|Jenkinsfile|\.github\/workflows\/[a-zA-Z0-9\-_]+\.yml|bitbucket-pipelines\.yml)",
        "desc": "Referência a arquivos de configuração de Pipeline.",
        "exploit": "Analise o histórico de commits ou o arquivo em si para achar credenciais de deploy e variáveis de ambiente."
    },

    # CRIPTOGRAFIA & AUTENTICAÇÃO
    "Private Key": {
        "regex": r"-----BEGIN (?:RSA|DSA|EC|PGP) PRIVATE KEY-----",
        "desc": "Bloco de Chave Privada Assimétrica.",
        "exploit": "CRÍTICO. Permite decifrar tráfego, assinar tokens ou acessar servidores via SSH."
    },
    "AWS API Key": {
        "regex": r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
        "desc": "Possível AWS Access Key ID.",
        "exploit": "Configure no AWS CLI e verifique permissões (sts get-caller-identity). Pode levar a takeover da conta cloud."
    },
    "JWT Token": {
        "regex": r"eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_.+/=]*",
        "desc": "JSON Web Token (JWT).",
        "exploit": "Decodifique (jwt.io). Verifique algoritmos fracos (None), expiração e dados sensíveis no payload."
    },
    "Generic Secret": {
        "regex": r"(?i)(?:secret|token|password|passwd|api[_-]?key)['\"]?\s*[:=]\s*['\"]([a-zA-Z0-9\-\_\+\=\/]{8,})['\"]",
        "desc": "Possível chave de API ou senha hardcoded detectada por heurística.",
        "exploit": "Teste a credencial contra os serviços da aplicação ou APIs externas identificadas."
    },

    # LÓGICA E DEBUG
    "Admin/Debug Route": {
        "regex": r"(?:\/actuator\/|\/server-status|\/console|\/swagger-ui|\/graphql|\/phpinfo\.php|\/env)",
        "desc": "Rota administrativa ou de debug exposta.",
        "exploit": "Acesse a rota. Pode vazar variáveis de ambiente, status do servidor ou permitir RCE (ex: Actuator)."
    },
    "Debug Parameter": {
        "regex": r"[\?&](?:debug=true|test=1|admin=1|show_errors=true)",
        "desc": "Parâmetro GET que altera o fluxo da aplicação.",
        "exploit": "Tente forçar erros verbosos ou bypass de autenticação alterando estes valores."
    },

    # RECONHECIMENTO GERAL
    "Full Path Disclosure": {
        "regex": r"(?:\/[a-zA-Z0-9_\-\/]+(?:\/var\/www|\/home\/|\/usr\/local)|[C-Z]:\\[a-zA-Z0-9_\\\-]+)",
        "desc": "Caminho completo de diretório do sistema operacional.",
        "exploit": "Ajuda em ataques de LFI/Path Traversal ao saber a estrutura exata de arquivos."
    },
    "Internal Email": {
        "regex": r"[a-zA-Z0-9\.\-_]+@[a-zA-Z0-9\.\-]+\.(?:com|net|org|br)",
        "desc": "Endereço de e-mail encontrado no código.",
        "exploit": "Útil para montar lista de alvos para Phishing ou Username Enumeration/Brute-force."
    }
}

class BirdCraftScanner:
    def __init__(self, input_file, threads=7, output_file="output-craftjs.txt"):
        self.input_file = input_file
        self.output_file = output_file
        self.threads = threads
        self.visited_urls = set()
        self.urls_to_scan = set()
        self.findings = {} # Chave: "Finding_Signature", Valor: {info, type, exploit, urls: []}
        self.lock = threading.Lock()
        self.scope_domains = set()

    def get_random_header(self):
        return {
            "User-Agent": random.choice(USER_AGENTS),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Connection": "keep-alive"
        }

    def normalize_url(self, url):
        if not url.startswith(('http://', 'https://')):
            return f'http://{url.strip()}'
        return url.strip()

    def load_targets(self):
        try:
            with open(self.input_file, 'r') as f:
                lines = f.readlines()
                for line in lines:
                    url = self.normalize_url(line)
                    self.urls_to_scan.add(url)
                    # Define o escopo baseando-se no domínio inicial
                    parsed = urlparse(url)
                    self.scope_domains.add(parsed.netloc)
            print(f"{Fore.BLUE}[*] Alvos carregados: {len(self.urls_to_scan)}")
        except FileNotFoundError:
            print(f"{Fore.RED}[!] Arquivo {self.input_file} não encontrado.")
            sys.exit(1)

    def is_in_scope(self, url):
        try:
            domain = urlparse(url).netloc
            # Permite subdomínios se o domínio base estiver no escopo
            for scope in self.scope_domains:
                if domain == scope or domain.endswith("." + scope):
                    return True
            return False
        except:
            return False

    def scan_url(self, url):
        with self.lock:
            if url in self.visited_urls:
                return
            self.visited_urls.add(url)

        print(f"{Fore.YELLOW}[>] Analisando: {url}")
        
        try:
            # Acesso estilo "Humano"
            time.sleep(random.uniform(0.5, 1.5)) 
            response = requests.get(url, headers=self.get_random_header(), timeout=10, verify=False)
            
            if response.status_code == 200:
                content = response.text
                self.analyze_content(url, content)
                self.extract_new_links(url, content)
            else:
                print(f"{Fore.RED}[!] Erro {response.status_code} em {url}")

        except requests.exceptions.RequestException as e:
            print(f"{Fore.RED}[!] Falha de conexão em {url}: {str(e)}")

    def extract_new_links(self, base_url, content):
        soup = BeautifulSoup(content, 'html.parser')
        new_links_found = 0
        
        for link in soup.find_all(['a', 'script', 'link']):
            href = link.get('href') or link.get('src')
            if href:
                full_url = urljoin(base_url, href)
                # Limpa âncoras e parâmetros para validação
                clean_url = full_url.split('#')[0] 
                
                if self.is_in_scope(clean_url) and clean_url not in self.visited_urls:
                    # Adiciona dinamicamente para escaneamento (cuidado com recursão infinita em produção)
                    # Aqui, para manter o script seguro, não adicionamos à fila principal de execução
                    # em tempo real neste exemplo simples, mas poderíamos usar uma Queue.
                    # Para este script, vamos focar na análise profunda das URLs fornecidas e links diretos 1 nível
                    pass 

    def analyze_content(self, url, content):
        for name, data in PATTERNS.items():
            matches = re.findall(data['regex'], content)
            if matches:
                # Remove duplicatas encontradas na MESMA página
                unique_matches = set(matches)
                for match in unique_matches:
                    # Chave única para evitar duplicata global no relatório
                    finding_key = f"{name}:{match}"
                    
                    with self.lock:
                        if finding_key not in self.findings:
                            self.findings[finding_key] = {
                                "type": name,
                                "content": match,
                                "desc": data['desc'],
                                "exploit": data['exploit'],
                                "urls": [url]
                            }
                        else:
                            if url not in self.findings[finding_key]['urls']:
                                self.findings[finding_key]['urls'].append(url)
                                
                        print(f"{Fore.GREEN}[+] ENCONTRADO: {name} em {url}")

    def generate_report(self):
        print(f"\n{Fore.CYAN}[*] Gerando relatório em {self.output_file}...")
        try:
            with open(self.output_file, 'w', encoding='utf-8') as f:
                f.write("=== RELATÓRIO DE ANÁLISE ESTÁTICA BIRD-CRAFTJS ===\n")
                f.write(f"Data: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("==================================================\n\n")

                if not self.findings:
                    f.write("Nenhuma informação crítica encontrada com os padrões atuais.\n")
                
                for key, data in self.findings.items():
                    f.write(f"[-] TIPO: {data['type']}\n")
                    f.write(f"    INFO ENCONTRADA: {data['content']}\n")
                    f.write(f"    DESCRIÇÃO: {data['desc']}\n")
                    f.write(f"    DICA DE EXPLORAÇÃO: {data['exploit']}\n")
                    f.write(f"    ENCONTRADO NAS URLS:\n")
                    for u in data['urls']:
                        f.write(f"      -> {u}\n")
                    f.write("-" * 60 + "\n")
            
            print(f"{Fore.GREEN}[OK] Relatório salvo com sucesso!")
            
        except Exception as e:
            print(f"{Fore.RED}[!] Erro ao salvar relatório: {e}")

    def run(self):
        self.load_targets()
        
        # Threading pool para performance
        print(f"{Fore.BLUE}[*] Iniciando scanner com {self.threads} threads...")
        
        # Fase 1: Scan das URLs iniciais
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(self.scan_url, url) for url in self.urls_to_scan]
            for future in as_completed(futures):
                pass # Aguarda conclusão
        
        # Fase 2 (Opcional): Implementar lógica recursiva de N níveis aqui se necessário
        
        self.generate_report()

# --- ENTRY POINT ---
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Bird-CraftJS: Static Analysis Tool for Pentesters")
    parser.add_argument("file", help="Arquivo .txt contendo as URLs")
    args = parser.parse_args()

    # Supressão de warnings de SSL inseguro (comum em pentest)
    requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

    scanner = BirdCraftScanner(input_file=args.file)
    scanner.run()
