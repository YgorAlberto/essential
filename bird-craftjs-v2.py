#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Bird-CraftJS - Web Source Code Analyzer for Penetration Testing
Author: Security Tool for Ethical Pentesting
"""

import argparse
import re
import sys
import threading
import time
import random
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError:
    print("[!] Install: pip install requests")
    sys.exit(1)

try:
    from bs4 import BeautifulSoup
except ImportError:
    print("[!] Install: pip install beautifulsoup4 lxml")
    sys.exit(1)

class Config:
    DEFAULT_THREADS = 10
    TIMEOUT = 15
    MAX_RETRIES = 3
    OUTPUT_FILE = "output-craftjs.txt"
    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    ]

class Patterns:
    API_ROUTES = [
        r'["\'](/api/v?\d*/[a-zA-Z0-9/_\-{}]+)["\']',
        r'["\'](/v\d+/[a-zA-Z0-9/_\-{}]+)["\']',
        r'fetch\s*\(\s*["\']([^"\']+)["\']',
        r'axios\.[a-z]+\s*\(\s*["\']([^"\']+)["\']',
        r'endpoint["\']?\s*[:=]\s*["\']([^"\']+)["\']',
        r'baseURL["\']?\s*[:=]\s*["\']([^"\']+)["\']',
    ]
    EMAIL = r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}'
    IPV4 = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    CREDENTIALS = [
        r'["\']?password["\']?\s*[:=]\s*["\']([^"\']{3,})["\']',
        r'["\']?secret["\']?\s*[:=]\s*["\']([^"\']{8,})["\']',
        r'["\']?api[_\-]?key["\']?\s*[:=]\s*["\']([^"\']{8,})["\']',
        r'["\']?auth[_\-]?token["\']?\s*[:=]\s*["\']([^"\']{8,})["\']',
        r'Authorization["\']?\s*[:=]\s*["\']Bearer\s+([^"\']+)["\']',
    ]
    SUBDOMAIN = r'(?:https?://)?([a-zA-Z0-9][a-zA-Z0-9\-]*\.)+[a-zA-Z0-9][a-zA-Z0-9\-]*\.[a-zA-Z]{2,}'
    CLOUD_TOKENS = {
        "AWS Key": r'AKIA[0-9A-Z]{16}',
        "Google API": r'AIza[0-9A-Za-z\-_]{35}',
        "GitHub Token": r'gh[pousr]_[A-Za-z0-9_]{36,}',
        "Slack Token": r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}',
        "Stripe Key": r'sk_(?:live|test)_[0-9a-zA-Z]{24,}',
        "JWT": r'eyJ[A-Za-z0-9_\-]*\.eyJ[A-Za-z0-9_\-]*\.[A-Za-z0-9_\-]*',
        "Private Key": r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----',
        "MongoDB URI": r'mongodb(?:\+srv)?://[^\s"\'<>]+',
        "PostgreSQL": r'postgres(?:ql)?://[^\s"\'<>]+',
        "S3 Bucket": r'(?:https?://)?[a-zA-Z0-9\-]+\.s3[.\-][a-z\-]*\.amazonaws\.com',
        "Discord Webhook": r'https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_\-]+',
        "Telegram Bot": r'[0-9]{8,10}:[A-Za-z0-9_\-]{35}',
        "SendGrid": r'SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}',
        "Twilio": r'SK[0-9a-fA-F]{32}',
    }

class HTTPClient:
    def __init__(self):
        self.session = requests.Session()
        retry = Retry(total=Config.MAX_RETRIES, backoff_factor=1, status_forcelist=[429,500,502,503,504])
        self.session.mount("http://", HTTPAdapter(max_retries=retry))
        self.session.mount("https://", HTTPAdapter(max_retries=retry))
    
    def _headers(self):
        return {
            "User-Agent": random.choice(Config.USER_AGENTS),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "DNT": "1",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
        }
    
    def is_alive(self, url):
        try:
            r = self.session.head(url, headers=self._headers(), timeout=Config.TIMEOUT, allow_redirects=True, verify=False)
            return r.status_code < 500
        except:
            try:
                r = self.session.get(url, headers=self._headers(), timeout=Config.TIMEOUT, allow_redirects=True, verify=False)
                return r.status_code < 500
            except:
                return False
    
    def fetch(self, url):
        time.sleep(random.uniform(0.3, 1.0))
        try:
            r = self.session.get(url, headers=self._headers(), timeout=Config.TIMEOUT, allow_redirects=True, verify=False)
            return r.text, r.status_code
        except Exception as e:
            return None, str(e)

class Extractor:
    def extract(self, content, url):
        findings = []
        full = self._expand(content)
        
        for p in Patterns.API_ROUTES:
            for m in re.finditer(p, full, re.I):
                v = m.group(1) if m.lastindex else m.group(0)
                findings.append(("API Route", v.strip('"\''), url))
        
        for m in re.finditer(Patterns.EMAIL, full, re.I):
            e = m.group(0)
            if not any(x in e.lower() for x in ['example.com','test.com','domain.com']):
                findings.append(("Email", e, url))
        
        for m in re.finditer(Patterns.IPV4, full):
            ip = m.group(0)
            if not self._is_private(ip):
                findings.append(("IPv4", ip, url))
        
        for p in Patterns.CREDENTIALS:
            for m in re.finditer(p, full, re.I):
                v = m.group(1) if m.lastindex else m.group(0)
                if len(v) >= 3 and not self._placeholder(v):
                    findings.append(("Credential", v, url))
        
        base = self._base_domain(url)
        for m in re.finditer(Patterns.SUBDOMAIN, full, re.I):
            s = m.group(0).lower().replace('https://','').replace('http://','')
            if base and base in s and s != base:
                findings.append(("Subdomain", s, url))
        
        for name, p in Patterns.CLOUD_TOKENS.items():
            for m in re.finditer(p, full, re.I):
                v = m.group(1) if m.lastindex and m.lastindex >= 1 else m.group(0)
                if not self._placeholder(v):
                    findings.append((f"Token/{name}", v[:100], url))
        
        return self._dedup(findings)
    
    def _expand(self, content):
        try:
            soup = BeautifulSoup(content, 'lxml')
            all_c = content
            for s in soup.find_all('script'):
                if s.string:
                    all_c += "\n" + s.string
            return all_c
        except:
            return content
    
    def _is_private(self, ip):
        p = ip.split('.')
        if len(p) != 4: return True
        try:
            f, s = int(p[0]), int(p[1])
            return f == 10 or f == 127 or (f == 172 and 16 <= s <= 31) or (f == 192 and s == 168) or f == 0
        except:
            return True
    
    def _placeholder(self, v):
        pl = ['xxx','your_','example','sample','test','placeholder','change_me','todo','null','undefined']
        return any(x in v.lower() for x in pl) or len(set(v)) < 3
    
    def _base_domain(self, url):
        try:
            p = urllib.parse.urlparse(url).netloc.split('.')
            return '.'.join(p[-2:]) if len(p) >= 2 else None
        except:
            return None
    
    def _dedup(self, f):
        seen, u = set(), []
        for i in f:
            k = (i[0], i[1])
            if k not in seen:
                seen.add(k)
                u.append(i)
        return u

class Scanner:
    def __init__(self, threads):
        self.threads = threads
        self.client = HTTPClient()
        self.extractor = Extractor()
        self.results = []
        self.lock = threading.Lock()
        self.stats = {"total": 0, "alive": 0, "scanned": 0, "findings": 0}
    
    def load(self, f):
        urls = []
        with open(f, 'r') as file:
            for line in file:
                u = line.strip()
                if u and not u.startswith('#'):
                    if not u.startswith(('http://','https://')):
                        u = 'https://' + u
                    urls.append(u)
        return urls
    
    def scan(self, url):
        print(f"[*] Checking: {url}")
        if not self.client.is_alive(url):
            print(f"[-] Offline: {url}")
            return
        with self.lock:
            self.stats["alive"] += 1
        print(f"[+] Alive: {url}")
        content, _ = self.client.fetch(url)
        if not content:
            return
        with self.lock:
            self.stats["scanned"] += 1
        findings = self.extractor.extract(content, url)
        with self.lock:
            self.stats["findings"] += len(findings)
            self.results.extend(findings)
        print(f"[+] Found {len(findings)} items: {url}")
    
    def run(self, urls):
        self.stats["total"] = len(urls)
        print(f"\n[*] Scanning {len(urls)} URLs with {self.threads} threads\n")
        with ThreadPoolExecutor(max_workers=self.threads) as ex:
            futures = [ex.submit(self.scan, u) for u in urls]
            for f in as_completed(futures):
                try: f.result()
                except Exception as e: print(f"[!] Error: {e}")
    
    def save(self, out):
        with open(out, 'w') as f:
            f.write(f"# Bird-CraftJS - {datetime.now()}\n# Stats: {self.stats}\n\n")
            for t, d, u in self.results:
                f.write(f"TITULO: {t}\nDADO: {d}\nURL: {u}\n\n")
        print(f"\n[+] Saved: {out}")

def main():
    print("\n🦅 BIRD-CRAFTJS - Web Source Analyzer\n")
    p = argparse.ArgumentParser()
    p.add_argument('-f', '--file', required=True, help='URLs file')
    p.add_argument('-t', '--threads', type=int, default=10, help='Threads (default: 10)')
    p.add_argument('-o', '--output', default='output-craftjs.txt', help='Output file')
    a = p.parse_args()
    
    if not Path(a.file).exists():
        print(f"[!] File not found: {a.file}")
        sys.exit(1)
    
    import urllib3
    urllib3.disable_warnings()
    
    s = Scanner(a.threads)
    urls = s.load(a.file)
    if not urls:
        print("[!] No URLs found")
        sys.exit(1)
    
    s.run(urls)
    s.save(a.output)
    print(f"\n[*] Done! Total:{s.stats['total']} Alive:{s.stats['alive']} Findings:{s.stats['findings']}")

if __name__ == "__main__":
    main()
