#!/usr/bin/env python3
"""
Bird Nmap Web Validator - Selenium Module
Valida URLs usando Selenium, captura screenshots e gera relatório HTML
Versão 3.0 - Index por ativo + Master dinâmico + Firefox primeiro
"""

import os
import sys
import time
import hashlib
import re
import json
from datetime import datetime
from urllib.parse import urlparse
from collections import defaultdict

# Verificar e instalar dependências
def check_dependencies():
    """Verifica e instala dependências necessárias"""
    required = ['selenium', 'webdriver_manager', 'PIL']
    module_names = {'PIL': 'Pillow'}
    missing = []
    
    for module in required:
        try:
            __import__(module)
        except ImportError:
            pkg_name = module_names.get(module, module)
            missing.append(pkg_name)
    
    if missing:
        print(f"[*] Instalando dependências: {', '.join(missing)}")
        import subprocess
        for module in missing:
            subprocess.check_call([sys.executable, '-m', 'pip', 'install', module, '-q'])

check_dependencies()

from selenium import webdriver
from selenium.webdriver.chrome.service import Service as ChromeService
from selenium.webdriver.chrome.options import Options as ChromeOptions
from selenium.webdriver.firefox.service import Service as FirefoxService
from selenium.webdriver.firefox.options import Options as FirefoxOptions
from selenium.webdriver.common.by import By
from selenium.common.exceptions import WebDriverException, TimeoutException
from PIL import Image, ImageDraw, ImageFont

try:
    from webdriver_manager.chrome import ChromeDriverManager
    from webdriver_manager.firefox import GeckoDriverManager
    HAS_WEBDRIVER_MANAGER = True
except ImportError:
    HAS_WEBDRIVER_MANAGER = False


class SeleniumValidator:
    """Validador de URLs usando Selenium"""
    
    def __init__(self, output_dir="paginas-web-encontradas"):
        self.output_dir = output_dir
        self.results = defaultdict(list)  # Organizado por ativo
        self.driver = None
        
        # Criar diretório de saída
        os.makedirs(self.output_dir, exist_ok=True)
    
    def init_driver(self):
        """Inicializa o WebDriver (Firefox primeiro, depois Chrome)"""
        
        # Tentar Firefox primeiro (conforme solicitado)
        try:
            options = FirefoxOptions()
            options.add_argument('--headless')
            options.add_argument('--width=1920')
            options.add_argument('--height=1080')
            options.set_preference('network.stricttransportsecurity.preloadlist', False)
            options.set_preference('security.cert_pinning.enforcement_level', 0)
            options.accept_insecure_certs = True
            
            if HAS_WEBDRIVER_MANAGER:
                service = FirefoxService(GeckoDriverManager().install())
                self.driver = webdriver.Firefox(service=service, options=options)
            else:
                self.driver = webdriver.Firefox(options=options)
            
            self.driver.set_page_load_timeout(15)
            print("[+] Firefox WebDriver inicializado com sucesso")
            return True
            
        except Exception as e:
            print(f"[!] Erro ao inicializar Firefox: {e}")
        
        # Tentar Chrome como fallback
        try:
            options = ChromeOptions()
            options.add_argument('--headless')
            options.add_argument('--no-sandbox')
            options.add_argument('--disable-dev-shm-usage')
            options.add_argument('--disable-gpu')
            options.add_argument('--window-size=1920,1080')
            options.add_argument('--ignore-certificate-errors')
            options.add_argument('--ignore-ssl-errors')
            options.add_argument('--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36')
            
            if HAS_WEBDRIVER_MANAGER:
                service = ChromeService(ChromeDriverManager().install())
                self.driver = webdriver.Chrome(service=service, options=options)
            else:
                self.driver = webdriver.Chrome(options=options)
            
            self.driver.set_page_load_timeout(15)
            print("[+] Chrome WebDriver inicializado com sucesso")
            return True
            
        except Exception as e:
            print(f"[!] Erro ao inicializar Chrome: {e}")
            return False
    
    def add_url_to_screenshot(self, screenshot_path, url):
        """Adiciona a URL na parte superior da imagem"""
        try:
            img = Image.open(screenshot_path)
            
            # Criar barra superior para a URL
            bar_height = 40
            new_img = Image.new('RGB', (img.width, img.height + bar_height), color=(30, 30, 50))
            new_img.paste(img, (0, bar_height))
            
            # Adicionar texto da URL
            draw = ImageDraw.Draw(new_img)
            
            # Tentar usar fonte do sistema
            try:
                font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf", 16)
            except:
                try:
                    font = ImageFont.truetype("/usr/share/fonts/TTF/DejaVuSansMono.ttf", 16)
                except:
                    font = ImageFont.load_default()
            
            # Desenhar URL
            text_color = (0, 212, 255)  # Cyan
            draw.text((10, 10), f"URL: {url}", fill=text_color, font=font)
            
            # Salvar imagem
            new_img.save(screenshot_path)
            return True
            
        except Exception as e:
            print(f"    [!] Erro ao adicionar URL na imagem: {e}")
            return False
    
    def validate_url(self, url, asset):
        """
        Valida uma URL e captura screenshot.
        Salva se a página responde (mesmo 4xx), não salva se timeout/conexão falhou.
        """
        
        result = {
            'url': url,
            'valid': False,
            'title': '',
            'description': '',
            'screenshot': '',
            'error': '',
            'status_hint': ''
        }
        
        try:
            print(f"  [*] Testando: {url}")
            
            self.driver.get(url)
            time.sleep(2)  # Aguardar carregamento
            
            # Verificar se página carregou
            current_url = self.driver.current_url
            
            # Obter título
            title = self.driver.title or "Sem título"
            result['title'] = title[:100] if title else "Sem título"
            
            # Detectar status pelo título (4xx, 5xx são válidos - serviço existe!)
            title_lower = title.lower()
            if any(code in title_lower for code in ['404', '403', '401', '500', '502', '503']):
                result['status_hint'] = 'Página de erro HTTP (serviço existe)'
            
            # Obter descrição (meta description ou primeiro parágrafo)
            description = self._get_description()
            result['description'] = description[:300] if description else "Sem descrição disponível"
            
            # Criar diretório para o ativo
            safe_asset = re.sub(r'[^\w\-.]', '_', asset)
            asset_dir = os.path.join(self.output_dir, safe_asset)
            os.makedirs(asset_dir, exist_ok=True)
            
            # Gerar nome único para screenshot
            url_hash = hashlib.md5(url.encode()).hexdigest()[:8]
            parsed = urlparse(url)
            port = parsed.port or (443 if parsed.scheme == 'https' else 80)
            screenshot_name = f"port_{port}_{url_hash}.png"
            screenshot_path = os.path.join(asset_dir, screenshot_name)
            
            # Capturar screenshot
            self.driver.save_screenshot(screenshot_path)
            
            # Adicionar URL na imagem
            self.add_url_to_screenshot(screenshot_path, url)
            
            result['screenshot'] = screenshot_name  # Só o nome, não o caminho completo
            result['valid'] = True
            
            print(f"  [+] Válida: {title[:50]}...")
            
        except TimeoutException:
            result['error'] = "Timeout ao carregar página"
            print(f"  [-] Timeout (não salvo): {url}")
            
        except WebDriverException as e:
            error_msg = str(e)[:100]
            result['error'] = error_msg
            # Não salvar se for erro de conexão
            print(f"  [-] Erro de conexão (não salvo): {url}")
            
        except Exception as e:
            result['error'] = str(e)[:100]
            print(f"  [-] Erro inesperado (não salvo): {url}")
        
        return result
    
    def _get_description(self):
        """Extrai descrição da página"""
        
        # Tentar meta description
        try:
            meta = self.driver.find_element(By.CSS_SELECTOR, 'meta[name="description"]')
            content = meta.get_attribute('content')
            if content:
                return content.strip()
        except:
            pass
        
        # Tentar og:description
        try:
            meta = self.driver.find_element(By.CSS_SELECTOR, 'meta[property="og:description"]')
            content = meta.get_attribute('content')
            if content:
                return content.strip()
        except:
            pass
        
        # Tentar primeiro parágrafo
        try:
            paragraphs = self.driver.find_elements(By.TAG_NAME, 'p')
            for p in paragraphs[:5]:
                text = p.text.strip()
                if len(text) > 50:
                    return text
        except:
            pass
        
        # Tentar h1
        try:
            h1 = self.driver.find_element(By.TAG_NAME, 'h1')
            if h1.text:
                return f"Página: {h1.text.strip()}"
        except:
            pass
        
        return "Sem descrição disponível"
    
    def validate_data(self, data_list):
        """Valida lista de dados (hostname|ip|port)"""
        
        print(f"\n[*] Iniciando validação de {len(data_list)} entradas...\n")
        
        # Agrupar por ativo
        assets = defaultdict(list)
        for data in data_list:
            parts = data.strip().split('|')
            if len(parts) >= 3:
                hostname, ip, port = parts[0], parts[1], parts[2]
                asset = hostname if hostname else ip
                assets[asset].append((hostname, ip, port))
        
        total = 0
        for asset, entries in assets.items():
            print(f"\n[*] Ativo: {asset}")
            
            # Gerar URLs únicas para este ativo
            urls_seen = set()
            for hostname, ip, port in entries:
                target = hostname if hostname else ip
                
                if port == "80":
                    urls = [f"http://{target}"]
                elif port == "443":
                    urls = [f"https://{target}"]
                else:
                    urls = [f"http://{target}:{port}", f"https://{target}:{port}"]
                
                for url in urls:
                    if url not in urls_seen:
                        urls_seen.add(url)
                        total += 1
                        print(f"[{total}]")
                        result = self.validate_url(url, asset)
                        
                        # Só adicionar se válido (página carregou)
                        if result['valid']:
                            self.results[asset].append(result)
                        
                        time.sleep(0.5)
        
        return self.results
    
    def generate_asset_index(self, asset, results):
        """Gera index.html para um ativo específico"""
        
        safe_asset = re.sub(r'[^\w\-.]', '_', asset)
        asset_dir = os.path.join(self.output_dir, safe_asset)
        
        html = f'''<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{asset} - Bird Nmap Web Validator</title>
    <style>
        :root {{
            --bg-primary: #0f0f23;
            --bg-secondary: #1a1a2e;
            --bg-card: #16213e;
            --text-primary: #e0e0e0;
            --text-secondary: #a0a0a0;
            --accent: #00d4ff;
            --accent-hover: #00b8e6;
            --success: #00ff88;
            --border: #2d2d4a;
        }}
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            min-height: 100vh;
            padding: 20px;
        }}
        .container {{ max-width: 1400px; margin: 0 auto; }}
        header {{
            text-align: center;
            padding: 30px 20px;
            background: linear-gradient(135deg, var(--bg-secondary) 0%, var(--bg-card) 100%);
            border-radius: 16px;
            margin-bottom: 30px;
            border: 1px solid var(--border);
        }}
        h1 {{
            font-size: 2rem;
            color: var(--accent);
            margin-bottom: 10px;
        }}
        .back-link {{
            color: var(--text-secondary);
            text-decoration: none;
            display: inline-block;
            margin-bottom: 15px;
        }}
        .back-link:hover {{ color: var(--accent); }}
        .stats {{
            display: flex;
            justify-content: center;
            gap: 30px;
            margin-top: 15px;
        }}
        .stat-value {{ font-size: 1.8rem; font-weight: bold; color: var(--success); }}
        .stat-label {{ color: var(--text-secondary); font-size: 0.9rem; }}
        .grid {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(400px, 1fr));
            gap: 20px;
        }}
        .card {{
            background: var(--bg-card);
            border-radius: 12px;
            overflow: hidden;
            border: 1px solid var(--border);
            transition: transform 0.3s, box-shadow 0.3s;
        }}
        .card:hover {{
            transform: translateY(-5px);
            box-shadow: 0 10px 30px rgba(0, 212, 255, 0.1);
        }}
        .card-image {{
            width: 100%;
            height: 280px;
            object-fit: cover;
            object-position: top;
            border-bottom: 1px solid var(--border);
            cursor: pointer;
        }}
        .card-content {{ padding: 20px; }}
        .card-title {{
            font-size: 1.1rem;
            margin-bottom: 10px;
            color: var(--text-primary);
            word-break: break-word;
        }}
        .card-url {{
            color: var(--accent);
            text-decoration: none;
            font-size: 0.9rem;
            word-break: break-all;
            display: block;
            margin-bottom: 10px;
        }}
        .card-url:hover {{ color: var(--accent-hover); text-decoration: underline; }}
        .card-description {{
            color: var(--text-secondary);
            font-size: 0.9rem;
            line-height: 1.5;
        }}
        .status-hint {{
            background: var(--bg-secondary);
            color: #ffaa00;
            padding: 5px 10px;
            border-radius: 5px;
            font-size: 0.8rem;
            margin-top: 10px;
            display: inline-block;
        }}
        .modal {{
            display: none;
            position: fixed;
            top: 0; left: 0;
            width: 100%; height: 100%;
            background: rgba(0, 0, 0, 0.9);
            z-index: 1000;
            justify-content: center;
            align-items: center;
        }}
        .modal.active {{ display: flex; }}
        .modal img {{ max-width: 95%; max-height: 95%; border-radius: 8px; }}
        .modal-close {{
            position: absolute;
            top: 20px; right: 30px;
            font-size: 2rem;
            color: white;
            cursor: pointer;
        }}
        footer {{
            text-align: center;
            padding: 30px;
            color: var(--text-secondary);
            font-size: 0.9rem;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <a href="../index.html" class="back-link">← Voltar ao índice</a>
            <h1>🖥️ {asset}</h1>
            <div class="stats">
                <div>
                    <div class="stat-value">{len(results)}</div>
                    <div class="stat-label">Páginas Encontradas</div>
                </div>
            </div>
        </header>
        
        <div class="grid">
'''
        
        for result in results:
            status_html = ""
            if result.get('status_hint'):
                status_html = f'<span class="status-hint">⚠️ {result["status_hint"]}</span>'
            
            html += f'''
            <div class="card">
                <img src="{result['screenshot']}" alt="{result['title']}" class="card-image" onclick="openModal(this.src)">
                <div class="card-content">
                    <h3 class="card-title">{result['title']}</h3>
                    <a href="{result['url']}" target="_blank" class="card-url">{result['url']}</a>
                    <p class="card-description">{result['description']}</p>
                    {status_html}
                </div>
            </div>
'''
        
        html += f'''
        </div>
        
        <footer>
            <p>Gerado em {datetime.now().strftime("%d/%m/%Y às %H:%M:%S")}</p>
            <p>Bird Nmap Web Validator</p>
        </footer>
    </div>
    
    <div class="modal" id="imageModal" onclick="closeModal()">
        <span class="modal-close">&times;</span>
        <img src="" alt="Screenshot ampliado" id="modalImage">
    </div>
    
    <script>
        function openModal(src) {{
            document.getElementById('modalImage').src = src;
            document.getElementById('imageModal').classList.add('active');
        }}
        function closeModal() {{
            document.getElementById('imageModal').classList.remove('active');
        }}
        document.addEventListener('keydown', function(e) {{
            if (e.key === 'Escape') closeModal();
        }});
    </script>
</body>
</html>
'''
        
        # Salvar index do ativo
        index_path = os.path.join(asset_dir, 'index.html')
        with open(index_path, 'w', encoding='utf-8') as f:
            f.write(html)
        
        # Salvar metadata JSON para o master index
        metadata = {
            'asset': asset,
            'count': len(results),
            'updated': datetime.now().isoformat(),
            'pages': [{'url': r['url'], 'title': r['title']} for r in results]
        }
        metadata_path = os.path.join(asset_dir, 'metadata.json')
        with open(metadata_path, 'w', encoding='utf-8') as f:
            json.dump(metadata, f, ensure_ascii=False, indent=2)
        
        return index_path
    
    def generate_master_index(self):
        """Gera index.html master ESTÁTICO com todos os dados embutidos"""
        
        # Calcular totais
        total_assets = len(self.results)
        total_pages = sum(len(results) for results in self.results.values())
        
        html = f'''<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Bird Nmap Web Validator - Master Index</title>
    <style>
        :root {{
            --bg-primary: #0f0f23;
            --bg-secondary: #1a1a2e;
            --bg-card: #16213e;
            --text-primary: #e0e0e0;
            --text-secondary: #a0a0a0;
            --accent: #00d4ff;
            --accent-hover: #00b8e6;
            --success: #00ff88;
            --border: #2d2d4a;
        }}
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            min-height: 100vh;
            padding: 20px;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        header {{
            text-align: center;
            padding: 40px 20px;
            background: linear-gradient(135deg, var(--bg-secondary) 0%, var(--bg-card) 100%);
            border-radius: 16px;
            margin-bottom: 30px;
            border: 1px solid var(--border);
        }}
        h1 {{
            font-size: 2.5rem;
            background: linear-gradient(90deg, var(--accent), var(--success));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            margin-bottom: 10px;
        }}
        .subtitle {{ color: var(--text-secondary); font-size: 1.1rem; }}
        .stats {{
            display: flex;
            justify-content: center;
            gap: 40px;
            margin-top: 20px;
        }}
        .stat-value {{ font-size: 2rem; font-weight: bold; color: var(--success); }}
        .stat-label {{ color: var(--text-secondary); font-size: 0.9rem; }}
        .assets-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(350px, 1fr));
            gap: 20px;
        }}
        .asset-card {{
            background: var(--bg-card);
            border-radius: 12px;
            padding: 25px;
            border: 1px solid var(--border);
            transition: transform 0.3s, box-shadow 0.3s;
            text-decoration: none;
            display: block;
        }}
        .asset-card:hover {{
            transform: translateY(-5px);
            box-shadow: 0 10px 30px rgba(0, 212, 255, 0.15);
        }}
        .asset-name {{
            font-size: 1.3rem;
            color: var(--accent);
            margin-bottom: 10px;
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        .asset-count {{
            background: var(--success);
            color: var(--bg-primary);
            padding: 3px 10px;
            border-radius: 15px;
            font-size: 0.85rem;
            font-weight: bold;
        }}
        .asset-pages {{
            color: var(--text-secondary);
            font-size: 0.9rem;
            margin-top: 10px;
        }}
        .asset-pages li {{
            margin: 5px 0;
            list-style: none;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }}
        .no-assets {{
            text-align: center;
            padding: 50px;
            color: var(--text-secondary);
            background: var(--bg-secondary);
            border-radius: 12px;
        }}
        footer {{
            text-align: center;
            padding: 30px;
            color: var(--text-secondary);
            font-size: 0.9rem;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🐦 Bird Nmap Web Validator</h1>
            <p class="subtitle">Relatório de Páginas Web Encontradas</p>
            <div class="stats">
                <div>
                    <div class="stat-value">{total_assets}</div>
                    <div class="stat-label">Ativos</div>
                </div>
                <div>
                    <div class="stat-value">{total_pages}</div>
                    <div class="stat-label">Páginas</div>
                </div>
            </div>
        </header>
        
        <div class="assets-grid">
'''
        
        # Gerar cards para cada ativo
        for asset in sorted(self.results.keys()):
            results = self.results[asset]
            safe_asset = re.sub(r'[^\w\-.]', '_', asset)
            
            # Criar lista de páginas para preview
            pages_html = ""
            pages_to_show = results[:3]
            for r in pages_to_show:
                title = r['title'][:40] + "..." if len(r['title']) > 40 else r['title']
                pages_html += f"<li>📄 {title}</li>\n"
            
            if len(results) > 3:
                pages_html += f"<li>... e mais {len(results) - 3}</li>\n"
            
            html += f'''
            <a href="{safe_asset}/index.html" class="asset-card">
                <div class="asset-name">
                    🖥️ {asset}
                    <span class="asset-count">{len(results)} páginas</span>
                </div>
                <ul class="asset-pages">
                    {pages_html}
                </ul>
            </a>
'''
        
        html += f'''
        </div>
        
        <footer>
            <p>Gerado em {datetime.now().strftime("%d/%m/%Y às %H:%M:%S")}</p>
            <p>Bird Nmap Web Validator</p>
        </footer>
    </div>
</body>
</html>
'''
        
        # Salvar master index
        master_path = os.path.join(self.output_dir, 'index.html')
        with open(master_path, 'w', encoding='utf-8') as f:
            f.write(html)
        
        print(f"\n[+] Master index salvo em: {master_path}")
        return master_path
    
    def generate_reports(self):
        """Gera todos os relatórios (index por ativo + master)"""
        
        if not self.results:
            print("\n[!] Nenhuma página válida encontrada")
            return None
        
        # Gerar index para cada ativo
        for asset, results in self.results.items():
            asset_index = self.generate_asset_index(asset, results)
            print(f"[+] Index do ativo '{asset}' salvo")
        
        # Gerar master index
        master_path = self.generate_master_index()
        
        return master_path
    
    def close(self):
        """Fecha o WebDriver"""
        if self.driver:
            self.driver.quit()


def main():
    if len(sys.argv) < 2:
        print("Uso: python3 selenium_validator.py <arquivo-dados>")
        print("Formato do arquivo: hostname|ip|porta (uma por linha)")
        sys.exit(1)
    
    data_file = sys.argv[1]
    
    if not os.path.exists(data_file):
        print(f"[ERRO] Arquivo não encontrado: {data_file}")
        sys.exit(1)
    
    # Ler dados
    with open(data_file, 'r') as f:
        data_list = [line.strip() for line in f if line.strip() and '|' in line]
    
    if not data_list:
        print("[ERRO] Nenhum dado encontrado no arquivo")
        sys.exit(1)
    
    # Inicializar validador
    validator = SeleniumValidator()
    
    if not validator.init_driver():
        print("[ERRO] Não foi possível inicializar o WebDriver")
        print("[INFO] Instale Firefox ou Chrome com os respectivos drivers")
        sys.exit(1)
    
    try:
        # Validar dados
        validator.validate_data(data_list)
        
        # Gerar relatórios
        validator.generate_reports()
        
        # Estatísticas
        total_valid = sum(len(results) for results in validator.results.values())
        print(f"\n[*] Resumo:")
        print(f"    - Ativos com páginas: {len(validator.results)}")
        print(f"    - Total de páginas: {total_valid}")
        
    finally:
        validator.close()


if __name__ == '__main__':
    main()
