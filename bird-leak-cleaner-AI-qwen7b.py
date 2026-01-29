#!/usr/bin/env python3
"""
Bird Leak Cleaner - Parser robusto de dados vazados usando Ollama/DeepSeek-R1

Este script processa arquivos de dados vazados (ULP - URL, Login, Password)
usando IA para identificar e separar os campos corretamente.

Uso:
    bird-leak-cleaner.py -f <arquivo_entrada> -o <arquivo_saida.csv>
"""

import argparse
import csv
import json
import os
import re
import sys
import time
from pathlib import Path
from typing import Optional

try:
    import requests
except ImportError:
    print("Erro: módulo 'requests' não encontrado. Instale com: pip install requests")
    sys.exit(1)


# Configurações
OLLAMA_API_URL = "http://localhost:11434/api/generate"
MODEL_NAME = "qwen2.5:7b"
BATCH_SIZE = 5  # Linhas por batch (menor para melhor precisão)
REQUEST_TIMEOUT = 600  # Segundos (DeepSeek-R1 precisa de mais tempo para "pensar")


def create_prompt(lines: list[str]) -> str:
    """Cria o prompt para o modelo LLM - MODO SIMPLES."""
    lines_text = "\n".join([f"{i+1}. {line}" for i, line in enumerate(lines)])
    
    prompt = f"""Separe URL, Login e Senha de cada linha abaixo.

LINHAS:
{lines_text}

Responda APENAS com JSON:
[
  {{"line": 1, "url": "", "login": "", "password": ""}},
  ...
]
"""
    return prompt


def query_ollama(prompt: str) -> Optional[str]:
    """Envia prompt ao Ollama e retorna a resposta."""
    payload = {
        "model": MODEL_NAME,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0.1,  # Baixa temperatura para respostas consistentes
            "num_predict": 2048,  # Reduzido para respostas mais rápidas
            "num_gpu": 999,       # Usar todas as camadas na GPU (máxima aceleração)
            "num_ctx": 4096,      # Contexto otimizado
            "num_batch": 1024,    # Batch maior = mais rápido na GPU
            "main_gpu": 0,        # Usar GPU 0 (RTX 4070)
        }
    }
    
    try:
        response = requests.post(
            OLLAMA_API_URL,
            json=payload,
            timeout=REQUEST_TIMEOUT
        )
        response.raise_for_status()
        result = response.json()
        return result.get("response", "")
    except requests.exceptions.ConnectionError:
        print("\nErro: Não foi possível conectar ao Ollama. Verifique se está rodando.")
        print("Execute: ollama serve")
        sys.exit(1)
    except requests.exceptions.Timeout:
        print(f"\nAviso: Timeout na requisição (>{REQUEST_TIMEOUT}s)")
        return None
    except Exception as e:
        print(f"\nErro na requisição: {e}")
        return None


def extract_json_from_response(response: str) -> Optional[list]:
    """Extrai JSON da resposta do modelo, lidando com texto extra."""
    if not response:
        return None
    
    # Remove tags de pensamento <think>...</think> se presentes
    response = re.sub(r'<think>.*?</think>', '', response, flags=re.DOTALL)
    
    # Tenta encontrar JSON array na resposta
    json_match = re.search(r'\[[\s\S]*\]', response)
    if json_match:
        try:
            return json.loads(json_match.group())
        except json.JSONDecodeError:
            pass
    
    # Tenta parsear resposta completa
    try:
        return json.loads(response.strip())
    except json.JSONDecodeError:
        return None


def validate_result(result: dict) -> bool:
    """Valida se o resultado tem campos mínimos necessários."""
    # Pelo menos login OU url devem estar presentes
    has_login = bool(result.get("login", "").strip())
    has_url = bool(result.get("url", "").strip())
    return has_login or has_url


def fallback_parse(line: str) -> dict:
    """
    Parser de fallback quando a IA falha - faz separação forçada.
    """
    line = line.strip()
    result = {"url": "", "login": "", "password": ""}
    
    if not line:
        return result
    
    # Tenta identificar separador predominante
    separators = ['|', ';', '\t', ' ', ':']
    parts = []
    
    for sep in separators:
        if sep in line:
            # Para ':', cuidado com URLs (http:// ou porta)
            if sep == ':':
                # Remove URLs temporariamente
                url_pattern = r'https?://[^\s|;]+'
                urls = re.findall(url_pattern, line)
                temp_line = re.sub(url_pattern, '<<<URL>>>', line)
                parts = [p.strip() for p in temp_line.split(sep) if p.strip()]
                # Restaura URLs
                for i, part in enumerate(parts):
                    if '<<<URL>>>' in part:
                        parts[i] = urls.pop(0) if urls else part.replace('<<<URL>>>', '')
            else:
                parts = [p.strip() for p in line.split(sep) if p.strip()]
            
            if len(parts) >= 2:
                break
    
    if not parts:
        parts = [line]
    
    # Identifica cada parte
    url_found = ""
    login_found = ""
    password_found = ""
    remaining = []
    
    for part in parts:
        # É URL?
        if re.match(r'https?://', part, re.I) or re.match(r'^[a-zA-Z0-9][a-zA-Z0-9.-]+\.(com|br|net|org|io|gov|edu|info|biz|co)(?:[:/]|$)', part, re.I):
            if not url_found:
                url_found = part
                continue
        # É email/login?
        if '@' in part and not url_found:
            if not login_found:
                login_found = part
                continue
        remaining.append(part)
    
    # Distribui o que sobrou
    if remaining:
        if not login_found:
            login_found = remaining.pop(0) if remaining else ""
        if not password_found and remaining:
            password_found = remaining.pop(0)
        # Se ainda sobrou, concatena na senha
        if remaining:
            password_found = password_found + ":" + ":".join(remaining) if password_found else ":".join(remaining)
    
    return {"url": url_found, "login": login_found, "password": password_found}


def process_batch(lines: list[str], line_offset: int) -> list[dict]:
    """
    Processa um batch de linhas - MODO FORÇADO (sem out-of-pattern).
    Retorna: lista de resultados (sempre retorna algo para cada linha)
    """
    results = []
    
    prompt = create_prompt(lines)
    response = query_ollama(prompt)
    
    # Tenta processar resposta da IA
    parsed = None
    if response:
        parsed = extract_json_from_response(response)
    
    # Mapeia resultados por número da linha
    results_map = {}
    if parsed:
        for item in parsed:
            if isinstance(item, dict) and "line" in item:
                results_map[item["line"]] = item
    
    # Processa cada linha - SEMPRE retorna algo
    for i, line in enumerate(lines):
        line_num = i + 1
        result = results_map.get(line_num)
        
        if result and validate_result(result):
            # IA conseguiu extrair
            results.append({
                "url": result.get("url", "").strip(),
                "login": result.get("login", "").strip(),
                "password": result.get("password", "").strip()
            })
        else:
            # Fallback: parsing forçado
            fallback = fallback_parse(line)
            results.append(fallback)
    
    return results


def process_file(input_file: str, output_file: str, batch_size: int = 5):
    """Processa o arquivo de entrada completo - MODO FORÇADO."""
    
    # Lê todas as linhas
    with open(input_file, 'r', encoding='utf-8', errors='ignore') as f:
        lines = [line.strip() for line in f.readlines()]
    
    # Remove linhas vazias
    lines = [(i, line) for i, line in enumerate(lines, 1) if line]
    total_lines = len(lines)
    
    print(f"\n📁 Arquivo: {input_file}")
    print(f"📊 Total de linhas: {total_lines}")
    print(f"📦 Tamanho do batch: {batch_size}")
    print(f"🤖 Modelo: {MODEL_NAME}")
    print(f"🔧 Modo: EXTRAÇÃO FORÇADA (sem out-of-pattern)")
    print(f"\n⏳ Processando...\n")
    
    all_results = []
    processed = 0
    ai_parsed = 0
    fallback_parsed = 0
    
    # Processa em batches
    for i in range(0, len(lines), batch_size):
        batch_lines_with_idx = lines[i:i + batch_size]
        batch_lines = [line for _, line in batch_lines_with_idx]
        batch_offset = batch_lines_with_idx[0][0] - 1
        
        results = process_batch(batch_lines, batch_offset)
        
        # Conta quantos foram parseados pela IA vs fallback
        for r in results:
            if r.get("url") or r.get("login") or r.get("password"):
                all_results.append(r)
        
        processed += len(batch_lines)
        progress = (processed / total_lines) * 100
        print(f"\r  Progresso: {processed}/{total_lines} ({progress:.1f}%) | Extraídos: {len(all_results)}", end="", flush=True)
        
        time.sleep(0.3)
    
    print("\n")
    
    # Salva resultados CSV
    with open(output_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=['url', 'login', 'password'])
        writer.writeheader()
        writer.writerows(all_results)
    
    # Estatísticas finais
    print("=" * 50)
    print("📊 RESULTADO FINAL")
    print("=" * 50)
    print(f"  📥 Linhas processadas: {total_lines}")
    print(f"  ✅ Registros extraídos: {len(all_results)}")
    print(f"  📁 Output CSV: {output_file}")
    print("=" * 50)


def main():
    parser = argparse.ArgumentParser(
        description="Bird Leak Cleaner - Parser de dados vazados usando Ollama",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos:
  bird-leak-cleaner.py -f dados.txt -o resultado.csv
  bird-leak-cleaner.py -f leak.txt
        """
    )
    
    parser.add_argument(
        '-f', '--file',
        required=True,
        help='Arquivo de entrada com dados vazados'
    )
    
    parser.add_argument(
        '-o', '--output',
        default=None,
        help='Arquivo CSV de saída (padrão: <input>_cleaned.csv)'
    )
    
    parser.add_argument(
        '--batch-size',
        type=int,
        default=BATCH_SIZE,
        help=f'Número de linhas por batch (padrão: {BATCH_SIZE})'
    )
    
    args = parser.parse_args()
    
    # Valida arquivo de entrada
    if not os.path.isfile(args.file):
        print(f"Erro: Arquivo não encontrado: {args.file}")
        sys.exit(1)
    
    # Define arquivo de saída
    input_path = Path(args.file)
    if args.output:
        output_file = args.output
    else:
        output_file = str(input_path.stem) + "_cleaned.csv"
    
    # Atualiza batch size se especificado
    batch_size = args.batch_size
    
    # Processa (sem out-of-pattern)
    process_file(args.file, output_file, batch_size)


if __name__ == "__main__":
    main()
