#!/usr/bin/env python3
"""Analisa XML do Nmap e gera um relatório HTML interativo da superfície de ataque."""

import argparse
import ipaddress
import json
import os
import re
import sys
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from datetime import datetime
from html import escape


SEVERITY_ORDER = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1, "none": 0}
SEVERITY_LABELS = {
    "critical": "Crítica",
    "high": "Alta",
    "medium": "Média",
    "low": "Baixa",
    "info": "Informativa",
    "none": "Sem achados",
}
SENSITIVE_PORTS = {
    "21": "FTP",
    "22": "SSH",
    "23": "Telnet",
    "25": "SMTP",
    "53": "DNS",
    "110": "POP3",
    "111": "RPC",
    "135": "MSRPC",
    "139": "NetBIOS",
    "445": "SMB",
    "1433": "MSSQL",
    "1521": "Oracle",
    "2049": "NFS",
    "2375": "Docker API",
    "3306": "MySQL",
    "3389": "RDP",
    "5432": "PostgreSQL",
    "5900": "VNC",
    "6379": "Redis",
    "9200": "Elasticsearch",
    "11211": "Memcached",
    "27017": "MongoDB",
}


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="color-scheme" content="dark">
    <meta name="description" content="Relatório técnico de superfície de ataque gerado a partir de XML do Nmap">
    <title>Attack Surface Intelligence | XPLOIT OPS</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Urbanist:wght@500;600;700;800;900&family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600;700&display=swap" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.7/dist/chart.umd.min.js"></script>
    <style>
        :root {
            --bg: #0f172a;
            --bg-deep: #020617;
            --panel: rgba(30, 41, 59, 0.64);
            --panel-solid: #172033;
            --panel-hover: rgba(30, 41, 59, 0.86);
            --line: rgba(255, 255, 255, 0.10);
            --line-strong: rgba(56, 189, 248, 0.28);
            --text: #ffffff;
            --text-soft: #cbd5e1;
            --muted: #94a3b8;
            --faint: #64748b;
            --red: #ef4444;
            --red-dark: #dc2626;
            --blue: #38bdf8;
            --blue-dark: #3b82f6;
            --green: #10b981;
            --amber: #fbbf24;
            --orange: #f97316;
            --purple: #a78bfa;
            --radius: 10px;
            --font-display: "Urbanist", system-ui, sans-serif;
            --font-body: "Inter", system-ui, sans-serif;
            --font-mono: "JetBrains Mono", ui-monospace, monospace;
        }

        * { box-sizing: border-box; }
        html { scroll-behavior: smooth; }
        body {
            margin: 0;
            min-width: 320px;
            background: var(--bg);
            color: var(--text);
            font-family: var(--font-body);
            line-height: 1.55;
            -webkit-font-smoothing: antialiased;
        }
        body::before {
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
        }
        button, input, select { font: inherit; }
        button { color: inherit; }
        .shell {
            width: min(1520px, calc(100% - 40px));
            margin: 0 auto;
            padding: 28px 0 72px;
            position: relative;
        }
        .topbar {
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 18px;
            padding: 4px 0 24px;
        }
        .brand {
            display: flex;
            align-items: center;
            gap: 12px;
            font-family: var(--font-display);
            letter-spacing: .12em;
            font-weight: 900;
        }
        .brand-mark {
            color: var(--red);
            font: 800 1.35rem var(--font-mono);
            letter-spacing: -.12em;
        }
        .brand-name { font-size: 1.08rem; }
        .brand-name span { color: var(--text-soft); font-weight: 600; }
        .report-id {
            color: var(--muted);
            font: 500 .72rem var(--font-mono);
            text-transform: uppercase;
            letter-spacing: .11em;
        }

        .hero {
            overflow: hidden;
            position: relative;
            border: 1px solid var(--line);
            background: linear-gradient(135deg, rgba(30,41,59,.88), rgba(15,23,42,.76));
            border-radius: 14px;
            padding: clamp(28px, 5vw, 58px);
            box-shadow: 0 26px 70px rgba(2, 6, 23, .34);
        }
        .hero::before {
            content: "";
            position: absolute;
            inset: 0 auto auto 0;
            width: 100%;
            height: 2px;
            background: linear-gradient(90deg, var(--red), var(--blue), transparent 76%);
        }
        .hero::after {
            content: "";
            position: absolute;
            width: 480px;
            height: 480px;
            right: -240px;
            top: -260px;
            border-radius: 50%;
            background: rgba(56, 189, 248, .08);
            filter: blur(10px);
        }
        .eyebrow {
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
        }
        .eyebrow strong { color: var(--red); }
        .hero h1 {
            max-width: 900px;
            margin: 0;
            font: 800 clamp(2.25rem, 5vw, 4.7rem)/.98 var(--font-display);
            letter-spacing: -.035em;
        }
        .hero h1 span { display: block; color: var(--red); }
        .hero-copy {
            max-width: 790px;
            color: var(--text-soft);
            font: 500 1rem/1.8 var(--font-mono);
            margin: 24px 0 0;
        }
        .scan-meta {
            display: grid;
            grid-template-columns: repeat(4, minmax(0, 1fr));
            gap: 1px;
            margin-top: 34px;
            border: 1px solid var(--line);
            background: var(--line);
            border-radius: 8px;
            overflow: hidden;
        }
        .meta-item { padding: 15px 17px; background: rgba(2,6,23,.56); min-width: 0; }
        .meta-label {
            display: block;
            margin-bottom: 6px;
            color: var(--faint);
            font: 600 .66rem var(--font-mono);
            text-transform: uppercase;
            letter-spacing: .1em;
        }
        .meta-value {
            display: block;
            overflow: hidden;
            color: var(--text-soft);
            font: 600 .8rem var(--font-mono);
            text-overflow: ellipsis;
            white-space: nowrap;
        }
        details.command {
            margin-top: 13px;
            border: 1px solid var(--line);
            border-radius: 7px;
            background: rgba(2,6,23,.62);
        }
        details.command summary {
            cursor: pointer;
            padding: 12px 16px;
            color: var(--blue);
            font: 600 .75rem var(--font-mono);
        }
        .command pre {
            margin: 0;
            padding: 0 16px 16px;
            color: var(--text-soft);
            font: 500 .74rem/1.65 var(--font-mono);
            white-space: pre-wrap;
            word-break: break-word;
        }

        .section { margin-top: 52px; scroll-margin-top: 18px; }
        .section-head {
            display: flex;
            justify-content: space-between;
            align-items: end;
            gap: 24px;
            margin-bottom: 18px;
        }
        .section-kicker {
            color: var(--red);
            font: 700 .7rem var(--font-mono);
            text-transform: uppercase;
            letter-spacing: .13em;
        }
        .section h2 {
            margin: 5px 0 0;
            font: 800 clamp(1.65rem, 3vw, 2.45rem) var(--font-display);
            letter-spacing: -.02em;
        }
        .section-description { max-width: 610px; margin: 0; color: var(--muted); font-size: .9rem; }

        .executive-grid {
            display: grid;
            grid-template-columns: minmax(300px, .82fr) minmax(0, 2fr);
            gap: 18px;
        }
        .risk-panel, .panel, .metric, .chart-panel, .table-panel {
            border: 1px solid var(--line);
            border-radius: var(--radius);
            background: var(--panel);
            backdrop-filter: blur(5px);
        }
        .risk-panel {
            padding: 25px;
            display: grid;
            align-content: space-between;
            min-height: 280px;
        }
        .risk-top { display: flex; align-items: center; gap: 22px; }
        .risk-ring {
            --score: 0;
            width: 112px;
            aspect-ratio: 1;
            border-radius: 50%;
            display: grid;
            place-items: center;
            flex: 0 0 auto;
            background: conic-gradient(var(--risk-color, var(--red)) calc(var(--score) * 1%), rgba(255,255,255,.07) 0);
            position: relative;
        }
        .risk-ring::before { content: ""; position: absolute; inset: 9px; border-radius: 50%; background: #111b2e; }
        .risk-ring strong { z-index: 1; font: 800 1.8rem var(--font-display); }
        .risk-label { margin: 0; font: 800 1.55rem var(--font-display); }
        .risk-caption { margin: 4px 0 0; color: var(--muted); font: 500 .72rem var(--font-mono); }
        .risk-reason { margin: 22px 0 0; color: var(--text-soft); font-size: .86rem; }
        .confidence-note {
            margin-top: 18px;
            padding: 12px 14px;
            border-left: 2px solid var(--blue);
            background: rgba(56,189,248,.07);
            color: var(--muted);
            font-size: .77rem;
        }
        .metrics-grid {
            display: grid;
            grid-template-columns: repeat(3, minmax(0, 1fr));
            gap: 12px;
        }
        .metric { padding: 19px; transition: border-color .2s, transform .2s; }
        .metric:hover { border-color: rgba(56,189,248,.34); transform: translateY(-2px); }
        .metric-label { color: var(--muted); font: 600 .68rem var(--font-mono); text-transform: uppercase; letter-spacing: .08em; }
        .metric-value { margin-top: 9px; font: 800 2rem var(--font-display); }
        .metric-value.red { color: var(--red); }
        .metric-value.blue { color: var(--blue); }
        .metric-value.green { color: var(--green); }
        .metric-detail { margin-top: 4px; color: var(--faint); font-size: .73rem; }

        .priority-grid, .charts-grid {
            display: grid;
            grid-template-columns: repeat(2, minmax(0, 1fr));
            gap: 18px;
        }
        .panel, .chart-panel { padding: 22px; min-width: 0; }
        .panel h3, .chart-panel h3 {
            margin: 0;
            font: 750 1.1rem var(--font-display);
        }
        .panel-subtitle, .chart-subtitle { margin: 5px 0 18px; color: var(--faint); font-size: .76rem; }
        .finding-list, .insight-list { list-style: none; margin: 0; padding: 0; }
        .finding-item, .insight-item {
            display: grid;
            grid-template-columns: minmax(0, 1fr) auto;
            gap: 14px;
            align-items: center;
            padding: 12px 0;
            border-top: 1px solid var(--line);
        }
        .finding-item:first-child, .insight-item:first-child { border-top: 0; padding-top: 0; }
        .finding-button, .insight-button {
            border: 0;
            padding: 0;
            text-align: left;
            background: transparent;
            cursor: pointer;
            min-width: 0;
        }
        .finding-id { color: var(--text); font: 700 .78rem var(--font-mono); }
        .finding-target { margin-top: 4px; color: var(--faint); font-size: .73rem; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
        .insight-title { color: var(--text-soft); font-size: .82rem; font-weight: 650; }
        .insight-detail { margin-top: 3px; color: var(--faint); font-size: .72rem; }
        .pill, .severity {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            min-height: 25px;
            padding: 4px 8px;
            border: 1px solid var(--line);
            border-radius: 4px;
            font: 700 .65rem var(--font-mono);
            white-space: nowrap;
        }
        .severity-critical { color: #fecaca; background: rgba(239,68,68,.16); border-color: rgba(239,68,68,.35); }
        .severity-high { color: #fed7aa; background: rgba(249,115,22,.14); border-color: rgba(249,115,22,.34); }
        .severity-medium { color: #fde68a; background: rgba(251,191,36,.12); border-color: rgba(251,191,36,.3); }
        .severity-low { color: #a7f3d0; background: rgba(16,185,129,.12); border-color: rgba(16,185,129,.3); }
        .severity-info, .severity-none { color: #bae6fd; background: rgba(56,189,248,.1); border-color: rgba(56,189,248,.25); }
        .empty-state { color: var(--faint); font: 500 .78rem var(--font-mono); }

        .charts-grid { margin-top: 18px; }
        .chart-panel.wide { grid-column: 1 / -1; }
        .chart-wrap { position: relative; height: 310px; }
        .chart-panel.wide .chart-wrap { height: 340px; }
        .chart-fallback { display: none; color: var(--amber); font: 600 .76rem var(--font-mono); }
        .chart-panel.chart-unavailable canvas { display: none; }
        .chart-panel.chart-unavailable .chart-fallback { display: block; padding: 36px 0; }
        .legend-note { margin: 11px 0 0; color: var(--faint); font: 500 .68rem var(--font-mono); }

        .table-panel { overflow: hidden; }
        .table-header { padding: 22px 22px 0; }
        .table-header h3 { margin: 0; font: 750 1.18rem var(--font-display); }
        .filterbar {
            display: grid;
            grid-template-columns: minmax(220px, 1.5fr) repeat(4, minmax(130px, .65fr)) auto;
            gap: 9px;
            margin-top: 16px;
        }
        .filterbar.finding-filters { grid-template-columns: minmax(220px, 1.4fr) repeat(3, minmax(145px, .65fr)) auto; }
        .control {
            width: 100%;
            min-height: 40px;
            padding: 9px 11px;
            border: 1px solid var(--line);
            border-radius: 4px;
            outline: none;
            background: rgba(2,6,23,.56);
            color: var(--text-soft);
            font: 500 .72rem var(--font-mono);
            transition: border-color .2s, box-shadow .2s;
        }
        .control:focus { border-color: var(--blue); box-shadow: 0 0 0 3px rgba(56,189,248,.09); }
        .control::placeholder { color: var(--faint); }
        select.control option { background: #111827; }
        .button-group { display: flex; gap: 7px; }
        .btn {
            min-height: 40px;
            padding: 9px 12px;
            border: 1px solid var(--line);
            border-radius: 3px;
            background: transparent;
            color: var(--text-soft);
            cursor: pointer;
            font: 700 .67rem var(--font-mono);
            text-transform: uppercase;
            letter-spacing: .04em;
            transition: .2s;
        }
        .btn:hover { border-color: var(--blue); color: var(--blue); background: rgba(56,189,248,.07); }
        .btn-primary { border-color: rgba(239,68,68,.45); background: var(--red); color: white; }
        .btn-primary:hover { border-color: var(--red-dark); background: var(--red-dark); color: white; }
        .table-status {
            display: flex;
            justify-content: space-between;
            gap: 20px;
            padding: 13px 22px;
            color: var(--faint);
            font: 500 .68rem var(--font-mono);
        }
        .active-filters { color: var(--blue); text-align: right; }
        .table-scroll { overflow: auto; max-height: 680px; border-top: 1px solid var(--line); }
        table { width: 100%; border-collapse: collapse; font-size: .76rem; }
        th {
            position: sticky;
            top: 0;
            z-index: 2;
            padding: 12px 14px;
            border-bottom: 1px solid var(--line);
            background: #111b2e;
            color: var(--muted);
            font: 700 .65rem var(--font-mono);
            text-align: left;
            text-transform: uppercase;
            letter-spacing: .065em;
            white-space: nowrap;
        }
        th.sortable { cursor: pointer; }
        th.sortable:hover { color: var(--blue); }
        th.sort-asc::after { content: "  ↑"; color: var(--blue); }
        th.sort-desc::after { content: "  ↓"; color: var(--blue); }
        td { padding: 12px 14px; border-bottom: 1px solid rgba(255,255,255,.055); color: var(--text-soft); vertical-align: top; }
        tbody tr { transition: background .15s; }
        tbody tr:hover { background: rgba(56,189,248,.045); }
        .mono { font-family: var(--font-mono); }
        .strong { color: var(--text); font-weight: 700; }
        .muted { color: var(--faint); }
        .nowrap { white-space: nowrap; }
        .port-tags { display: flex; flex-wrap: wrap; gap: 5px; max-width: 330px; }
        .port-tag {
            border: 1px solid rgba(56,189,248,.23);
            border-radius: 3px;
            padding: 3px 6px;
            background: rgba(56,189,248,.07);
            color: var(--blue);
            cursor: pointer;
            font: 650 .66rem var(--font-mono);
        }
        .port-tag:hover { border-color: var(--blue); }
        .scope-public { color: #fecaca; }
        .scope-private { color: #a7f3d0; }
        .scope-other { color: var(--muted); }
        .hidden-row { display: none; }
        .no-results {
            display: none;
            padding: 26px;
            border-top: 1px solid var(--line);
            color: var(--faint);
            text-align: center;
            font: 500 .76rem var(--font-mono);
        }
        .table-panel.is-empty .no-results { display: block; }
        .evidence {
            max-width: 430px;
            color: var(--muted);
            font-size: .71rem;
            overflow-wrap: anywhere;
        }

        .coverage-strip {
            display: grid;
            grid-template-columns: repeat(5, 1fr);
            gap: 1px;
            border: 1px solid var(--line);
            border-radius: 7px;
            background: var(--line);
            overflow: hidden;
        }
        .coverage-item { padding: 16px; background: rgba(2,6,23,.5); }
        .coverage-item strong { display: block; font: 800 1.2rem var(--font-display); }
        .coverage-item span { color: var(--faint); font: 600 .65rem var(--font-mono); text-transform: uppercase; }

        footer {
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 18px;
            margin-top: 48px;
            padding-top: 22px;
            border-top: 1px solid var(--line);
            color: var(--faint);
            font: 500 .68rem var(--font-mono);
        }
        footer a { color: var(--blue); text-decoration: none; }

        @media (max-width: 1100px) {
            .executive-grid { grid-template-columns: 1fr; }
            .filterbar, .filterbar.finding-filters { grid-template-columns: repeat(2, minmax(0,1fr)); }
            .filterbar .search-wide { grid-column: 1 / -1; }
            .button-group { grid-column: 1 / -1; }
            .scan-meta { grid-template-columns: repeat(2, 1fr); }
        }
        @media (max-width: 760px) {
            .shell { width: min(100% - 22px, 1520px); padding-top: 16px; }
            .topbar, .section-head, footer { align-items: flex-start; flex-direction: column; }
            .hero { padding: 25px 19px; }
            .scan-meta, .metrics-grid, .priority-grid, .charts-grid, .coverage-strip { grid-template-columns: 1fr; }
            .chart-panel.wide { grid-column: auto; }
            .filterbar, .filterbar.finding-filters { grid-template-columns: 1fr; }
            .filterbar .search-wide, .button-group { grid-column: auto; }
            .risk-top { align-items: flex-start; }
            .table-status { flex-direction: column; gap: 5px; }
            .active-filters { text-align: left; }
        }
        @media print {
            body { background: white; color: #111827; }
            body::before, .filterbar, .button-group, .legend-note { display: none !important; }
            .shell { width: 100%; padding: 0; }
            .hero, .risk-panel, .panel, .metric, .chart-panel, .table-panel { break-inside: avoid; background: white; color: #111827; border-color: #cbd5e1; }
            .table-scroll { max-height: none; overflow: visible; }
            th { position: static; background: #e2e8f0; color: #334155; }
            td, .hero-copy, .section-description, .metric-label, .metric-detail, .panel-subtitle { color: #334155; }
        }
    </style>
</head>
<body>
<main class="shell">
    <div class="topbar">
        <div class="brand" aria-label="Xploit Ops">
            <span class="brand-mark">&gt;X&lt;</span>
            <span class="brand-name">XPLOIT <span>OPS</span></span>
        </div>
        <div class="report-id">attack_surface // {{report_id}}</div>
    </div>

    <header class="hero">
        <div class="eyebrow"><strong>&gt;_</strong> modo_análise: concluído</div>
        <h1>Attack Surface <span>Intelligence</span></h1>
        <p class="hero-copy">Leitura técnica do inventário Nmap, com cobertura do scan, exposição por ativo e correlações de segurança separadas por nível de evidência.</p>
        <div class="scan-meta">
            <div class="meta-item"><span class="meta-label">Fonte</span><span class="meta-value" title="{{filename}}">{{filename}}</span></div>
            <div class="meta-item"><span class="meta-label">Gerado em</span><span class="meta-value">{{timestamp}}</span></div>
            <div class="meta-item"><span class="meta-label">Scanner</span><span class="meta-value">{{scanner}}</span></div>
            <div class="meta-item"><span class="meta-label">Duração / status</span><span class="meta-value">{{elapsed}} · {{scan_exit}}</span></div>
        </div>
        {{nmap_command}}
    </header>

    <section class="section" id="overview">
        <div class="section-head">
            <div><div class="section-kicker">01 // postura</div><h2>Resumo executivo</h2></div>
            <p class="section-description">Priorização baseada na severidade máxima dos achados correlacionados, densidade de portas abertas e exposição de serviços sensíveis.</p>
        </div>
        <div class="executive-grid">
            <article class="risk-panel">
                <div>
                    <div class="risk-top">
                        <div class="risk-ring" style="--score: {{risk_score}}; --risk-color: {{risk_color}}"><strong>{{risk_score}}</strong></div>
                        <div><p class="risk-label">{{risk_level}}</p><p class="risk-caption">índice de priorização / 100</p></div>
                    </div>
                    <p class="risk-reason">{{risk_reason}}</p>
                </div>
                <div class="confidence-note">Correlação de versão não equivale a vulnerabilidade confirmada. Itens do Vulners são marcados como potenciais; resultados NSE positivos aparecem separadamente.</div>
            </article>
            <div class="metrics-grid">
                <article class="metric"><div class="metric-label">Hosts ativos</div><div class="metric-value blue">{{hosts_up}}</div><div class="metric-detail">{{total_hosts}} alvos no resumo do scan</div></article>
                <article class="metric"><div class="metric-label">Hosts expostos</div><div class="metric-value red">{{hosts_exposed}}</div><div class="metric-detail">{{public_hosts}} endereços públicos</div></article>
                <article class="metric"><div class="metric-label">Endpoints abertos</div><div class="metric-value red">{{open_ports}}</div><div class="metric-detail">{{sensitive_endpoints}} em portas sensíveis</div></article>
                <article class="metric"><div class="metric-label">Serviços identificados</div><div class="metric-value green">{{unique_services}}</div><div class="metric-detail">{{unknown_services}} endpoints sem fingerprint</div></article>
                <article class="metric"><div class="metric-label">CVEs únicos correlacionados</div><div class="metric-value">{{unique_cves}}</div><div class="metric-detail">{{total_findings}} ocorrências por ativo/porta</div></article>
                <article class="metric"><div class="metric-label">Ocorrências críticas + altas</div><div class="metric-value red">{{critical_high}}</div><div class="metric-detail">{{nse_positive}} achados NSE positivos</div></article>
            </div>
        </div>
    </section>

    <section class="section" id="coverage">
        <div class="section-head">
            <div><div class="section-kicker">02 // cobertura</div><h2>Qualidade do scan</h2></div>
            <p class="section-description">{{coverage_description}}</p>
        </div>
        <div class="coverage-strip">
            <div class="coverage-item"><strong>{{ports_observed}}</strong><span>portas contabilizadas</span></div>
            <div class="coverage-item"><strong>{{open_ports}}</strong><span>abertas</span></div>
            <div class="coverage-item"><strong>{{closed_ports}}</strong><span>fechadas</span></div>
            <div class="coverage-item"><strong>{{filtered_ports}}</strong><span>filtradas</span></div>
            <div class="coverage-item"><strong>{{os_detected}}</strong><span>SO identificado</span></div>
        </div>
    </section>

    <section class="section" id="priorities">
        <div class="section-head">
            <div><div class="section-kicker">03 // prioridade</div><h2>Sinais para investigação</h2></div>
            <p class="section-description">Pontos que merecem validação manual primeiro. Clique em um item para abrir a visão detalhada já filtrada.</p>
        </div>
        <div class="priority-grid">
            <article class="panel">
                <h3>Achados de maior severidade</h3>
                <p class="panel-subtitle">Ordenados por CVSS e tipo de evidência</p>
                <ul class="finding-list">{{priority_findings}}</ul>
            </article>
            <article class="panel">
                <h3>Exposição operacional</h3>
                <p class="panel-subtitle">Serviços sensíveis, fingerprints ausentes e concentração por host</p>
                <ul class="insight-list">{{exposure_insights}}</ul>
            </article>
        </div>
    </section>

    <section class="section" id="charts">
        <div class="section-head">
            <div><div class="section-kicker">04 // telemetria</div><h2>Distribuições relevantes</h2></div>
            <p class="section-description">Os gráficos são acionáveis: clique em barras ou segmentos para aplicar o filtro correspondente nas tabelas.</p>
        </div>
        <div class="charts-grid">
            <article class="chart-panel">
                <h3>Achados por severidade</h3><p class="chart-subtitle">Ocorrências únicas por ativo, porta e identificador</p>
                <div class="chart-wrap"><canvas id="severityChart"></canvas><div class="chart-fallback">Chart.js indisponível; os dados permanecem nas tabelas.</div></div>
                <p class="legend-note">Clique para filtrar os achados.</p>
            </article>
            <article class="chart-panel">
                <h3>Estados das portas</h3><p class="chart-subtitle">Inclui extraports agregadas pelo Nmap</p>
                <div class="chart-wrap"><canvas id="statesChart"></canvas><div class="chart-fallback">Chart.js indisponível; os dados permanecem nas tabelas.</div></div>
                <p class="legend-note">Clique para filtrar portas explicitamente listadas.</p>
            </article>
            <article class="chart-panel">
                <h3>Portas abertas mais recorrentes</h3><p class="chart-subtitle">Frequência por host</p>
                <div class="chart-wrap"><canvas id="portsChart"></canvas><div class="chart-fallback">Chart.js indisponível; os dados permanecem nas tabelas.</div></div>
                <p class="legend-note">Clique em uma barra para isolar a porta.</p>
            </article>
            <article class="chart-panel">
                <h3>Serviços abertos mais comuns</h3><p class="chart-subtitle">Somente fingerprints de endpoints abertos</p>
                <div class="chart-wrap"><canvas id="servicesChart"></canvas><div class="chart-fallback">Chart.js indisponível; os dados permanecem nas tabelas.</div></div>
                <p class="legend-note">Clique em uma barra para filtrar o serviço.</p>
            </article>
            <article class="chart-panel wide">
                <h3>Hosts prioritários</h3><p class="chart-subtitle">Comparação entre endpoints abertos e índice de priorização</p>
                <div class="chart-wrap"><canvas id="hostsChart"></canvas><div class="chart-fallback">Chart.js indisponível; os dados permanecem nas tabelas.</div></div>
                <p class="legend-note">Clique em um host para abrir seu inventário.</p>
            </article>
        </div>
    </section>

    <section class="section" id="assets">
        <div class="section-head">
            <div><div class="section-kicker">05 // ativos</div><h2>Inventário de hosts</h2></div>
            <p class="section-description">Escopo, sistema operacional, exposição e concentração de achados por ativo.</p>
        </div>
        <article class="table-panel" id="hostsPanel">
            <div class="table-header">
                <h3>Hosts observados</h3>
                <div class="filterbar">
                    <input class="control search-wide" id="hostSearch" type="search" placeholder="IP, hostname, SO ou serviço...">
                    <select class="control" id="hostState"><option value="">Todos os estados</option><option value="up">Ativo</option><option value="down">Inativo</option><option value="unknown">Desconhecido</option></select>
                    <select class="control" id="hostScope"><option value="">Todo escopo</option><option value="public">Público</option><option value="private">Privado</option><option value="other">Outro</option></select>
                    <select class="control" id="hostSeverity"><option value="">Toda severidade</option><option value="critical">Crítica</option><option value="high">Alta</option><option value="medium">Média</option><option value="low">Baixa</option><option value="info">Informativa</option><option value="none">Sem achados</option></select>
                    <input class="control" id="hostMinPorts" type="number" min="0" placeholder="Mín. portas abertas">
                    <div class="button-group"><button class="btn" data-reset="hostsTable">Limpar</button><button class="btn btn-primary" data-export="hostsTable">CSV</button></div>
                </div>
            </div>
            <div class="table-status"><span id="hostsTableCount"></span><span class="active-filters" id="hostsTableActive"></span></div>
            <div class="table-scroll">
                <table id="hostsTable">
                    <thead><tr>
                        <th class="sortable" data-type="text">Ativo</th>
                        <th class="sortable" data-type="text">Estado / escopo</th>
                        <th class="sortable" data-type="number">Portas abertas</th>
                        <th class="sortable" data-type="text">Serviços</th>
                        <th class="sortable" data-type="text">Sistema operacional</th>
                        <th class="sortable" data-type="number">Achados</th>
                        <th class="sortable" data-type="number">Prioridade</th>
                    </tr></thead>
                    <tbody>{{hosts_table}}</tbody>
                </table>
            </div>
            <div class="no-results">Nenhum host corresponde aos filtros atuais.</div>
        </article>
    </section>

    <section class="section" id="ports">
        <div class="section-head">
            <div><div class="section-kicker">06 // endpoints</div><h2>Inventário de portas</h2></div>
            <p class="section-description">Portas explicitamente descritas no XML, com produto, versão e severidade máxima correlacionada.</p>
        </div>
        <article class="table-panel" id="portsPanel">
            <div class="table-header">
                <h3>Endpoints detalhados</h3>
                <div class="filterbar">
                    <input class="control search-wide" id="portSearch" type="search" placeholder="Host, produto, versão ou serviço...">
                    <input class="control" id="portExpression" placeholder="Porta: 22,80,8000-9000">
                    <input class="control" id="serviceSearch" placeholder="Serviço exato/parte">
                    <select class="control" id="portState"><option value="">Todos os estados</option>{{port_state_options}}</select>
                    <select class="control" id="portSeverity"><option value="">Toda severidade</option><option value="critical">Crítica</option><option value="high">Alta</option><option value="medium">Média</option><option value="low">Baixa</option><option value="info">Informativa</option><option value="none">Sem achados</option></select>
                    <div class="button-group"><button class="btn" data-reset="portsTable">Limpar</button><button class="btn btn-primary" data-export="portsTable">CSV</button></div>
                </div>
            </div>
            <div class="table-status"><span id="portsTableCount"></span><span class="active-filters" id="portsTableActive"></span></div>
            <div class="table-scroll">
                <table id="portsTable">
                    <thead><tr>
                        <th class="sortable" data-type="text">Host</th>
                        <th class="sortable" data-type="number">Porta</th>
                        <th class="sortable" data-type="text">Estado</th>
                        <th class="sortable" data-type="text">Serviço</th>
                        <th class="sortable" data-type="text">Produto / versão</th>
                        <th class="sortable" data-type="number">Achados</th>
                        <th class="sortable" data-type="number">CVSS máx.</th>
                    </tr></thead>
                    <tbody>{{ports_table}}</tbody>
                </table>
            </div>
            <div class="no-results">Nenhum endpoint corresponde aos filtros atuais.</div>
        </article>
    </section>

    <section class="section" id="findings">
        <div class="section-head">
            <div><div class="section-kicker">07 // correlações</div><h2>Achados de segurança</h2></div>
            <p class="section-description">CVE correlacionado por versão é hipótese de investigação; “NSE positivo” indica que um script reportou condição vulnerável sem mensagem negativa ou erro.</p>
        </div>
        <article class="table-panel" id="findingsPanel">
            <div class="table-header">
                <h3>Evidências e referências</h3>
                <div class="filterbar finding-filters">
                    <input class="control search-wide" id="findingSearch" type="search" placeholder="CVE, script, host, porta ou evidência...">
                    <select class="control" id="findingSeverity"><option value="">Toda severidade</option><option value="critical">Crítica</option><option value="high">Alta</option><option value="medium">Média</option><option value="low">Baixa</option><option value="info">Informativa</option></select>
                    <select class="control" id="findingConfidence"><option value="">Toda evidência</option><option value="correlated">Correlação de versão</option><option value="nse-positive">NSE positivo</option></select>
                    <input class="control" id="findingMinCvss" type="number" min="0" max="10" step=".1" placeholder="CVSS mínimo">
                    <div class="button-group"><button class="btn" data-reset="findingsTable">Limpar</button><button class="btn btn-primary" data-export="findingsTable">CSV</button></div>
                </div>
            </div>
            <div class="table-status"><span id="findingsTableCount"></span><span class="active-filters" id="findingsTableActive"></span></div>
            <div class="table-scroll">
                <table id="findingsTable">
                    <thead><tr>
                        <th class="sortable" data-type="text">Identificador</th>
                        <th class="sortable" data-type="number">CVSS</th>
                        <th class="sortable" data-type="text">Severidade</th>
                        <th class="sortable" data-type="text">Host / porta</th>
                        <th class="sortable" data-type="text">Evidência</th>
                        <th class="sortable" data-type="text">Origem</th>
                    </tr></thead>
                    <tbody>{{findings_table}}</tbody>
                </table>
            </div>
            <div class="no-results">Nenhum achado corresponde aos filtros atuais.</div>
        </article>
    </section>

    <footer>
        <span><span class="brand-mark">&gt;X&lt;</span> relatório técnico gerado localmente</span>
        <span>Identidade visual inspirada em <a href="https://xploitops.com" target="_blank" rel="noopener noreferrer">xploitops.com</a> · {{timestamp}}</span>
    </footer>
</main>

<script>
(function () {
    "use strict";

    const chartData = {{chart_payload}};
    const controls = {
        hostsTable: ["hostSearch", "hostState", "hostScope", "hostSeverity", "hostMinPorts"],
        portsTable: ["portSearch", "portExpression", "serviceSearch", "portState", "portSeverity"],
        findingsTable: ["findingSearch", "findingSeverity", "findingConfidence", "findingMinCvss"]
    };

    function normalize(value) {
        return String(value || "").normalize("NFD").replace(/[\\u0300-\\u036f]/g, "").toLowerCase().trim();
    }

    function visibleRows(tableId) {
        return Array.from(document.querySelectorAll("#" + tableId + " tbody tr")).filter(function (row) {
            return !row.classList.contains("hidden-row");
        });
    }

    function portMatches(value, expression) {
        const port = Number(value);
        const source = expression.trim();
        if (!source) return true;
        return source.split(",").some(function (part) {
            const token = part.trim();
            if (/^\\d+$/.test(token)) return port === Number(token);
            const match = token.match(/^(\\d+)\\s*-\\s*(\\d+)$/);
            return match ? port >= Number(match[1]) && port <= Number(match[2]) : false;
        });
    }

    function renderFilterStatus(tableId, labels) {
        const total = document.querySelectorAll("#" + tableId + " tbody tr").length;
        const visible = visibleRows(tableId).length;
        document.getElementById(tableId + "Count").textContent = visible + " de " + total + " registros";
        document.getElementById(tableId + "Active").textContent = labels.filter(Boolean).join(" · ");
        document.getElementById(tableId.replace("Table", "Panel")).classList.toggle("is-empty", visible === 0);
    }

    function filterHosts() {
        const query = normalize(document.getElementById("hostSearch").value);
        const state = document.getElementById("hostState").value;
        const scope = document.getElementById("hostScope").value;
        const severity = document.getElementById("hostSeverity").value;
        const minPorts = Number(document.getElementById("hostMinPorts").value || 0);
        document.querySelectorAll("#hostsTable tbody tr").forEach(function (row) {
            const match = (!query || normalize(row.dataset.search).includes(query))
                && (!state || row.dataset.state === state)
                && (!scope || row.dataset.scope === scope)
                && (!severity || row.dataset.severity === severity)
                && Number(row.dataset.open || 0) >= minPorts;
            row.classList.toggle("hidden-row", !match);
        });
        renderFilterStatus("hostsTable", [
            query && "busca: " + query,
            state && "estado: " + state,
            scope && "escopo: " + scope,
            severity && "severidade: " + severity,
            minPorts > 0 && "portas ≥ " + minPorts
        ]);
    }

    function filterPorts() {
        const query = normalize(document.getElementById("portSearch").value);
        const expression = document.getElementById("portExpression").value;
        const service = normalize(document.getElementById("serviceSearch").value);
        const state = document.getElementById("portState").value;
        const severity = document.getElementById("portSeverity").value;
        document.querySelectorAll("#portsTable tbody tr").forEach(function (row) {
            const match = (!query || normalize(row.dataset.search).includes(query))
                && portMatches(row.dataset.port, expression)
                && (!service || normalize(row.dataset.service).includes(service))
                && (!state || row.dataset.state === state)
                && (!severity || row.dataset.severity === severity);
            row.classList.toggle("hidden-row", !match);
        });
        renderFilterStatus("portsTable", [
            query && "busca: " + query,
            expression && "porta: " + expression,
            service && "serviço: " + service,
            state && "estado: " + state,
            severity && "severidade: " + severity
        ]);
    }

    function filterFindings() {
        const query = normalize(document.getElementById("findingSearch").value);
        const severity = document.getElementById("findingSeverity").value;
        const confidence = document.getElementById("findingConfidence").value;
        const minCvss = Number(document.getElementById("findingMinCvss").value || 0);
        document.querySelectorAll("#findingsTable tbody tr").forEach(function (row) {
            const match = (!query || normalize(row.dataset.search).includes(query))
                && (!severity || row.dataset.severity === severity)
                && (!confidence || row.dataset.confidence === confidence)
                && Number(row.dataset.cvss || 0) >= minCvss;
            row.classList.toggle("hidden-row", !match);
        });
        renderFilterStatus("findingsTable", [
            query && "busca: " + query,
            severity && "severidade: " + severity,
            confidence && "evidência: " + confidence,
            minCvss > 0 && "CVSS ≥ " + minCvss
        ]);
    }

    const filterFunctions = {hostsTable: filterHosts, portsTable: filterPorts, findingsTable: filterFindings};

    Object.keys(controls).forEach(function (tableId) {
        controls[tableId].forEach(function (controlId) {
            document.getElementById(controlId).addEventListener("input", filterFunctions[tableId]);
            document.getElementById(controlId).addEventListener("change", filterFunctions[tableId]);
        });
    });

    document.querySelectorAll("[data-reset]").forEach(function (button) {
        button.addEventListener("click", function () {
            controls[button.dataset.reset].forEach(function (id) { document.getElementById(id).value = ""; });
            filterFunctions[button.dataset.reset]();
        });
    });

    function csvCell(value) {
        let text = String(value).replace(/\\s+/g, " ").trim();
        if (/^[=+\\-@]/.test(text)) text = "'" + text;
        return '"' + text.replace(/"/g, '""') + '"';
    }

    document.querySelectorAll("[data-export]").forEach(function (button) {
        button.addEventListener("click", function () {
            const table = document.getElementById(button.dataset.export);
            const header = Array.from(table.querySelectorAll("thead th")).map(function (cell) { return csvCell(cell.textContent); });
            const rows = visibleRows(button.dataset.export).map(function (row) {
                return Array.from(row.cells).map(function (cell) { return csvCell(cell.textContent); }).join(",");
            });
            const blob = new Blob(["\\ufeff" + [header.join(",")].concat(rows).join("\\n")], {type: "text/csv;charset=utf-8"});
            const link = document.createElement("a");
            link.href = URL.createObjectURL(blob);
            link.download = button.dataset.export.replace("Table", "").toLowerCase() + "_filtrado.csv";
            link.click();
            setTimeout(function () { URL.revokeObjectURL(link.href); }, 1000);
        });
    });

    document.querySelectorAll("th.sortable").forEach(function (header) {
        header.addEventListener("click", function () {
            const table = header.closest("table");
            const body = table.tBodies[0];
            const index = Array.from(header.parentNode.children).indexOf(header);
            const ascending = !header.classList.contains("sort-asc");
            table.querySelectorAll("th").forEach(function (cell) { cell.classList.remove("sort-asc", "sort-desc"); });
            header.classList.add(ascending ? "sort-asc" : "sort-desc");
            Array.from(body.rows).sort(function (a, b) {
                let left = a.cells[index].dataset.sort || a.cells[index].textContent.trim();
                let right = b.cells[index].dataset.sort || b.cells[index].textContent.trim();
                if (header.dataset.type === "number") {
                    left = Number(left) || 0;
                    right = Number(right) || 0;
                    return ascending ? left - right : right - left;
                }
                return ascending
                    ? left.localeCompare(right, "pt-BR", {numeric: true})
                    : right.localeCompare(left, "pt-BR", {numeric: true});
            }).forEach(function (row) { body.appendChild(row); });
        });
    });

    function focusTable(sectionId, controlId, value, filterFunction) {
        document.getElementById(controlId).value = value;
        filterFunction();
        document.getElementById(sectionId).scrollIntoView({behavior: "smooth", block: "start"});
    }

    document.querySelectorAll("[data-filter-port]").forEach(function (button) {
        button.addEventListener("click", function () {
            focusTable("ports", "portExpression", button.dataset.filterPort, filterPorts);
        });
    });
    document.querySelectorAll("[data-filter-finding]").forEach(function (button) {
        button.addEventListener("click", function () {
            focusTable("findings", "findingSearch", button.dataset.filterFinding, filterFindings);
        });
    });
    document.querySelectorAll("[data-filter-host]").forEach(function (button) {
        button.addEventListener("click", function () {
            focusTable("assets", "hostSearch", button.dataset.filterHost, filterHosts);
        });
    });
    document.querySelectorAll("[data-filter-service]").forEach(function (button) {
        button.addEventListener("click", function () {
            focusTable("ports", "serviceSearch", button.dataset.filterService, filterPorts);
        });
    });

    filterHosts();
    filterPorts();
    filterFindings();

    if (typeof Chart === "undefined") {
        document.querySelectorAll(".chart-panel").forEach(function (panel) { panel.classList.add("chart-unavailable"); });
        return;
    }

    Chart.defaults.color = "#94a3b8";
    Chart.defaults.borderColor = "rgba(255,255,255,.08)";
    Chart.defaults.font.family = '"Inter", system-ui, sans-serif';

    const palette = {red: "#ef4444", orange: "#f97316", amber: "#fbbf24", green: "#10b981", blue: "#38bdf8", purple: "#a78bfa", slate: "#64748b"};
    const common = {
        responsive: true,
        maintainAspectRatio: false,
        interaction: {mode: "nearest", intersect: true},
        plugins: {
            legend: {position: "bottom", labels: {usePointStyle: true, boxWidth: 8, padding: 18}},
            tooltip: {backgroundColor: "#020617", borderColor: "rgba(56,189,248,.3)", borderWidth: 1, padding: 12}
        }
    };

    const severityChart = new Chart(document.getElementById("severityChart"), {
        type: "doughnut",
        data: {labels: chartData.severity.labels, datasets: [{data: chartData.severity.values, backgroundColor: [palette.red, palette.orange, palette.amber, palette.green, palette.blue], borderColor: "#0f172a", borderWidth: 3}]},
        options: Object.assign({}, common, {
            cutout: "66%",
            onClick: function (_, elements) {
                if (!elements.length) return;
                const keys = ["critical", "high", "medium", "low", "info"];
                focusTable("findings", "findingSeverity", keys[elements[0].index], filterFindings);
            }
        })
    });

    new Chart(document.getElementById("statesChart"), {
        type: "doughnut",
        data: {labels: chartData.states.labels, datasets: [{data: chartData.states.values, backgroundColor: [palette.red, palette.green, palette.amber, palette.slate, palette.purple], borderColor: "#0f172a", borderWidth: 3}]},
        options: Object.assign({}, common, {
            cutout: "66%",
            onClick: function (_, elements) {
                if (!elements.length) return;
                focusTable("ports", "portState", chartData.states.keys[elements[0].index], filterPorts);
            }
        })
    });

    function horizontalOptions(onClick) {
        return {
            responsive: true,
            maintainAspectRatio: false,
            indexAxis: "y",
            scales: {x: {beginAtZero: true, ticks: {precision: 0}}, y: {grid: {display: false}}},
            plugins: {legend: {display: false}, tooltip: common.plugins.tooltip},
            onClick: onClick
        };
    }

    new Chart(document.getElementById("portsChart"), {
        type: "bar",
        data: {labels: chartData.ports.labels, datasets: [{data: chartData.ports.values, backgroundColor: "rgba(239,68,68,.72)", borderColor: palette.red, borderWidth: 1, borderRadius: 3}]},
        options: horizontalOptions(function (_, elements) {
            if (!elements.length) return;
            focusTable("ports", "portExpression", chartData.ports.keys[elements[0].index], filterPorts);
        })
    });

    new Chart(document.getElementById("servicesChart"), {
        type: "bar",
        data: {labels: chartData.services.labels, datasets: [{data: chartData.services.values, backgroundColor: "rgba(56,189,248,.66)", borderColor: palette.blue, borderWidth: 1, borderRadius: 3}]},
        options: horizontalOptions(function (_, elements) {
            if (!elements.length) return;
            focusTable("ports", "serviceSearch", chartData.services.keys[elements[0].index], filterPorts);
        })
    });

    new Chart(document.getElementById("hostsChart"), {
        type: "bar",
        data: {
            labels: chartData.hosts.labels,
            datasets: [
                {label: "Portas abertas", data: chartData.hosts.openPorts, backgroundColor: "rgba(56,189,248,.62)", borderColor: palette.blue, borderWidth: 1, borderRadius: 3, yAxisID: "y"},
                {label: "Prioridade", data: chartData.hosts.riskScores, backgroundColor: "rgba(239,68,68,.60)", borderColor: palette.red, borderWidth: 1, borderRadius: 3, yAxisID: "risk"}
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {beginAtZero: true, ticks: {precision: 0}, title: {display: true, text: "Portas abertas"}},
                risk: {beginAtZero: true, max: 100, position: "right", grid: {drawOnChartArea: false}, title: {display: true, text: "Prioridade / 100"}}
            },
            plugins: common.plugins,
            onClick: function (_, elements) {
                if (!elements.length) return;
                focusTable("assets", "hostSearch", chartData.hosts.keys[elements[0].index], filterHosts);
            }
        }
    });
}());
</script>
</body>
</html>
"""


def h(value):
    """Escapa conteúdo não confiável antes de inseri-lo no HTML."""
    return escape(str(value if value is not None else ""), quote=True)


def safe_json(value):
    """Serializa dados para JavaScript sem permitir fechamento da tag script."""
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).replace("</", "<\\/")


def to_int(value, default=0):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def to_float(value, default=0.0):
    try:
        number = float(value)
        return number if 0 <= number <= 10 else default
    except (TypeError, ValueError):
        return default


def clean_text(value, limit=None):
    text = re.sub(r"\s+", " ", value or "").strip()
    return text[:limit] if limit else text


def severity_from_score(score):
    if score >= 9:
        return "critical"
    if score >= 7:
        return "high"
    if score >= 4:
        return "medium"
    if score > 0:
        return "low"
    return "info"


def highest_severity(findings):
    if not findings:
        return "none"
    return max(
        (finding.get("severity", "info") for finding in findings),
        key=lambda severity: SEVERITY_ORDER.get(severity, 0),
    )


def classify_scope(address):
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return "other", "Outro"

    if ip.is_global:
        return "public", "Público"
    if ip.is_private:
        return "private", "Privado"
    return "other", "Reservado"


def simplify_os_name(name):
    lowered = (name or "").lower()
    families = [
        ("linux", "Linux"),
        ("windows", "Windows"),
        ("mac os", "macOS"),
        ("macos", "macOS"),
        ("android", "Android"),
        ("ios", "iOS"),
        ("freebsd", "FreeBSD"),
        ("openbsd", "OpenBSD"),
        ("solaris", "Solaris"),
    ]
    for needle, family in families:
        if needle in lowered:
            return family
    return clean_text(name) or "Desconhecido"


def explicit_severity_from_output(output):
    match = re.search(
        r"(?:risk\s*factor|severity|risk)\s*[:=]\s*(critical|high|medium|moderate|low)",
        output,
        re.IGNORECASE,
    )
    if not match:
        return None
    value = match.group(1).lower()
    return "medium" if value == "moderate" else value


def scores_from_output(output):
    patterns = [
        r"\bCVSS(?:v\d(?:\.\d)?)?(?:\s+score)?\s*[:=]?\s*(10(?:\.0)?|[0-9](?:\.[0-9])?)\b",
        r"\bscore\s*[:=]\s*(10(?:\.0)?|[0-9](?:\.[0-9])?)\b",
    ]
    scores = []
    for pattern in patterns:
        scores.extend(to_float(value) for value in re.findall(pattern, output, re.IGNORECASE))
    return [score for score in scores if score > 0]


def extract_script_findings(script, host, port, service):
    """Extrai CVEs correlacionados e resultados NSE realmente positivos."""
    script_id = clean_text(script.get("id", "unknown-script"))
    output = script.get("output", "") or ""
    findings = []
    exploit_references = set()

    if script_id.lower() == "vulners":
        for table in script.findall(".//table"):
            fields = {
                elem.get("key", ""): clean_text(elem.text)
                for elem in table.findall("elem")
                if elem.get("key")
            }
            identifier = fields.get("id", "").upper()
            if fields.get("is_exploit", "").lower() == "true" and identifier:
                exploit_references.add((host, str(port), identifier))

            if not identifier.startswith("CVE-") and fields.get("type", "").lower() != "cve":
                continue

            score = to_float(fields.get("cvss"))
            findings.append(
                {
                    "id": identifier,
                    "host": host,
                    "port": str(port),
                    "service": service,
                    "cvss": score,
                    "severity": severity_from_score(score),
                    "confidence": "correlated",
                    "source": script_id,
                    "evidence": "Correspondência de CPE/versão reportada pelo Vulners; requer validação manual.",
                }
            )
        return findings, exploit_references

    normalized_output = clean_text(output)
    lowered = normalized_output.lower()
    negative_markers = (
        "not vulnerable",
        "not vuln",
        "couldn't find",
        "could not find",
        "no vulnerabilities",
        "0 vulnerabilities",
        "script execution failed",
        "error:",
        "timed out",
    )
    if not normalized_output or any(marker in lowered for marker in negative_markers):
        return [], exploit_references

    structured_state = " ".join(
        clean_text(elem.text).lower()
        for elem in script.findall(".//elem")
        if (elem.get("key") or "").lower() in {"state", "status"}
    )
    positive = bool(re.search(r"\bvulnerable\b", lowered)) or "vulnerable" in structured_state
    if not positive:
        return [], exploit_references

    identifiers = {match.upper() for match in re.findall(r"\bCVE-\d{4}-\d{4,}\b", normalized_output, re.IGNORECASE)}
    script_cve = re.search(r"cve[-_]?(\d{4})[-_]?(\d{4,})", script_id, re.IGNORECASE)
    if script_cve:
        identifiers.add(f"CVE-{script_cve.group(1)}-{script_cve.group(2)}")
    if not identifiers:
        identifiers.add(script_id)

    scores = scores_from_output(normalized_output)
    score = max(scores, default=0.0)
    explicit_severity = explicit_severity_from_output(normalized_output)
    severity = explicit_severity or severity_from_score(score)
    evidence = clean_text(normalized_output, 500)

    for identifier in sorted(identifiers):
        findings.append(
            {
                "id": identifier,
                "host": host,
                "port": str(port),
                "service": service,
                "cvss": score,
                "severity": severity,
                "confidence": "nse-positive",
                "source": script_id,
                "evidence": evidence,
            }
        )
    return findings, exploit_references


def calculate_host_risk(host):
    max_severity = highest_severity(host["vulnerabilities"])
    severity_base = {
        "critical": 74,
        "high": 56,
        "medium": 36,
        "low": 17,
        "info": 7,
        "none": 0,
    }[max_severity]
    sensitive_count = sum(
        1
        for port in host["ports"]
        if port["state"] == "open" and str(port["port"]) in SENSITIVE_PORTS
    )
    exposure_points = min(14, host["open_ports_count"] * 2)
    sensitive_points = min(12, sensitive_count * 3)
    return min(100, severity_base + exposure_points + sensitive_points)


def risk_label(score):
    if score >= 80:
        return "Crítico", "#ef4444"
    if score >= 60:
        return "Alto", "#f97316"
    if score >= 35:
        return "Médio", "#fbbf24"
    if score > 0:
        return "Baixo", "#10b981"
    return "Informativo", "#38bdf8"


def register_findings(data, host_data, port_data, findings):
    for finding in findings:
        key = (finding["host"], finding["port"], finding["id"])
        existing = data["_finding_index"].get(key)
        if existing is not None:
            if finding["cvss"] > existing["cvss"]:
                existing.update(finding)
            continue

        data["_finding_index"][key] = finding
        data["vulnerabilities"].append(finding)
        host_data["vulnerabilities"].append(finding)
        if port_data is not None:
            port_data["vulnerabilities"].append(finding)


def parse_nmap_xml(xml_file):
    """Analisa XML do Nmap, preservando cobertura agregada e nível de evidência."""
    try:
        tree = ET.parse(xml_file)
    except (ET.ParseError, OSError) as error:
        print(f"Erro ao analisar '{xml_file}': {error}", file=sys.stderr)
        return None

    root = tree.getroot()
    for element in root.iter():
        if "}" in element.tag:
            element.tag = element.tag.rsplit("}", 1)[-1]

    if root.tag != "nmaprun":
        print(f"Erro: '{xml_file}' não parece ser um XML do Nmap.", file=sys.stderr)
        return None

    run_hosts = root.find("runstats/hosts")
    finished = root.find("runstats/finished")
    scaninfo = []
    for item in root.findall("scaninfo"):
        scaninfo.append(
            {
                "type": item.get("type", "desconhecido"),
                "protocol": item.get("protocol", "desconhecido"),
                "numservices": to_int(item.get("numservices")),
                "services": item.get("services", ""),
            }
        )

    data = {
        "nmap_command": root.get("args", "Comando não disponível"),
        "scanner": f"Nmap {root.get('version', 'desconhecido')}",
        "scan_start": root.get("startstr", "Não informado"),
        "scan_exit": finished.get("exit", "desconhecido") if finished is not None else "desconhecido",
        "elapsed": f"{finished.get('elapsed')}s" if finished is not None and finished.get("elapsed") else "não informado",
        "scan_summary": finished.get("summary", "") if finished is not None else "",
        "scaninfo": scaninfo,
        "hosts": [],
        "ports_info": [],
        "vulnerabilities": [],
        "_finding_index": {},
        "_exploit_references": set(),
        "stats": {
            "total_hosts": to_int(run_hosts.get("total")) if run_hosts is not None else 0,
            "hosts_up": to_int(run_hosts.get("up")) if run_hosts is not None else 0,
            "hosts_down": to_int(run_hosts.get("down")) if run_hosts is not None else 0,
            "hosts_exposed": 0,
            "public_hosts": 0,
            "total_ports": 0,
            "open_ports": 0,
            "closed_ports": 0,
            "filtered_ports": 0,
            "port_states": Counter(),
            "unique_services": 0,
            "unknown_services": 0,
            "service_names": set(),
            "os_guesses": Counter(),
            "protocols": Counter(),
            "vulnerabilities": Counter(),
            "total_vulnerabilities": 0,
            "unique_cves": 0,
            "exploit_references": 0,
            "nse_positive": 0,
            "sensitive_endpoints": 0,
        },
    }

    for host_index, host in enumerate(root.findall("host"), start=1):
        status_element = host.find("status")
        status = status_element.get("state", "unknown") if status_element is not None else "unknown"
        addresses = {
            address.get("addrtype", "unknown"): address.get("addr", "")
            for address in host.findall("address")
            if address.get("addr")
        }
        identity = addresses.get("ipv4") or addresses.get("ipv6")
        hostnames = [
            hostname.get("name", "")
            for hostname in host.findall("hostnames/hostname")
            if hostname.get("name")
        ]
        if not identity:
            identity = hostnames[0] if hostnames else f"host-{host_index}"

        scope, scope_label = classify_scope(identity)
        host_data = {
            "ip": identity,
            "addresses": addresses,
            "hostnames": hostnames,
            "status": status,
            "status_reason": status_element.get("reason", "") if status_element is not None else "",
            "scope": scope,
            "scope_label": scope_label,
            "ports": [],
            "os": "Desconhecido",
            "os_family": "Desconhecido",
            "os_accuracy": 0,
            "open_ports_count": 0,
            "vulnerabilities": [],
            "risk_score": 0,
            "max_severity": "none",
        }

        ports_element = host.find("ports")
        if ports_element is not None:
            for extra in ports_element.findall("extraports"):
                state = extra.get("state", "other").lower()
                count = to_int(extra.get("count"))
                data["stats"]["port_states"][state] += count
                data["stats"]["total_ports"] += count

            for port in ports_element.findall("port"):
                state_element = port.find("state")
                state = state_element.get("state", "unknown").lower() if state_element is not None else "unknown"
                protocol = port.get("protocol", "unknown").lower()
                port_id = port.get("portid", "0")

                service_element = port.find("service")
                service_name = "desconhecido"
                product = ""
                version = ""
                extra_info = ""
                cpes = []
                confidence = 0
                if service_element is not None:
                    service_name = service_element.get("name", "desconhecido") or "desconhecido"
                    tunnel = service_element.get("tunnel", "")
                    if tunnel and not service_name.startswith(tunnel + "/"):
                        service_name = f"{tunnel}/{service_name}"
                    product = service_element.get("product", "")
                    version = service_element.get("version", "")
                    extra_info = service_element.get("extrainfo", "")
                    confidence = to_int(service_element.get("conf"))
                    cpes = [clean_text(cpe.text) for cpe in service_element.findall("cpe") if clean_text(cpe.text)]

                version_display = clean_text(" ".join(value for value in (product, version, extra_info) if value))
                port_data = {
                    "host": identity,
                    "port": port_id,
                    "protocol": protocol,
                    "state": state,
                    "state_reason": state_element.get("reason", "") if state_element is not None else "",
                    "service": service_name,
                    "product": product,
                    "version": version_display,
                    "service_confidence": confidence,
                    "cpes": cpes,
                    "vulnerabilities": [],
                    "max_cvss": 0.0,
                    "max_severity": "none",
                }

                data["stats"]["port_states"][state] += 1
                data["stats"]["total_ports"] += 1
                if state == "open":
                    data["stats"]["open_ports"] += 1
                    host_data["open_ports_count"] += 1
                    data["stats"]["protocols"][protocol] += 1
                    if service_name == "desconhecido":
                        data["stats"]["unknown_services"] += 1
                    else:
                        data["stats"]["service_names"].add(service_name)
                    if port_id in SENSITIVE_PORTS:
                        data["stats"]["sensitive_endpoints"] += 1
                elif state == "closed":
                    data["stats"]["closed_ports"] += 1
                elif state == "filtered":
                    data["stats"]["filtered_ports"] += 1

                for script in port.findall("script"):
                    findings, exploit_refs = extract_script_findings(
                        script, identity, port_id, service_name
                    )
                    data["_exploit_references"].update(exploit_refs)
                    register_findings(data, host_data, port_data, findings)

                port_data["max_cvss"] = max(
                    (finding["cvss"] for finding in port_data["vulnerabilities"]),
                    default=0.0,
                )
                port_data["max_severity"] = highest_severity(port_data["vulnerabilities"])
                host_data["ports"].append(port_data)
                data["ports_info"].append(port_data)

        for script in host.findall("hostscript/script"):
            findings, exploit_refs = extract_script_findings(
                script, identity, "host", "host-script"
            )
            data["_exploit_references"].update(exploit_refs)
            register_findings(data, host_data, None, findings)

        os_matches = host.findall("os/osmatch")
        if os_matches:
            best_match = max(os_matches, key=lambda match: to_int(match.get("accuracy")))
            host_data["os"] = clean_text(best_match.get("name", "Desconhecido"))
            host_data["os_accuracy"] = to_int(best_match.get("accuracy"))
        else:
            os_class = host.find("os/osclass")
            if os_class is not None:
                host_data["os"] = clean_text(
                    " ".join(
                        value
                        for value in (
                            os_class.get("vendor", ""),
                            os_class.get("osfamily", ""),
                            os_class.get("type", ""),
                        )
                        if value
                    )
                ) or "Desconhecido"
                host_data["os_accuracy"] = to_int(os_class.get("accuracy"))

        host_data["os_family"] = simplify_os_name(host_data["os"])
        data["stats"]["os_guesses"][host_data["os_family"]] += 1
        host_data["max_severity"] = highest_severity(host_data["vulnerabilities"])
        host_data["risk_score"] = calculate_host_risk(host_data)
        data["hosts"].append(host_data)

    if not data["stats"]["total_hosts"]:
        data["stats"]["total_hosts"] = len(data["hosts"])
    if run_hosts is None:
        data["stats"]["hosts_up"] = sum(host["status"] == "up" for host in data["hosts"])
        data["stats"]["hosts_down"] = sum(host["status"] == "down" for host in data["hosts"])

    data["stats"]["hosts_exposed"] = sum(host["open_ports_count"] > 0 for host in data["hosts"])
    data["stats"]["public_hosts"] = sum(host["scope"] == "public" for host in data["hosts"])
    data["stats"]["unique_services"] = len(data["stats"]["service_names"])
    data["stats"]["total_vulnerabilities"] = len(data["vulnerabilities"])
    data["stats"]["unique_cves"] = len(
        {finding["id"] for finding in data["vulnerabilities"] if finding["id"].startswith("CVE-")}
    )
    data["stats"]["exploit_references"] = len(data["_exploit_references"])
    data["stats"]["nse_positive"] = sum(
        finding["confidence"] == "nse-positive" for finding in data["vulnerabilities"]
    )
    data["stats"]["vulnerabilities"].update(
        finding["severity"] for finding in data["vulnerabilities"]
    )

    # Compatibilidade com os nomes usados pela versão anterior.
    data["stats"]["closed_ports"] = data["stats"]["port_states"].get("closed", 0)
    data["stats"]["filtered_ports"] = data["stats"]["port_states"].get("filtered", 0)

    data.pop("_finding_index", None)
    data.pop("_exploit_references", None)
    return data


def calculate_risk_level(data):
    """Mantém a API anterior, agora usando o índice calculado por host."""
    score = max((host["risk_score"] for host in data.get("hosts", [])), default=0)
    return risk_label(score)[0]


def severity_badge(severity):
    label = SEVERITY_LABELS.get(severity, severity.title())
    return f'<span class="severity severity-{h(severity)}">{h(label)}</span>'


def confidence_label(confidence):
    return "NSE positivo" if confidence == "nse-positive" else "Correlação de versão"


def build_priority_findings(findings):
    ordered = sorted(
        findings,
        key=lambda item: (
            SEVERITY_ORDER.get(item["severity"], 0),
            item["confidence"] == "nse-positive",
            item["cvss"],
        ),
        reverse=True,
    )[:12]
    if not ordered:
        return '<li class="empty-state">Nenhum achado positivo ou CVE correlacionado no XML.</li>'

    rows = []
    for finding in ordered:
        score = f'{finding["cvss"]:.1f}' if finding["cvss"] else "s/ score"
        target = f'{finding["host"]}:{finding["port"]} · {finding["service"]} · {score}'
        rows.append(
            f"""
            <li class="finding-item">
                <button class="finding-button" data-filter-finding="{h(finding['id'])}">
                    <div class="finding-id">{h(finding['id'])}</div>
                    <div class="finding-target">{h(target)}</div>
                </button>
                {severity_badge(finding['severity'])}
            </li>"""
        )
    return "".join(rows)


def build_exposure_insights(data):
    insights = []
    sensitive_counter = Counter()
    for port in data["ports_info"]:
        if port["state"] == "open" and port["port"] in SENSITIVE_PORTS:
            sensitive_counter[port["port"]] += 1

    for port, count in sensitive_counter.most_common(6):
        insights.append(
            (
                "port",
                port,
                f'{SENSITIVE_PORTS[port]} em {count} endpoint{"s" if count != 1 else ""}',
                f"Porta {port} aberta; valide necessidade, ACL e exposição externa.",
                str(count),
            )
        )

    if data["stats"]["unknown_services"]:
        insights.append(
            (
                "service",
                "desconhecido",
                f'{data["stats"]["unknown_services"]} endpoint(s) sem fingerprint',
                "A ausência de identificação reduz a qualidade da triagem.",
                str(data["stats"]["unknown_services"]),
            )
        )

    exposed_hosts = sorted(
        (host for host in data["hosts"] if host["open_ports_count"]),
        key=lambda host: (host["risk_score"], host["open_ports_count"]),
        reverse=True,
    )
    if exposed_hosts:
        top = exposed_hosts[0]
        insights.append(
            (
                "host",
                top["ip"],
                f'{top["ip"]} concentra a maior prioridade',
                f'{top["open_ports_count"]} portas abertas · índice {top["risk_score"]}/100.',
                str(top["risk_score"]),
            )
        )

    if not insights:
        return '<li class="empty-state">Nenhum sinal de exposição operacional entre as portas explicitamente listadas.</li>'

    output = []
    for kind, value, title, detail, count in insights[:8]:
        attribute = {
            "port": f'data-filter-port="{h(value)}"',
            "host": f'data-filter-host="{h(value)}"',
            "service": f'data-filter-service="{h(value)}"',
        }[kind]
        output.append(
            f"""
            <li class="insight-item">
                <button class="insight-button" {attribute}>
                    <div class="insight-title">{h(title)}</div>
                    <div class="insight-detail">{h(detail)}</div>
                </button>
                <span class="pill">{h(count)}</span>
            </li>"""
        )
    return "".join(output)


def host_table_rows(data):
    rows = []
    state_labels = {"up": "Ativo", "down": "Inativo", "unknown": "Desconhecido"}
    for host in sorted(data["hosts"], key=lambda item: (item["risk_score"], item["open_ports_count"]), reverse=True):
        open_ports = [port for port in host["ports"] if port["state"] == "open"]
        port_buttons = [
            f'<button class="port-tag" data-filter-port="{h(port["port"])}" title="{h(port["service"])}">{h(port["port"])}/{h(port["protocol"])}</button>'
            for port in open_ports[:14]
        ]
        if len(open_ports) > 14:
            port_buttons.append(f'<span class="pill">+{len(open_ports) - 14}</span>')

        services = sorted({port["service"] for port in open_ports})
        service_text = ", ".join(services) if services else "Nenhum"
        hostname_text = ", ".join(host["hostnames"]) if host["hostnames"] else "sem hostname"
        os_text = host["os"]
        if host["os_accuracy"]:
            os_text += f' ({host["os_accuracy"]}%)'
        findings_count = len(host["vulnerabilities"])
        risk_name, _ = risk_label(host["risk_score"])
        search_text = " ".join(
            [
                host["ip"],
                hostname_text,
                service_text,
                host["os"],
                host["scope_label"],
                host["status"],
            ]
        )

        rows.append(
            f"""
            <tr data-search="{h(search_text)}" data-state="{h(host['status'])}" data-scope="{h(host['scope'])}" data-severity="{h(host['max_severity'])}" data-open="{host['open_ports_count']}">
                <td><div class="mono strong">{h(host['ip'])}</div><div class="muted">{h(hostname_text)}</div></td>
                <td><span class="pill">{h(state_labels.get(host['status'], host['status']))}</span> <span class="scope-{h(host['scope'])}">{h(host['scope_label'])}</span></td>
                <td data-sort="{host['open_ports_count']}"><div class="port-tags">{''.join(port_buttons) if port_buttons else '<span class="muted">Nenhuma</span>'}</div></td>
                <td>{h(service_text)}</td>
                <td>{h(os_text)}</td>
                <td data-sort="{findings_count}"><span class="strong">{findings_count}</span> · {severity_badge(host['max_severity'])}</td>
                <td data-sort="{host['risk_score']}"><span class="strong">{host['risk_score']}</span>/100 · {h(risk_name)}</td>
            </tr>"""
        )
    return "".join(rows)


def port_table_rows(data):
    rows = []
    for port in sorted(
        data["ports_info"],
        key=lambda item: (
            item["state"] != "open",
            -SEVERITY_ORDER.get(item["max_severity"], 0),
            item["host"],
            to_int(item["port"]),
        ),
    ):
        finding_count = len(port["vulnerabilities"])
        score_display = f'{port["max_cvss"]:.1f}' if port["max_cvss"] else "—"
        product = port["version"] or "Não identificado"
        search_text = " ".join(
            [
                port["host"],
                port["port"],
                port["protocol"],
                port["state"],
                port["service"],
                product,
            ]
        )
        rows.append(
            f"""
            <tr data-search="{h(search_text)}" data-port="{h(port['port'])}" data-service="{h(port['service'])}" data-state="{h(port['state'])}" data-severity="{h(port['max_severity'])}">
                <td class="mono strong">{h(port['host'])}</td>
                <td class="mono nowrap" data-sort="{to_int(port['port'])}">{h(port['port'])}/{h(port['protocol'])}</td>
                <td><span class="pill">{h(port['state'])}</span><div class="muted">{h(port['state_reason'])}</div></td>
                <td><span class="strong">{h(port['service'])}</span><div class="muted">confiança Nmap: {port['service_confidence']}/10</div></td>
                <td>{h(product)}</td>
                <td data-sort="{finding_count}">{finding_count} · {severity_badge(port['max_severity'])}</td>
                <td data-sort="{port['max_cvss']}"><span class="mono strong">{h(score_display)}</span></td>
            </tr>"""
        )
    return "".join(rows)


def finding_table_rows(data):
    ordered = sorted(
        data["vulnerabilities"],
        key=lambda item: (
            SEVERITY_ORDER.get(item["severity"], 0),
            item["cvss"],
            item["confidence"] == "nse-positive",
            item["id"],
        ),
        reverse=True,
    )
    rows = []
    for finding in ordered:
        score_display = f'{finding["cvss"]:.1f}' if finding["cvss"] else "—"
        evidence = finding["evidence"]
        search_text = " ".join(
            [
                finding["id"],
                finding["host"],
                finding["port"],
                finding["service"],
                finding["source"],
                evidence,
            ]
        )
        rows.append(
            f"""
            <tr data-search="{h(search_text)}" data-severity="{h(finding['severity'])}" data-confidence="{h(finding['confidence'])}" data-cvss="{finding['cvss']}">
                <td class="mono strong">{h(finding['id'])}</td>
                <td class="mono" data-sort="{finding['cvss']}">{h(score_display)}</td>
                <td>{severity_badge(finding['severity'])}</td>
                <td><span class="mono strong">{h(finding['host'])}:{h(finding['port'])}</span><div class="muted">{h(finding['service'])}</div></td>
                <td><span class="pill">{h(confidence_label(finding['confidence']))}</span><div class="evidence">{h(evidence)}</div></td>
                <td class="mono">{h(finding['source'])}</td>
            </tr>"""
        )
    return "".join(rows)


def build_chart_payload(data):
    severity_keys = ["critical", "high", "medium", "low", "info"]
    state_order = ["open", "closed", "filtered", "unfiltered", "unknown"]
    remaining_states = sorted(set(data["stats"]["port_states"]) - set(state_order))
    state_keys = [
        state
        for state in state_order + remaining_states
        if data["stats"]["port_states"].get(state, 0) > 0
    ]
    state_labels_map = {
        "open": "Abertas",
        "closed": "Fechadas",
        "filtered": "Filtradas",
        "unfiltered": "Não filtradas",
        "unknown": "Desconhecidas",
    }

    port_counter = Counter(
        port["port"] for port in data["ports_info"] if port["state"] == "open"
    )
    top_ports = sorted(
        port_counter.items(), key=lambda item: (-item[1], to_int(item[0]))
    )[:10]

    service_counter = Counter(
        port["service"]
        for port in data["ports_info"]
        if port["state"] == "open" and port["service"] != "desconhecido"
    )
    top_services = service_counter.most_common(10)

    top_hosts = sorted(
        (host for host in data["hosts"] if host["open_ports_count"] > 0),
        key=lambda host: (host["risk_score"], host["open_ports_count"]),
        reverse=True,
    )[:12]

    return {
        "severity": {
            "labels": [SEVERITY_LABELS[key] for key in severity_keys],
            "values": [data["stats"]["vulnerabilities"].get(key, 0) for key in severity_keys],
        },
        "states": {
            "keys": state_keys,
            "labels": [state_labels_map.get(key, key.title()) for key in state_keys],
            "values": [data["stats"]["port_states"][key] for key in state_keys],
        },
        "ports": {
            "keys": [port for port, _ in top_ports],
            "labels": [f"Porta {port}" for port, _ in top_ports],
            "values": [count for _, count in top_ports],
        },
        "services": {
            "keys": [service for service, _ in top_services],
            "labels": [service for service, _ in top_services],
            "values": [count for _, count in top_services],
        },
        "hosts": {
            "keys": [host["ip"] for host in top_hosts],
            "labels": [host["ip"] for host in top_hosts],
            "openPorts": [host["open_ports_count"] for host in top_hosts],
            "riskScores": [host["risk_score"] for host in top_hosts],
        },
    }


def coverage_description(data):
    if data["scaninfo"]:
        descriptions = []
        for item in data["scaninfo"]:
            amount = item["numservices"]
            label = f'{item["type"]}/{item["protocol"]}'
            descriptions.append(f"{label}: {amount} portas/serviços solicitados")
        return "; ".join(descriptions) + ". Estados agregados do Nmap foram incluídos na cobertura."
    return "O XML não contém scaninfo; a cobertura considera as portas explícitas e extraports disponíveis."


def risk_reason(data, score):
    stats = data["stats"]
    highest = highest_severity(data["vulnerabilities"])
    severity_text = SEVERITY_LABELS.get(highest, "Sem achados").lower()
    return (
        f"Maior severidade observada: {severity_text}. "
        f"{stats['open_ports']} endpoints abertos, "
        f"{stats['sensitive_endpoints']} em portas sensíveis e "
        f"{stats['total_vulnerabilities']} correlações/achados priorizáveis. "
        f"O índice máximo entre os hosts foi {score}/100."
    )


def generate_html_report(data, xml_filename, output_file="nmap_report.html"):
    """Gera o relatório HTML interativo e autocontido, exceto fontes/Chart.js."""
    stats = data["stats"]
    risk_score = max((host["risk_score"] for host in data["hosts"]), default=0)
    risk_name, risk_color = risk_label(risk_score)
    critical_high = (
        stats["vulnerabilities"].get("critical", 0)
        + stats["vulnerabilities"].get("high", 0)
    )
    os_detected = sum(host["os"] != "Desconhecido" for host in data["hosts"])

    command_html = ""
    if data.get("nmap_command") and data["nmap_command"] != "Comando não disponível":
        command_html = (
            '<details class="command"><summary>&gt; comando_nmap</summary>'
            f'<pre>{h(data["nmap_command"])}</pre></details>'
        )

    explicit_states = sorted(
        state for state, count in stats["port_states"].items() if count > 0
    )
    state_labels = {
        "open": "Abertas",
        "closed": "Fechadas",
        "filtered": "Filtradas",
        "unfiltered": "Não filtradas",
        "unknown": "Desconhecidas",
    }
    state_options = "".join(
        f'<option value="{h(state)}">{h(state_labels.get(state, state.title()))}</option>'
        for state in explicit_states
    )

    chart_payload = build_chart_payload(data)
    timestamp = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    report_id = datetime.now().strftime("%Y%m%d-%H%M%S")

    replacements = {
        "{{report_id}}": report_id,
        "{{timestamp}}": timestamp,
        "{{filename}}": h(os.path.basename(str(xml_filename))),
        "{{scanner}}": h(data.get("scanner", "Nmap")),
        "{{elapsed}}": h(data.get("elapsed", "não informado")),
        "{{scan_exit}}": h(data.get("scan_exit", "desconhecido")),
        "{{nmap_command}}": command_html,
        "{{risk_score}}": str(risk_score),
        "{{risk_color}}": risk_color,
        "{{risk_level}}": h(risk_name),
        "{{risk_reason}}": h(risk_reason(data, risk_score)),
        "{{hosts_up}}": str(stats["hosts_up"]),
        "{{total_hosts}}": str(stats["total_hosts"]),
        "{{hosts_exposed}}": str(stats["hosts_exposed"]),
        "{{public_hosts}}": str(stats["public_hosts"]),
        "{{open_ports}}": str(stats["open_ports"]),
        "{{sensitive_endpoints}}": str(stats["sensitive_endpoints"]),
        "{{unique_services}}": str(stats["unique_services"]),
        "{{unknown_services}}": str(stats["unknown_services"]),
        "{{unique_cves}}": str(stats["unique_cves"]),
        "{{total_findings}}": str(stats["total_vulnerabilities"]),
        "{{critical_high}}": str(critical_high),
        "{{nse_positive}}": str(stats["nse_positive"]),
        "{{coverage_description}}": h(coverage_description(data)),
        "{{ports_observed}}": str(stats["total_ports"]),
        "{{closed_ports}}": str(stats["closed_ports"]),
        "{{filtered_ports}}": str(stats["filtered_ports"]),
        "{{os_detected}}": str(os_detected),
        "{{priority_findings}}": build_priority_findings(data["vulnerabilities"]),
        "{{exposure_insights}}": build_exposure_insights(data),
        "{{hosts_table}}": host_table_rows(data),
        "{{ports_table}}": port_table_rows(data),
        "{{findings_table}}": finding_table_rows(data),
        "{{port_state_options}}": state_options,
        "{{chart_payload}}": safe_json(chart_payload),
    }

    template_placeholders = set(re.findall(r"\{\{[a-z_]+\}\}", HTML_TEMPLATE))
    missing = sorted(template_placeholders - set(replacements))
    if missing:
        raise ValueError(f"Placeholders sem valor: {', '.join(missing)}")
    placeholder_pattern = re.compile(
        "|".join(re.escape(placeholder) for placeholder in sorted(replacements, key=len, reverse=True))
    )
    html_content = placeholder_pattern.sub(
        lambda match: str(replacements[match.group(0)]),
        HTML_TEMPLATE,
    )

    try:
        with open(output_file, "w", encoding="utf-8") as report:
            report.write(html_content)
    except OSError as error:
        raise OSError(f"Não foi possível salvar o relatório '{output_file}': {error}") from error

    return output_file


def build_argument_parser():
    parser = argparse.ArgumentParser(
        description="Gera um dashboard técnico a partir de um XML do Nmap."
    )
    parser.add_argument("xml_file", help="arquivo XML produzido pelo Nmap (-oX)")
    parser.add_argument(
        "-o",
        "--output",
        help="arquivo HTML de saída (padrão: nmap_report_DATA_HORA.html)",
    )
    return parser


def main(argv=None):
    args = build_argument_parser().parse_args(argv)
    xml_file = args.xml_file

    if not os.path.isfile(xml_file):
        print(f"Erro: arquivo não encontrado ou inválido: {xml_file}", file=sys.stderr)
        return 1

    print(f"Analisando arquivo: {xml_file}")
    data = parse_nmap_xml(xml_file)
    if data is None:
        return 1

    output_file = args.output or f"nmap_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    if os.path.realpath(output_file) == os.path.realpath(xml_file):
        print("Erro: o arquivo de saída não pode sobrescrever o XML de entrada.", file=sys.stderr)
        return 1
    try:
        result_file = generate_html_report(data, xml_file, output_file)
    except (OSError, ValueError) as error:
        print(f"Erro ao gerar relatório: {error}", file=sys.stderr)
        return 1

    stats = data["stats"]
    risk_score = max((host["risk_score"] for host in data["hosts"]), default=0)
    print(f"Relatório gerado: {result_file}")
    print("Estatísticas consolidadas:")
    print(f"  • Hosts ativos: {stats['hosts_up']} / {stats['total_hosts']}")
    print(f"  • Portas contabilizadas: {stats['total_ports']}")
    print(f"  • Portas abertas: {stats['open_ports']}")
    print(f"  • Serviços identificados: {stats['unique_services']}")
    print(f"  • CVEs únicos correlacionados: {stats['unique_cves']}")
    print(f"  • Ocorrências de achados: {stats['total_vulnerabilities']}")
    print(f"  • Achados NSE positivos: {stats['nse_positive']}")
    print(f"  • Índice máximo de priorização: {risk_score}/100")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
