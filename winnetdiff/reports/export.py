from __future__ import annotations
import argparse
import base64
import codecs
import csv
import ctypes
import datetime as dt
import io
import ipaddress
import json
import locale
import ntpath
import os
import platform
import queue
import re
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.parse
import uuid
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional
if os.name == 'nt':
    import winreg
else:
    winreg = None
from winnetdiff.collectors.security import normalize_binary_path
from winnetdiff.core.models import APP_NAME, Report, Finding, Probe
from winnetdiff.core.privacy import redact, redacted_data
from winnetdiff.core.i18n import tr, localized_data
from winnetdiff.probes.pmtu import pmtu_summary


_REPORT_LABELS = {
    'en': {'time': 'Time', 'system': 'System', 'admin': 'Administrator', 'targets': 'Targets',
           'layers': 'Five-layer diagnosis', 'evidence': 'Evidence', 'reason': 'Reasoning',
           'confidence': 'Evidence grade', 'alternatives': 'Alternative explanations', 'verify': 'Next verification',
           'conditions': 'Applicability', 'risk': 'Repair risk', 'limitations': 'Limitations and incomplete checks',
           'history': 'Repair and rollback history', 'scenarios': 'Candidate causes', 'rollback': 'Rollback',
           'timing': 'DNS / TCP / TLS / HTTP (milliseconds; one connection per attempt)',
           'table': '|Domain|Family|Address|DNS ms|TCP ms|TLS ms|HTTP ms|Stage|HTTP|Attempts|',
           'commands': 'Manual review only. Back up and separately confirm before any change.'},
    'zh-CN': {'time': '时间', 'system': '系统', 'admin': '管理员', 'targets': '目标', 'layers': '五层诊断',
              'evidence': '证据', 'reason': '推理依据', 'confidence': '证据等级', 'alternatives': '其他可能解释',
              'verify': '下一步验证', 'conditions': '适用条件', 'risk': '修复风险', 'limitations': '限制与未完成检查',
              'history': '修复与恢复记录', 'scenarios': '候选原因', 'rollback': '恢复方法',
              'timing': 'DNS / TCP / TLS / HTTP（毫秒；每次尝试共用同一连接）',
              'table': '|域名|协议|地址|DNS ms|TCP ms|TLS ms|HTTP ms|阶段|HTTP|尝试|',
              'commands': '仅供人工审阅。任何修改前须备份并额外确认。'},
    'zh-TW': {'time': '時間', 'system': '系統', 'admin': '管理員', 'targets': '目標', 'layers': '五層診斷',
              'evidence': '證據', 'reason': '推理依據', 'confidence': '證據等級', 'alternatives': '其他可能解釋',
              'verify': '下一步驗證', 'conditions': '適用條件', 'risk': '修復風險', 'limitations': '限制與未完成檢查',
              'history': '修復與回復紀錄', 'scenarios': '候選原因', 'rollback': '回復方法',
              'timing': 'DNS / TCP / TLS / HTTP（毫秒；每次嘗試共用同一連線）',
              'table': '|網域|協定|位址|DNS ms|TCP ms|TLS ms|HTTP ms|階段|HTTP|嘗試|',
              'commands': '僅供人工審閱。任何修改前須備份並額外確認。'},
}


def report_data(report: Report, full: bool = False) -> dict[str, Any]:
    data = asdict(report)
    locale = report.locale
    for finding in data['findings']:
        for key in ('severity', 'layer', 'title', 'interpretation', 'confidence', 'rollback', 'reasoning'):
            finding[key] = tr(finding[key], locale)
        for key in ('alternatives', 'verification', 'conditions'):
            finding[key] = [tr(value, locale) for value in finding[key]]
    data['limitations'] = [tr(value, locale) for value in data['limitations']]
    data['scenarios'] = localized_data(data['scenarios'], locale)
    data['security'] = localized_data(data['security'], locale)
    for layer in data['layers'].values():
        for key in ('status', 'confidence', 'interpretation', 'suggested_action'):
            if key in layer:
                layer[key] = tr(layer[key], locale)
    return data if full else redacted_data(data)


def evidence_text(report: Report, full: bool = False) -> str:
    return json.dumps(report_data(report, full), ensure_ascii=False, indent=2, default=str)


def _presentation_report(report: Report, full: bool) -> Report:
    data = report_data(report, full)
    data['findings'] = [Finding(**row) for row in data['findings']]
    data['probes'] = [Probe(**row) for row in data['probes']]
    return Report(**data)


def summarize(report: Report, full: bool = False, expert: bool = True) -> str:
    report = _presentation_report(report, full)
    labels, locale = _REPORT_LABELS[report.locale], report.locale
    lines = [f'{APP_NAME} v{report.version}', f"{labels['time']}: {report.generated_at}",
             f"{labels['system']}: {report.device}", f"{labels['admin']}: {report.administrator}",
             f"{labels['targets']}: {', '.join(report.hosts)}", '', labels['timing']]
    for probe in report.probes:
        lines.append(f'{probe.host} {probe.family} {probe.ip} DNS={probe.dns_ms} TCP={probe.tcp_ms} TLS={probe.tls_ms} HTTP={probe.http_ms} {probe.stage}; attempts={len(probe.attempts)}')
        if probe.error:
            lines.append('  ' + probe.error)
    lines.extend(['', labels['layers']])
    lines.extend(f"{tr(name, locale)}: {tr(layer['status'], locale)}" for name, layer in report.layers.items())
    for finding in report.findings:
        lines.extend(['', f'[{tr(finding.severity, locale)}] {tr(finding.title, locale)}',
                      f"{labels['confidence']}: {finding.evidence_grade}",
                      f"{labels['reason']}: {tr(finding.interpretation, locale)}",
                      f"{labels['verify']}: " + '; '.join(tr(value, locale) for value in finding.verification)])
        if expert:
            lines.extend([labels['evidence'] + ':', finding.evidence])
    for auxiliary in report.pmtu:
        lines.extend(['', tr('PMTU auxiliary evidence', locale), pmtu_summary(auxiliary, locale)])
    if report.proxy_paths:
        lines.extend(['', tr('Proxy path comparison', locale), json.dumps(report.proxy_paths, ensure_ascii=False, indent=2)])
    lines.extend(['', labels['limitations'], *[tr(value, locale) for value in report.limitations]])
    text = '\n'.join(lines)
    return text


def repair_text(report: Report) -> str:
    report = _presentation_report(report, False)
    labels, locale = _REPORT_LABELS[report.locale], report.locale
    lines = [labels['commands'], '']
    for finding in report.findings:
        if finding.commands or finding.action:
            lines.extend([tr(finding.title, locale), tr(finding.interpretation, locale),
                          finding.evidence, *finding.commands])
            if finding.rollback:
                lines.append(labels['rollback'] + ': ' + tr(finding.rollback, locale))
            lines.append('')
    return '\n'.join(lines)


# Markdown reports are pasted into issue trackers and chats. Inventory strings
# (service names and ImagePaths, adapter names, command errors) are set by other
# local software and may contain newlines, backticks, brackets or angle brackets.
# Outside code they must not create structure; inside code they must not close
# the fence. Redaction markers such as <ip-...> are raw HTML tags in CommonMark
# and must be escaped to stay visible.
_MARKDOWN_SPECIAL = re.compile(r'([\\`*_\[\]<>&|.:])')


def markdown_text(value: Any, *, line_start: bool = False) -> str:
    """One line of literal Markdown text: no structure, links, HTML or code spans."""
    text = _MARKDOWN_SPECIAL.sub(r'\\\1', re.sub(r'[\r\n]+', ' ', str(value)))
    # GFM's email extension links even an escaped @. Split that token using
    # a zero-width space; JSON remains the lossless machine-readable export.
    text = text.replace('@', '@\u200b')
    if line_start:
        # Paragraph/list content must not start a heading, list, rule or setext underline.
        text = text.lstrip()
        ordered = re.match(r'\d{1,9}(?=[.)])', text)
        if ordered:
            text = ordered.group(0) + '\\' + text[ordered.end():]
        elif text[:1] in ('#', '-', '+', '=', '~'):
            text = '\\' + text
    return text


def markdown_code_block(content: Any, info: str = '') -> list[str]:
    """Verbatim fenced block whose fence is longer than any backtick run inside it."""
    content = str(content)
    longest = max((len(run) for run in re.findall(r'`+', content)), default=0)
    fence = '`' * max(3, longest + 1)
    return [fence + info, content, fence]


def _markdown_row(cells: list[Any]) -> str:
    return '|' + '|'.join(markdown_text(cell) for cell in cells) + '|'


def markdown_report(report: Report, full: bool = False) -> str:
    report = _presentation_report(report, full)
    labels, locale = _REPORT_LABELS[report.locale], report.locale
    text = markdown_text
    lines = [f'# {APP_NAME} v{text(report.version)}', '',
             f"- {labels['time']}: {text(report.generated_at)}", f"- {labels['system']}: {text(report.device)}",
             f"- {labels['admin']}: {text(report.administrator)}", f"- {labels['targets']}: {text(', '.join(report.hosts))}", '',
             labels['table'], '|---|---|---|---:|---:|---:|---:|---|---|---:|']
    for p in report.probes:
        lines.append(_markdown_row([p.host, p.family, p.ip, p.dns_ms, p.tcp_ms, p.tls_ms, p.http_ms,
                                    p.stage, p.http_status, len(p.attempts)]))
    for finding in report.findings:
        lines.extend(['', f'## [{text(tr(finding.severity, locale))}] {text(tr(finding.title, locale))}', '',
                      f"{labels['confidence']}: {text(finding.evidence_grade)}", '',
                      text(tr(finding.interpretation, locale), line_start=True)])
        for key, values in [('alternatives', finding.alternatives), ('verify', finding.verification), ('conditions', finding.conditions)]:
            if values:
                lines.extend(['', labels[key], '', *['- ' + text(tr(value, locale), line_start=True) for value in values]])
        lines.extend(['', labels['evidence'], '', *markdown_code_block(finding.evidence, 'text')])
        if finding.commands:
            lines.extend(['', labels['commands'], '', *markdown_code_block('\n'.join(finding.commands), 'powershell')])
        if finding.rollback:
            lines.extend(['', labels['rollback'] + ': ' + text(tr(finding.rollback, locale))])
    if report.dns_audit:
        lines.extend(['', '## ' + text(tr('DNS / Fake-IP context', locale)), '',
                      *markdown_code_block(json.dumps(report.dns_audit, ensure_ascii=False, indent=2), 'json')])
    if report.pmtu:
        lines.extend(['', '## ' + text(tr('PMTU auxiliary evidence', locale)), '',
                      *markdown_code_block(json.dumps(report.pmtu, ensure_ascii=False, indent=2), 'json')])
    if report.proxy_paths:
        lines.extend(['', '## ' + text(tr('Proxy path comparison', locale)), '',
                      *markdown_code_block(json.dumps(report.proxy_paths, ensure_ascii=False, indent=2), 'json')])
    scenarios = localized_data(report.scenarios, locale) if full else redacted_data(localized_data(report.scenarios, locale))
    history = report.repair_history if full else redacted_data(report.repair_history)
    lines.extend(['', '## ' + labels['scenarios'], '',
                  *markdown_code_block(json.dumps(scenarios, ensure_ascii=False, indent=2), 'json'),
                  '', '## ' + labels['limitations'], '', *['- ' + text(tr(value, locale), line_start=True) for value in report.limitations],
                  '', '## ' + labels['history'], '',
                  *markdown_code_block(json.dumps(history, ensure_ascii=False, indent=2), 'json')])
    return '\n'.join(lines) + '\n'
