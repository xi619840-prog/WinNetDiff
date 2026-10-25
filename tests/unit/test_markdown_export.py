"""Markdown reports must not let inventory strings create structure or escape code.

The scanner encodes the CommonMark rules that matter here (spec 0.31):
- 4.5 fenced code: a closing backtick fence is indented at most three spaces,
  has at least as many backticks as the opening fence, and nothing but spaces
  or tabs after it. CR, LF and CRLF all end a line.
- 6.3 code spans, 6.6 raw HTML open tags (`<` ASCII letter, then letters,
  digits or hyphens), 6.5 autolinks and 6.3 inline links `[text](dest)`.
A backslash before ASCII punctuation makes it literal (2.4).
"""
import json
import re
import unittest
from pathlib import Path

import windows_net_diffdiag as app
from winnetdiff.core import privacy
from winnetdiff.core.models import Finding, Probe, Report, VERSION
from winnetdiff.reports import export

OPEN_FENCE = re.compile(r'^ {0,3}(`{3,})([^`]*)$')
CLOSE_FENCE = re.compile(r'^ {0,3}(`{3,})[ \t]*$')
UNESCAPED = r'(?<!\\)'
RAW_HTML_TAG = re.compile(UNESCAPED + r'<[A-Za-z][A-Za-z0-9-]*(?:\s[^<>]*)?/?>')
AUTOLINK = re.compile(UNESCAPED + r'<[A-Za-z][A-Za-z0-9+.-]{1,31}:[^\s<>]*>')
INLINE_LINK = re.compile(UNESCAPED + r'\[[^\]]*' + UNESCAPED + r'\]\(')
CODE_SPAN = re.compile(UNESCAPED + r'`')

PATH_ERROR = ('C:\\Vendor\\svc.sys\n```\n'
              '**Recommended fix:** download the [repair tool](https://evil.invalid/fix.exe)\n```')
SERVICE = 'VendorSvc — see [support](https://evil.invalid/help) `code` <b>x</b> <https://evil.invalid/a>'


def classify(markdown):
    """Yield (in_code_block, line) for each line under CommonMark fence rules."""
    fence = None
    for line in re.split(r'\r\n|\r|\n', markdown):
        if fence is None:
            opened = OPEN_FENCE.match(line)
            if opened:
                fence = len(opened.group(1))
            yield bool(opened), line
        else:
            closed = CLOSE_FENCE.match(line)
            yield True, line
            if closed and len(closed.group(1)) >= fence:
                fence = None


def hostile_report(locale='en', title_suffix=''):
    return Report(VERSION, '2026-10-25T00:00:00+08:00', 'Synthetic Windows 11', False, ['www.example.com'],
                  {'errors': []}, {'errors': []},
                  [Probe('www.example.com', 'IPv4', ip='192.168.31.27', stage='http_ok', dns_ms=1, tcp_ms=2,
                         tls_ms=3, http_ms=4, http_status=200)],
                  {'errors': [PATH_ERROR]},
                  [Finding('可疑', '安全/驅動', 'Suspected orphan component: ' + SERVICE + title_suffix, PATH_ERROR,
                           '# not a heading\nsecond line', alternatives=['1. not a list', '- not nested'],
                           verification=['Get-AuthenticodeSignature -LiteralPath ' + "'C:\\x`y.sys'"],
                           commands=['echo ```', 'echo ````'], rollback='[undo](https://evil.invalid/u)')],
                  ['- limitation with <user> marker'], locale=locale)


class MarkdownReportSafetyTests(unittest.TestCase):
    def setUp(self):
        privacy.set_pseudonym_key(bytes(32))
        app.set_pseudonym_key(bytes(32))

    def tearDown(self):
        privacy.set_pseudonym_key(None)
        app.set_pseudonym_key(None)

    def render(self, module, report, full=False):
        return module.markdown_report(report, full)

    def test_hostile_strings_never_reach_markdown_structure(self):
        for label, module in (('modular', export), ('standalone', app)):
            for full in (False, True):
                with self.subTest(module=label, full=full):
                    markdown = self.render(module, hostile_report(), full)
                    outside = [line for code, line in classify(markdown) if not code]
                    for line in outside:
                        self.assertIsNone(INLINE_LINK.search(line), line)
                        self.assertIsNone(RAW_HTML_TAG.search(line), line)
                        self.assertIsNone(AUTOLINK.search(line), line)
                        self.assertIsNone(CODE_SPAN.search(line), line)
                    self.assertFalse(any('evil.invalid/fix.exe' in line for line in outside))
                    self.assertFalse(any(re.match(r' {0,3}#+ not a heading', line) for line in outside))
                    self.assertFalse(any(re.match(r' {0,3}(?:\d+[.)]|[-+*]) not', line) for line in outside))

    def test_code_blocks_are_verbatim_and_closed(self):
        markdown = self.render(export, hostile_report(), full=True)
        blocks, current, fence = [], None, None
        for line in re.split(r'\r\n|\r|\n', markdown):
            if current is None:
                opened = OPEN_FENCE.match(line)
                if opened:
                    current, fence = [], len(opened.group(1))
            else:
                closed = CLOSE_FENCE.match(line)
                if closed and len(closed.group(1)) >= fence:
                    blocks.append('\n'.join(current))
                    current = None
                else:
                    current.append(line)
        self.assertIsNone(current, 'a fenced block was left open')
        self.assertIn(PATH_ERROR, blocks)
        self.assertIn('echo ```\necho ````', blocks)

    def test_redaction_markers_stay_visible_as_text(self):
        markdown = self.render(export, hostile_report())
        outside = '\n'.join(line for code, line in classify(markdown) if not code)
        self.assertNotIn('192.168.31.27', markdown)
        self.assertRegex(outside, r'\\<ip-[0-9a-f]{12}\\>')
        self.assertIn('\\<private-value-redacted\\>', outside)

    def test_table_rows_keep_their_column_count(self):
        report = hostile_report()
        report.probes[0].ip = 'a|b'
        report.probes[0].stage = 'x|y|z'
        rows = [line for code, line in classify(self.render(export, report, full=True))
                if not code and line.startswith('|') and 'www.example.com' in re.sub(r'\\([!-/:-@\[-`{-~])', r'\1', line)]
        self.assertEqual(1, len(rows))
        self.assertEqual(11, len(re.findall(UNESCAPED + r'\|', rows[0])))

    def test_newlines_in_titles_cannot_start_blocks(self):
        markdown = self.render(export, hostile_report(title_suffix='\n# Injected heading\n```'))
        self.assertFalse(any(line.startswith('# Injected') for code, line in classify(markdown) if not code))
        self.assertEqual(1, sum(line.startswith('## [') and 'Injected heading' in line for code, line in classify(markdown)))

    def test_localized_reports_are_escaped_the_same_way(self):
        for locale in ('zh-CN', 'zh-TW'):
            with self.subTest(locale=locale):
                outside = [line for code, line in classify(self.render(export, hostile_report(locale))) if not code]
                self.assertTrue(all(INLINE_LINK.search(line) is None for line in outside))


class MarkdownHelperTests(unittest.TestCase):
    def test_fence_is_longer_than_any_backtick_run(self):
        for content, fence in (('plain', '```'), ('a ``` b', '````'), ('`````', '``````'), ('x\r```', '````')):
            with self.subTest(content=content):
                self.assertEqual([fence + 'json', content, fence], export.markdown_code_block(content, 'json'))

    def test_text_escaping_is_reversible_by_a_commonmark_reader(self):
        value = 'C:\\a [b](c) `d` <e> & f | g * h'
        escaped = export.markdown_text(value)
        self.assertEqual(value, re.sub(r'\\([!-/:-@\[-`{-~])', r'\1', escaped).replace('\u200b', ''))

    def test_snapshot_comparison_markdown_uses_dynamic_fences(self):
        cli_source = Path(export.__file__).resolve().parents[1] / 'cli.py'
        self.assertNotIn('```', cli_source.read_text(encoding='utf-8'))


if __name__ == '__main__':
    unittest.main()
