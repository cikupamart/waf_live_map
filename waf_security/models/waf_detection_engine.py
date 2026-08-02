# -*- coding: utf-8 -*-
"""
WAF Detection Engine
=====================
Modul ini berisi kumpulan pattern (signature) berbasis regex untuk
mendeteksi payload berbahaya yang umum digunakan dalam serangan web.

Pendekatan ini disebut "signature-based detection" - salah satu teknik
paling dasar dan paling banyak dipelajari dalam konsep WAF. Kelemahannya:
signature bisa di-bypass dengan teknik obfuscation/encoding, sehingga
di real-world biasanya dikombinasikan dengan teknik lain seperti
anomaly detection, machine learning, atau virtual patching.
"""

import re
import urllib.parse
import logging

_logger = logging.getLogger(__name__)


class ThreatSignatures:
    """Kumpulan signature (pola regex) untuk berbagai jenis serangan."""

    # ---------------------------------------------------------------
    # SQL Injection
    # ---------------------------------------------------------------
    SQL_INJECTION_PATTERNS = [
        r"(\%27)|(\')|(\-\-)|(\%23)|(#)",                       # quote / comment
        r"((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))",   # ' = or ;
        r"\bunion\b.{1,100}\bselect\b",
        r"\bselect\b.{1,100}\bfrom\b",
        r"\binsert\b.{1,100}\binto\b",
        r"\bupdate\b.{1,100}\bset\b",
        r"\bdelete\b.{1,100}\bfrom\b",
        r"\bdrop\b.{1,100}\b(table|database)\b",
        r"\bexec(\s|\+)+(x|s)p\w+",
        r"\bor\b\s+\d+\s*=\s*\d+",                               # OR 1=1
        r"\band\b\s+\d+\s*=\s*\d+",
        r"'\s*or\s*'?\d",
        r"waitfor\s+delay",
        r"benchmark\s*\(",
        r"sleep\s*\(\s*\d+\s*\)",
        r"information_schema",
        r"pg_sleep\s*\(",
        r"into\s+outfile",
        r"load_file\s*\(",
    ]

    # ---------------------------------------------------------------
    # Cross Site Scripting (XSS)
    # ---------------------------------------------------------------
    XSS_PATTERNS = [
        r"<script[^>]*>.*?</script>",
        r"<script[^>]*>",
        r"javascript\s*:",
        r"vbscript\s*:",
        r"on(load|error|click|mouseover|focus|blur|change|submit)\s*=",
        r"<iframe[^>]*>",
        r"<embed[^>]*>",
        r"<object[^>]*>",
        r"<img[^>]+src\s*=\s*[\"']?javascript:",
        r"<svg[^>]*onload",
        r"expression\s*\(",
        r"document\.(cookie|location|write)",
        r"eval\s*\(",
        r"alert\s*\(",
        r"String\.fromCharCode",
        r"<\s*meta[^>]+http-equiv",
    ]

    # ---------------------------------------------------------------
    # Remote Code Execution (RCE) / Command Injection
    # ---------------------------------------------------------------
    RCE_PATTERNS = [
        r";\s*(ls|cat|whoami|id|pwd|uname)\b",
        r"\|\s*(ls|cat|whoami|id|pwd|nc|netcat)\b",
        r"`.*`",                                     # backticks
        r"\$\([^)]+\)",                               # $(command)
        r"\b(system|exec|shell_exec|passthru|popen|proc_open)\s*\(",
        r"\bos\.(system|popen|exec)\w*\s*\(",
        r"\bsubprocess\.\w+\s*\(",
        r"__import__\s*\(",
        r"\bwget\s+http",
        r"\bcurl\s+http",
        r"base64_decode\s*\(",
        r"powershell\s+-",
        r"nc\s+-e\s",
        r"/bin/(ba)?sh",
        r"cmd(\.exe)?\s*/c",
    ]

    # ---------------------------------------------------------------
    # Path Traversal / Local File Inclusion
    # ---------------------------------------------------------------
    PATH_TRAVERSAL_PATTERNS = [
        r"\.\./",
        r"\.\.\\",
        r"%2e%2e%2f",
        r"%2e%2e/",
        r"\.\.%2f",
        r"/etc/passwd",
        r"/etc/shadow",
        r"boot\.ini",
        r"win\.ini",
        r"\\windows\\win\.ini",
        r"php://filter",
        r"php://input",
        r"file://",
        r"c:\\\\windows",
    ]

    @classmethod
    def _compile(cls, patterns):
        return [re.compile(p, re.IGNORECASE | re.DOTALL) for p in patterns]


# Pre-compile semua pattern sekali saat module di-load (performa lebih baik)
_COMPILED = {
    'sql_injection': ThreatSignatures._compile(ThreatSignatures.SQL_INJECTION_PATTERNS),
    'xss': ThreatSignatures._compile(ThreatSignatures.XSS_PATTERNS),
    'rce': ThreatSignatures._compile(ThreatSignatures.RCE_PATTERNS),
    'path_traversal': ThreatSignatures._compile(ThreatSignatures.PATH_TRAVERSAL_PATTERNS),
}


def _normalize(value):
    """Normalisasi string: url-decode berlapis untuk mengurangi bypass sederhana
    via encoding (contoh: %2527 -> %27 -> ')."""
    if not isinstance(value, str):
        try:
            value = str(value)
        except Exception:
            return ""
    decoded = value
    for _ in range(3):
        try:
            new_decoded = urllib.parse.unquote(decoded)
        except Exception:
            break
        if new_decoded == decoded:
            break
        decoded = new_decoded
    return decoded


def scan_value(value, enabled_checks):
    """
    Scan satu nilai (string) terhadap semua kategori ancaman yang aktif.

    :param value: nilai mentah dari request (param, header, path, dll)
    :param enabled_checks: dict {threat_type: bool}
    :return: list of tuples (threat_type, pattern_matched, matched_text) atau []
    """
    findings = []
    if not value:
        return findings

    normalized = _normalize(value)

    for threat_type, patterns in _COMPILED.items():
        if not enabled_checks.get(threat_type):
            continue
        for pattern in patterns:
            match = pattern.search(normalized)
            if match:
                findings.append((threat_type, pattern.pattern, match.group(0)[:200]))
                break  # satu match per kategori sudah cukup untuk trigger
    return findings


def scan_request_data(data_dict, enabled_checks):
    """
    Scan seluruh dict (misal request.params atau headers) dan kembalikan
    semua temuan.

    :param data_dict: dict of key -> value
    :return: list of findings [(threat_type, pattern, matched_text, source_key), ...]
    """
    all_findings = []
    if not data_dict:
        return all_findings

    for key, value in data_dict.items():
        # value bisa berupa list (multi-value param)
        values = value if isinstance(value, (list, tuple)) else [value]
        for v in values:
            findings = scan_value(v, enabled_checks)
            for threat_type, pattern, matched_text in findings:
                all_findings.append((threat_type, pattern, matched_text, key))
    return all_findings


SEVERITY_MAP = {
    'sql_injection': 'critical',
    'rce': 'critical',
    'xss': 'high',
    'path_traversal': 'high',
}
