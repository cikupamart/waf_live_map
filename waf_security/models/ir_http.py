# -*- coding: utf-8 -*-
import logging

from odoo import models, api
from odoo.http import request
from werkzeug.exceptions import Forbidden, TooManyRequests

from . import waf_detection_engine as engine
from .waf_rate_limiter import request_tracker, threat_violation_tracker

_logger = logging.getLogger(__name__)

MAX_BODY_SCAN_BYTES = 200_000  # jangan scan body raksasa (misal upload file besar)

# CATATAN PORTING: Override `_dispatch(cls, endpoint)` sebagai classmethod
# pada `ir.http` adalah extension point yang sudah stabil di Odoo 16 dan
# beberapa versi setelahnya. Titik masuk SEMUA request HTTP Odoo, jadi tetap
# WAJIB diuji di staging setelah install: buka beberapa halaman utama
# (login, backend, website jika dipakai), pastikan tidak ada request
# normal yang ikut ter-blokir, sebelum dipakai di production.


class IrHttp(models.AbstractModel):
    _inherit = 'ir.http'

    # ------------------------------------------------------------------
    # Helper methods
    # ------------------------------------------------------------------
    @classmethod
    def _waf_get_client_ip(cls):
        httprequest = request.httprequest
        # Hormati X-Forwarded-For jika Odoo di belakang reverse proxy
        # (pastikan proxy_mode = True di odoo.conf agar ini aman/tidak dipalsukan)
        return httprequest.environ.get('HTTP_X_FORWARDED_FOR', httprequest.remote_addr) \
            or httprequest.remote_addr or 'unknown'

    @classmethod
    def _waf_is_excluded_path(cls, config, path):
        if not config or not config.excluded_paths:
            return False
        for prefix in config.excluded_paths.splitlines():
            prefix = prefix.strip()
            if prefix and path.startswith(prefix):
                return True
        return False

    @classmethod
    def _waf_gather_request_data(cls):
        """Kumpulkan semua sumber input yang perlu dipindai: query string,
        form data, dan body JSON (untuk request JSON-RPC ala Odoo)."""
        httprequest = request.httprequest
        data = {}
        try:
            for k, v in httprequest.args.items(multi=True):
                data.setdefault(k, []).append(v)
        except Exception:
            pass
        try:
            for k, v in httprequest.form.items(multi=True):
                data.setdefault(k, []).append(v)
        except Exception:
            pass

        json_blob = None
        try:
            if httprequest.content_type and 'json' in httprequest.content_type:
                raw = httprequest.get_data(cache=True, as_text=True)
                if raw and len(raw) <= MAX_BODY_SCAN_BYTES:
                    json_blob = raw
        except Exception:
            pass
        if json_blob:
            data['__json_body__'] = [json_blob]

        return data

    @classmethod
    def _waf_block(cls, reason_message):
        _logger.warning("WAF: request diblokir - %s", reason_message)
        raise Forbidden(description="Request diblokir oleh WAF Security.")

    @classmethod
    def _waf_check_file_extensions(cls, config):
        """Periksa nama file yang di-upload (multipart/form-data) terhadap
        rule block/whitelist ekstensi. Return tuple (blocked_filename,
        extension) kalau ada pelanggaran, atau None kalau aman/tidak ada
        file di request ini."""
        try:
            files = request.httprequest.files
        except Exception:
            return None
        if not files:
            return None

        FileExtRule = request.env['waf.file.extension.rule'].sudo()
        mode = config.file_extension_mode

        if mode == 'blacklist':
            rule_set = FileExtRule.get_blocked_extensions()
        else:
            rule_set = FileExtRule.get_whitelisted_extensions()

        for _key, storage in files.items(multi=True):
            filename = getattr(storage, 'filename', None)
            if not filename or '.' not in filename:
                continue
            ext = filename.rsplit('.', 1)[-1].lower().strip()
            if not ext:
                continue
            if mode == 'blacklist' and ext in rule_set:
                return (filename, ext)
            if mode == 'whitelist' and ext not in rule_set:
                return (filename, ext)
        return None

    # ------------------------------------------------------------------
    # Main dispatch override
    # ------------------------------------------------------------------
    @classmethod
    def _dispatch(cls, endpoint):
        env = request.env
        try:
            WafConfig = env['waf.config'].sudo()
            config = WafConfig.get_active_config()
        except Exception:
            # Tabel belum ada (misal saat instalasi awal) -> lewati WAF
            config = False

        if not config or not config.active:
            return super()._dispatch(endpoint)

        path = request.httprequest.path
        if cls._waf_is_excluded_path(config, path):
            return super()._dispatch(endpoint)

        ip = cls._waf_get_client_ip()
        IpRule = env['waf.ip.rule'].sudo()
        WafLog = env['waf.log'].sudo()
        block_mode = config.block_mode == 'block'

        # 1) Whitelist selalu lolos semua pengecekan lain
        if IpRule.is_whitelisted(ip):
            return super()._dispatch(endpoint)

        # 2) Blacklist -> tolak langsung
        if IpRule.is_blacklisted(ip):
            WafLog.log_event(
                ip_address=ip, url=path, method=request.httprequest.method,
                threat_type='blacklisted', severity='high',
                action_taken='blocked' if block_mode else 'logged',
                user_agent=request.httprequest.headers.get('User-Agent'),
            )
            if block_mode:
                cls._waf_block("IP di-blacklist: %s" % ip)

        # 3) Rate limiting
        if config.enable_rate_limiting:
            count = request_tracker.hit(ip, config.rate_limit_window)
            if count > config.rate_limit_requests:
                WafLog.log_event(
                    ip_address=ip, url=path, method=request.httprequest.method,
                    threat_type='rate_limit', severity='medium',
                    matched_payload=f"{count} request dalam {config.rate_limit_window}s",
                    action_taken='blocked' if block_mode else 'logged',
                    user_agent=request.httprequest.headers.get('User-Agent'),
                )
                cls._waf_maybe_autoban(config, IpRule, ip, 'Rate limit exceeded')
                if block_mode:
                    raise TooManyRequests(description="Terlalu banyak request. Coba lagi nanti.")

        # 4) Threat detection (SQLi, XSS, RCE, Path Traversal)
        enabled_checks = {
            'sql_injection': config.enable_sql_injection_detection,
            'xss': config.enable_xss_detection,
            'rce': config.enable_rce_detection,
            'path_traversal': config.enable_path_traversal_detection,
        }
        if any(enabled_checks.values()):
            data = cls._waf_gather_request_data()
            # Scan juga path URL itu sendiri (path traversal sering di path)
            data['__url_path__'] = [path]

            findings = engine.scan_request_data(data, enabled_checks)
            if findings:
                threat_type, pattern, matched_text, source_key = findings[0]
                severity = engine.SEVERITY_MAP.get(threat_type, 'medium')
                WafLog.log_event(
                    ip_address=ip, url=path, method=request.httprequest.method,
                    threat_type=threat_type, severity=severity,
                    matched_pattern=pattern, matched_payload=matched_text,
                    source_field=source_key,
                    action_taken='blocked' if block_mode else 'logged',
                    user_agent=request.httprequest.headers.get('User-Agent'),
                )
                cls._waf_maybe_autoban(
                    config, IpRule, ip, f'Terdeteksi {threat_type} pada field {source_key}')
                if block_mode:
                    cls._waf_block(f"{threat_type} terdeteksi dari {ip} pada field {source_key}")

        # 4.5) File extension block/whitelist (untuk request yang bawa upload file)
        if config.enable_file_extension_filtering:
            violation = cls._waf_check_file_extensions(config)
            if violation:
                filename, ext = violation
                WafLog.log_event(
                    ip_address=ip, url=path, method=request.httprequest.method,
                    threat_type='file_extension', severity='medium',
                    matched_payload=f"File: {filename} (ekstensi: .{ext})",
                    source_field='file_upload',
                    action_taken='blocked' if block_mode else 'logged',
                    user_agent=request.httprequest.headers.get('User-Agent'),
                )
                if block_mode:
                    cls._waf_block(
                        f"Upload file dengan ekstensi .{ext} ditolak "
                        f"(mode: {config.file_extension_mode})")

        # Lanjutkan ke dispatch normal Odoo
        response = super()._dispatch(endpoint)

        # 5) Security headers pada response
        try:
            cls._waf_apply_security_headers(config, response)
        except Exception:
            _logger.exception("WAF: gagal menambahkan security headers")

        return response

    @classmethod
    def _waf_maybe_autoban(cls, config, IpRule, ip, reason):
        if not config.auto_ban_enabled:
            return
        violations = threat_violation_tracker.hit(ip, 3600)  # window 1 jam
        if violations >= config.auto_ban_threshold:
            IpRule.auto_ban_ip(ip, reason, duration_hours=config.auto_ban_duration_hours)
            _logger.warning("WAF: IP %s otomatis di-ban. Alasan: %s", ip, reason)

    @classmethod
    def _waf_apply_security_headers(cls, config, response):
        if not config.enable_security_headers:
            return
        headers = getattr(response, 'headers', None)
        if headers is None:
            return

        if config.enable_csp and config.csp_policy:
            headers['Content-Security-Policy'] = config.csp_policy.replace('\n', ' ').strip()

        if config.enable_hsts:
            headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'

        if config.enable_x_frame_options:
            headers['X-Frame-Options'] = config.x_frame_options_value or 'SAMEORIGIN'

        headers['X-Content-Type-Options'] = 'nosniff'
        headers['X-XSS-Protection'] = '1; mode=block'
        headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
