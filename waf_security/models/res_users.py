# -*- coding: utf-8 -*-
import logging

from odoo import models, api
from odoo.exceptions import AccessDenied
from odoo.http import request

from .waf_rate_limiter import login_failure_tracker

_logger = logging.getLogger(__name__)


class ResUsers(models.Model):
    _inherit = 'res.users'

    # ------------------------------------------------------------------
    # CATATAN: signature `_login()` di Odoo 16 masih bentuk lama
    #   _login(cls, db, login, password, user_agent_env=None)
    # Mulai Odoo 17, ini berubah jadi credential-based:
    #   _login(cls, db, credential, user_agent_env=None)
    # Kalau nanti Anda upgrade instance ke Odoo 17+, override ini WAJIB
    # disesuaikan ke signature baru (lihat versi modul untuk Odoo 17/18).
    # ------------------------------------------------------------------
    @classmethod
    def _login(cls, db, login, password, user_agent_env=None):
        """Bungkus proses login (signature Odoo 16) untuk melacak percobaan
        login gagal per IP, dan blokir preemptif jika sudah melewati ambang
        batas brute force."""
        ip = 'unknown'
        try:
            if request:
                httprequest = request.httprequest
                ip = httprequest.environ.get('HTTP_X_FORWARDED_FOR', httprequest.remote_addr) \
                    or httprequest.remote_addr or 'unknown'
        except Exception:
            pass

        try:
            with cls.pool.cursor() as cr:
                env = api.Environment(cr, api.SUPERUSER_ID, {})
                config = env['waf.config'].get_active_config()
                if config and config.enable_brute_force_protection:
                    current_count = login_failure_tracker.count(ip, config.brute_force_window)
                    if current_count >= config.brute_force_max_attempts:
                        env['waf.log'].log_event(
                            ip_address=ip, url='/web/login', method='POST',
                            threat_type='brute_force', severity='high',
                            matched_payload=f"{current_count} percobaan login gagal",
                            action_taken='blocked',
                        )
                        raise AccessDenied()
        except AccessDenied:
            raise
        except Exception:
            _logger.exception("WAF: gagal memeriksa status brute force")

        try:
            result = super()._login(db, login, password, user_agent_env=user_agent_env)
            login_failure_tracker.reset(ip)
            return result
        except AccessDenied:
            try:
                with cls.pool.cursor() as cr:
                    env = api.Environment(cr, api.SUPERUSER_ID, {})
                    config = env['waf.config'].get_active_config()
                    window = config.brute_force_window if config else 300
                    count = login_failure_tracker.hit(ip, window)
                    if config and config.enable_brute_force_protection:
                        threshold = config.brute_force_max_attempts
                        env['waf.log'].log_event(
                            ip_address=ip, url='/web/login', method='POST',
                            threat_type='brute_force',
                            severity='medium' if count < threshold else 'high',
                            matched_payload=f"Percobaan login gagal ke-{count} (login: {login})",
                            action_taken='logged' if count < threshold else 'blocked',
                        )
                        if config.auto_ban_enabled and count >= threshold:
                            env['waf.ip.rule'].auto_ban_ip(
                                ip, 'Brute force login terdeteksi',
                                duration_hours=config.auto_ban_duration_hours)
            except Exception:
                _logger.exception("WAF: gagal mencatat kegagalan login")
            raise
