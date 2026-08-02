# -*- coding: utf-8 -*-
from odoo import http
from odoo.http import request


class WafSecurityController(http.Controller):
    """Endpoint JSON internal untuk widget frontend (Live Attack Map &
    Dashboard Monitoring). Dipanggil lewat RPC dari Owl component, BUKAN
    dimaksudkan untuk diakses publik - karena itu setiap endpoint memverifikasi
    user login & keanggotaan group WAF Viewer/Manager sebelum mengembalikan
    data apa pun.
    """

    def _check_waf_access(self):
        """Return True jika user saat ini boleh melihat data WAF."""
        user = request.env.user
        if user._is_public():
            return False
        return user.has_group('waf_security.group_waf_viewer')

    @http.route('/waf_security/live_attack_feed', type='json', auth='user')
    def live_attack_feed(self, minutes=60, limit=200):
        if not self._check_waf_access():
            return {'error': 'access_denied'}
        config = request.env['waf.config'].sudo().get_active_config()
        data = request.env['waf.log'].sudo().get_live_attack_feed(
            minutes=minutes, limit=limit)
        return {
            'attacks': data,
            'geoip_enabled': bool(config and config.enable_geoip_lookup),
        }

    @http.route('/waf_security/dashboard_stats', type='json', auth='user')
    def dashboard_stats(self):
        if not self._check_waf_access():
            return {'error': 'access_denied'}
        return request.env['waf.log'].sudo().get_dashboard_stats()
