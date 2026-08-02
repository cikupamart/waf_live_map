# -*- coding: utf-8 -*-
import logging
import json
import urllib.request

from odoo import models, fields, api

_logger = logging.getLogger(__name__)


class WafLog(models.Model):
    _name = 'waf.log'
    _description = 'WAF Audit Log'
    _order = 'create_date desc'
    _rec_name = 'display_name_computed'

    ip_address = fields.Char(string='Alamat IP', index=True)
    user_id = fields.Many2one('res.users', string='User')
    url = fields.Char(string='URL')
    method = fields.Char(string='HTTP Method')
    threat_type = fields.Selection([
        ('sql_injection', 'SQL Injection'),
        ('xss', 'XSS'),
        ('rce', 'RCE / Command Injection'),
        ('path_traversal', 'Path Traversal'),
        ('rate_limit', 'Rate Limit Exceeded'),
        ('brute_force', 'Brute Force Login'),
        ('blacklisted', 'Blacklisted IP'),
        ('file_extension', 'Ekstensi File Diblokir'),
        ('other', 'Lainnya'),
    ], string='Jenis Ancaman', index=True)
    severity = fields.Selection([
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical'),
    ], string='Severity', default='medium', index=True)
    matched_pattern = fields.Char(string='Pattern yang Cocok')
    matched_payload = fields.Text(string='Payload Terdeteksi')
    source_field = fields.Char(string='Sumber (Parameter/Header)')
    request_snippet = fields.Text(string='Cuplikan Request')
    action_taken = fields.Selection([
        ('logged', 'Hanya Dicatat'),
        ('blocked', 'Diblokir'),
        ('banned', 'IP Di-ban'),
    ], string='Tindakan', default='logged')
    user_agent = fields.Char(string='User Agent')

    # --- Geolocation (untuk Live Attack Map) ---
    latitude = fields.Float(string='Latitude', digits=(10, 6))
    longitude = fields.Float(string='Longitude', digits=(10, 6))
    country_code = fields.Char(string='Kode Negara')
    country_name = fields.Char(string='Negara')
    city = fields.Char(string='Kota')
    geo_status = fields.Selection([
        ('pending', 'Menunggu'),
        ('resolved', 'Berhasil'),
        ('skipped', 'Dilewati (IP privat/lokal)'),
        ('failed', 'Gagal'),
    ], string='Status Geo', default='pending', index=True)

    display_name_computed = fields.Char(compute='_compute_display_name_computed', store=True)

    # PENTING: nama method ini SENGAJA bukan `_compute_display_name` -
    # itu nama yang dipakai Odoo secara internal untuk compute method
    # bawaan field `display_name` (field reserved yang ada di semua
    # model). Kalau nama method compute kita sama persis, Odoo akan
    # menganggap method ini SEBAGAI compute method untuk `display_name`
    # juga (karena konvensi penamaan `_compute_<field>`), padahal isinya
    # cuma mengisi `display_name_computed` - field `display_name` yang
    # sebenarnya jadi tidak pernah ke-assign, dan Odoo melempar error
    # "Compute method failed to assign ... .display_name". Ini contoh
    # bagus soal bahaya penamaan yang bentrok dengan konvensi framework.
    @api.depends('ip_address', 'threat_type')
    def _compute_display_name_computed(self):
        for rec in self:
            rec.display_name_computed = f"[{rec.threat_type or '-'}] {rec.ip_address or '-'}"

    @api.model
    def log_event(self, ip_address=None, user_id=None, url=None, method=None,
                  threat_type='other', severity='medium', matched_pattern=None,
                  matched_payload=None, source_field=None, request_snippet=None,
                  action_taken='logged', user_agent=None):
        """Entry point utama untuk mencatat event WAF dan memicu alert bila perlu."""
        vals = {
            'ip_address': ip_address,
            'user_id': user_id,
            'url': url,
            'method': method,
            'threat_type': threat_type,
            'severity': severity,
            'matched_pattern': matched_pattern,
            'matched_payload': matched_payload,
            'source_field': source_field,
            'request_snippet': request_snippet,
            'action_taken': action_taken,
            'user_agent': user_agent,
        }
        log = self.sudo().create(vals)
        try:
            log._maybe_send_alert()
        except Exception:
            _logger.exception("WAF: gagal mengirim alert")
        return log

    def _maybe_send_alert(self):
        self.ensure_one()
        config = self.env['waf.config'].sudo().get_active_config()
        if not config:
            return

        severity_order = {'low': 0, 'medium': 1, 'high': 2, 'critical': 3}
        min_severity = severity_order.get(config.alert_min_severity, 2)
        current_severity = severity_order.get(self.severity, 0)
        if current_severity < min_severity:
            return

        subject = f"[WAF ALERT] {self.threat_type} terdeteksi dari IP {self.ip_address}"
        body = (
            f"Waktu: {self.create_date}\n"
            f"IP: {self.ip_address}\n"
            f"URL: {self.url}\n"
            f"Method: {self.method}\n"
            f"Jenis Ancaman: {self.threat_type}\n"
            f"Severity: {self.severity}\n"
            f"Tindakan: {self.action_taken}\n"
            f"Pattern: {self.matched_pattern}\n"
            f"Payload: {self.matched_payload}\n"
        )

        if config.enable_email_alert and config.alert_email_to:
            self._send_email_alert(config, subject, body)

        if config.enable_telegram_alert and config.telegram_bot_token and config.telegram_chat_id:
            self._send_telegram_alert(config, subject + "\n\n" + body)

    def _send_email_alert(self, config, subject, body):
        try:
            mail_values = {
                'subject': subject,
                'body_html': f"<pre>{body}</pre>",
                'email_to': config.alert_email_to,
                'auto_delete': True,
            }
            self.env['mail.mail'].sudo().create(mail_values).send()
        except Exception:
            _logger.exception("WAF: gagal mengirim email alert")

    def _send_telegram_alert(self, config, text):
        """Kirim alert ke Telegram menggunakan Bot API.
        Menggunakan urllib bawaan agar tidak menambah dependency eksternal.
        """
        try:
            url = f"https://api.telegram.org/bot{config.telegram_bot_token}/sendMessage"
            data = json.dumps({
                'chat_id': config.telegram_chat_id,
                'text': text[:4000],
            }).encode('utf-8')
            req = urllib.request.Request(
                url, data=data, headers={'Content-Type': 'application/json'})
            urllib.request.urlopen(req, timeout=5)
        except Exception:
            _logger.exception("WAF: gagal mengirim telegram alert")

    @api.model
    def cron_cleanup_old_logs(self):
        """Dipanggil oleh scheduled action untuk membersihkan log lama."""
        config = self.env['waf.config'].sudo().get_active_config()
        retention_days = config.log_retention_days if config else 90
        if retention_days <= 0:
            return
        threshold = fields.Datetime.now() - __import__('datetime').timedelta(days=retention_days)
        old_logs = self.sudo().search([('create_date', '<', threshold)])
        old_logs.unlink()

    # ------------------------------------------------------------------
    # Geolocation untuk Live Attack Map
    # ------------------------------------------------------------------
    # Resolusi IP->lokasi SENGAJA dilakukan async lewat cron, BUKAN pada saat
    # request diblokir (di ir_http._dispatch). Kalau dipanggil sinkron di situ,
    # setiap request yang diblokir jadi ikut menunggu network call ke API
    # eksternal - bisa memperlambat WAF itu sendiri atau bahkan gagal total
    # kalau API geolocation sedang down. Jadi log tetap tercatat instan,
    # dan lokasinya menyusul diisi oleh cron beberapa saat kemudian.
    @staticmethod
    def _is_public_ip(ip_address):
        try:
            import ipaddress
            ip_obj = ipaddress.ip_address(ip_address.split(',')[0].strip())
            return not (
                ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
                or ip_obj.is_reserved or ip_obj.is_multicast
            )
        except Exception:
            return False

    @api.model
    def _cron_resolve_geo(self, batch_size=40):
        """Resolve lokasi geografis untuk log yang belum ada koordinatnya.
        Memakai ip-api.com (free tier, non-komersial, batch endpoint,
        limit ~45 request/menit) - tidak perlu API key. Kalau instance Anda
        butuh volume lebih besar atau dipakai komersial, ganti ke provider
        berbayar (mis. ipinfo.io, MaxMind GeoLite2 lokal) di method ini.

        Method ini TIDAK melakukan apa pun kecuali `enable_geoip_lookup`
        diaktifkan eksplisit di Konfigurasi WAF - supaya tidak ada panggilan
        ke layanan eksternal tanpa admin sadar mengaktifkannya.
        """
        config = self.env['waf.config'].sudo().get_active_config()
        if not config or not config.enable_geoip_lookup:
            return

        try:
            import requests
        except ImportError:
            _logger.warning("WAF: library 'requests' tidak tersedia, geo resolution dilewati.")
            return

        pending = self.sudo().search([('geo_status', '=', 'pending')], limit=batch_size)
        if not pending:
            return

        to_lookup = []
        for log in pending:
            ip = (log.ip_address or '').split(',')[0].strip()
            if not ip or not self._is_public_ip(ip):
                log.write({'geo_status': 'skipped'})
                continue
            to_lookup.append(log)

        if not to_lookup:
            return

        # ip-api.com mendukung batch lookup (maks 100 IP per call) lewat
        # POST ke endpoint /batch - lebih efisien daripada satu request per IP.
        try:
            payload = [{'query': (log.ip_address or '').split(',')[0].strip()} for log in to_lookup]
            resp = requests.post(
                'http://ip-api.com/batch?fields=status,country,countryCode,city,lat,lon,query',
                json=payload, timeout=10,
            )
            results = resp.json() if resp.status_code == 200 else []
        except Exception:
            _logger.exception("WAF: gagal memanggil layanan geolocation")
            results = []

        results_by_ip = {r.get('query'): r for r in results if isinstance(r, dict)}

        for log in to_lookup:
            ip = (log.ip_address or '').split(',')[0].strip()
            result = results_by_ip.get(ip)
            if not result or result.get('status') != 'success':
                log.write({'geo_status': 'failed'})
                continue
            log.write({
                'latitude': result.get('lat') or 0.0,
                'longitude': result.get('lon') or 0.0,
                'country_code': result.get('countryCode') or False,
                'country_name': result.get('country') or False,
                'city': result.get('city') or False,
                'geo_status': 'resolved',
            })

    @api.model
    def get_live_attack_feed(self, minutes=60, limit=200):
        """Data untuk widget Live Attack Map: log yang sudah ter-geolokasi
        dalam N menit terakhir. Dipakai oleh controller JSON endpoint."""
        threshold = fields.Datetime.now() - __import__('datetime').timedelta(minutes=minutes)
        logs = self.sudo().search([
            ('geo_status', '=', 'resolved'),
            ('create_date', '>=', threshold),
        ], order='create_date desc', limit=limit)
        return [{
            'id': log.id,
            'ip': log.ip_address,
            'lat': log.latitude,
            'lon': log.longitude,
            'city': log.city or '',
            'country': log.country_name or '',
            'country_code': (log.country_code or '').lower(),
            'threat_type': log.threat_type,
            'severity': log.severity,
            'action_taken': log.action_taken,
            'url': log.url or '',
            'time': log.create_date.strftime('%Y-%m-%d %H:%M:%S') if log.create_date else '',
        } for log in logs]

    @api.model
    def get_dashboard_stats(self):
        """Ringkasan angka untuk Dashboard Monitoring (stat cards)."""
        import datetime
        now = fields.Datetime.now()
        today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        last_24h = now - datetime.timedelta(hours=24)

        Log = self.sudo()
        IpRule = self.env['waf.ip.rule'].sudo()

        total_today = Log.search_count([('create_date', '>=', today_start)])
        blocked_today = Log.search_count([
            ('create_date', '>=', today_start), ('action_taken', '=', 'blocked')])
        critical_24h = Log.search_count([
            ('create_date', '>=', last_24h), ('severity', '=', 'critical')])
        active_bans = IpRule.search_count([
            ('rule_type', '=', 'blacklist'), ('active', '=', True)])

        by_threat = {}
        for group in Log.read_group(
                [('create_date', '>=', last_24h)], ['threat_type'], ['threat_type']):
            by_threat[group['threat_type'] or 'other'] = group['threat_type_count']

        return {
            'total_today': total_today,
            'blocked_today': blocked_today,
            'critical_24h': critical_24h,
            'active_bans': active_bans,
            'by_threat_24h': by_threat,
        }
