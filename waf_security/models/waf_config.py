# -*- coding: utf-8 -*-
from odoo import models, fields, api


class WafConfig(models.Model):
    _name = 'waf.config'
    _description = 'WAF Security Configuration'
    _rec_name = 'name'

    name = fields.Char(default='Default WAF Configuration', required=True)
    active = fields.Boolean(default=True, string='WAF Aktif')

    # --- Detection toggles ---
    enable_sql_injection_detection = fields.Boolean(
        string='Deteksi SQL Injection', default=True)
    enable_xss_detection = fields.Boolean(
        string='Deteksi XSS', default=True)
    enable_rce_detection = fields.Boolean(
        string='Deteksi RCE', default=True)
    enable_path_traversal_detection = fields.Boolean(
        string='Deteksi Path Traversal', default=True)

    # --- Mode ---
    block_mode = fields.Selection([
        ('monitor', 'Monitor Only (hanya log, tidak blokir)'),
        ('block', 'Block (blokir request mencurigakan)'),
    ], default='block', string='Mode Operasi', required=True)

    # --- Rate limiting ---
    enable_rate_limiting = fields.Boolean(string='Aktifkan Rate Limiting', default=True)
    rate_limit_requests = fields.Integer(
        string='Maks. Request', default=100,
        help='Jumlah maksimum request yang diizinkan dalam periode waktu tertentu')
    rate_limit_window = fields.Integer(
        string='Periode Waktu (detik)', default=60)

    # --- Brute force protection (login) ---
    enable_brute_force_protection = fields.Boolean(
        string='Aktifkan Proteksi Brute Force', default=True)
    brute_force_max_attempts = fields.Integer(
        string='Maks. Percobaan Login Gagal', default=5)
    brute_force_window = fields.Integer(
        string='Periode Waktu Brute Force (detik)', default=300)

    # --- Auto ban ---
    auto_ban_enabled = fields.Boolean(string='Aktifkan Auto Ban', default=True)
    auto_ban_duration_hours = fields.Integer(
        string='Durasi Auto Ban (jam)', default=24)
    auto_ban_threshold = fields.Integer(
        string='Ambang Batas Pelanggaran Sebelum Ban', default=3,
        help='Berapa kali IP terdeteksi melakukan serangan sebelum otomatis di-ban')

    # --- Security headers ---
    enable_security_headers = fields.Boolean(
        string='Aktifkan Security Headers', default=True)
    enable_hsts = fields.Boolean(string='Aktifkan HSTS', default=True)
    enable_csp = fields.Boolean(string='Aktifkan Content-Security-Policy', default=True)
    csp_policy = fields.Text(
        string='CSP Policy',
        default="default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
                "style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; "
                "font-src 'self' data:;")
    enable_x_frame_options = fields.Boolean(default=True, string='X-Frame-Options')
    x_frame_options_value = fields.Selection([
        ('DENY', 'DENY'),
        ('SAMEORIGIN', 'SAMEORIGIN'),
    ], default='SAMEORIGIN', string='Nilai X-Frame-Options')

    # --- Alerting ---
    enable_email_alert = fields.Boolean(string='Aktifkan Alert Email', default=False)
    alert_email_to = fields.Char(string='Kirim Alert ke Email')
    alert_min_severity = fields.Selection([
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical'),
    ], default='high', string='Minimum Severity untuk Alert')

    enable_telegram_alert = fields.Boolean(string='Aktifkan Alert Telegram', default=False)
    telegram_bot_token = fields.Char(string='Telegram Bot Token')
    telegram_chat_id = fields.Char(string='Telegram Chat ID')

    # --- Log retention ---
    log_retention_days = fields.Integer(
        string='Retensi Log (hari)', default=90,
        help='Log lebih lama dari ini akan otomatis dihapus oleh cron job')

    # --- Excluded paths (agar tidak mengganggu asset/static Odoo) ---
    excluded_paths = fields.Text(
        string='Path yang Dikecualikan (satu per baris)',
        default='/web/static\n/websocket\n/longpolling\n/web/webclient\n/web/assets')

    # --- File Extension Block/Whitelist ---
    enable_file_extension_filtering = fields.Boolean(
        string='Aktifkan Filter Ekstensi File', default=True,
        help='Periksa ekstensi file yang di-upload lewat request ini terhadap '
             'daftar rule di menu WAF Security > File Extension Rule.')
    file_extension_mode = fields.Selection([
        ('blacklist', 'Blacklist (tolak ekstensi yang ada di daftar block)'),
        ('whitelist', 'Whitelist (hanya izinkan ekstensi yang ada di daftar whitelist)'),
    ], default='blacklist', string='Mode Filter Ekstensi', required=True,
        help='Whitelist jauh lebih ketat - pastikan sudah menambahkan semua '
             'ekstensi yang memang dibutuhkan sebelum mengaktifkan mode ini, '
             'atau upload file normal (gambar, PDF, dsb) bisa ikut terblokir.')

    # --- GeoIP Lookup (untuk Live Attack Map) ---
    enable_geoip_lookup = fields.Boolean(
        string='Aktifkan GeoIP Lookup (Live Attack Map)', default=False,
        help='NONAKTIF secara default karena memanggil layanan pihak ketiga '
             '(ip-api.com) untuk menerjemahkan IP penyerang menjadi lokasi '
             'geografis. Hanya IP yang sudah terdeteksi WAF yang dikirim, '
             'bukan data bisnis/pengguna instance ini. Wajib aktif kalau '
             'ingin melihat titik-titik di Live Attack Map.')

    # --- Subscription Monitor ---
    # Disimpan langsung sebagai field di sini (bukan lewat res.config.settings)
    # supaya tidak perlu inherit ke view Settings umum Odoo yang strukturnya
    # berbeda-beda antar versi/instalasi.
    subscription_monitor_enabled = fields.Boolean(
        string='Aktifkan Subscription Monitor', default=False,
        help='Jika aktif, ringkasan data instance ini akan dikirim berkala '
             'ke dashboard yang dikonfigurasi di bawah.')
    subscription_monitor_api_url = fields.Char(string='URL Dashboard (API Endpoint)')
    subscription_monitor_api_key = fields.Char(string='API Key')
    subscription_monitor_manual_expiration_date = fields.Char(
        string='Tanggal Kadaluarsa Manual (untuk Community)',
        help='Diisi manual jika instance ini Community (tidak punya field '
             'expiration Enterprise bawaan Odoo). Format: YYYY-MM-DD')
    subscription_monitor_include_user_list = fields.Boolean(
        string='Sertakan Daftar User (Nama, Login, Login Terakhir)', default=False,
        help='NONAKTIF secara default. Jika diaktifkan, data yang dikirim '
             'akan menyertakan daftar user internal beserta nama, login, dan '
             'waktu login terakhir mereka - ini termasuk data pribadi (PII). '
             'Pastikan sudah sesuai kebijakan privasi organisasi Anda sebelum '
             'mengaktifkan opsi ini.')
    subscription_monitor_instance_uuid = fields.Char(
        string='Instance UUID', compute='_compute_subscription_monitor_instance_uuid',
        help='Identifier unik & permanen untuk instance ini di dashboard.')

    def _compute_subscription_monitor_instance_uuid(self):
        uid = self.env['waf.subscription.monitor']._get_instance_uuid()
        for rec in self:
            rec.subscription_monitor_instance_uuid = uid

    def action_subscription_monitor_sync_now(self):
        self.ensure_one()
        self.env['waf.subscription.monitor'].sync_now(raise_on_error=True)
        return {
            'type': 'ir.actions.client',
            'tag': 'display_notification',
            'params': {
                'title': 'WAF Subscription Monitor',
                'message': 'Data berhasil dikirim ke dashboard.',
                'type': 'success',
                'sticky': False,
            },
        }

    @api.model
    def get_active_config(self):
        """Ambil konfigurasi aktif (singleton pattern sederhana)."""
        config = self.search([('active', '=', True)], limit=1)
        if not config:
            config = self.search([], limit=1)
        return config
