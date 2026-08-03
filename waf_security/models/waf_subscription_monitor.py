# -*- coding: utf-8 -*-
import json
import logging
import uuid

from odoo import api, fields, models, release
from odoo.exceptions import UserError

_logger = logging.getLogger(__name__)

try:
    import requests
except ImportError:  # pragma: no cover
    requests = None


class WafSubscriptionLog(models.Model):
    _name = 'waf.subscription.log'
    _description = 'WAF Subscription Monitor - Sync Log'
    _order = 'create_date desc'

    name = fields.Char(string='Ringkasan', default='Sync ke dashboard')
    state = fields.Selection([
        ('success', 'Sukses'),
        ('error', 'Gagal'),
    ], string='Status', required=True)
    http_status = fields.Char(string='HTTP Status')
    payload = fields.Text(string='Payload Terkirim')
    response = fields.Text(string='Response Server')
    create_date = fields.Datetime(string='Waktu', readonly=True)


class WafSubscriptionMonitor(models.AbstractModel):
    """Kumpulan logic untuk mengambil data instance dan mengirimnya
    ke dashboard eksternal (mis. dashboard milik partner/MSP yang
    mengelola instance ini).

    Model ini abstract (tidak menyimpan record), dipanggil dari cron
    maupun tombol manual di form Konfigurasi WAF (menu WAF Security >
    Konfigurasi > tab Subscription Monitor). Semua pengaturan yang bisa
    diedit user (enabled, URL, API key, dll) disimpan sebagai field biasa
    di model `waf.config` - BUKAN lewat res.config.settings/ir.config_
    parameter - supaya modul ini tidak bergantung pada struktur halaman
    Settings umum Odoo yang berbeda-beda antar versi/instalasi.

    Satu-satunya yang tetap disimpan di ir.config_parameter adalah
    instance_uuid, karena itu murni identifier internal permanen, bukan
    sesuatu yang perlu diedit user lewat form.

    CATATAN PRIVASI - PENTING:
    -----------------------------
    Data yang dikirim bisa mencakup daftar user internal (nama, login,
    waktu login terakhir) jika opsi "Sertakan Daftar User" di form
    Konfigurasi WAF diaktifkan. Data ini adalah PII (Personally
    Identifiable Information) karyawan. Pastikan:
    1. Admin instance SADAR dan SETUJU fitur ini aktif serta ke mana
       data dikirim (URL dashboard dikonfigurasi eksplisit, bukan
       hardcoded tanpa sepengetahuan admin).
    2. Kalau tidak benar-benar perlu detail per-user, biarkan toggle
       "Sertakan Daftar User" nonaktif - default-nya memang OFF, dan sync
       hanya mengirim ringkasan agregat (jumlah user, dsb), bukan nama/
       email individual.
    3. Cek regulasi privasi data yang berlaku (mis. UU PDP di Indonesia,
       atau GDPR jika ada user/data subject di Eropa) sebelum mengaktifkan
       pengiriman data personal ke pihak ketiga.
    """
    _name = 'waf.subscription.monitor'
    _description = 'WAF Subscription Monitor - Core Logic'

    # ---------------------------------------------------------------
    # Helper instance UUID (satu-satunya yang tetap pakai ir.config_parameter)
    # ---------------------------------------------------------------
    @api.model
    def _get_instance_uuid(self):
        """UUID unik & persisten per database, dibuat sekali saja."""
        icp = self.env['ir.config_parameter'].sudo()
        uid = icp.get_param('waf_security.subscription_monitor.instance_uuid')
        if not uid:
            uid = str(uuid.uuid4())
            icp.set_param('waf_security.subscription_monitor.instance_uuid', uid)
        return uid

    @api.model
    def _is_enterprise(self):
        return bool(self.env['ir.module.module'].sudo().search_count([
            ('name', '=', 'web_enterprise'),
            ('state', '=', 'installed'),
        ]))

    # ---------------------------------------------------------------
    # Pengumpulan data instance
    # ---------------------------------------------------------------
    @api.model
    def _collect_instance_data(self, config):
        icp = self.env['ir.config_parameter'].sudo()
        Users = self.env['res.users'].sudo()

        active_user_count = Users.search_count([
            ('active', '=', True),
            ('share', '=', False),  # exclude portal/public user
        ])
        total_user_count = Users.search_count([('active', '=', True)])

        companies = self.env['res.company'].sudo().search([])

        data = {
            'instance_uuid': self._get_instance_uuid(),
            'database_name': self.env.cr.dbname,
            'domain': icp.get_param('web.base.url'),
            'odoo_version': release.version,
            'edition': 'enterprise' if self._is_enterprise() else 'community',
            'active_internal_users': active_user_count,
            'active_total_users': total_user_count,
            'companies': [{
                'name': c.name,
                'country': c.country_id.name or '',
            } for c in companies],
            'main_company': self.env.company.name,
            # Field standar Odoo Enterprise untuk tanggal kadaluarsa subscription.
            # Untuk Community, field ini biasanya kosong; boleh diisi manual lewat
            # menu WAF Security > Konfigurasi > tab Subscription Monitor.
            'subscription_expiration_date': (
                icp.get_param('database.expiration_date')
                or config.subscription_monitor_manual_expiration_date
                or False
            ),
            'installed_apps_count': self.env['ir.module.module'].sudo().search_count(
                [('state', '=', 'installed')]
            ),
        }

        # Daftar user internal (nama, login, waktu login terakhir) HANYA
        # dikirim jika admin secara eksplisit mengaktifkan opsi ini.
        # Default: OFF (lihat catatan privasi di docstring class ini).
        if config.subscription_monitor_include_user_list:
            internal_users = Users.search([
                ('active', '=', True),
                ('share', '=', False),
            ])
            data['user_logins'] = [{
                'name': u.name,
                'login': u.login,
                'last_login': u.login_date.strftime('%Y-%m-%d %H:%M:%S') if u.login_date else False,
            } for u in internal_users]

        return data

    # ---------------------------------------------------------------
    # Pengiriman ke dashboard
    # ---------------------------------------------------------------
    @api.model
    def sync_now(self, raise_on_error=False):
        """Kumpulkan data instance dan kirim ke dashboard eksternal.
        Dipanggil dari cron maupun tombol manual di form Konfigurasi WAF.
        """
        if requests is None:
            _logger.error("Library 'requests' tidak tersedia di environment ini.")
            if raise_on_error:
                raise UserError("Library 'requests' tidak tersedia di server Odoo.")
            return False

        config = self.env['waf.config'].sudo().get_active_config()
        if not config:
            msg = 'Konfigurasi WAF belum ada.'
            if raise_on_error:
                raise UserError(msg)
            return False

        if not config.subscription_monitor_enabled and not raise_on_error:
            # Sync manual (raise_on_error=True) tetap boleh jalan walau belum
            # di-enable, untuk keperluan test koneksi.
            return False

        api_url = config.subscription_monitor_api_url
        api_key = config.subscription_monitor_api_key

        if not api_url or not api_key:
            msg = 'URL Dashboard atau API Key belum dikonfigurasi.'
            _logger.warning(msg)
            self.env['waf.subscription.log'].sudo().create({
                'state': 'error',
                'response': msg,
            })
            if raise_on_error:
                raise UserError(msg)
            return False

        payload = self._collect_instance_data(config)

        try:
            resp = requests.post(
                api_url,
                json=payload,
                headers={
                    'Content-Type': 'application/json',
                    'Authorization': 'Bearer %s' % api_key,
                },
                timeout=15,
            )
            log_vals = {
                'payload': json.dumps(payload, indent=2, ensure_ascii=False),
                'http_status': str(resp.status_code),
            }
            if 200 <= resp.status_code < 300:
                log_vals.update({
                    'state': 'success',
                    'response': resp.text[:5000],
                })
                self.env['waf.subscription.log'].sudo().create(log_vals)
                return True
            else:
                log_vals.update({
                    'state': 'error',
                    'response': resp.text[:5000],
                })
                self.env['waf.subscription.log'].sudo().create(log_vals)
                if raise_on_error:
                    raise UserError(
                        'Gagal mengirim data ke dashboard (HTTP %s): %s'
                        % (resp.status_code, resp.text[:500])
                    )
                return False
        except requests.exceptions.RequestException as e:
            _logger.exception('Gagal terhubung ke dashboard monitoring')
            self.env['waf.subscription.log'].sudo().create({
                'payload': json.dumps(payload, indent=2, ensure_ascii=False),
                'state': 'error',
                'response': str(e)[:5000],
            })
            if raise_on_error:
                raise UserError('Gagal terhubung ke dashboard: %s' % e)
            return False

    @api.model
    def _cron_sync(self):
        """Entry point untuk scheduled action."""
        self.sync_now(raise_on_error=False)
