# -*- coding: utf-8 -*-
from odoo import models, fields, api
from datetime import timedelta


class WafIpRule(models.Model):
    _name = 'waf.ip.rule'
    _description = 'WAF IP Whitelist / Blacklist Rule'
    _rec_name = 'ip_address'
    _order = 'create_date desc'

    ip_address = fields.Char(string='Alamat IP', required=True, index=True)
    rule_type = fields.Selection([
        ('whitelist', 'Whitelist (Selalu Diizinkan)'),
        ('blacklist', 'Blacklist (Selalu Diblokir)'),
    ], required=True, default='blacklist', string='Tipe Rule')
    reason = fields.Char(string='Alasan')
    is_auto = fields.Boolean(
        string='Auto-generated', default=False,
        help='True jika IP ini di-ban otomatis oleh sistem (bukan manual admin)')
    active = fields.Boolean(default=True)
    expire_date = fields.Datetime(
        string='Berlaku Sampai',
        help='Kosongkan untuk permanen. Setelah tanggal ini rule otomatis nonaktif.')
    violation_count = fields.Integer(string='Jumlah Pelanggaran', default=0)
    last_violation_date = fields.Datetime(string='Pelanggaran Terakhir')

    _sql_constraints = [
        ('ip_rule_type_uniq', 'unique(ip_address, rule_type)',
         'Rule untuk kombinasi IP dan tipe ini sudah ada!'),
    ]

    @api.model
    def is_whitelisted(self, ip_address):
        self._expire_old_rules()
        return bool(self.search_count([
            ('ip_address', '=', ip_address),
            ('rule_type', '=', 'whitelist'),
            ('active', '=', True),
        ]))

    @api.model
    def is_blacklisted(self, ip_address):
        self._expire_old_rules()
        return bool(self.search_count([
            ('ip_address', '=', ip_address),
            ('rule_type', '=', 'blacklist'),
            ('active', '=', True),
        ]))

    @api.model
    def _expire_old_rules(self):
        """Nonaktifkan rule blacklist otomatis yang sudah melewati expire_date."""
        now = fields.Datetime.now()
        expired = self.search([
            ('active', '=', True),
            ('expire_date', '!=', False),
            ('expire_date', '<', now),
        ])
        if expired:
            expired.write({'active': False})

    @api.model
    def auto_ban_ip(self, ip_address, reason, duration_hours=24):
        """Tambahkan atau perbarui IP ke blacklist secara otomatis."""
        existing = self.search([
            ('ip_address', '=', ip_address),
            ('rule_type', '=', 'blacklist'),
        ], limit=1)
        expire = fields.Datetime.now() + timedelta(hours=duration_hours) if duration_hours else False
        vals = {
            'reason': reason,
            'is_auto': True,
            'active': True,
            'expire_date': expire,
            'last_violation_date': fields.Datetime.now(),
        }
        if existing:
            vals['violation_count'] = existing.violation_count + 1
            existing.write(vals)
            return existing
        vals.update({'ip_address': ip_address, 'rule_type': 'blacklist', 'violation_count': 1})
        return self.create(vals)
