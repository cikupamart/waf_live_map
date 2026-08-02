# -*- coding: utf-8 -*-
from odoo import models, fields, api


class WafFileExtensionRule(models.Model):
    _name = 'waf.file.extension.rule'
    _description = 'WAF File Extension Block/Whitelist Rule'
    _rec_name = 'extension'
    _order = 'extension'

    extension = fields.Char(
        string='Ekstensi', required=True,
        help='Tanpa titik, mis. "php" bukan ".php". Tidak case-sensitive.')
    rule_type = fields.Selection([
        ('block', 'Block (tolak upload dengan ekstensi ini)'),
        ('whitelist', 'Whitelist (izinkan upload dengan ekstensi ini)'),
    ], required=True, default='block', string='Tipe Rule')
    reason = fields.Char(string='Alasan/Catatan')
    active = fields.Boolean(default=True)

    _sql_constraints = [
        ('ext_rule_type_uniq', 'unique(extension, rule_type)',
         'Rule untuk kombinasi ekstensi dan tipe ini sudah ada!'),
    ]

    @api.model_create_multi
    def create(self, vals_list):
        for vals in vals_list:
            if vals.get('extension'):
                vals['extension'] = vals['extension'].strip().lstrip('.').lower()
        return super().create(vals_list)

    def write(self, vals):
        if vals.get('extension'):
            vals['extension'] = vals['extension'].strip().lstrip('.').lower()
        return super().write(vals)

    @api.model
    def get_blocked_extensions(self):
        rules = self.search([('rule_type', '=', 'block'), ('active', '=', True)])
        return set(rules.mapped('extension'))

    @api.model
    def get_whitelisted_extensions(self):
        rules = self.search([('rule_type', '=', 'whitelist'), ('active', '=', True)])
        return set(rules.mapped('extension'))
