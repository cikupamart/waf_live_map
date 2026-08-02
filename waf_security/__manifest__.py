# -*- coding: utf-8 -*-
{
    'name': 'WAF Security + Live Map - Web Application Firewall',
    'version': '16.0.1.0.0',
    'category': 'Tools',
    'summary': 'Web Application Firewall untuk Odoo 16 ',
    'images': ['static/description/banner.png'],
    'price': 79.9,
    'currency': 'EUR',
    'description': """

WAF Security for Odoo 16
=========================
Modul Web Application Firewall (WAF)
yang terintegrasi langsung di dalam Odoo.

Fitur:
------
* Request Inspection (setiap request masuk diperiksa)
* SQL Injection Detection
* XSS (Cross Site Scripting) Detection
* RCE (Remote Code Execution) Detection
* Path Traversal Detection
* IP Whitelist / Blacklist
* File Extension Block/Whitelist (untuk upload file)
* Rate Limiting
* Brute Force Protection (login)
* Security Headers (CSP, HSTS, X-Frame-Options, dll)
* Audit Log lengkap
* Dashboard Monitoring (stat card real-time)
* Live Attack Map (visualisasi geografis serangan, opsional/OFF default)
* Auto Ban IP mencurigakan
* Alert via Email & Telegram
* Subscription Monitor - kirim status instance (versi, jumlah user,
  tanggal expired) ke dashboard eksternal yang dikonfigurasi admin
  (opsional, OFF secara default)

CATATAN PENTING (untuk pembelajaran):
--------------------------------------
Modul ini adalah alat bantu belajar (educational tool) untuk memahami
cara kerja WAF berbasis signature/regex. Modul ini BUKAN pengganti WAF
production-grade (seperti ModSecurity, Cloudflare WAF, AWS WAF, dsb).
Untuk deployment production sesungguhnya, tetap gunakan WAF di layer
reverse proxy/network (Nginx + ModSecurity, Cloudflare, dll) sebagai
lapisan pertama, dan modul ini sebagai lapisan tambahan (defense in depth).

Fitur Subscription Monitor dan GeoIP Lookup (Live Attack Map) NONAKTIF
secara default dan memerlukan konfigurasi/aktivasi eksplisit sebelum
memanggil layanan eksternal - lihat README.md.
    """,
    'author': 'Ufed Tech',
    'website': 'http://ufed.store',
    'license': 'LGPL-3',
    'depends': ['base', 'web', 'mail'],
    'external_dependencies': {
        'python': ['requests'],
    },
    'data': [
        'security/waf_security_groups.xml',
        'security/ir.model.access.csv',
        'data/waf_cron.xml',
        'data/waf_default_data.xml',
        'views/waf_config_views.xml',
        'views/waf_log_views.xml',
        'views/waf_ip_rule_views.xml',
        'views/waf_file_extension_views.xml',
        'views/waf_dashboard_views.xml',
        'views/waf_live_map_views.xml',
        'views/waf_subscription_monitor_views.xml',
        'views/menu_views.xml',
    ],
    'assets': {
        'web.assets_backend': [
            'waf_security/static/src/js/waf_dashboard.js',
            'waf_security/static/src/js/waf_live_map.js',
            'waf_security/static/src/xml/waf_dashboard.xml',
            'waf_security/static/src/xml/waf_live_map.xml',
            'waf_security/static/src/scss/waf_dashboard.scss',
            'waf_security/static/src/scss/waf_live_map.scss',
        ],
    },
    'installable': True,
    'application': True,
    'auto_install': False,
}
