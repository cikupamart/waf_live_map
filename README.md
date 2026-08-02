# WAF Security untuk Odoo 16

Modul Web Application
Firewall (WAF) yang terintegrasi langsung di dalam aplikasi Odoo.

Modul ini dikembangkan berdampingan dengan versi Odoo 17/18 - lini fitur
paling lengkap (Dashboard, Live Attack Map, File Extension Rule, dsb)
dibangun/diperbaiki di sana lebih dulu.
Dua penyesuaian teknis yang dilakukan supaya kompatibel dengan Odoo 16:

1. **Syntax `attrs` dipakai kembali** — Odoo 16 belum mendukung syntax
   `invisible="not field"` langsung (itu baru ada mulai Odoo 17). Semua
   kondisi visibility di `views/waf_config_views.xml` pakai bentuk lama:
   `attrs="{'invisible': [('field','=',False)]}"`.
2. **Signature `res.users._login()` bentuk lama** — Odoo 16 memakai
   `_login(cls, db, login, password, user_agent_env=None)`, BUKAN bentuk
   credential-dict yang baru ada mulai Odoo 17
   (`_login(cls, db, credential, user_agent_env=None)`). Override brute
   force protection di `models/res_users.py` sudah disesuaikan ke bentuk
   lama ini.

**PENTING:** karena poin ke-2 menyentuh mekanisme login inti, WAJIB diuji
manual di staging dulu sebelum dipakai di production:
- Login normal via `/web/login` (harus tetap berhasil)
- Login gagal berkali-kali (harus ter-log di Audit Log dan IP ter-ban
  sesuai threshold yang dikonfigurasi)

Kalau nanti instance ini di-upgrade ke Odoo 17+, override `_login` dan
syntax `attrs` di atas WAJIB disesuaikan lagi ke bentuk baru (lihat versi
modul untuk Odoo 17/18 sebagai referensi).

Bagian lain (deteksi ancaman, rate limiting, IP rule, file extension
filter, GeoIP, security headers, dashboard OWL, subscription monitor,
alerting) tidak menyentuh API inti Odoo yang berubah antar versi, jadi
logikanya identik dengan versi 17/18.

## Cara Instalasi

1. Salin folder `waf_security` ke dalam addons path Odoo 16, misalnya:
   ```
   /opt/odoo16/custom-addons/waf_security
   ```
2. Restart service Odoo dan update apps list:
   ```
   ./odoo-bin -c odoo.conf -u base --stop-after-init
   ```
   atau melalui UI: Apps > Update Apps List.
3. Cari "WAF Security" di menu Apps, lalu klik **Install**.
4. Setelah terinstall, menu **WAF Security** akan muncul di sidebar utama
   (hanya terlihat oleh user yang tergabung dalam group `WAF: Viewer` atau
   `WAF: Administrator`). Secara default, Administrator Odoo otomatis
   masuk ke group Administrator WAF.

## Struktur Menu

* **Dashboard** — stat card real-time (total event hari ini, diblokir
  hari ini, critical 24 jam, IP ter-ban aktif) + breakdown jenis ancaman,
  auto-refresh tiap 15 detik.
* **Statistik Lanjutan (Graph/Pivot)** — analisis data historis pakai
  graph & pivot view bawaan Odoo, untuk drill-down lebih dalam.
* **Live Attack Map** — peta dunia interaktif (Leaflet + OpenStreetMap)
  menampilkan titik asal serangan secara real-time, auto-refresh tiap
  8 detik. Butuh GeoIP Lookup diaktifkan dulu di Konfigurasi (lihat
  bagian Fitur Tambahan) dan koneksi internet dari BROWSER user (untuk
  memuat peta), bukan dari server.
* **Audit Log** — daftar lengkap semua kejadian yang dicatat WAF.
* **IP Whitelist/Blacklist** — kelola IP yang selalu diizinkan/diblokir.
* **File Extension Rule** — kelola ekstensi file yang di-block atau
  di-whitelist untuk upload (mis. .php, .exe, .sh secara default
  di-block sebagai titik awal).
* **Konfigurasi** — atur seluruh perilaku WAF (deteksi, rate limit,
  brute force, security headers, filter ekstensi file, GeoIP, alert
  email/telegram, subscription monitor).

## Konsep yang Dipelajari

1. **Request Inspection** — dilakukan dengan meng-override method
   `_dispatch()` pada model `ir.http`, yang merupakan titik masuk semua
   HTTP request di Odoo (`models/ir_http.py`).
2. **Signature-based Detection** — pola regex untuk SQLi, XSS, RCE, dan
   Path Traversal ada di `models/waf_detection_engine.py`. Silakan
   modifikasi/tambahkan pattern untuk latihan.
3. **Rate Limiting & Brute Force** — menggunakan sliding window counter
   in-memory (`models/waf_rate_limiter.py`). Proteksi brute force login
   di-hook lewat override `res.users._login()`.
4. **File Extension Filtering** — memeriksa `request.httprequest.files`
   (upload multipart) terhadap rule di `waf.file.extension.rule`, mode
   blacklist (tolak ekstensi tertentu) atau whitelist (hanya izinkan
   ekstensi tertentu) - lihat `_waf_check_file_extensions()` di
   `models/ir_http.py`.
5. **Auto Ban** — ketika jumlah pelanggaran suatu IP melewati ambang
   batas dalam periode waktu tertentu, IP otomatis dimasukkan ke
   blacklist dengan masa berlaku (expire) tertentu.
6. **Security Headers** — CSP, HSTS, X-Frame-Options, X-Content-Type-Options,
   dll ditambahkan ke setiap response.
7. **Audit Log & Alerting** — setiap kejadian dicatat ke model `waf.log`,
   dan bila severity-nya melewati ambang, dikirim alert lewat email
   (`mail.mail`) dan/atau Telegram Bot API.
8. **Dashboard & Live Map berbasis OWL Component** — `static/src/js/
   waf_dashboard.js` dan `waf_live_map.js` adalah contoh custom Odoo
   client action (bukan act_window biasa), polling data lewat endpoint
   JSON kustom di `controllers/main.py`, dengan pengecekan hak akses
   group di setiap endpoint.

## Batasan (Penting untuk Dipahami)

* Rate limiting & brute force tracker bersifat **in-memory per worker
  process**. Jika Odoo dijalankan multi-worker, counter tidak dibagi
  antar worker. Untuk production sungguhan, gunakan penyimpanan
  terpusat seperti Redis.
* Deteksi berbasis regex/signature bisa di-*bypass* dengan teknik
  encoding/obfuscation tingkat lanjut — ini contoh keterbatasan nyata
  dari pendekatan signature-based, cocok jadi bahan diskusi kelas.
* Filter ekstensi file hanya memeriksa NAMA file (ekstensi), bukan isi
  file (magic bytes/konten sebenarnya). File berbahaya yang di-rename
  ekstensinya (mis. `shell.php` jadi `shell.jpg`) tidak akan tertangkap
  fitur ini - ini keterbatasan lain yang bagus untuk didiskusikan di
  kelas (bandingkan dengan validasi MIME-type/magic-bytes yang lebih kuat).
* Live Attack Map butuh Leaflet.js/OpenStreetMap tiles dimuat dari CDN
  oleh BROWSER user - kalau instance dipakai di jaringan tertutup tanpa
  akses internet, peta tidak akan tampil (fitur WAF lain tetap normal).
* Modul ini **bukan pengganti** WAF layer jaringan/proxy production
  (Cloudflare, AWS WAF, Nginx+ModSecurity). Gunakan sebagai lapisan
  tambahan (defense in depth) dan sebagai media belajar.
* Uji coba pattern SQLi/XSS/dsb sebaiknya dilakukan di environment
  development/lab milik sendiri, bukan sistem produksi orang lain.

## Fitur Tambahan (Opsional, OFF Secara Default)

### Live Attack Map (GeoIP Lookup)

Menampilkan peta dunia dengan titik-titik lokasi asal serangan yang
terdeteksi WAF, real-time. Butuh dua hal:

1. **GeoIP Lookup diaktifkan** di menu **WAF Security > Konfigurasi >
   tab GeoIP & File Extension**. NONAKTIF secara default karena setiap
   IP yang terdeteksi WAF (bukan trafik normal) akan dikirim ke layanan
   pihak ketiga gratis **ip-api.com** untuk diterjemahkan jadi lokasi
   geografis. Proses ini berjalan **async lewat cron setiap 2 menit**
   (`_cron_resolve_geo`), bukan pada saat request sedang diproses -
   supaya tidak memperlambat WAF itu sendiri. Kalau toggle ini nonaktif,
   cron tidak melakukan panggilan apa pun ke luar.
2. **Koneksi internet dari browser user** untuk memuat Leaflet.js dan
   ubin peta (map tiles) dari OpenStreetMap via CDN. Ini terpisah dari
   poin 1 - GeoIP lookup terjadi di server, peta (visual) dimuat di
   browser.

Data yang dikirim ke ip-api.com hanya alamat IP penyerang yang sudah
terdeteksi WAF - bukan data bisnis atau data pengguna instance Anda.

### File Extension Block/Whitelist

Memeriksa nama file yang di-upload lewat request (multipart/form-data)
terhadap daftar rule di menu **WAF Security > File Extension Rule**.
Dua mode (atur di Konfigurasi > tab GeoIP & File Extension):

- **Blacklist** (default) — tolak upload dengan ekstensi yang ada di
  daftar block. Modul ini sudah menyertakan daftar awal ekstensi umum
  yang rawan disalahgunakan sebagai web shell/executable (.php, .exe,
  .sh, .jsp, .asp, .aspx, .dll, .ps1, dst) - sesuaikan sendiri sesuai
  kebutuhan (hapus kalau memang perlu terima ekstensi tertentu).
- **Whitelist** — jauh lebih ketat, HANYA izinkan ekstensi yang ada di
  daftar whitelist, semua yang lain ditolak. Pastikan sudah menambahkan
  semua ekstensi yang memang dibutuhkan bisnis (gambar, PDF, dsb)
  sebelum mengaktifkan mode ini, kalau tidak upload normal ikut terblokir.

Keterbatasan: fitur ini hanya memeriksa NAMA/ekstensi file, bukan isi
sebenarnya (magic bytes). File yang di-rename ekstensinya tidak
tertangkap - bagus untuk bahan diskusi soal validasi konten vs nama file.

### Subscription Monitor

Mengirim ringkasan status instance (versi Odoo, edisi, jumlah user aktif,
tanggal kadaluarsa) secara berkala ke dashboard **api.odoo.my.id**. URL
dashboard & API key sudah terisi otomatis (bisa diganti ke dashboard lain
jika perlu) — tapi sinkronisasi TIDAK berjalan sampai admin membuka
form Konfigurasi WAF dan mengaktifkan toggle-nya secara eksplisit.
Tidak ada data yang terkirim secara diam-diam.

Pengaturan ini disimpan sebagai field biasa di model `waf.config` (bukan
lewat halaman Settings umum Odoo / `res.config.settings`) - dengan
sengaja, supaya modul ini tidak bergantung pada struktur internal
halaman Settings yang berbeda-beda antar versi dan bahkan antar
instalasi Odoo (tergantung app apa saja yang terinstall).

**Cara mengaktifkan:**
Buka menu **WAF Security > Konfigurasi**, buka tab "Subscription
Monitor", cek/sesuaikan URL dashboard & API key yang sudah terisi,
nyalakan toggle "Aktifkan Subscription Monitor", klik "Test & Sync
Sekarang". Setelah berhasil, aktifkan cron job **WAF: Sync Subscription
Monitor** (Settings > Technical > Scheduled Actions) agar sync berjalan
otomatis setiap hari.

**PENTING — soal privasi data:**
Secara default, data yang dikirim hanya berupa ringkasan agregat (jumlah
user, versi, tanggal expired) — **tidak** menyertakan nama atau email
siapa pun. Ada opsi terpisah "Sertakan daftar user (PII)" yang, jika
diaktifkan, akan menambahkan nama, login, dan waktu login terakhir semua
user internal ke dalam data yang dikirim. Opsi ini OFF secara default.
Sebelum mengaktifkannya, pastikan Anda:
- Punya alasan bisnis yang jelas untuk butuh data per-user tersebut.
- Memberi tahu (atau punya izin dari) organisasi yang datanya dikirim.
- Memeriksa kepatuhan terhadap regulasi privasi data yang berlaku
  (mis. UU PDP di Indonesia) sebelum mengirim data personal karyawan
  ke server pihak ketiga.

Log setiap percobaan sync (berhasil/gagal, payload yang terkirim, response
server) tetap terlihat di menu **WAF Security > Subscription Monitor Log**
(khusus group Administrator WAF) — ini sengaja tidak disembunyikan, supaya
siapa pun yang mengelola instance selalu bisa melihat data apa saja yang
sudah/akan terkirim ke luar.


## Contoh Skenario test

1. Coba akses `/web?x=<script>alert(1)</script>` pada instance dev lokal,
   lihat apakah tercatat di Audit Log sebagai `xss`.
2. Ubah `block_mode` ke `monitor`, ulangi request yang sama, amati bedanya
   (tidak diblokir, hanya dicatat).
3. Coba login gagal berkali-kali dan amati kapan IP otomatis di-ban.
4. Tambahkan pattern regex baru di `waf_detection_engine.py` lalu uji.
5. (Opsional) Aktifkan Subscription Monitor dengan URL dashboard dummy
   (mis. https://webhook.site) untuk melihat payload apa saja yang
   dikirim, tanpa/dengan opsi "sertakan daftar user" — bandingkan isinya
   sebagai bahan diskusi soal minimisasi data (data minimization).
