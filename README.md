# PamRec — Parameter Reconnaissance Tool

```
██████╗  █████╗ ███╗   ███╗██████╗ ███████╗ ██████╗
██╔══██╗██╔══██╗████╗ ████║██╔══██╗██╔════╝██╔════╝
██████╔╝███████║██╔████╔██║██████╔╝█████╗  ██║
██╔═══╝ ██╔══██║██║╚██╔╝██║██╔══██╗██╔══╝  ██║
██║     ██║  ██║██║ ╚═╝ ██║██║  ██║███████╗╚██████╗
╚═╝     ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝ ╚═════╝
  Parameter Reconnaissance Tool  v2.0
  For authorized security testing only
```

> ⚠️ **Disclaimer:** PamRec hanya boleh digunakan pada target yang telah mendapat izin resmi (authorized). Penggunaan tanpa izin terhadap sistem milik orang lain adalah ilegal. Penulis tidak bertanggung jawab atas penyalahgunaan tool ini.

---

## Daftar Isi

- [Tentang PamRec](#tentang-pamrec)
- [Fitur Utama](#fitur-utama)
- [Kategori Parameter & Risiko](#kategori-parameter--risiko)
- [Instalasi](#instalasi)
- [Cara Penggunaan](#cara-penggunaan)
- [Opsi CLI Lengkap](#opsi-cli-lengkap)
- [Contoh Penggunaan](#contoh-penggunaan)
- [Format Output](#format-output)
- [Fase Scanning](#fase-scanning)

---

## Tentang PamRec

PamRec adalah tool reconnaissance berbasis Python untuk menemukan dan menganalisis parameter HTTP pada sebuah web target. Tool ini menggabungkan berbagai sumber — mulai dari crawling halaman, ekstraksi JavaScript, sitemap, hingga data historis dari Wayback Machine — untuk menghasilkan daftar parameter lengkap beserta potensi kerentanan yang terkait.

Cocok digunakan oleh:
- **Bug Hunter** — mencari attack surface parameter yang bisa dieksploit
- **Penetration Tester** — fase recon sebelum pengujian lebih dalam
- **Security Researcher** — analisis struktur URL dan parameter suatu aplikasi web

---

## Fitur Utama

| Fitur | Keterangan |
|---|---|
| 🕷️ Web Crawling | Crawl halaman secara rekursif sesuai kedalaman yang ditentukan |
| 📄 HTML Form Extraction | Ekstrak parameter dari form, input, select, textarea |
| ⚙️ JavaScript Analysis | Scan inline JS dan file JS eksternal untuk menemukan parameter tersembunyi |
| 🗺️ Sitemap & Robots.txt | Ambil URL parameterized dari sitemap.xml dan robots.txt |
| 🕰️ Wayback Machine CDX | Query arsip historis untuk menemukan parameter yang sudah tidak terlihat |
| 🌐 Common Crawl | Opsional: query indeks Common Crawl sebagai sumber tambahan |
| 🔍 Wordlist Fuzzing | Probe aktif dengan wordlist 150+ parameter umum |
| 🎨 Live Output | Tampilan real-time di terminal dengan pewarnaan risiko |
| 📊 Multi-Format Export | Export ke HTML (report interaktif), JSON, atau TXT |
| ⛔ Graceful Stop | Tekan `Ctrl+X` kapan saja — hasil parsial tetap tersimpan |

---

## Kategori Parameter & Risiko

PamRec secara otomatis mengkategorikan setiap parameter yang ditemukan dan mengaitkannya dengan potensi kerentanan:

| Kategori | Risiko | Contoh Kerentanan |
|---|---|---|
| `file` | 🔴 CRITICAL | Local File Inclusion, Path Traversal, Arbitrary Upload |
| `redirect` | 🟠 HIGH | Open Redirect, SSRF |
| `injection` | 🟠 HIGH | XSS, SQLi, Command Injection, SSTI |
| `auth` | 🟠 HIGH | Authentication Bypass, Token Leak |
| `network` | 🟠 HIGH | SSRF, Internal Network Access |
| `id` | 🟡 MEDIUM | IDOR (Insecure Direct Object Reference) |
| `search` | 🟡 MEDIUM | XSS / SQL Injection via Search |
| `config` | 🔵 LOW | Information Disclosure, Debug Mode |
| `pagination` | 🩵 INFO | Business Logic, Data Enumeration |
| `other` | ⚪ INFO | Unknown — perlu review manual |

---

## Instalasi

### Prasyarat

- Python **3.8+**
- pip

### 1. Clone atau Download

```bash
git clone https://github.com/bro-dika/pamrec.git
cd pamrec
```

Atau cukup download file `pamrec.py` secara langsung.

### 2. Install Dependensi

```bash
pip install requests beautifulsoup4 rich
```

**Daftar modul yang dibutuhkan:**

| Modul | Versi Minimum | Keterangan |
|---|---|---|
| `requests` | 2.28+ | HTTP client untuk crawling dan fetching |
| `beautifulsoup4` | 4.11+ | HTML parser untuk ekstraksi parameter |
| `rich` | 13.0+ | Tampilan terminal yang berwarna dan terformat |

> `urllib.parse`, `re`, `json`, `threading`, `signal`, `argparse` sudah termasuk dalam Python standard library — tidak perlu diinstall.

### 3. Verifikasi Instalasi

```bash
python pamrec.py --help
```

Jika banner ASCII dan daftar opsi muncul, instalasi berhasil.

---

## Cara Penggunaan

### Penggunaan Dasar

```bash
python pamrec.py -u https://target.com
```

Ini akan menjalankan scan penuh dengan pengaturan default:
- Crawl kedalaman 2
- Ekstraksi JS aktif
- Query Wayback Machine aktif
- Output: file HTML otomatis di direktori saat ini

### Scan Cepat (tanpa Wayback)

```bash
python pamrec.py -u https://target.com --no-wayback --depth 1
```

### Scan Lengkap dengan Semua Sumber

```bash
python pamrec.py -u https://target.com --wayback --commoncrawl --deep-js --fuzz --depth 3
```

### Menghentikan Scan

Tekan **`Ctrl+X`** kapan saja. Scan akan berhenti secara graceful dan hasil parsial tetap disimpan ke file output.

---

## Opsi CLI Lengkap

```
python pamrec.py -u URL [opsi]
```

| Opsi | Default | Keterangan |
|---|---|---|
| `-u`, `--url` | *(wajib)* | URL target (dengan atau tanpa parameter) |
| `--wayback` | aktif | Query Wayback Machine CDX API |
| `--no-wayback` | — | Nonaktifkan Wayback Machine |
| `--commoncrawl` | nonaktif | Query Common Crawl index (sumber tambahan) |
| `--deep-js` | aktif | Ekstrak parameter dari file JS |
| `--no-js` | — | Nonaktifkan ekstraksi JS |
| `--fuzz` | nonaktif | Aktifkan wordlist fuzzing (probe aktif) |
| `--depth` | `2` | Kedalaman crawl halaman |
| `--timeout` | `10` | Timeout HTTP request (detik) |
| `--max-js` | `20` | Jumlah maksimum file JS per halaman |
| `--cookies` | — | Cookie string: `key=val; key2=val2` |
| `--header` | — | Header tambahan (bisa diulang): `Key: Value` |
| `-o`, `--output` | *(auto)* | Path file output (default: auto-generated) |
| `--format` | `html` | Format output: `html`, `json`, atau `txt` |
| `--quiet` | — | Sembunyikan tabel hasil di terminal |

---

## Contoh Penggunaan

### Scan URL dengan parameter yang sudah ada

```bash
python pamrec.py -u "https://example.com/video?id=12"
```

### Scan toko online dengan beberapa parameter

```bash
python pamrec.py -u "https://shop.example.com/product?id=5&cat=shoes"
```

### Scan mendalam dengan Wayback + JS extraction, output HTML

```bash
python pamrec.py -u https://target.com --wayback --deep-js -o report.html
```

### Scan dengan fuzzing aktif + Common Crawl, output JSON

```bash
python pamrec.py -u https://target.com --fuzz --commoncrawl --format json
```

### Scan dengan autentikasi (cookie session)

```bash
python pamrec.py -u https://target.com --cookies "session=abc123; csrftoken=xyz"
```

### Scan dengan header kustom (Bearer token)

```bash
python pamrec.py -u https://target.com --header "Authorization: Bearer eyJhbGc..."
```

### Scan cepat tanpa Wayback, kedalaman 1, mode diam

```bash
python pamrec.py -u https://target.com --no-wayback --depth 1 --quiet
```

### Scan dalam, kedalaman 3, simpan ke file tertentu

```bash
python pamrec.py -u https://target.com --depth 3 -o hasil_recon.html
```

---

## Format Output

### HTML (default)
Report interaktif yang bisa dibuka di browser. Berisi:
- Ringkasan statistik (total param, risk breakdown)
- Tabel URL dengan parameter yang ditemukan (warna per risiko)
- Endpoint map — parameter per path
- Tabel semua parameter beserta constructed URL, kategori, dan sumber

```bash
python pamrec.py -u https://target.com --format html -o report.html
```

### JSON
Data mentah lengkap dalam format JSON, cocok untuk diproses lebih lanjut atau diintegrasikan dengan tool lain.

```bash
python pamrec.py -u https://target.com --format json -o result.json
```

Struktur JSON yang dihasilkan:
```json
{
  "target": "https://target.com",
  "domain": "target.com",
  "scan_time": "2025-01-15T10:30:00",
  "parameters": { ... },
  "url_param_map": { ... },
  "endpoint_map": { ... },
  "stats": { ... }
}
```

### TXT
Output plain text yang bisa dibaca langsung atau disimpan sebagai log.

```bash
python pamrec.py -u https://target.com --format txt -o report.txt
```

---

## Fase Scanning

PamRec menjalankan scanning dalam 7 fase secara berurutan:

```
Phase 1/7  →  Ekstrak parameter langsung dari URL target
Phase 2/7  →  Crawl halaman (HTML forms, links, data-* attributes)
Phase 3/7  →  Cek sitemap.xml dan robots.txt
Phase 4/7  →  Ekstrak dari file JavaScript
Phase 5/7  →  Query Wayback Machine (CDX API)
Phase 6/7  →  Query Common Crawl (jika --commoncrawl aktif)
Phase 7/7  →  Wordlist fuzzing aktif (jika --fuzz aktif)
```

Setiap fase memberikan output real-time di terminal, menampilkan parameter yang ditemukan beserta konstruksi URL contoh dan level risikonya.

---

## Penamaan File Output Otomatis

Jika tidak menggunakan `-o`, file output akan diberi nama otomatis dengan format:

```
pamrec_<domain>_<timestamp>.<format>
```

Contoh:
```
pamrec_example_com_20250115_103045.html
```

---

## Lisensi & Etika

Tool ini dibuat **semata-mata untuk keperluan keamanan yang sah**, antara lain:
- Bug bounty pada program resmi
- Penetration testing dengan kontrak/izin tertulis
- Pengujian terhadap sistem milik sendiri

**Dilarang keras** menggunakan PamRec untuk:
- Mengakses atau menguji sistem tanpa izin
- Kegiatan ilegal dalam bentuk apapun

---

*PamRec v2.0 — Parameter Reconnaissance Tool*
