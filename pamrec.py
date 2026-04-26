#!/usr/bin/env python3
"""
PamRec - Parameter Reconnaissance Tool
Authorized security testing only.
"""

import sys
import re
import json
import time
import signal
import argparse
import threading
import urllib.parse
from collections import defaultdict
from datetime import datetime
from pathlib import Path

try:
    import requests
    from bs4 import BeautifulSoup
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
    from rich.text import Text
    from rich import print as rprint
    from rich.rule import Rule
    from rich.tree import Tree
    from rich.live import Live
    from rich.layout import Layout
    from rich.columns import Columns
    from rich.align import Align
except ImportError as e:
    print(f"[!] Missing dependency: {e}")
    print("[*] Run: pip install requests beautifulsoup4 rich")
    sys.exit(1)

console = Console()

# ─── Global stop flag (Ctrl+X) ───────────────────────────────────────────────

_stop_event = threading.Event()

def _handle_stop(signum, frame):
    """Handle Ctrl+X (SIGINT) — graceful stop."""
    if not _stop_event.is_set():
        console.print("\n[bold yellow][!] Ctrl+X detected — stopping gracefully, saving results...[/bold yellow]")
        _stop_event.set()

signal.signal(signal.SIGINT, _handle_stop)

# ─── Banner ───────────────────────────────────────────────────────────────────

BANNER = """[bold cyan]
██████╗  █████╗ ███╗   ███╗██████╗ ███████╗ ██████╗
██╔══██╗██╔══██╗████╗ ████║██╔══██╗██╔════╝██╔════╝
██████╔╝███████║██╔████╔██║██████╔╝█████╗  ██║
██╔═══╝ ██╔══██║██║╚██╔╝██║██╔══██╗██╔══╝  ██║
██║     ██║  ██║██║ ╚═╝ ██║██║  ██║███████╗╚██████╗
╚═╝     ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝ ╚═════╝
[/bold cyan][bold white]  Parameter Reconnaissance Tool  v2.0[/bold white]
  [dim]For authorized security testing only | Press Ctrl+X to stop[/dim]
"""

# ─── Parameter Categories ────────────────────────────────────────────────────

PARAM_CATEGORIES = {
    "file": [
        "file", "filename", "filepath", "path", "dir", "folder", "upload",
        "document", "attachment", "img", "image", "photo", "avatar",
        "download", "src", "source", "resource", "load", "include", "read",
        "template", "view", "page", "module", "theme", "skin", "style",
        "preview", "thumb", "thumbnail", "asset", "media", "static",
    ],
    "redirect": [
        "url", "redirect", "next", "return", "returnurl", "goto",
        "link", "target", "dest", "destination", "redir", "continue",
        "forward", "ref", "referer", "callback", "back", "location",
        "to", "from", "uri", "href", "jump", "out", "exit",
    ],
    "auth": [
        "token", "key", "api_key", "apikey", "secret", "password", "pass",
        "pwd", "auth", "access_token", "session", "sid", "cookie",
        "jwt", "bearer", "credential", "login", "username", "email",
        "user", "account", "hash", "signature", "nonce", "csrf", "xsrf",
        "otp", "pin", "passcode", "verification", "verify",
    ],
    "id": [
        "id", "uid", "user_id", "userid", "item_id", "post_id", "product_id",
        "order_id", "pid", "oid", "mid", "cid", "gid", "fid", "tid",
        "record", "entry", "object", "ref", "uuid", "slug", "code",
        "sku", "asin", "barcode", "serial",
    ],
    "search": [
        "q", "query", "search", "keyword", "keywords", "term", "terms",
        "s", "find", "filter", "category", "tag", "type", "sort",
        "order", "orderby", "group", "field", "column", "where",
    ],
    "injection": [
        "name", "value", "data", "input", "text", "content", "body",
        "msg", "message", "comment", "title", "description", "note",
        "sql", "cmd", "exec", "command", "run", "eval", "expr",
        "script", "action", "method", "format", "output", "out",
        "xml", "json", "html", "raw", "payload",
    ],
    "config": [
        "debug", "test", "dev", "mode", "lang", "language", "locale",
        "region", "country", "timezone", "tz", "format", "version",
        "v", "ver", "api_version", "config", "setting", "option",
        "param", "env", "stage", "feature", "flag",
    ],
    "pagination": [
        "page", "p", "pg", "offset", "limit", "start", "end",
        "from", "size", "count", "per_page", "pagesize", "rows",
        "num", "index", "cursor", "after", "before", "skip", "take",
    ],
    "network": [
        "host", "hostname", "domain", "ip", "port", "server", "address",
        "endpoint", "base_url", "api_url", "proxy", "gateway", "service",
        "backend", "upstream", "remote",
    ],
}

RISK_LEVELS = {
    "file":       ("CRITICAL", "red",     "Local File Inclusion / Path Traversal / Arbitrary Upload"),
    "redirect":   ("HIGH",     "orange1", "Open Redirect / SSRF"),
    "injection":  ("HIGH",     "orange1", "XSS / SQLi / Command Injection / SSTI"),
    "auth":       ("HIGH",     "orange1", "Authentication Bypass / Token Leak"),
    "network":    ("HIGH",     "orange1", "SSRF / Internal Network Access"),
    "id":         ("MEDIUM",   "yellow",  "IDOR / Insecure Direct Object Reference"),
    "search":     ("MEDIUM",   "yellow",  "XSS / SQL Injection via Search"),
    "config":     ("LOW",      "blue",    "Information Disclosure / Debug Mode"),
    "pagination": ("INFO",     "cyan",    "Business Logic / Data Enumeration"),
    "other":      ("INFO",     "white",   "Unknown — Manual review needed"),
}

COMMON_PARAM_WORDLIST = [
    "id", "page", "q", "search", "query", "file", "url", "path", "dir",
    "name", "type", "sort", "order", "limit", "offset", "size", "start",
    "end", "from", "to", "date", "year", "month", "day", "lang", "locale",
    "format", "output", "callback", "token", "key", "api_key", "secret",
    "user", "username", "email", "password", "auth", "session", "redirect",
    "next", "return", "target", "action", "method", "data", "value",
    "content", "text", "title", "body", "msg", "category", "tag", "slug",
    "code", "ref", "hash", "debug", "test", "mode", "version", "v",
    "filter", "view", "template", "theme", "include", "load", "src",
    "source", "image", "img", "photo", "avatar", "upload", "download",
    "attachment", "document", "file_name", "filename", "filepath", "folder",
    "module", "product", "item", "post", "article", "user_id", "order_id",
    "item_id", "product_id", "post_id", "pid", "uid", "cid", "uuid",
    "access_token", "refresh_token", "jwt", "nonce", "csrf", "xsrf",
    "host", "domain", "ip", "port", "server", "endpoint", "service",
    "feature", "flag", "option", "setting", "config", "env", "stage",
    "export", "import", "backup", "admin", "report", "log",
    "status", "state", "step", "flow", "process", "task",
    "lat", "lng", "latitude", "longitude", "location", "place",
    "cursor", "after", "before", "skip", "take", "per_page",
    "video", "playlist", "channel", "watch", "embed", "autoplay",
    "width", "height", "quality", "resolution", "bitrate", "codec",
    "category_id", "section", "chapter", "lesson", "course", "module_id",
    "shop", "store", "cart", "checkout", "coupon", "discount", "promo",
    "affiliate", "ref_id", "campaign", "utm_source", "utm_medium", "utm_campaign",
    "price", "currency", "amount", "qty", "quantity", "stock",
    "sort_by", "order_by", "direction", "asc", "desc",
    "preview", "draft", "published", "archive", "trash",
    "include_deleted", "with_trashed", "scope",
    "tab", "panel", "section_id", "widget",
    "report_type", "chart", "graph", "metric",
]

JS_PARAM_PATTERNS = [
    r'[\?&]([a-zA-Z_][a-zA-Z0-9_-]{1,40})=',
    r'name=["\']([a-zA-Z_][a-zA-Z0-9_-]{1,40})["\']',
    r'params\[[\'"]([\w-]{1,40})[\'"]\]',
    r'getParam\([\'"]([a-zA-Z_][a-zA-Z0-9_-]{1,40})[\'"]\)',
    r'URLSearchParams\b.*?\.get\([\'"]([a-zA-Z_][a-zA-Z0-9_-]{1,40})[\'"]\)',
    r'req\.(?:query|body|params)\.([a-zA-Z_][a-zA-Z0-9_-]{1,40})',
    r'request\.(?:GET|POST|args)\.get\([\'"]([a-zA-Z_][a-zA-Z0-9_-]{1,40})[\'"]\)',
    r'data-param=["\']([a-zA-Z_][a-zA-Z0-9_-]{1,40})["\']',
    r'["\']([a-zA-Z_][a-zA-Z0-9_]{2,25})["\']:\s*(?:req|request|params|query|body)\.',
    r'(?:axios|fetch|get|post)\([^)]*[\?&]([a-zA-Z_][a-zA-Z0-9_-]{1,40})=',
    r'\.append\([\'"]([a-zA-Z_][a-zA-Z0-9_-]{1,40})[\'"]',
    r'queryString\.([a-zA-Z_][a-zA-Z0-9_-]{1,40})',
    r'searchParams\.set\([\'"]([a-zA-Z_][a-zA-Z0-9_-]{1,40})[\'"]',
    r'new\s+URLSearchParams\(\{[^}]*[\'"]([a-zA-Z_][a-zA-Z0-9_-]{1,40})[\'"]',
    r'\$_(?:GET|POST|REQUEST)\[[\'"]([a-zA-Z_][a-zA-Z0-9_-]{1,40})[\'"]',
]

# Extra patterns to find real param names in page source / meta / sitemaps
HTML_META_PARAM_PATTERNS = [
    r'<input[^>]+name=["\']([a-zA-Z_][a-zA-Z0-9_\-]{1,40})["\']',
    r'<select[^>]+name=["\']([a-zA-Z_][a-zA-Z0-9_\-]{1,40})["\']',
    r'<textarea[^>]+name=["\']([a-zA-Z_][a-zA-Z0-9_\-]{1,40})["\']',
    r'<button[^>]+name=["\']([a-zA-Z_][a-zA-Z0-9_\-]{1,40})["\']',
    r'data-field=["\']([a-zA-Z_][a-zA-Z0-9_\-]{1,40})["\']',
    r'data-param=["\']([a-zA-Z_][a-zA-Z0-9_\-]{1,40})["\']',
    r'data-key=["\']([a-zA-Z_][a-zA-Z0-9_\-]{1,40})["\']',
]

# ─── Helpers ─────────────────────────────────────────────────────────────────

def normalize_url(url):
    if not url.startswith(("http://", "https://")):
        return "https://" + url
    return url


def categorize_param(name):
    lower = name.lower()
    for cat, kws in PARAM_CATEGORIES.items():
        if any(kw == lower or kw in lower or lower in kw for kw in kws):
            return cat
    return "other"


def get_risk(category):
    return RISK_LEVELS.get(category, RISK_LEVELS["other"])


def parse_url_params(url):
    """Extract parameters directly from a URL's query string."""
    try:
        parsed = urllib.parse.urlparse(url)
        if not parsed.query:
            return {}
        return dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
    except Exception:
        return {}


def strip_params(url):
    """Return URL without query string."""
    try:
        p = urllib.parse.urlparse(url)
        return urllib.parse.urlunparse(p._replace(query="", fragment=""))
    except Exception:
        return url


def is_same_domain(url, domain):
    try:
        return urllib.parse.urlparse(url).netloc == domain
    except Exception:
        return False


def is_valid_param_name(name):
    return bool(
        name
        and 1 < len(name) < 50
        and re.match(r'^[a-zA-Z_][a-zA-Z0-9_\-\.]*$', name)
        and not name.startswith(("http", "www", "ftp"))
    )


def is_likely_real_param(name, value=""):
    """Extra filter: skip tracking-only / analytics noise if needed."""
    noise = {"fbclid", "gclid", "msclkid", "dclid", "_ga", "_gid",
             "mc_cid", "mc_eid", "igshid"}
    return name.lower() not in noise

# ─── Extraction ──────────────────────────────────────────────────────────────

def extract_params_from_html(html, base_url=""):
    soup = BeautifulSoup(html, "html.parser")
    params = {}

    # Forms — most reliable source
    for form in soup.find_all("form"):
        action = form.get("action", "")
        method = form.get("method", "get").upper()
        # Parse params from action URL
        if action and "?" in action:
            for k, v in parse_url_params(action).items():
                if is_valid_param_name(k):
                    params[k] = v

        for inp in form.find_all(["input", "textarea", "select", "button"]):
            name = inp.get("name") or inp.get("id")
            if name and is_valid_param_name(name):
                val = inp.get("value", inp.get("placeholder", ""))
                if isinstance(val, list):
                    val = val[0] if val else ""
                params[name] = str(val)[:80]

    # Attributes with URLs (href, src, action, data-*)
    for tag in soup.find_all(True):
        for attr in ["href", "src", "action", "data-url", "data-href",
                     "data-src", "data-action", "data-link", "formaction"]:
            val = tag.get(attr, "")
            if isinstance(val, list):
                val = " ".join(val)
            if val and "=" in val:
                for k, v in parse_url_params(val).items():
                    if is_valid_param_name(k):
                        params[k] = v

    # data-* param/key/field attributes
    for tag in soup.find_all(True):
        for attr_name, attr_val in tag.attrs.items():
            if isinstance(attr_val, list):
                attr_val = " ".join(attr_val)
            if isinstance(attr_val, str) and attr_name.startswith("data-"):
                for suffix in ["-param", "-key", "-name", "-field", "-id",
                                "-filter", "-sort", "-query", "-search"]:
                    if attr_name.endswith(suffix):
                        clean = re.sub(r'^data-', '', attr_name).replace(suffix, "")
                        if clean and is_valid_param_name(clean):
                            params[clean] = attr_val

    # Meta refresh / canonical with params
    for meta in soup.find_all("meta"):
        content = meta.get("content", "")
        if content and "url=" in content.lower():
            url_part = re.search(r'url=([^\s;]+)', content, re.I)
            if url_part:
                for k, v in parse_url_params(url_part.group(1)).items():
                    if is_valid_param_name(k):
                        params[k] = v

    # Regex patterns on raw HTML for missed cases
    for pattern in HTML_META_PARAM_PATTERNS:
        for match in re.findall(pattern, html, re.IGNORECASE):
            name = match if isinstance(match, str) else match[0]
            if is_valid_param_name(name) and name not in params:
                params[name] = "[html-attr]"

    return params


def extract_params_from_js(js_content):
    params = {}
    for pattern in JS_PARAM_PATTERNS:
        for match in re.findall(pattern, js_content, re.IGNORECASE):
            name = match[0] if isinstance(match, tuple) else match
            if is_valid_param_name(name) and not name.startswith(("http", "www")):
                params[name] = "[js-extracted]"
    return params


def collect_links_and_params(soup, base_url, domain):
    """Return (links_with_params, links_without_params) from page."""
    links_with = {}
    links_without = set()

    for tag in soup.find_all(True):
        for attr in ["href", "src", "action", "data-href", "data-url", "formaction"]:
            raw = tag.get(attr, "")
            if isinstance(raw, list):
                raw = raw[0] if raw else ""
            if not raw or raw.startswith(("#", "mailto:", "tel:", "javascript:", "data:")):
                continue
            if not raw.startswith("http"):
                raw = urllib.parse.urljoin(base_url, raw)
            if not is_same_domain(raw, domain):
                continue
            params = parse_url_params(raw)
            if params:
                links_with[raw] = params
            else:
                clean = strip_params(raw)
                # Skip static assets
                if not re.search(r'\.(css|js|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot|pdf|zip)$',
                                 clean, re.I):
                    links_without.add(clean)

    return links_with, links_without

# ─── Sitemap / Robots ─────────────────────────────────────────────────────────

def fetch_sitemap(base_url, session, timeout=10):
    """Try to fetch sitemap.xml and robots.txt for extra URLs."""
    collected = {}
    parsed = urllib.parse.urlparse(base_url)
    root = f"{parsed.scheme}://{parsed.netloc}"

    candidates = [
        f"{root}/sitemap.xml",
        f"{root}/sitemap_index.xml",
        f"{root}/robots.txt",
    ]
    for url in candidates:
        if _stop_event.is_set():
            break
        try:
            r = session.get(url, timeout=timeout)
            if r.status_code != 200:
                continue
            # Extract all URLs
            found_urls = re.findall(r'https?://[^\s<>"]+', r.text)
            for u in found_urls:
                params = parse_url_params(u)
                if params and is_same_domain(u, parsed.netloc):
                    collected[u] = params
        except Exception:
            pass
    return collected

# ─── Wayback ─────────────────────────────────────────────────────────────────

def fetch_wayback(domain, progress_cb=None):
    """Fetch historical URLs from Wayback Machine CDX API."""
    collected = {}
    api = (
        f"http://web.archive.org/cdx/search/cdx"
        f"?url={domain}/*&output=json&fl=original&collapse=urlkey"
        f"&limit=2000&filter=statuscode:200"
    )
    try:
        if progress_cb:
            progress_cb("Querying Wayback Machine CDX...")
        r = requests.get(api, timeout=25)
        if r.status_code == 200:
            data = r.json()
            for entry in data[1:]:
                if _stop_event.is_set():
                    break
                url = entry[0]
                params = parse_url_params(url)
                if params:
                    collected[url] = params
    except Exception:
        pass
    return collected

# ─── Common Crawl (bonus source) ──────────────────────────────────────────────

def fetch_commoncrawl(domain, progress_cb=None):
    """Fetch URLs from Common Crawl index API (CC-Index)."""
    collected = {}
    api = (
        f"https://index.commoncrawl.org/CC-MAIN-2024-10-index"
        f"?url={domain}/*&output=json&limit=500"
    )
    try:
        if progress_cb:
            progress_cb("Querying Common Crawl index...")
        r = requests.get(api, timeout=20)
        if r.status_code == 200:
            for line in r.text.strip().splitlines():
                if _stop_event.is_set():
                    break
                try:
                    obj = json.loads(line)
                    url = obj.get("url", "")
                    params = parse_url_params(url)
                    if params:
                        collected[url] = params
                except Exception:
                    pass
    except Exception:
        pass
    return collected

# ─── JS Files ────────────────────────────────────────────────────────────────

def fetch_js_files(soup, base_url, session, max_js=20):
    params = {}
    scripts = soup.find_all("script", src=True)[:max_js]
    for script in scripts:
        if _stop_event.is_set():
            break
        src = script["src"]
        if not src.startswith("http"):
            src = urllib.parse.urljoin(base_url, src)
        # Skip CDN/external analytics JS
        if any(x in src for x in ["google-analytics", "googletagmanager",
                                    "facebook.net", "connect.facebook",
                                    "hotjar", "intercom", "crisp"]):
            continue
        try:
            r = session.get(src, timeout=8)
            if r.status_code == 200:
                params.update(extract_params_from_js(r.text))
        except Exception:
            continue
    return params

# ─── Wordlist Probe ───────────────────────────────────────────────────────────

def probe_wordlist(target_url, session, existing_params, timeout=5, verbose_cb=None):
    """
    Actively probe URL with wordlist parameters.
    Detects which params get a *different* response (content-length / status change).
    """
    found = {}
    sep = "&" if "?" in target_url else "?"

    # Baseline — send a param we know is fake
    baseline_status = 200
    baseline_len = 0
    try:
        baseline_r = session.get(f"{target_url}{sep}__pamrec_baseline__=1", timeout=timeout, allow_redirects=False)
        baseline_status = baseline_r.status_code
        baseline_len = len(baseline_r.content)
    except Exception:
        pass

    total = len(COMMON_PARAM_WORDLIST)
    for i, param in enumerate(COMMON_PARAM_WORDLIST):
        if _stop_event.is_set():
            break
        if param in existing_params:
            continue
        probe_url = f"{target_url}{sep}{param}=PAMREC1"
        try:
            r = session.get(probe_url, timeout=timeout, allow_redirects=False)
            status = r.status_code
            length = len(r.content)
            # Consider "interesting" if status or length meaningfully differs
            if status not in (400, 404, 410):
                length_diff = abs(length - baseline_len)
                is_interesting = (
                    status != baseline_status or
                    length_diff > 50
                )
                if is_interesting:
                    found[param] = {
                        "value": "PAMREC1",
                        "probe_status": status,
                        "length_delta": length_diff,
                        "sources": ["wordlist-probe"],
                    }
        except Exception:
            pass

        if verbose_cb and i % 20 == 0:
            verbose_cb(f"Fuzzing wordlist... {i}/{total}")

    return found

# ─── Live Parameter Display ───────────────────────────────────────────────────

def build_example_url(base_url, param_name, param_value):
    """
    Construct a full example URL showing exactly where the parameter appears.
    e.g. https://example.com/image?filename=abc.jpg
    """
    # Strip any existing query/fragment from base
    parsed = urllib.parse.urlparse(base_url)
    clean_base = urllib.parse.urlunparse(parsed._replace(query="", fragment=""))

    # Use real value if meaningful, else use a readable placeholder
    placeholder_map = {
        "id": "123", "user_id": "456", "post_id": "789", "product_id": "42",
        "page": "2", "limit": "10", "offset": "0", "size": "20",
        "q": "search_term", "query": "search_term", "search": "keyword",
        "url": "https://example.com", "redirect": "https://example.com",
        "next": "/dashboard", "return": "/home", "goto": "/page",
        "file": "document.pdf", "filename": "file.txt", "filepath": "/var/www/file",
        "path": "/etc/passwd", "dir": "/uploads", "src": "image.jpg",
        "img": "photo.jpg", "image": "picture.png", "photo": "avatar.jpg",
        "token": "eyJhbGciOiJIUzI1NiJ9...", "key": "API_KEY_HERE",
        "api_key": "sk-xxxxxxxxxxxx", "secret": "s3cr3t",
        "password": "P@ssw0rd", "pass": "P@ssw0rd",
        "session": "sess_abc123xyz", "jwt": "eyJhbGc...",
        "email": "user@example.com", "username": "admin",
        "lang": "en", "locale": "en_US", "format": "json",
        "debug": "true", "mode": "dev", "version": "1.0",
        "host": "localhost", "domain": "example.com", "ip": "127.0.0.1",
        "port": "8080", "callback": "myFunction",
        "sort": "created_at", "order": "desc", "orderby": "name",
        "category": "electronics", "tag": "sale", "slug": "my-post-title",
        "type": "admin", "status": "active", "action": "delete",
        "data": '<script>alert(1)</script>', "input": "test_value",
        "content": "Hello World", "title": "My Title",
        "download": "report.zip", "upload": "file.php",
        "template": "base.html", "theme": "dark", "view": "list",
        "ref": "homepage", "code": "ABC123", "hash": "a1b2c3d4",
        "cursor": "eyJpZCI6MTJ9", "after": "100", "before": "200",
    }

    # Prefer the real value if it's meaningful
    real_val = str(param_value) if param_value and param_value not in (
        "[js-extracted]", "[html-attr]", "PAMREC1", ""
    ) else None

    display_val = real_val or placeholder_map.get(param_name.lower(), f"{param_name}_value")

    return f"{clean_base}?{param_name}={display_val}"


class LiveTracker:
    """Real-time console display of found parameters during scan — shows full URL."""

    def __init__(self, target_url):
        self.target = target_url
        self.found = {}        # param -> {category, risk, value, url, sources}
        self._lock = threading.Lock()

    def add(self, source_url, name, value, source):
        with self._lock:
            if name not in self.found:
                cat = categorize_param(name)
                risk, color, vuln = get_risk(cat)
                example_url = build_example_url(source_url, name, value)
                self.found[name] = {
                    "value": value,
                    "example_url": example_url,
                    "category": cat,
                    "risk": risk,
                    "risk_color": color,
                    "vulnerability": vuln,
                    "sources": set(),
                }
                self._print_new(name, self.found[name], source)
            self.found[name]["sources"].add(source)

    def _print_new(self, name, data, source):
        color = data["risk_color"]
        risk  = data["risk"]
        cat   = data["category"]
        url   = data["example_url"]

        # Parse URL to display with colored parts
        parsed = urllib.parse.urlparse(url)
        # Highlight the param name inside the query string
        query_colored = parsed.query.replace(
            f"{name}=",
            f"[bold {color}]{name}[/bold {color}]="
        )
        full_url_display = (
            f"[dim]{parsed.scheme}://[/dim]"
            f"[bold white]{parsed.netloc}[/bold white]"
            f"[white]{parsed.path}[/white]"
            f"[dim]?[/dim]{query_colored}"
        )

        console.print(
            f"  [bold green][+][/bold green] "
            f"{full_url_display}  "
            f"[[bold {color}]{risk}[/bold {color}]] [dim]{cat}[/dim]"
        )


# ─── Core Scanner ─────────────────────────────────────────────────────────────

def scan_target(
    target_url,
    wordlist_fuzz=False,
    wayback=True,
    commoncrawl=False,
    deep_js=True,
    crawl_depth=2,
    timeout=10,
    cookies=None,
    extra_headers=None,
    live_output=True,
    max_js=20,
):
    target_url = normalize_url(target_url)
    parsed_root = urllib.parse.urlparse(target_url)
    domain = parsed_root.netloc

    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate, br",
    })
    if extra_headers:
        session.headers.update(extra_headers)
    if cookies:
        session.cookies.update(cookies)

    tracker = LiveTracker(target_url) if live_output else None

    # ── Data structures ───────────────────────────────────────────
    url_param_map = {}     # url -> { param -> value }
    global_params = {}     # param -> {value, sources}
    endpoint_map = defaultdict(set)

    def register(url, params_dict, source):
        if not params_dict or _stop_event.is_set():
            return
        base = strip_params(url)
        if url not in url_param_map:
            url_param_map[url] = {}
        for k, v in params_dict.items():
            if not is_valid_param_name(k):
                continue
            if not is_likely_real_param(k, v):
                continue
            url_param_map[url][k] = v
            endpoint_map[base].add(k)
            if k not in global_params:
                global_params[k] = {"value": v, "sources": set()}
            global_params[k]["sources"].add(source)
            if tracker:
                tracker.add(url, k, v, source)

    # ── Step 0: Status check on target URL ───────────────────────
    console.print(f"\n[bold cyan][*] Target:[/bold cyan] [white]{target_url}[/white]")
    try:
        head_r = session.head(target_url, timeout=timeout, allow_redirects=True)
        status = head_r.status_code
        server = head_r.headers.get("Server", "?")
        powered_by = head_r.headers.get("X-Powered-By", "")
        tech_info = f"Server: {server}"
        if powered_by:
            tech_info += f" | X-Powered-By: {powered_by}"
        console.print(f"[bold cyan][*] Status:[/bold cyan] [bold green]{status}[/bold green]  [dim]{tech_info}[/dim]")
    except Exception:
        console.print("[dim]  (HEAD request failed, continuing...)[/dim]")

    # ── Step 1: Params already in target URL ──────────────────────
    console.print("\n[bold cyan][*] Phase 1/7:[/bold cyan] Extracting params from URL directly...")
    url_direct = parse_url_params(target_url)
    if url_direct:
        console.print(f"  [bold green][✓][/bold green] Found [bold]{len(url_direct)}[/bold] param(s) in URL query string")
    register(target_url, url_direct, "url-direct")

    # ── Step 2: Crawl main page ───────────────────────────────────
    console.print(f"[bold cyan][*] Phase 2/7:[/bold cyan] Crawling (depth={crawl_depth})...")
    visited = set()
    to_visit = {strip_params(target_url)}
    all_soups = {}
    urls_crawled = 0

    for depth in range(crawl_depth):
        if _stop_event.is_set():
            break
        next_batch = set()
        for page_url in list(to_visit):
            if _stop_event.is_set():
                break
            if page_url in visited:
                continue
            visited.add(page_url)
            urls_crawled += 1
            try:
                resp = session.get(page_url, timeout=timeout, verify=True)
                resp.raise_for_status()
            except requests.exceptions.SSLError:
                try:
                    resp = session.get(page_url, timeout=timeout, verify=False)
                except Exception:
                    continue
            except Exception:
                continue

            html_text = resp.text
            soup = BeautifulSoup(html_text, "html.parser")
            all_soups[page_url] = soup

            html_params = extract_params_from_html(html_text, page_url)
            if html_params:
                register(page_url, html_params, "html")

            if deep_js:
                for script in soup.find_all("script", src=False):
                    if script.string:
                        js_p = extract_params_from_js(script.string)
                        if js_p:
                            register(page_url, js_p, "js-inline")

            links_with, links_without = collect_links_and_params(soup, page_url, domain)
            for url_w_param, params in links_with.items():
                register(url_w_param, params, "crawl")
            next_batch.update(links_without)

        to_visit = next_batch - visited
        console.print(f"  [dim]  Depth {depth+1}: {urls_crawled} pages crawled, {len(to_visit)} queued[/dim]")

    # ── Step 3: Sitemap / robots.txt ─────────────────────────────
    if not _stop_event.is_set():
        console.print("[bold cyan][*] Phase 3/7:[/bold cyan] Checking sitemap.xml / robots.txt...")
        sitemap_data = fetch_sitemap(target_url, session, timeout)
        if sitemap_data:
            console.print(f"  [bold green][✓][/bold green] Found {len(sitemap_data)} parameterized URL(s) in sitemap/robots")
        for url, params in sitemap_data.items():
            register(url, params, "sitemap")

    # ── Step 4: JS files ──────────────────────────────────────────
    if deep_js and not _stop_event.is_set():
        console.print(f"[bold cyan][*] Phase 4/7:[/bold cyan] Extracting from JS files (max {max_js})...")
        js_count = 0
        for page_url, soup in list(all_soups.items())[:5]:
            if _stop_event.is_set():
                break
            js_params = fetch_js_files(soup, page_url, session, max_js)
            if js_params:
                js_count += len(js_params)
                register(page_url, js_params, "js-file")
        if js_count:
            console.print(f"  [bold green][✓][/bold green] Extracted {js_count} param reference(s) from JS")

    # ── Step 5: Wayback Machine ───────────────────────────────────
    if wayback and not _stop_event.is_set():
        console.print("[bold cyan][*] Phase 5/7:[/bold cyan] Querying Wayback Machine (CDX API)...")
        wb_data = fetch_wayback(domain)
        if wb_data:
            console.print(f"  [bold green][✓][/bold green] Found {len(wb_data)} historical URL(s) with params")
        for url, params in wb_data.items():
            if _stop_event.is_set():
                break
            register(url, params, "wayback")

    # ── Step 6: Common Crawl ─────────────────────────────────────
    if commoncrawl and not _stop_event.is_set():
        console.print("[bold cyan][*] Phase 6/7:[/bold cyan] Querying Common Crawl index...")
        cc_data = fetch_commoncrawl(domain)
        if cc_data:
            console.print(f"  [bold green][✓][/bold green] Found {len(cc_data)} URL(s) from Common Crawl")
        for url, params in cc_data.items():
            if _stop_event.is_set():
                break
            register(url, params, "commoncrawl")
    else:
        console.print("[bold cyan][*] Phase 6/7:[/bold cyan] [dim]Common Crawl skipped (use --commoncrawl to enable)[/dim]")

    # ── Step 7: Wordlist fuzzing ──────────────────────────────────
    if wordlist_fuzz and not _stop_event.is_set():
        console.print(f"[bold cyan][*] Phase 7/7:[/bold cyan] [bold yellow]Active wordlist fuzzing ({len(COMMON_PARAM_WORDLIST)} probes)...[/bold yellow]")
        console.print("  [dim](This sends real requests — authorized targets only)[/dim]")

        def fuzz_cb(msg):
            console.print(f"  [dim]{msg}[/dim]", end="\r")

        fuzz_results = probe_wordlist(target_url, session, global_params,
                                      timeout=5, verbose_cb=fuzz_cb)
        if fuzz_results:
            console.print(f"\n  [bold green][✓][/bold green] Wordlist found {len(fuzz_results)} potentially active param(s)")
        for k, meta in fuzz_results.items():
            if _stop_event.is_set():
                break
            register(target_url, {k: meta["value"]}, "wordlist-probe")
    else:
        console.print("[bold cyan][*] Phase 7/7:[/bold cyan] [dim]Wordlist fuzzing skipped (use --fuzz to enable)[/dim]")

    # ── Enrich global params ──────────────────────────────────────
    final_params = {}
    for name, data in global_params.items():
        cat = categorize_param(name)
        risk, color, vuln = get_risk(cat)
        final_params[name] = {
            "value": data["value"],
            "sources": sorted(data["sources"]),
            "category": cat,
            "risk": risk,
            "risk_color": color,
            "vulnerability": vuln,
        }

    final_url_map = {}
    for url, params in url_param_map.items():
        enriched = {}
        for k, v in params.items():
            if not is_valid_param_name(k):
                continue
            cat = categorize_param(k)
            risk, color, vuln = get_risk(cat)
            enriched[k] = {
                "value": v,
                "category": cat,
                "risk": risk,
                "risk_color": color,
                "vulnerability": vuln,
            }
        if enriched:
            final_url_map[url] = enriched

    risk_count = defaultdict(int)
    cat_count = defaultdict(int)
    for p in final_params.values():
        risk_count[p["risk"]] += 1
        cat_count[p["category"]] += 1

    return {
        "target": target_url,
        "domain": domain,
        "scan_time": datetime.now().isoformat(),
        "parameters": final_params,
        "url_param_map": final_url_map,
        "endpoint_map": {k: sorted(v) for k, v in endpoint_map.items()},
        "interrupted": _stop_event.is_set(),
        "stats": {
            "total_params": len(final_params),
            "urls_with_params": len(final_url_map),
            "endpoints_found": len(endpoint_map),
            "urls_crawled": urls_crawled,
            "risk_breakdown": dict(risk_count),
            "category_breakdown": dict(cat_count),
        },
    }

# ─── Display ──────────────────────────────────────────────────────────────────

RISK_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def sort_params(params_dict):
    return sorted(params_dict.items(), key=lambda x: RISK_ORDER.get(x[1]["risk"], 99))


def display_results(results):
    console.print()
    console.rule("[bold cyan]═══ PAMREC SCAN RESULTS ═══[/bold cyan]")

    stats = results["stats"]
    risk  = stats.get("risk_breakdown", {})

    if results.get("interrupted"):
        console.print("[bold yellow]⚠  Scan was interrupted (Ctrl+X) — results are partial.[/bold yellow]\n")

    # ── Summary Panel ─────────────────────────────────────────────
    summary = (
        f"[bold]Target:[/bold]           {results['target']}\n"
        f"[bold]Domain:[/bold]           {results['domain']}\n"
        f"[bold]Scan Time:[/bold]        {results['scan_time']}\n"
        f"[bold]URLs Crawled:[/bold]     {stats['urls_crawled']}\n"
        f"[bold]Endpoints Found:[/bold]  {stats['endpoints_found']}\n"
        f"[bold]URLs with Params:[/bold] {stats['urls_with_params']}\n"
        f"[bold]Total Parameters:[/bold] [bold green]{stats['total_params']}[/bold green]\n\n"
        f"[bold red]CRITICAL:[/bold red] {risk.get('CRITICAL',0)}  "
        f"[bold orange1]HIGH:[/bold orange1] {risk.get('HIGH',0)}  "
        f"[bold yellow]MEDIUM:[/bold yellow] {risk.get('MEDIUM',0)}  "
        f"[bold blue]LOW:[/bold blue] {risk.get('LOW',0)}  "
        f"[bold cyan]INFO:[/bold cyan] {risk.get('INFO',0)}"
    )
    console.print(Panel(summary, title="[bold]PamRec Summary[/bold]", border_style="cyan"))
    console.print()

    # ── Section 1: Discovered URLs (parameters visible in query string) ────────
    console.rule("[bold yellow]▸ DISCOVERED URLs WITH PARAMETERS[/bold yellow]")
    console.print(
        "[dim]  These are real URLs found on the site that already contain parameters:[/dim]\n"
    )

    if results["url_param_map"]:
        for url, params in sorted(results["url_param_map"].items()):
            parsed = urllib.parse.urlparse(url)

            # Print the full URL with colored param names in query
            if parsed.query:
                query_parts = []
                for part in parsed.query.split("&"):
                    if "=" in part:
                        k, v = part.split("=", 1)
                        pdata = params.get(k, {})
                        col = pdata.get("risk_color", "white")
                        query_parts.append(
                            f"[bold {col}]{k}[/bold {col}]"
                            f"[dim]=[/dim]"
                            f"[white]{v}[/white]"
                        )
                    else:
                        query_parts.append(f"[dim]{part}[/dim]")
                query_display = "[dim]?[/dim]" + "[dim]&[/dim]".join(query_parts)
            else:
                query_display = ""

            full_url_line = (
                f"[bold green]URL:[/bold green] "
                f"[dim]{parsed.scheme}://[/dim]"
                f"[bold white]{parsed.netloc}[/bold white]"
                f"[white]{parsed.path}[/white]"
                f"{query_display}"
            )
            console.print(full_url_line)

            # Under each URL, list each param with its own reconstructed URL example
            for pname, pdata in sorted(params.items(),
                                        key=lambda x: RISK_ORDER.get(x[1]["risk"], 99)):
                color = pdata["risk_color"]
                val   = str(pdata["value"])[:50]
                # Build clean single-param example URL
                example = build_example_url(url, pname, pdata["value"])
                ex_parsed = urllib.parse.urlparse(example)
                ex_query  = ex_parsed.query.replace(
                    f"{pname}=",
                    f"[bold {color}]{pname}[/bold {color}]="
                )
                ex_url_display = (
                    f"[dim]{ex_parsed.scheme}://[/dim]"
                    f"[bold white]{ex_parsed.netloc}[/bold white]"
                    f"[white]{ex_parsed.path}[/white]"
                    f"[dim]?[/dim]{ex_query}"
                )
                console.print(
                    f"    [bold green]├─[/bold green] {ex_url_display}"
                    f"  [[bold {color}]{pdata['risk']}[/bold {color}]]"
                    f"  [dim]{pdata['category']} — {pdata['vulnerability']}[/dim]"
                )
            console.print()
    else:
        console.print("[dim]  No URLs with parameters in query string found.[/dim]\n")

    # ── Section 2: All Parameters → constructed URLs (including html/js sources) ──
    console.rule("[bold cyan]▸ ALL FOUND PARAMETERS — CONSTRUCTED URLs[/bold cyan]")
    console.print(
        "[dim]  Every discovered parameter shown as a full URL (including those from forms, JS, Wayback):[/dim]\n"
    )

    # Build a per-param -> best source URL mapping
    # Prefer URL that actually appeared in query string; fallback to endpoint_map base
    param_to_url = {}   # param_name -> best base URL
    for url, params in results["url_param_map"].items():
        for pname in params:
            if pname not in param_to_url:
                param_to_url[pname] = url

    # For params only found in html/js, use endpoint_map base URL
    for endpoint, plist in results["endpoint_map"].items():
        for pname in plist:
            if pname not in param_to_url:
                param_to_url[pname] = endpoint

    # Fallback: use target root
    target_root = strip_params(results["target"])

    if results["parameters"]:
        table = Table(
            border_style="dim",
            header_style="bold cyan",
            show_lines=True,
            expand=True,
        )
        table.add_column("Constructed URL", style="white", no_wrap=False, min_width=45)
        table.add_column("Risk",      no_wrap=True, min_width=9)
        table.add_column("Category",  no_wrap=True, min_width=10)
        table.add_column("Vulnerability", style="dim", min_width=35)
        table.add_column("Source",    style="dim",  max_width=22)

        for pname, pdata in sort_params(results["parameters"]):
            color  = pdata["risk_color"]
            base   = param_to_url.get(pname, target_root)
            ex_url = build_example_url(base, pname, pdata["value"])

            # Color the param name inside the URL string
            ex_parsed = urllib.parse.urlparse(ex_url)
            ex_query  = ex_parsed.query.replace(
                f"{pname}=",
                f"[bold {color}]{pname}[/bold {color}]="
            )
            url_display = (
                f"[dim]{ex_parsed.scheme}://[/dim]"
                f"[bold white]{ex_parsed.netloc}[/bold white]"
                f"[white]{ex_parsed.path}[/white]"
                f"[dim]?[/dim]{ex_query}"
            )

            table.add_row(
                url_display,
                f"[bold {color}]{pdata['risk']}[/bold {color}]",
                pdata["category"],
                pdata["vulnerability"],
                ", ".join(pdata["sources"]),
            )
        console.print(table)
    else:
        console.print("[dim]  No parameters found.[/dim]")
    console.print()

    # ── Section 3: Endpoint Map ───────────────────────────────────
    if results["endpoint_map"]:
        console.rule("[bold blue]▸ ENDPOINT MAP — Parameters per Path[/bold blue]")
        console.print()
        ep_table = Table(border_style="dim", header_style="bold blue",
                         show_lines=True, expand=True)
        ep_table.add_column("Endpoint (Base URL)", style="cyan", no_wrap=False, min_width=40)
        ep_table.add_column("Parameters Discovered", style="white")
        ep_table.add_column("#", style="dim", justify="right", width=4)

        for endpoint, params in sorted(results["endpoint_map"].items()):
            sp = sorted(params)
            # Show each param as a chip with its risk color
            param_display = ""
            for p in sp:
                pdata = results["parameters"].get(p, {})
                col   = pdata.get("risk_color", "white")
                param_display += f"[bold {col}]{p}[/bold {col}]  "
            ep_table.add_row(endpoint, param_display.strip(), str(len(sp)))
        console.print(ep_table)
        console.print()

    # ── Section 4: Category Breakdown ────────────────────────────
    cat_bd = stats.get("category_breakdown", {})
    if cat_bd:
        console.rule("[bold dim]▸ CATEGORY BREAKDOWN[/bold dim]")
        console.print()
        cat_table = Table(border_style="dim", header_style="bold dim",
                          show_lines=False, expand=False)
        cat_table.add_column("Category", style="white", min_width=12)
        cat_table.add_column("Count", justify="right", style="bold cyan")
        cat_table.add_column("Risk Level", style="dim")

        for cat, cnt in sorted(cat_bd.items(), key=lambda x: -x[1]):
            risk_name, color, _ = RISK_LEVELS.get(cat, ("INFO", "white", ""))
            cat_table.add_row(cat, str(cnt), f"[{color}]{risk_name}[/{color}]")
        console.print(Align.center(cat_table))
        console.print()

# ─── Export ───────────────────────────────────────────────────────────────────

def export_results(results, fmt, output_file):
    if fmt == "json":
        # Make sources serializable
        out = json.loads(json.dumps(results, default=str))
        with open(output_file, "w") as f:
            json.dump(out, f, indent=2)

    elif fmt == "txt":
        # Build param -> best URL map
        param_to_url = {}
        for url, params in results["url_param_map"].items():
            for pname in params:
                if pname not in param_to_url:
                    param_to_url[pname] = url
        for endpoint, plist in results["endpoint_map"].items():
            for pname in plist:
                if pname not in param_to_url:
                    param_to_url[pname] = endpoint
        target_root = strip_params(results["target"])

        with open(output_file, "w", encoding="utf-8") as f:
            f.write("PamRec — Parameter Reconnaissance Report\n")
            f.write("=" * 72 + "\n")
            f.write(f"Target    : {results['target']}\n")
            f.write(f"Date      : {results['scan_time']}\n")
            f.write(f"Total     : {results['stats']['total_params']} parameters\n")
            if results.get("interrupted"):
                f.write("STATUS    : INTERRUPTED (partial results)\n")
            f.write("=" * 72 + "\n\n")

            f.write("[ ALL PARAMETERS — CONSTRUCTED URLs ]\n\n")
            for pname, pdata in sort_params(results["parameters"]):
                base = param_to_url.get(pname, target_root)
                ex_url = build_example_url(base, pname, pdata["value"])
                f.write(f"  [{pdata['risk']:8}] {ex_url}\n")
                f.write(f"             Category : {pdata['category']}\n")
                f.write(f"             Vuln     : {pdata['vulnerability']}\n")
                f.write(f"             Sources  : {', '.join(pdata['sources'])}\n\n")

            f.write("[ URLS WITH PARAMETERS (as found) ]\n\n")
            for url, params in sorted(results["url_param_map"].items()):
                f.write(f"  {url}\n")
                for pname, pdata in sorted(params.items(),
                                           key=lambda x: RISK_ORDER.get(x[1]["risk"], 99)):
                    ex_url = build_example_url(url, pname, pdata["value"])
                    f.write(f"    ├─ [{pdata['risk']:8}] {ex_url}\n")
                    f.write(f"    │              Cat: {pdata['category']} | {pdata['vulnerability']}\n")
                f.write("\n")

            f.write("[ ENDPOINT MAP ]\n\n")
            for ep, params in sorted(results["endpoint_map"].items()):
                f.write(f"  {ep}\n")
                for pname in sorted(params):
                    pdata = results["parameters"].get(pname, {})
                    ex_url = build_example_url(ep, pname,
                                               pdata.get("value", "value"))
                    f.write(f"    → {ex_url}\n")
                f.write("\n")

            f.write("[ ALL PARAMETERS — RISK SORTED ]\n\n")
            for pname, pdata in sort_params(results["parameters"]):
                f.write(f"[{pdata['risk']:8}] {pname}\n")
                f.write(f"  Category : {pdata['category']}\n")
                f.write(f"  Value    : {pdata['value']}\n")
                f.write(f"  Vuln     : {pdata['vulnerability']}\n")
                f.write(f"  Sources  : {', '.join(pdata['sources'])}\n\n")

    elif fmt == "html":
        _generate_html(results, output_file)

    console.print(f"\n[bold green][✓] Results saved → {output_file}[/bold green]")


def _generate_html(results, output_file):
    risk_colors = {
        "CRITICAL": "#ef4444",
        "HIGH":     "#f97316",
        "MEDIUM":   "#eab308",
        "LOW":      "#3b82f6",
        "INFO":     "#06b6d4",
    }

    # Build URL param map HTML
    url_map_html = ""
    for url, params in sorted(results["url_param_map"].items()):
        parsed = urllib.parse.urlparse(url)

        # Build highlighted query string
        if parsed.query:
            highlighted_parts = []
            for part in parsed.query.split("&"):
                if "=" in part:
                    k, v = part.split("=", 1)
                    pdata = params.get(k, {})
                    col = risk_colors.get(pdata.get("risk", "INFO"), "#888")
                    highlighted_parts.append(
                        f'<span style="color:{col};font-weight:700">{k}</span>'
                        f'<span style="color:#8b949e">=</span>'
                        f'<span style="color:#c9d1d9">{v}</span>'
                    )
                else:
                    highlighted_parts.append(f'<span style="color:#8b949e">{part}</span>')
            query_display = '<span style="color:#8b949e">?</span>' + \
                            '<span style="color:#8b949e">&amp;</span>'.join(highlighted_parts)
        else:
            query_display = ""

        params_rows = ""
        for pname, pdata in sorted(params.items(),
                                    key=lambda x: RISK_ORDER.get(x[1]["risk"], 99)):
            col = risk_colors.get(pdata["risk"], "#888")
            val = str(pdata['value'])[:40] if pdata['value'] not in ("[js-extracted]", "[html-attr]") else ""
            params_rows += f"""
            <tr>
              <td><code class="param-name">{pname}</code></td>
              <td class="val-cell">{val or '<i style="color:#484f58">empty</i>'}</td>
              <td><span class="badge cat-{pdata['category']}">{pdata['category']}</span></td>
              <td><span class="risk-badge" style="background:{col}">{pdata['risk']}</span></td>
              <td class="vuln-cell">{pdata['vulnerability']}</td>
            </tr>"""

        url_map_html += f"""
        <div class="url-block">
          <div class="url-header">
            <span class="url-scheme">{parsed.scheme}://</span><span class="url-domain">{parsed.netloc}</span><span class="url-path">{parsed.path}</span>{query_display}
          </div>
          <table class="inner-table">
            <thead><tr><th>Parameter</th><th>Value</th><th>Category</th><th>Risk</th><th>Vulnerability</th></tr></thead>
            <tbody>{params_rows}</tbody>
          </table>
        </div>"""

    # Endpoint map HTML
    ep_rows = ""
    for ep, plist in sorted(results["endpoint_map"].items()):
        param_chips = "".join(f'<span class="chip">{p}</span>' for p in sorted(plist))
        ep_rows += f"<tr><td class='ep-url'><code>{ep}</code></td><td>{param_chips}</td><td style='color:#8b949e;text-align:right'>{len(plist)}</td></tr>"

    # Build param -> best base URL map
    param_to_url_html = {}
    for url, params in results["url_param_map"].items():
        for pname in params:
            if pname not in param_to_url_html:
                param_to_url_html[pname] = url
    for endpoint, plist in results["endpoint_map"].items():
        for pname in plist:
            if pname not in param_to_url_html:
                param_to_url_html[pname] = endpoint
    target_root_html = strip_params(results["target"])

    # All-params table — main column is the constructed URL
    all_params_rows = ""
    for pname, pdata in sort_params(results["parameters"]):
        col  = risk_colors.get(pdata["risk"], "#888")
        base = param_to_url_html.get(pname, target_root_html)
        ex_url = build_example_url(base, pname, pdata.get("value", ""))

        # Build HTML URL display: highlight param name in query
        ex_parsed = urllib.parse.urlparse(ex_url)
        query_html = ex_parsed.query.replace(
            f"{pname}=",
            f'<span style="color:{col};font-weight:700">{pname}</span>='
        )
        url_display_html = (
            f'<span style="color:#8b949e">{ex_parsed.scheme}://</span>'
            f'<span style="color:#79c0ff;font-weight:700">{ex_parsed.netloc}</span>'
            f'<span style="color:#e6edf3">{ex_parsed.path}</span>'
            f'<span style="color:#8b949e">?</span>'
            f'{query_html}'
        )

        sources_html = "".join(f'<span class="chip">{s}</span>' for s in pdata['sources'])
        all_params_rows += f"""
        <tr>
          <td class="url-cell"><code class="url-constructed">{url_display_html}</code></td>
          <td><span class="badge cat-{pdata['category']}">{pdata['category']}</span></td>
          <td><span class="risk-badge" style="background:{col}">{pdata['risk']}</span></td>
          <td class="vuln-cell">{pdata['vulnerability']}</td>
          <td class="src-cell">{sources_html}</td>
        </tr>"""

    stats = results["stats"]
    risk = stats.get("risk_breakdown", {})
    cat_bd = stats.get("category_breakdown", {})

    interrupted_banner = ""
    if results.get("interrupted"):
        interrupted_banner = '<div style="background:#7c2d12;color:#fdba74;padding:.8rem 1.5rem;border-radius:6px;margin-bottom:1.5rem;font-weight:700">⚠ Scan was interrupted (Ctrl+X) — results are partial.</div>'

    # Category breakdown cards
    cat_cards = ""
    for cat, cnt in sorted(cat_bd.items(), key=lambda x: -x[1]):
        risk_name, _, _ = RISK_LEVELS.get(cat, ("INFO", "white", ""))
        cat_cards += f'<div class="cat-card"><div class="cat-num">{cnt}</div><div class="cat-lbl">{cat}</div><div class="cat-risk">{risk_name}</div></div>'

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PamRec — {results['domain']}</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:'Courier New',monospace;background:#0a0d12;color:#c9d1d9;min-height:100vh}}
a{{color:#58a6ff;text-decoration:none}}

.header{{background:linear-gradient(160deg,#0d1117 0%,#161b22 100%);padding:2rem 2.5rem;border-bottom:1px solid #21262d}}
.ascii-art{{color:#58a6ff;font-size:0.52rem;line-height:1.15;white-space:pre;margin-bottom:1.2rem;opacity:.9}}
.header h1{{color:#e6edf3;font-size:1.35rem;font-weight:700;letter-spacing:.05em}}
.header .meta{{color:#8b949e;font-size:0.78rem;margin-top:.3rem}}

.container{{max-width:1600px;margin:0 auto;padding:2rem 2.5rem}}

.stats-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:.9rem;margin:2rem 0}}
.stat-card{{background:#161b22;border:1px solid #21262d;border-radius:10px;padding:1.1rem;text-align:center;transition:border-color .2s}}
.stat-card:hover{{border-color:#30363d}}
.stat-num{{font-size:1.9rem;font-weight:700;color:#58a6ff}}
.stat-label{{font-size:.72rem;color:#8b949e;margin-top:.2rem;text-transform:uppercase;letter-spacing:1px}}
.stat-critical .stat-num{{color:#ef4444}}
.stat-high .stat-num{{color:#f97316}}
.stat-medium .stat-num{{color:#eab308}}
.stat-low .stat-num{{color:#3b82f6}}
.stat-info .stat-num{{color:#06b6d4}}

.section-title{{color:#e6edf3;font-size:1rem;font-weight:600;margin:2.5rem 0 1rem;padding:.5rem 0;border-bottom:1px solid #21262d;letter-spacing:.05em}}
.section-title span{{color:#58a6ff}}

.url-block{{background:#0d1117;border:1px solid #21262d;border-radius:8px;margin-bottom:1.2rem;overflow:hidden}}
.url-header{{padding:.75rem 1.2rem;background:#161b22;border-bottom:1px solid #21262d;font-size:.82rem;word-break:break-all;line-height:1.6}}
.url-scheme{{color:#8b949e}}
.url-domain{{color:#79c0ff;font-weight:700}}
.url-path{{color:#e6edf3}}

table{{width:100%;border-collapse:collapse;font-size:.82rem}}
th{{background:#161b22;color:#58a6ff;padding:.6rem 1rem;text-align:left;font-size:.72rem;text-transform:uppercase;letter-spacing:1px;border-bottom:1px solid #21262d}}
td{{padding:.6rem 1rem;border-bottom:1px solid #161b22;vertical-align:middle}}
tr:last-child td{{border-bottom:none}}
tr:hover td{{background:#0d1117}}
.inner-table{{background:#0a0d12}}
.outer-table{{background:#161b22;border:1px solid #21262d;border-radius:8px;overflow:hidden}}

code.param-name{{color:#79c0ff;background:#0d1117;padding:2px 6px;border-radius:4px;font-size:.82rem}}
code.url-constructed{{font-size:.8rem;background:transparent;word-break:break-all;line-height:1.7}}
.url-cell{{max-width:600px;word-break:break-all}}
.val-cell{{color:#8b949e;font-size:.8rem;max-width:200px;word-break:break-all}}
.vuln-cell{{color:#8b949e;font-size:.8rem}}
.src-cell{{font-size:.75rem}}
.ep-url code{{color:#6e9ef7;font-size:.8rem}}

.risk-badge{{padding:2px 9px;border-radius:20px;font-size:.68rem;font-weight:700;color:#fff;display:inline-block;letter-spacing:.5px}}
.badge{{padding:2px 8px;border-radius:4px;font-size:.72rem;display:inline-block;font-weight:600}}
.cat-file{{background:#7f1d1d;color:#fca5a5}}
.cat-redirect{{background:#7c2d12;color:#fdba74}}
.cat-auth{{background:#713f12;color:#fde047}}
.cat-injection{{background:#1e3a5f;color:#93c5fd}}
.cat-id{{background:#14532d;color:#86efac}}
.cat-search{{background:#312e81;color:#c4b5fd}}
.cat-config{{background:#164e63;color:#67e8f9}}
.cat-pagination{{background:#1e293b;color:#94a3b8}}
.cat-network{{background:#4a1d96;color:#ddd6fe}}
.cat-other{{background:#27272a;color:#a1a1aa}}

.chip{{background:#21262d;color:#8b949e;border:1px solid #30363d;padding:2px 8px;border-radius:4px;font-size:.72rem;margin:2px;display:inline-block}}

.cat-grid{{display:flex;flex-wrap:wrap;gap:.7rem;margin:1rem 0 2rem}}
.cat-card{{background:#161b22;border:1px solid #21262d;border-radius:8px;padding:.8rem 1.2rem;text-align:center;min-width:90px}}
.cat-num{{font-size:1.5rem;font-weight:700;color:#58a6ff}}
.cat-lbl{{font-size:.72rem;color:#8b949e;text-transform:uppercase;letter-spacing:.5px;margin-top:.2rem}}
.cat-risk{{font-size:.65rem;color:#484f58;margin-top:.1rem}}

.footer{{text-align:center;color:#484f58;font-size:.73rem;padding:2rem;border-top:1px solid #21262d;margin-top:3rem}}
</style>
</head>
<body>
<div class="header">
<div class="container">
<div class="ascii-art">██████╗  █████╗ ███╗   ███╗██████╗ ███████╗ ██████╗
██╔══██╗██╔══██╗████╗ ████║██╔══██╗██╔════╝██╔════╝
██████╔╝███████║██╔████╔██║██████╔╝█████╗  ██║
██╔═══╝ ██╔══██║██║╚██╔╝██║██╔══██╗██╔══╝  ██║
██║     ██║  ██║██║ ╚═╝ ██║██║  ██║███████╗╚██████╗
╚═╝     ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝ ╚═════╝</div>
<h1>Parameter Reconnaissance Report</h1>
<div class="meta">Target: <strong>{results['target']}</strong> &nbsp;|&nbsp; {results['scan_time']}{' &nbsp;|&nbsp; <span style="color:#f97316">⚠ INTERRUPTED</span>' if results.get('interrupted') else ''}</div>
</div>
</div>

<div class="container">
{interrupted_banner}

<div class="stats-grid">
  <div class="stat-card"><div class="stat-num">{stats['total_params']}</div><div class="stat-label">Total Params</div></div>
  <div class="stat-card"><div class="stat-num">{stats['urls_with_params']}</div><div class="stat-label">URLs w/ Params</div></div>
  <div class="stat-card"><div class="stat-num">{stats['endpoints_found']}</div><div class="stat-label">Endpoints</div></div>
  <div class="stat-card"><div class="stat-num">{stats['urls_crawled']}</div><div class="stat-label">Crawled</div></div>
  <div class="stat-card stat-critical"><div class="stat-num">{risk.get('CRITICAL',0)}</div><div class="stat-label">Critical</div></div>
  <div class="stat-card stat-high"><div class="stat-num">{risk.get('HIGH',0)}</div><div class="stat-label">High</div></div>
  <div class="stat-card stat-medium"><div class="stat-num">{risk.get('MEDIUM',0)}</div><div class="stat-label">Medium</div></div>
  <div class="stat-card stat-low"><div class="stat-num">{risk.get('LOW',0)}</div><div class="stat-label">Low</div></div>
  <div class="stat-card stat-info"><div class="stat-num">{risk.get('INFO',0)}</div><div class="stat-label">Info</div></div>
</div>

<h2 class="section-title">▸ <span>Category Breakdown</span></h2>
<div class="cat-grid">{cat_cards}</div>

<h2 class="section-title">▸ <span>URLs with Parameters (Live Evidence)</span></h2>
{url_map_html if url_map_html else '<p style="color:#484f58;padding:.5rem 0">No URLs with parameters found.</p>'}

<h2 class="section-title">▸ <span>Endpoint Parameter Map</span></h2>
<table class="outer-table">
<thead><tr><th>Endpoint</th><th>Parameters Found</th><th style="text-align:right">#</th></tr></thead>
<tbody>{ep_rows}</tbody>
</table>

<h2 class="section-title">▸ <span>All Parameters — Constructed URLs</span></h2>
<p style="color:#8b949e;font-size:.8rem;margin-bottom:1rem">Every discovered parameter shown as a full URL. The <span style="color:#f97316;font-weight:700">highlighted</span> part is the parameter name.</p>
<table class="outer-table">
<thead><tr><th>Constructed URL</th><th>Category</th><th>Risk</th><th>Vulnerability</th><th>Sources</th></tr></thead>
<tbody>{all_params_rows}</tbody>
</table>

<div class="footer">
  Generated by PamRec v2.0 &nbsp;|&nbsp; For authorized security testing only &nbsp;|&nbsp; {results['scan_time']}
</div>
</div>
</body>
</html>"""

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(html)

# ─── CLI ─────────────────────────────────────────────────────────────────────

def main():
    console.print(BANNER)

    parser = argparse.ArgumentParser(
        prog="pamrec",
        description="PamRec — Parameter Reconnaissance Tool v2.0",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python pamrec.py -u https://example.com
  python pamrec.py -u "https://example.com/video?id=12"
  python pamrec.py -u "https://shop.example.com/product?id=5&cat=shoes"
  python pamrec.py -u https://target.com --wayback --deep-js -o report.html
  python pamrec.py -u https://target.com --fuzz --commoncrawl --format json
  python pamrec.py -u https://target.com --depth 3 --cookies "session=abc123"
  python pamrec.py -u https://target.com --header "Authorization: Bearer TOKEN"
  python pamrec.py -u https://target.com --no-wayback --depth 1 --quiet

Stop anytime with Ctrl+X — partial results will be saved.
        """
    )
    parser.add_argument("-u", "--url",       required=True,
                        help="Target URL (with or without parameters)")
    parser.add_argument("--wayback",         action="store_true", default=True,
                        help="Query Wayback Machine CDX (default: on)")
    parser.add_argument("--no-wayback",      action="store_true",
                        help="Disable Wayback Machine")
    parser.add_argument("--commoncrawl",     action="store_true",
                        help="Query Common Crawl index (extra source)")
    parser.add_argument("--deep-js",         action="store_true", default=True,
                        help="Extract params from JS files (default: on)")
    parser.add_argument("--no-js",           action="store_true",
                        help="Disable JS extraction")
    parser.add_argument("--fuzz",            action="store_true",
                        help="Active wordlist probe — authorized targets only")
    parser.add_argument("--depth",           type=int, default=2,
                        help="Crawl depth (default: 2)")
    parser.add_argument("--timeout",         type=int, default=10,
                        help="HTTP timeout seconds (default: 10)")
    parser.add_argument("--max-js",          type=int, default=20,
                        help="Max JS files to fetch per page (default: 20)")
    parser.add_argument("--cookies",         type=str,
                        help="Cookies string: key=val; key2=val2")
    parser.add_argument("--header",          action="append", metavar="K: V",
                        help="Extra header (repeatable)")
    parser.add_argument("-o", "--output",    type=str,
                        help="Output file path (auto-named if omitted)")
    parser.add_argument("--format",          choices=["html", "json", "txt"],
                        default="html",
                        help="Output format (default: html)")
    parser.add_argument("--quiet",           action="store_true",
                        help="Skip terminal display of results table")

    args = parser.parse_args()

    use_wayback = args.wayback and not args.no_wayback
    use_js      = args.deep_js and not args.no_js

    cookies = {}
    if args.cookies:
        for pair in args.cookies.split(";"):
            pair = pair.strip()
            if "=" in pair:
                k, v = pair.split("=", 1)
                cookies[k.strip()] = v.strip()

    headers = {}
    if args.header:
        for h in args.header:
            if ":" in h:
                k, v = h.split(":", 1)
                headers[k.strip()] = v.strip()

    console.print("[bold cyan]─────────────────────────────────────────────────────[/bold cyan]")
    console.print(f"[dim]Press [bold]Ctrl+X[/bold] at any time to stop and save partial results[/dim]")
    console.print("[bold cyan]─────────────────────────────────────────────────────[/bold cyan]\n")

    start_time = time.time()

    results = scan_target(
        target_url=args.url,
        wordlist_fuzz=args.fuzz,
        wayback=use_wayback,
        commoncrawl=args.commoncrawl,
        deep_js=use_js,
        crawl_depth=args.depth,
        timeout=args.timeout,
        cookies=cookies or None,
        extra_headers=headers or None,
        live_output=True,
        max_js=args.max_js,
    )

    elapsed = time.time() - start_time
    console.print(f"\n[bold green][✓] Scan finished in {elapsed:.1f}s[/bold green]")
    console.print(f"[bold green]    {results['stats']['total_params']} unique parameter(s) found across "
                  f"{results['stats']['urls_with_params']} URL(s)[/bold green]\n")

    if not args.quiet:
        display_results(results)

    # Auto-name output file
    out = args.output
    if not out:
        domain_clean = results["domain"].replace(".", "_").replace(":", "_")
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        out = f"pamrec_{domain_clean}_{ts}.{args.format}"

    export_results(results, args.format, out)


if __name__ == "__main__":
    main()
