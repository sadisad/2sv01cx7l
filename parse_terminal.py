import json
import re

raw_terminal_output = """
      verify 103.123.25.94      -> no | ERR HTTPSConnectionPool(host='go.id', port=443): Max retries exceeded with url: / (Caused by ConnectTimeoutError(<HTTPSConnection(host='go.id', port=443) at 0x1ee446d89a0>, 'Connection to go.id timed out. (connect timeout=15)')) | None
      verify 157.15.124.87      -> no | ERR HTTPSConnectionPool(host='go.id', port=443): Max retries exceeded with url: / (Caused by ConnectTimeoutError(<HTTPSConnection(host='go.id', port=443) at 0x1ee446db640>, 'Connection to go.id timed out. (connect timeout=15)')) | None
      verify 103.119.139.17     -> OK | nginx | 200
      verify 103.110.89.187     -> OK | Apache | 302
      verify 144.79.65.52       -> OK |  | 403
      verify 103.108.9.26       -> OK | Apache | 200
      verify 103.170.105.198    -> OK |  | 503
      verify 123.108.101.18     -> OK | nginx | 403
      verify 103.248.25.48      -> no | ERR HTTPSConnectionPool(host='go.id', port=443): Max retries exceeded with url: / (Caused by ConnectTimeoutError(<HTTPSConnection(host='go.id', port=443) at 0x1ee446daef0>, 'Connection to go.id timed out. (connect timeout=15)')) | None
      verify 115.187.23.252     -> OK | nginx | 200
      verify 103.112.245.7      -> OK | Apache | 200
      verify 103.119.139.17     -> OK | nginx | 200
      verify 103.65.236.131     -> no | ERR HTTPSConnectionPool(host='go.id', port=443): Max retries exceeded with url: / (Caused by ConnectTimeoutError(<HTTPSConnection(host='go.id', port=443) at 0x1ee446db670>, 'Connection to go.id timed out. (connect timeout=15)')) | None
      verify 111.221.43.222     -> OK |  | 502
      verify 182.253.93.154     -> OK |  | 503
      verify 123.253.54.51      -> OK | nginx | 200
      verify 103.157.117.166    -> OK | LiteSpeed | 200
      verify 103.8.238.156      -> OK | Apache | 200
      verify 103.141.238.34     -> OK | Apache | 200
      verify 103.165.248.30     -> OK | nginx | 301
      verify 103.248.25.148     -> OK | nginx | 301
      verify 103.170.105.49     -> OK | Apache | 200
      verify 103.247.8.102      -> OK | Apache | 200
      verify 103.225.242.176    -> OK | Apache/2.4.52 (Ubuntu) | 403
      verify 163.53.193.214     -> OK |  | 503
      verify 23.203.165.16      -> OK | AkamaiGHost | 400
      verify 23.203.165.8       -> OK | AkamaiGHost | 400
      verify 72.60.76.208       -> OK | nginx | 502
      verify 103.225.242.176    -> OK | Apache/2.4.52 (Ubuntu) | 403
      verify 103.225.242.176    -> OK | Apache/2.4.52 (Ubuntu) | 403
      verify 119.235.250.58     -> OK | Microsoft-IIS/10.0 | 500
      verify 103.225.242.176    -> OK | Apache/2.4.52 (Ubuntu) | 403
      verify 103.225.242.176    -> OK | Apache/2.4.52 (Ubuntu) | 403
      verify 103.225.242.176    -> OK | Apache/2.4.52 (Ubuntu) | 403
      verify 103.225.242.176    -> OK | Apache/2.4.52 (Ubuntu) | 403
      verify 127.0.0.1          -> no | ERR HTTPSConnectionPool(host='go.id', port=443): Max retries exceeded with url: / (Caused by NewConnectionError("HTTPSConnection(host='go.id', port=443): Failed to establish a new connection: [WinError 10061] No connection could be made because the target machine actively refused it")) | None
      verify 103.225.242.176    -> OK | Apache/2.4.52 (Ubuntu) | 403
      verify 103.225.242.176    -> OK | Apache/2.4.52 (Ubuntu) | 403
      verify 103.225.242.176    -> OK | Apache/2.4.52 (Ubuntu) | 403
      verify 103.119.139.17     -> OK | nginx | 200
      verify 198.252.98.102     -> OK | LiteSpeed | 200
      verify 144.79.65.52       -> OK |  | 403
      verify 103.141.105.74     -> no | ERR HTTPSConnectionPool(host='go.id', port=443): Max retries exceeded with url: / (Caused by NewConnectionError("HTTPSConnection(host='go.id', port=443): Failed to establish a new connection: [WinError 10061] No connection could be made because the target machine actively refused it")) | None
      verify 163.53.193.214     -> OK |  | 503
      verify 103.53.193.42      -> no | ERR HTTPSConnectionPool(host='go.id', port=443): Max retries exceeded with url: / (Caused by NewConnectionError("HTTPSConnection(host='go.id', port=443): Failed to establish a new connection: [WinError 10061] No connection could be made because the target machine actively refused it")) | None
      verify 103.42.205.220     -> OK |  | 302
      verify 203.14.183.98      -> OK | Apache/2.4.25 | 302
      verify 203.14.183.98      -> OK | Apache/2.4.25 | 302
      verify 202.10.51.236      -> OK |  | 503
      verify 162.0.227.145      -> OK | nginx | 200
      verify 103.8.238.44       -> OK |  | 503
"""

def parse_terminal():
    entries = []
    pattern = re.compile(r"verify\s+([\d\.]+)\s+->\s+(\w+)\s+\|\s*(.*?)\s*\|\s*(\d+|None)?$")
    for line in raw_terminal_output.strip().split("\n"):
        line = line.strip()
        m = pattern.search(line)
        if m:
            ip, status, srv, code = m.groups()
            entries.append({
                "ip": ip,
                "verified": (status == "OK"),
                "server": srv.strip() if srv.strip() else None,
                "status_code": int(code) if code and code.isdigit() else None,
                "raw": line
            })

    output_path = "terminal_verified.json"
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(entries, f, indent=2, ensure_ascii=False)

    print(f"Berhasil mengonversi {len(entries)} baris ke {output_path}")

if __name__ == "__main__":
    parse_terminal()
