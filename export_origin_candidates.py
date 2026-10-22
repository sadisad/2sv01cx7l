import json

with open('terminal_verified.json', 'r', encoding='utf-8') as f:
    data = json.load(f)

ok_list = [x for x in data if x['verified']]

unique_ok = {}
for x in ok_list:
    ip = x['ip']
    if ip not in unique_ok:
        unique_ok[ip] = {
            'ip': ip,
            'server': x['server'] if x['server'] else "Unknown",
            'status_code': x['status_code'],
            'is_origin_candidate': True
        }

failed_list = [x for x in data if not x['verified']]
unique_failed = {}
for x in failed_list:
    ip = x['ip']
    if ip not in unique_failed:
        unique_failed[ip] = {
            'ip': ip,
            'error': x['server'],
            'status_code': x['status_code']
        }

result = {
    "target": "baznas.go.id",
    "summary": {
        "total_probed_in_terminal": len(data),
        "total_valid_origin_candidates": len(unique_ok),
        "total_failed_or_timeout": len(unique_failed)
    },
    "origin_candidates": list(unique_ok.values()),
    "failed_probes": list(unique_failed.values())
}

with open('origin_candidates.json', 'w', encoding='utf-8') as f:
    json.dump(result, f, indent=2, ensure_ascii=False)

print(f"Selesai! Ditemukan {len(unique_ok)} kandidat origin unik (OK) dari {len(data)} baris.")
for c in unique_ok.values():
    print(f"  - {c['ip']:<18} | Server: {c['server']:<28} | Status: {c['status_code']}")
