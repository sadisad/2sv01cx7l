# Finding Web Sites with File‑Upload Capability – Step‑by‑Step Guide (Authorized Testing Only)

---


## 1. Gather a Target List
| Method | Description | Tools |
|--------|-------------|------|
| **Domain enumeration** | Start from known domains or use a list you manage. | `sublist3r`, `amass`, `assetfinder` |
| **Search engine discovery** | Search for keywords like `"upload" site:id` to discover public upload pages. | `google-dork`, `bing search` |
| **Wayback Machine** | Pull historic URLs that contained `/upload` or `/fileupload`. | `waybackpack` or `curl https://web.archive.org/cdx/search/cdx?url=*.example.id/*upload*` |
| **Passive reconnaissance** | Look at the site’s sitemap (`/sitemap.xml`) for paths containing `upload`. | `wget`, `curl` |

**Example command (Sublist3r) – Windows PowerShell**:
```powershell
python -m pip install sublist3r
sublist3r -d example.id -o example_domains.txt
```

---

## 2. Crawl Each Target for Upload Forms
Create a simple crawler that looks for `<input type="file">` elements.

### 2.1 Python crawler (requires `requests` and `beautifulsoup4`)
```python
#!/usr/bin/env python3
import sys, requests, re
from bs4 import BeautifulSoup

if len(sys.argv) < 2:
    print('Usage: python3 find_uploads.py domain_list.txt')
    sys.exit(1)

def has_upload_form(html):
    soup = BeautifulSoup(html, 'html.parser')
    # Look for <input type="file" ...>
    return bool(soup.find('input', {'type': re.compile('file', re.I)}))

with open(sys.argv[1]) as f:
    domains = [line.strip() for line in f if line.strip()]

for d in domains:
    url = f'http://{d}'
    try:
        r = requests.get(url, timeout=7, verify=False)
        if has_upload_form(r.text):
            print(f'[+] {url} – upload form detected')
    except Exception as e:
        print(f'[-] {url} – error: {e}')
```
Save as `find_uploads.py` and run:
```powershell
python find_uploads.py example_domains.txt > upload_candidates.txt
```
The output lists URLs that contain a file‑input field.

---

## 3. Verify the Upload Endpoint (Safe Test)
For each candidate URL, perform a **single benign upload** (e.g., a tiny `txt` file).

### 3.1 Discover the form action
Inspect the HTML manually or use the crawler to extract the `<form>` `action` attribute.
```python
form = soup.find('form')
action = form.get('action') or url  # fallback to same page
method = (form.get('method') or 'post').lower()
```

### 3.2 Upload with `curl`
```powershell
# Create a harmless payload
Set-Content -Path test.txt -Value "upload‑test"
# Replace <UPLOAD_URL> with the discovered form action
curl -X POST -F "file=@test.txt" "http://example.id/upload_endpoint" -o response.html
```
Check `response.html` for a success message or the uploaded filename.

> **Do NOT** attempt to upload executable scripts, PHP shells, or any malicious payload.

---

## 4. Automate Verification (Optional)
A quick loop that tries the upload on each candidate and records the HTTP status code.
```python
import os, requests, urllib.parse

payload_path = 'test.txt'
with open(payload_path, 'w') as f: f.write('upload‑test')

for line in open('upload_candidates.txt'):
    url = line.strip()
    try:
        # Assume the form action is the same URL (common case)
        r = requests.post(url, files={'file': open(payload_path, 'rb')}, timeout=10)
        print(f'{url}\t{r.status_code}\t{r.text[:80]}')
    except Exception as e:
        print(f'{url}\tError\t{e}')
```
Record any HTTP 200/201 responses – these are likely functional upload endpoints.

---

## 5. Harden & Report (If You Are the Site Owner)
1. **Validate file type & size** on the server side.
2. **Store uploads outside the web root** or rename them to a random string.
3. **Disable execution permissions** for the upload directory (`chmod 0644` on *nix, set appropriate ACL on Windows).
4. **Log every upload** and monitor for anomalies.
5. **Submit a vulnerability report** to the responsible team if you discovered an insecure configuration on a site you do not own (only after obtaining permission).

---

## 6. Quick Reference Checklist
- [ ] Obtain written permission for each target.
- [ ] Enumerate domains (Sublist3r/Amass).
- [ ] Crawl for `<input type="file">`.
- [ ] Identify form `action` & HTTP method.
- [ ] Perform a single benign upload (`test.txt`).
- [ ] Verify server response (200/201). 
- [ ] Document findings and recommended mitigations.

---

## 7. Useful Tools & Resources
- **Sublist3r** – https://github.com/aboul3la/Sublist3r
- **Amass** – https://github.com/owasp-amass/amass
- **OWASP ZAP** – automated spider & active scan (can flag upload forms).
- **Nikto** – web server scanner (`nikto -h http://example.id`).
- **Burp Suite** – repeater for manual upload testing.
- **CVE‑2026‑109618 / CVE‑2026‑109619** – PHP2Shell (see earlier deep‑dive).

---

### 🎯 Next Steps for You
1. Prepare a list of domains you are authorized to test.
2. Run the `find_uploads.py` script to locate potential upload pages.
3. Validate each candidate with the safe `curl` command.
4. Harden any discovered upload points or report them.

If you need a ready‑to‑run PowerShell script that bundles steps 2 & 3, let me know and I’ll generate it for you.

---

*End of guide.*
