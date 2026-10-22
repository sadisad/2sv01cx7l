# find_origin.ps1 — cari IP origin di belakang Cloudflare
$domain = "baznas.go.id"

# Rentang IPv4 resmi Cloudflare (untuk difilter)
$cfCidr = @(
 '103.21.244.0/22','103.22.200.0/22','103.31.4.0/22','104.16.0.0/13','104.24.0.0/14',
 '108.162.192.0/18','131.0.72.0/22','141.101.64.0/18','162.158.0.0/15','172.64.0.0/13',
 '173.245.48.0/20','188.114.96.0/20','190.93.240.0/20','197.234.240.0/22','198.41.128.0/17'
)
function ToU32([string]$ip){
  $b=[System.Net.IPAddress]::Parse($ip).GetAddressBytes()
  [uint32]$b[0]*16777216 + [uint32]$b[1]*65536 + [uint32]$b[2]*256 + [uint32]$b[3]
}
$ranges = foreach($c in $cfCidr){
  $p=$c.Split('/'); $n=[int]$p[1]; $base=ToU32 $p[0]
  $mask = if($n -eq 0){[uint32]0}else{[uint32]([uint32]0xFFFFFFFF -shl (32-$n))}
  [pscustomobject]@{Net=($base -band $mask); Mask=$mask}
}
function Is-CF([string]$ip){
  $v=ToU32 $ip
  foreach($r in $ranges){ if(($v -band $r.Mask) -eq $r.Net){ return $true } }
  $false
}

# --- Kumpulkan kandidat subdomain ---
$subs = New-Object System.Collections.Generic.HashSet[string]
try{
  $j = Invoke-RestMethod "https://crt.sh/?q=%25.$domain&output=json" -TimeoutSec 60
  foreach($e in $j){ foreach($n in ($e.name_value -split "`n")){ [void]$subs.Add($n.Trim().ToLower()) } }
  Write-Host "[+] crt.sh: $($subs.Count) nama" -ForegroundColor Green
}catch{ Write-Host "[!] crt.sh gagal: $_" -ForegroundColor Yellow }

$wl = @('www','mail','smtp','webmail','cpanel','ftp','portal','dev','staging','test','api',
        'admin','intranet','simba','alpha14','alpha2','bucket-api','cdn','static','vpn',
        'remote','beta','demo','git','jenkins','sso','login','app','dashboard','backend',
        'old','new','db','monitoring','grafana','mobile','assets','mail2','mx')
foreach($w in $wl){ [void]$subs.Add("$w.$domain") }

# --- Resolve & filter ---
$hits=@()
foreach($s in ($subs | Sort-Object)){
  try{
    $a = Resolve-DnsName -Name $s -Type A -ErrorAction Stop | Where-Object {$_.IPAddress}
    foreach($r in $a){
      $ip=$r.IPAddress
      if(Is-CF $ip){
        "{0,-45} {1,-18} {2}" -f $s,$ip,"cloudflare"
      } else {
        Write-Host ("{0,-45} {1,-18} *** ORIGIN CANDIDATE ***" -f $s,$ip) -ForegroundColor Cyan
        $hits += [pscustomobject]@{Sub=$s;IP=$ip}
      }
    }
  }catch{}
}

# --- MX / SPF (sering bocorkan hosting) ---
Write-Host "`n[=] MX record:" -ForegroundColor Magenta
(Resolve-DnsName -Name $domain -Type MX -ErrorAction SilentlyContinue) |
  ForEach-Object { "  $($_.NameExchange)  pref=$($_.Preference)" }
Write-Host "[=] SPF/TXT:" -ForegroundColor Magenta
(Resolve-DnsName -Name $domain -Type TXT -ErrorAction SilentlyContinue).Strings |
  Where-Object { $_ -match "spf|include|ip4" }

# --- Verifikasi tiap kandidat langsung (harus muncul Apache/nginx, bukan cloudflare) ---
foreach($h in $hits){
  Write-Host "`n=== Verifikasi $($h.IP) ($($h.Sub)) ===" -ForegroundColor Yellow
  curl.exe -sI --resolve "$domain`:443:$($h.IP)" "https://$domain/" |
    Select-String -Pattern "server|x-powered|cf-ray|via|x-cache|set-cookie"
}