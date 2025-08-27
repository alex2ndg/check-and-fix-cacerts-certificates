# Cert Checker – Java Truststore (PowerShell)

Validate HTTPS connectivity to a list of URLs using a specific Java truststore (`cacerts`).  
If a URL fails with a PKIX path error, automatically fetch the server's **full certificate chain** and import it into `cacerts` (after backing it up), then re-validate.

- **Platform:** Windows (PowerShell 5.1+ or PowerShell 7+)
- **Requires:** JDK with `java`, `javac`, `keytool` (tested with Zulu 17)
- **Outputs:** HTML email summary (+ TXT attachment), optional **Action Required** email, local logs/reports

---

## Features

- Detects `PKIX path building failed` / `unable to find valid certification path…`.
- Exports the presented **certificate chain** (one `.crt` PEM file with all blocks).
- Backs up `cacerts` before any modification.
- Cleans old chain entries `Alias-CA-*` to avoid stale intermediates.
- Imports chain: `Alias` for leaf, `Alias-CA-1..N` for intermediates/root.
- Re-validates with Java using the specified truststore.
- **HTML emails** with dynamic subject (`OK/FIXED/FAILED/ERROR/PKIX/Total`) and attached TXT report.
- Detailed **Action Required** email if auto-fix fails.

---

## Getting Started

### 1) Prepare a CSV with targets
Create `targets.csv` (commit-safe: no secrets):

```csv
Alias,Url
Example1,https://api.example.com/health
Example2,https://partners.example.net/ping
```

### 2) Run the script (elevated PowerShell)
```powershell
Set-Location '<repo-or-scripts-path>'
.\Check-And-Fix-Java-Trust.ps1 `
  -ZuluHome "C:\Program Files\Zulu\zulu-17" `
  -TrustStorePath "C:\Program Files\Zulu\zulu-17\lib\security\cacerts" `
  -TrustStorePassword "changeit" `
  -WorkDir ".\logs" `
  -TargetsPath ".\targets.csv" `
  -AutoFix `
  -NotifyOnAll:$false `
  -SmtpServer "smtp.example.com" `
  -MailFrom "mailer@example.com" `
  -MailTo "ops@example.com"
```

Admin rights required to modify cacerts under Program Files.

### Parameters (highlights)
-TargetsPath <csv>: CSV with columns Alias,Url. Alternatively, pass -Targets @(@{Alias='A';Url='https://...'}, ...).
-AutoFix: Attempt automatic remediation on PKIX error.
-DryRun: Validate only; do not modify cacerts.
-NotifyOnAll: 
  true → always send summary.
  false → only send summary if something was fixed.
  If auto-fix fails, an Action Required email is always sent.
-NoEmail: Disable all email sending (useful in CI/tests).
-SmtpServer/-SmtpPort/-SmtpUseSsl/-MailFrom/-MailTo/-MailCc: email settings (placeholders by default).
-WorkDir: where backups/logs/reports and temporary artifacts go.

### What gets written where?
- Transcript/log: logs/run_YYYYMMDD_HHMMSS.log
- TXT report: logs/report_YYYYMMDD_HHMMSS.txt (also attached to emails)
- cacerts backup: logs/cacerts_YYYYMMDD_HHMMSS.bak
- Exported chain(s): logs/<Alias>_YYYYMMDD_HHMMSS.crt

### Scheduling (Windows Task Scheduler)

  Action (PowerShell 7 example):
```
Program/script:  C:\Program Files\PowerShell\7\pwsh.exe
Arguments:       -NoProfile -ExecutionPolicy Bypass -File "<path>\Check-And-Fix-Java-Trust.ps1" -TargetsPath "<path>\targets.csv" -AutoFix -NotifyOnAll:$false
Start in:        <path>
```
  Tick “Run with highest privileges.”
  Use an account with network access to the target URLs.

### Notes & Tips
- 401/403 responses typically mean TLS succeeded but the endpoint requires auth. The script records the HTTP code; TLS handshake is what matters here.
- The script imports leaf + CAs. If your policy is “trust CAs only”, adjust Import-CertChainToCacerts to skip the first block.
- Proxies are not used for the chain capture (it opens a TCP socket to host:443). Java validation could be extended to pass -Dhttps.proxyHost/Port if needed.
- Consider pinning or curating which CAs to trust instead of trusting any server-presented root.

### Uninstall / Rollback
- Restore the latest backup from the working directory:
```
Copy-Item ".\logs\cacerts_YYYYMMDD_HHMMSS.bak" "C:\Program Files\Zulu\zulu-17\lib\security\cacerts"
```
