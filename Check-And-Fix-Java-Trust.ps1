<# =====================================================================
  Check-And-Fix-Java-Trust.ps1
  v2.0 (Generic – PS 5.1 compatible)

  WHAT THIS SCRIPT DOES
  ---------------------
  - Validates HTTPS handshake to a list of URLs using a given Java truststore (cacerts).
  - If validation fails with "PKIX path building failed / unable to find valid certification path":
      * Extracts the server's full certificate chain (leaf + intermediates + root) into ONE PEM .crt file.
      * Backs up cacerts.
      * Removes the previous alias and any stale "<Alias>-CA-*" entries (via Remove-AliasChain).
      * Imports the entire chain into cacerts (leaf as <Alias>, intermediates/root as <Alias>-CA-1/2/...).
      * Re-validates and reports the outcome.
  - Produces:
      * A local TXT report (CSV-like) under the working directory.
      * An HTML email report (summary) with dynamic subject + TXT attachment.
      * An HTML "Action required" email if auto-fix failed for any URL (with detailed errors) + TXT attachment.
  - Logs a transcript of the entire run to the working directory.

  DESIGN GOALS
  ------------
  - Safe: Truststore is backed up before changes. Requires Administrator rights on Windows.
  - Minimal deps: Only needs a Java JDK (java, javac, keytool).
  - Portable config: Targets (Alias,Url) are loaded from a CSV file to avoid hardcoding sensitive endpoints.

  QUICK START (elevated PowerShell)
  ---------------------------------
    Set-Location '<repo-or-scripts-path>'
    .\Check-And-Fix-Java-Trust.ps1 -TargetsPath '.\targets.csv' -AutoFix -NotifyOnAll:$false

  CSV FORMAT (targets.csv)
  ------------------------
    Alias,Url
    Example1,https://api.example.com/health
    Example2,https://partners.example.net/ping

  SECURITY / DISCLAIMER
  ---------------------
  - This script modifies the Java truststore. Review the code and understand the implications.
  - Only import chains from sources you trust. Consider importing CA certificates rather than leaf certs if policy requires.

  CHANGELOG (from v1.x family)
  ----------------------------
  v2.0 (generic)
    - Removed any company-specific names/addresses.
    - Introduced CSV-driven targets (Alias,Url).
    - Kept: HTML emails, dynamic subject, TXT attachment, Remove-AliasChain, PS 5.1 compatibility.
 ===================================================================== #>

[CmdletBinding()]
param(
  # --- Java / truststore configuration ---------------------------------------
  # Zulu/OpenJDK home (must contain bin\java.exe, bin\javac.exe, bin\keytool.exe)
  [string]$ZuluHome = "C:\Program Files\Zulu\zulu-17",

  # Java truststore and password
  [string]$TrustStorePath = "C:\Program Files\Zulu\zulu-17\lib\security\cacerts",
  [string]$TrustStorePassword = "changeit",

  # --- Working dir and targets config ----------------------------------------
  # Working directory for logs, backups, exported chains, temp Java sources
  [string]$WorkDir = "C:\Scripts\cert-checker\logs",

  # CSV path with targets (Alias,Url). Example:
  #   Alias,Url
  #   Example1,https://api.example.com/health
  [string]$TargetsPath = "C:\Scripts\cert-checker\targets.csv",

  # Optional: pass targets in-memory (array of @{Alias='x';Url='y'}), overrides CSV if provided
  [object[]]$Targets,

  # --- Notification policy ----------------------------------------------------
  # true  -> always send summary (OK or not)
  # false -> send summary only if issues were found and fixed automatically
  [bool]$NotifyOnAll = $true,

  # Disable any email sending
  [switch]$NoEmail,

  # --- SMTP / Email (placeholders) -------------------------------------------
  # Replace with your relay / addresses OR pass as parameters from CI/secret store
  [string]$SmtpServer = "smtp.example.com",
  [int]$SmtpPort = 25,
  [switch]$SmtpUseSsl = $false,
  [string]$MailFrom = "mailer@example.com",
  [string]$MailTo   = "ops@example.com",
  [string]$MailCc   = "",
  [string]$MailSubject = "[Cert Checker] Execution report",
  [string]$SmtpUser = "",    # leave empty for anonymous relay
  [string]$SmtpPassword = "",

  # --- Control flags ----------------------------------------------------------
  # Validate only, do not modify cacerts
  [switch]$DryRun,

  # Attempt auto-fix for PKIX failures
  [switch]$AutoFix
)

# ------------------------- Console helpers -------------------------
function Write-Info  { param($m) Write-Host "[INFO ] $m"  -ForegroundColor Cyan }
function Write-Warn  { param($m) Write-Host "[WARN ] $m"  -ForegroundColor Yellow }
function Write-Error2{ param($m) Write-Host "[ERROR] $m" -ForegroundColor Red }
function New-Dir     { param($p) if (-not (Test-Path $p)) { New-Item -ItemType Directory -Path $p | Out-Null } }

# System.Web for HTML encoding in emails (safe if not present)
try { Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue } catch {}

# ------------------------- Setup logging / environment -----------------------
New-Dir $WorkDir
$TimeStamp = Get-Date -Format "yyyyMMdd_HHmmss"
$LogPath   = Join-Path $WorkDir "run_$TimeStamp.log"
Start-Transcript -Path $LogPath -Force | Out-Null

# Must run elevated to write under Program Files
$IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
if (-not $IsAdmin) {
  Write-Error2 "This script must run as Administrator (needs to write under Program Files)."
  Stop-Transcript | Out-Null
  exit 1
}

# Resolve Java tool paths
$JavaExe    = Join-Path $ZuluHome "bin\java.exe"
$JavacExe   = Join-Path $ZuluHome "bin\javac.exe"
$KeytoolExe = Join-Path $ZuluHome "bin\keytool.exe"
foreach ($bin in @($JavaExe,$JavacExe,$KeytoolExe)) {
  if (-not (Test-Path $bin)) {
    Write-Error2 "Not found: $bin"
    Stop-Transcript | Out-Null
    exit 1
  }
}

# ------------------------- Load targets from CSV or param --------------------
function Load-Targets {
  <#
    PURPOSE
      Return an array of hashtables @{Alias='...'; Url='...'} representing targets to check.

    PRIORITY
      1) If -Targets param was supplied, use it (after minimal validation).
      2) Else, load from CSV at -TargetsPath (must have columns Alias,Url).
      3) Else, return a small in-memory sample (safe placeholders).
  #>
  if ($Targets -and $Targets.Count -gt 0) {
    $list = @()
    foreach ($t in $Targets) {
      if ($t.Alias -and $t.Url) { $list += @{ Alias = [string]$t.Alias; Url = [string]$t.Url } }
    }
    if ($list.Count -gt 0) { return ,$list }
  }
  if (Test-Path $TargetsPath) {
    try {
      $csv = Import-Csv -Path $TargetsPath
      $list = @()
      foreach ($row in $csv) {
        if ($row.Alias -and $row.Url) {
          $list += @{ Alias = [string]$row.Alias; Url = [string]$row.Url }
        }
      }
      if ($list.Count -gt 0) { return ,$list }
      Write-Warn "CSV '$TargetsPath' loaded but contains no valid rows (need Alias,Url)."
    } catch {
      Write-Error2 "Failed to parse CSV '$TargetsPath': $($_.Exception.Message)"
    }
  }
  Write-Warn "No targets provided; using safe sample."
  return ,(@(
    @{ Alias="Example1"; Url="https://api.example.com/health" }
    @{ Alias="Example2"; Url="https://partners.example.net/ping" }
  ))
}

$AliasUrlMap = Load-Targets

# ------------------------- Process runner (captures stdout/stderr/exit) -----
function Invoke-Proc {
  param(
    [Parameter(Mandatory)] [string]$FilePath,
    [Parameter(Mandatory)] [string[]]$Arguments,
    [string]$WorkingDirectory = $PWD.Path,
    [int]$TimeoutSeconds = 120
  )
  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = $FilePath
  $psi.Arguments = ($Arguments -join " ")
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError  = $true
  $psi.UseShellExecute = $false
  $psi.CreateNoWindow = $true
  $psi.WorkingDirectory = $WorkingDirectory

  $p = New-Object System.Diagnostics.Process
  $p.StartInfo = $psi
  [void]$p.Start()
  if (-not $p.WaitForExit($TimeoutSeconds * 1000)) {
    try { $p.Kill() } catch {}
    return @{ ExitCode = 124; StdOut = ""; StdErr = "Timeout after $TimeoutSeconds s" }
  }
  return @{
    ExitCode = $p.ExitCode
    StdOut   = $p.StandardOutput.ReadToEnd()
    StdErr   = $p.StandardError.ReadToEnd()
  }
}

# ------------------------- Truststore helpers -------------------------------
function Backup-TrustStore {
  param([string]$Src, [string]$DestDir)
  New-Dir $DestDir
  $bak = Join-Path $DestDir ("cacerts_" + (Get-Date -Format "yyyyMMdd_HHmmss") + ".bak")
  Copy-Item -Path $Src -Destination $bak -Force
  Write-Info "cacerts backup created: $bak"
  return $bak
}

function Test-AliasExists {
  param([string]$Alias)
  $args = @("-list","-keystore","`"$TrustStorePath`"","-storepass","`"$TrustStorePassword`"","-alias","`"$Alias`"")
  $r = Invoke-Proc -FilePath $KeytoolExe -Arguments $args -TimeoutSeconds 30
  return ($r.ExitCode -eq 0)
}

function Remove-AliasFromCacerts {
  param([string]$Alias)
  $args = @("-delete","-keystore","`"$TrustStorePath`"","-storepass","`"$TrustStorePassword`"","-alias","`"$Alias`"")
  $r = Invoke-Proc -FilePath $KeytoolExe -Arguments $args -TimeoutSeconds 30
  if ($r.ExitCode -ne 0) {
    Write-Warn "Could not delete alias '$Alias' (may not exist): $($r.StdErr.Trim())"
  } else {
    Write-Info "Deleted alias '$Alias' from cacerts."
  }
}

function Remove-AliasChain {
  <#
    PURPOSE
      Cleans up any "<AliasBase>-CA-*" entries previously created for intermediates/roots.
      This avoids leaving stale entries when the server changes its chain.
  #>
  param([Parameter(Mandatory)][string]$AliasBase)

  $args = @("-list","-keystore","`"$TrustStorePath`"","-storepass","`"$TrustStorePassword`"")
  $r = Invoke-Proc -FilePath $KeytoolExe -Arguments $args -TimeoutSeconds 30
  if ($r.ExitCode -ne 0) {
    Write-Warn "Could not list aliases for cleanup of '$AliasBase': $($r.StdErr.Trim())"
    return
  }

  ($r.StdOut -split "`r?`n") | ForEach-Object {
    if ($_ -match "Alias name:\s*(.+)$") {
      $name = $Matches[1].Trim()
      if ($name -like "$AliasBase-CA-*") { Remove-AliasFromCacerts -Alias $name }
    }
  }
}

function Import-CertChainToCacerts {
  <#
    PURPOSE
      Given ONE PEM file containing a concatenated chain, split and import into cacerts as:
        - <AliasBase>        -> leaf
        - <AliasBase>-CA-1+  -> intermediates/root
  #>
  param(
    [Parameter(Mandatory)][string]$AliasBase,
    [Parameter(Mandatory)][string]$CrtPath
  )

  $pemText = Get-Content -Raw -Path $CrtPath
  $pattern = "-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----"
  $matches = [System.Text.RegularExpressions.Regex]::Matches($pemText, $pattern, "Singleline")
  if ($matches.Count -eq 0) { throw "No certificates found in $CrtPath" }

  for ($i=0; $i -lt $matches.Count; $i++) {
    $block = "-----BEGIN CERTIFICATE-----" + $matches[$i].Groups[1].Value + "-----END CERTIFICATE-----"
    $tmp = Join-Path $WorkDir "tmp_$($AliasBase)_$i.crt"
    Set-Content -Path $tmp -Value $block -NoNewline

    $aliasToUse = if ($i -eq 0) { $AliasBase } else { "$AliasBase-CA-$i" }
    $args = @("-importcert","-trustcacerts","-noprompt",
              "-keystore","`"$TrustStorePath`"","-storepass","`"$TrustStorePassword`"",
              "-alias","`"$aliasToUse`"","-file","`"$tmp`"")
    $r = Invoke-Proc -FilePath $KeytoolExe -Arguments $args -TimeoutSeconds 30
    if ($r.ExitCode -ne 0) {
      Write-Error2 "Error importing '$aliasToUse' from ${tmp}: $($r.StdErr.Trim())"
      throw "Import failed for '$aliasToUse'"
    } else {
      Write-Info "Imported '$aliasToUse' into cacerts."
    }
  }
}

# ------------------------- Certificate chain extraction ---------------------
function Export-ServerCertChainPem {
  <#
    PURPOSE
      Connects via TLS to host:port of the URL, captures the presented certificate and builds its chain.
      Writes ONE PEM file (leaf + intermediates/root).

    NOTE
      The validation callback accepts-any certificate; this connection is only for acquiring the chain,
      not for transferring application data.
  #>
  param(
    [Parameter(Mandatory)][string]$Url,
    [Parameter(Mandatory)][string]$OutPath
  )

  $u          = [Uri]$Url
  $serverHost = $u.Host
  $port       = if ($u.Port -gt 0 -and $u.Port -ne 443) { $u.Port } else { 443 }

  Write-Info "Fetching TLS chain from ${serverHost}:${port} ..."
  $tcp = New-Object System.Net.Sockets.TcpClient($serverHost, $port)
  try {
    $sslStream = New-Object System.Net.Security.SslStream(
      $tcp.GetStream(),
      $false,
      ({ param($s,$c,$ch,$e) return $true }),
      $null
    )
    $sslStream.AuthenticateAsClient($serverHost)

    $remoteCert  = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($sslStream.RemoteCertificate)
    $chain       = New-Object System.Security.Cryptography.X509Certificates.X509Chain
    [void]$chain.Build($remoteCert)

    function To-Pem([byte[]]$bytes) {
      $b64 = [System.Convert]::ToBase64String($bytes)
      $lines = ($b64 -split "(.{1,64})" | Where-Object { $_ -and $_.Length -gt 0 })
      return "-----BEGIN CERTIFICATE-----`n" + ($lines -join "`n") + "`n-----END CERTIFICATE-----`n"
    }

    $sb = New-Object System.Text.StringBuilder
    # Leaf first
    [void]$sb.Append((To-Pem -bytes $remoteCert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)))
    # Remaining chain
    foreach ($elem in $chain.ChainElements) {
      if ($elem.Certificate.Thumbprint -ne $remoteCert.Thumbprint) {
        [void]$sb.Append((To-Pem -bytes $elem.Certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)))
      }
    }

    Set-Content -Path $OutPath -Value $sb.ToString() -NoNewline
    Write-Info "TLS chain saved as ONE PEM file: $OutPath"
    return $OutPath
  }
  finally {
    try { $sslStream.Dispose() } catch {}
    try { $tcp.Close() } catch {}
  }
}

# ------------------------- Java-based validation (HEAD over HTTPS) ----------
function Test-UrlWithJavaKeystore {
  <#
    PURPOSE
      Compiles and runs a tiny Java program that performs an HTTPS HEAD using the supplied truststore.

    RETURNS
      Hashtable:
        Success  (bool)
        HttpCode (int or null)
        StdOut   (string)
        StdErr   (string)
        ErrorType ("PKIX" | "Other" | null)
  #>
  param([Parameter(Mandatory)][string]$Url)

  $javaSrc = @"
import javax.net.ssl.HttpsURLConnection;
import java.net.URL;

public class SslCheck {
  public static void main(String[] args) throws Exception {
    if (args.length < 1) {
      System.err.println("URL required");
      System.exit(2);
    }
    String u = args[0];
    URL url = new URL(u);
    HttpsURLConnection con = (HttpsURLConnection) url.openConnection();
    con.setRequestMethod("HEAD");
    con.setConnectTimeout(15000);
    con.setReadTimeout(15000);
    con.connect();
    int code = con.getResponseCode();
    System.out.println("HTTP " + code);
    con.disconnect();
  }
}
"@

  $tmpDir = Join-Path $WorkDir "java"
  New-Dir $tmpDir
  $src = Join-Path $tmpDir "SslCheck.java"
  Set-Content -Path $src -Value $javaSrc -Encoding UTF8

  # Compile
  $r1 = Invoke-Proc -FilePath $JavacExe -Arguments @("`"$src`"") -WorkingDirectory $tmpDir -TimeoutSeconds 60
  if ($r1.ExitCode -ne 0) {
    return @{ Success = $false; HttpCode = $null; StdOut = $r1.StdOut; StdErr = "Compilation error SslCheck.java: " + $r1.StdErr; ErrorType = "Other" }
  }

  # Run with truststore
  $args = @(
    "-Djavax.net.ssl.trustStore=`"$TrustStorePath`"",
    "-Djavax.net.ssl.trustStorePassword=`"$TrustStorePassword`"",
    "-Dhttps.protocols=TLSv1.2,TLSv1.3",
    "-cp","`"$tmpDir`"","SslCheck","`"$Url`""
  )
  $r2 = Invoke-Proc -FilePath $JavaExe -Arguments $args -WorkingDirectory $tmpDir -TimeoutSeconds 60

  $out = ($r2.StdOut + "`n" + $r2.StdErr)
  $pkix = ($out -match "PKIX path building failed" -or $out -match "unable to find valid certification path to requested target")

  if ($r2.ExitCode -eq 0 -and ($r2.StdOut -match "HTTP\s+(\d{3})")) {
    $code = [int]([regex]::Match($r2.StdOut, "HTTP\s+(\d{3})").Groups[1].Value)
    return @{ Success = $true; HttpCode = $code; StdOut = $r2.StdOut; StdErr = $r2.StdErr; ErrorType = $null }
  } elseif ($pkix) {
    return @{ Success = $false; HttpCode = $null; StdOut = $r2.StdOut; StdErr = $r2.StdErr; ErrorType = "PKIX" }
  } else {
    return @{ Success = $false; HttpCode = $null; StdOut = $r2.StdOut; StdErr = $r2.StdErr; ErrorType = "Other" }
  }
}

# ------------------------- HTML helpers / email bodies ----------------------
function HtmlEncode { param([string]$s) if ($s -ne $null) { return [System.Web.HttpUtility]::HtmlEncode($s) } else { return "" } }

function Get-StatusColor {
  param([string]$status)
  switch -Regex ($status) {
    "^(OK)$"      { return "#d1fae5" } # green-100
    "^(FIXED)$"   { return "#fef3c7" } # amber-100
    "^(PKIX)$"    { return "#e5e7eb" } # gray-200
    "^(FAILED)$"  { return "#fecaca" } # red-200
    "^(ERROR)$"   { return "#fecaca" } # red-200
    default       { return "#ffffff" }
  }
}

function Build-HtmlReport {
  <#
    PURPOSE
      Build an HTML summary (metadata + results table). CRT column shows "n/a" when no .crt generated.
  #>
  param(
    [string]$Title,
    [System.Collections.Generic.List[object]]$Report,
    [string]$ZuluHome,
    [string]$TrustStorePath,
    [string]$LogPath,
    [string]$ReportPath,
    [string]$BackupPath
  )

  $rows = New-Object System.Text.StringBuilder
  foreach ($r in $Report) {
    $bg      = Get-StatusColor -status $r.Status
    $alias   = HtmlEncode $r.Alias
    $status  = HtmlEncode $r.Status
    $action  = HtmlEncode $r.Action
    $url     = HtmlEncode $r.Url
    $details = HtmlEncode ($r.Details -replace "`r?`n"," ")

    if ($r.CrtPath -and $r.CrtPath.Trim()) {
      $crtCell = "<code>$([System.Web.HttpUtility]::HtmlEncode($r.CrtPath))</code>"
    } else {
      $crtCell = "<span style='color:#9ca3af'>n/a</span>"
    }

    [void]$rows.AppendLine(@"
<tr style='background:$bg'>
  <td style='padding:8px;border:1px solid #e5e7eb;font-family:Segoe UI,Arial;'>$alias</td>
  <td style='padding:8px;border:1px solid #e5e7eb;font-family:Segoe UI,Arial;'>$status</td>
  <td style='padding:8px;border:1px solid #e5e7eb;font-family:Segoe UI,Arial;'>$action</td>
  <td style='padding:8px;border:1px solid #e5e7eb;font-family:Segoe UI,Arial;word-break:break-all;'>$url</td>
  <td style='padding:8px;border:1px solid #e5e7eb;font-family:Segoe UI,Arial;'>$details</td>
  <td style='padding:8px;border:1px solid #e5e7eb;font-family:Segoe UI,Arial;word-break:break-all;'>$crtCell</td>
</tr>
"@)
  }

  $backupHtml = if ($BackupPath) {
    "<div style='margin:2px 0'>Backup: <code>$([System.Web.HttpUtility]::HtmlEncode($BackupPath))</code></div>"
  } else { "" }

  $html = @"
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>$([System.Web.HttpUtility]::HtmlEncode($Title))</title>
</head>
<body style="margin:0;padding:0;background:#f9fafb;">
  <div style="max-width:980px;margin:24px auto;background:#ffffff;border:1px solid #e5e7eb;border-radius:8px;overflow:hidden;">
    <div style="background:#1E2D55;color:#fff;padding:16px 20px;font-family:Segoe UI,Arial;">
      <h1 style="margin:0;font-size:18px;">$([System.Web.HttpUtility]::HtmlEncode($Title))</h1>
    </div>
    <div style="padding:16px 20px;font-family:Segoe UI,Arial;color:#111827;">
      <div style='margin:2px 0'>Date: <strong>$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</strong></div>
      <div style='margin:2px 0'>ZuluHome: <code>$([System.Web.HttpUtility]::HtmlEncode($ZuluHome))</code></div>
      <div style='margin:2px 0'>cacerts: <code>$([System.Web.HttpUtility]::HtmlEncode($TrustStorePath))</code></div>
      $backupHtml
      <div style='margin:2px 0'>Log: <code>$([System.Web.HttpUtility]::HtmlEncode($LogPath))</code></div>
      <div style='margin:2px 0'>Report: <code>$([System.Web.HttpUtility]::HtmlEncode($ReportPath))</code></div>

      <h2 style="margin:16px 0 8px 0;font-size:16px;">Results</h2>
      <table cellpadding="0" cellspacing="0" style="border-collapse:collapse;width:100%;background:#fff;">
        <thead>
          <tr style="background:#f3f4f6">
            <th style="text-align:left;padding:8px;border:1px solid #e5e7eb;font-family:Segoe UI,Arial;">Alias</th>
            <th style="text-align:left;padding:8px;border:1px solid #e5e7eb;font-family:Segoe UI,Arial;">Status</th>
            <th style="text-align:left;padding:8px;border:1px solid #e5e7eb;font-family:Segoe UI,Arial;">Action</th>
            <th style="text-align:left;padding:8px;border:1px solid #e5e7eb;font-family:Segoe UI,Arial;">URL</th>
            <th style="text-align:left;padding:8px;border:1px solid #e5e7eb;font-family:Segoe UI,Arial;">Details</th>
            <th style="text-align:left;padding:8px;border:1px solid #e5e7eb;font-family:Segoe UI,Arial;">CRT</th>
          </tr>
        </thead>
        <tbody>
          $rows
        </tbody>
      </table>
      <p style="margin-top:10px;color:#6b7280;font-size:12px;">The plain-text report (.txt) is attached to this email.</p>
    </div>
  </div>
  <div style="text-align:center;color:#6b7280;font-size:12px;margin:12px 0;font-family:Segoe UI,Arial;">
    <div>Automated message from Cert Checker</div>
  </div>
</body>
</html>
"@
  return $html
}

function Build-HtmlFailure {
  <#
    PURPOSE
      Build an HTML "Action required" email listing each failed attempt with full error context.
  #>
  param(
    [System.Collections.Generic.List[object]]$FailuresDetail,
    [string]$TrustStorePath,
    [string]$LogPath
  )

  $blocks = New-Object System.Text.StringBuilder
  foreach ($f in $FailuresDetail) {
    $alias = HtmlEncode $f.Alias
    $url   = HtmlEncode $f.Url
    $stage = HtmlEncode $f.Stage
    $crt   = HtmlEncode $f.CrtPath
    $err   = HtmlEncode $f.Error
    [void]$blocks.AppendLine(@"
      <div style="border:1px solid #fca5a5;background:#fef2f2;border-radius:6px;padding:12px;margin:10px 0;">
        <div><strong>Alias:</strong> $alias</div>
        <div><strong>URL:</strong> $url</div>
        <div><strong>Stage:</strong> $stage</div>
        <div><strong>CRT:</strong> <code>$crt</code></div>
        <div style="margin-top:8px;"><strong>Error:</strong></div>
        <pre style="white-space:pre-wrap;background:#fff;border:1px solid #e5e7eb;border-radius:4px;padding:8px;margin:0;">$err</pre>
      </div>
"@)
  }

  $html = @"
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>[Cert Checker] Action required – auto-fix failed</title>
</head>
<body style="margin:0;padding:0;background:#fff7ed;">
  <div style="max-width:980px;margin:24px auto;background:#ffffff;border:1px solid #f59e0b;border-radius:8px;overflow:hidden;">
    <div style="background:#c2410c;color:#fff;padding:16px 20px;font-family:Segoe UI,Arial;">
      <h1 style="margin:0;font-size:18px;">[Cert Checker] Action required – auto-fix failed</h1>
    </div>
    <div style="padding:16px 20px;font-family:Segoe UI,Arial;color:#111827;">
      <div style='margin:2px 0'>Date: <strong>$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</strong></div>
      <div style='margin:2px 0'>cacerts: <code>$([System.Web.HttpUtility]::HtmlEncode($TrustStorePath))</code></div>
      <div style='margin:2px 0'>Log: <code>$([System.Web.HttpUtility]::HtmlEncode($LogPath))</code></div>

      <h2 style="margin:16px 0 8px 0;font-size:16px;">Details</h2>
      $blocks
      <p style="margin-top:10px;color:#6b7280;font-size:12px;">The plain-text report (.txt) is attached to this email.</p>
    </div>
  </div>
  <div style="text-align:center;color:#6b7280;font-size:12px;margin:12px 0;font-family:Segoe UI,Arial;">
    <div>Automated message from Cert Checker</div>
  </div>
</body>
</html>
"@
  return $html
}

# ------------------------- Email (HTML + attachments) -----------------------
function Send-EmailReport {
  <#
    PURPOSE
      Sends an HTML email (with CC and attachments). Uses System.Net.Mail.SmtpClient for compatibility.
  #>
  param(
    [string]$Subject,
    [string]$HtmlBody,
    [string[]]$Attachments
  )
  if ($NoEmail) { Write-Warn "Email sending disabled (-NoEmail)."; return }

  try {
    $msg = New-Object System.Net.Mail.MailMessage
    $msg.From = $MailFrom
    $MailTo.Split(",") | ForEach-Object { if ($_.Trim()) { [void]$msg.To.Add($_.Trim()) } }
    if ($MailCc) { $MailCc.Split(",") | ForEach-Object { if ($_.Trim()) { [void]$msg.CC.Add($_.Trim()) } } }
    $msg.Subject = $Subject
    $msg.IsBodyHtml = $true
    $msg.Body = $HtmlBody

    if ($Attachments) {
      foreach ($p in $Attachments) {
        if ($p -and (Test-Path $p)) {
          $att = New-Object System.Net.Mail.Attachment($p)
          [void]$msg.Attachments.Add($att)
        }
      }
    }

    $client = New-Object System.Net.Mail.SmtpClient($SmtpServer, $SmtpPort)
    $client.EnableSsl = [bool]$SmtpUseSsl
    if ($SmtpUser -and $SmtpPassword) {
      $client.Credentials = New-Object System.Net.NetworkCredential($SmtpUser, $SmtpPassword)
    }
    $client.Send($msg)
    Write-Info "Email sent: $Subject"
    $msg.Dispose()
  } catch {
    Write-Error2 "Error sending email: $($_.Exception.Message)"
  }
}

# ------------------------- Dynamic subject ----------------------------------
function Build-DynamicSubject {
  <#
    PURPOSE
      Construct a subject line including counts by status.
      Example: "[Cert Checker] OK:3 | FIXED:1 | FAILED:0 | ERROR:0 | PKIX:0 (Total:4)"
  #>
  param(
    [Parameter(Mandatory)][System.Collections.Generic.List[object]]$Report,
    [string]$Prefix = "[Cert Checker]"
  )
  $ok     = ($Report | Where-Object { $_.Status -eq "OK" }).Count
  $fixed  = ($Report | Where-Object { $_.Status -eq "FIXED" }).Count
  $failed = ($Report | Where-Object { $_.Status -eq "FAILED" }).Count
  $error  = ($Report | Where-Object { $_.Status -eq "ERROR" }).Count
  $pkix   = ($Report | Where-Object { $_.Status -eq "PKIX" }).Count
  $total  = $Report.Count
  return "$Prefix OK:$ok | FIXED:$fixed | FAILED:$failed | ERROR:$error | PKIX:$pkix (Total:$total)"
}

# ------------------------- MAIN --------------------------------------------
Write-Info  "ZuluHome: $ZuluHome"
Write-Info  "cacerts : $TrustStorePath"
Write-Info  "WorkDir : $WorkDir"
Write-Info  "Targets : $TargetsPath"
Write-Info  "AutoFix : " + ($AutoFix.IsPresent)
Write-Info  "DryRun  : " + ($DryRun.IsPresent)
Write-Info  "NotifyOnAll: $NotifyOnAll"

# Backup if we might modify cacerts
$BackupPath = $null
if ($AutoFix -and -not $DryRun) {
  $BackupPath = Backup-TrustStore -Src $TrustStorePath -DestDir $WorkDir
}

$Report = New-Object System.Collections.Generic.List[object]
$FailuresDetail = New-Object System.Collections.Generic.List[object]

foreach ($item in $AliasUrlMap) {
  $alias = $item.Alias
  $url   = $item.Url

  Write-Host ""
  Write-Info "=== Processing [$alias] $url ==="

  $aliasExists = Test-AliasExists -Alias $alias
  if (-not $aliasExists) { Write-Warn "Alias '$alias' not found in cacerts." }

  # 1) Validate via Java + cacerts
  $probe = Test-UrlWithJavaKeystore -Url $url
  if ($probe.Success) {
    Write-Info "TLS OK (HTTP $($probe.HttpCode))."
    $Report.Add([pscustomobject]@{
      Alias = $alias; Url = $url; Status = "OK"; Details = "HTTP $($probe.HttpCode)"; Action = "None"; CrtPath = ""
    })
    continue
  }

  # 2) On PKIX -> attempt auto-fix (if allowed)
  if ($probe.ErrorType -eq "PKIX") {
    Write-Warn "Detected PKIX path building failed."

    if ($DryRun) {
      Write-Warn "DryRun active: NOT fixing, reporting only."
      $Report.Add([pscustomobject]@{
        Alias = $alias; Url = $url; Status = "PKIX"; Details = "Validation failed (dry-run)"; Action = "Export chain & import"; CrtPath = ""
      })
      continue
    }

    if ($AutoFix) {
      $crtPath = $null
      try {
        # 2.1) Export chain as ONE PEM file
        $crtPath = Join-Path $WorkDir ("$alias" + "_" + (Get-Date -Format "yyyyMMdd_HHmmss") + ".crt")
        Export-ServerCertChainPem -Url $url -OutPath $crtPath | Out-Null

        # 2.2) Remove previous alias + any residual Alias-CA-*
        if ($aliasExists) { Remove-AliasFromCacerts -Alias $alias }
        Remove-AliasChain -AliasBase $alias

        # 2.3) Import entire chain
        Import-CertChainToCacerts -AliasBase $alias -CrtPath $crtPath

        # 2.4) Revalidate
        $probe2 = Test-UrlWithJavaKeystore -Url $url
        if ($probe2.Success) {
          Write-Info "Fixed. TLS now OK (HTTP $($probe2.HttpCode))."
          $Report.Add([pscustomobject]@{
            Alias = $alias; Url = $url; Status = "FIXED"; Details = "HTTP $($probe2.HttpCode)"; Action = "Reimported chain"; CrtPath = [string]$crtPath
          })
        } else {
          $errFull = "After reimport: Type=$($probe2.ErrorType) | StdOut=$($probe2.StdOut) | StdErr=$($probe2.StdErr)"
          Write-Error2 "Still failing: $errFull"
          $Report.Add([pscustomobject]@{
            Alias = $alias; Url = $url; Status = "FAILED"; Details = "Not fixed"; Action = "Manual review"; CrtPath = [string]$crtPath
          })
          $FailuresDetail.Add([pscustomobject]@{
            Alias=$alias; Url=$url; Stage="Post-Import Validation"; Error=$errFull; CrtPath=[string]$crtPath
          })
        }
      }
      catch {
        $err = $_.Exception | Out-String
        Write-Error2 "Exception while fixing [$alias]: $($err.Trim())"
        $Report.Add([pscustomobject]@{
          Alias = $alias; Url = $url; Status = "ERROR"; Details = "Exception during fix"; Action = "Manual review"; CrtPath = [string]$crtPath
        })
        $FailuresDetail.Add([pscustomobject]@{
          Alias=$alias; Url=$url; Stage="Import Chain"; Error=$err; CrtPath=[string]$crtPath
        })
      }
    } else {
      Write-Warn "AutoFix disabled. Reporting the PKIX failure."
      $Report.Add([pscustomobject]@{
        Alias = $alias; Url = $url; Status = "PKIX"; Details = "Validation failed"; Action = "Enable -AutoFix to correct"; CrtPath = ""
      })
    }
  }
  else {
    # 3) Non-PKIX errors (DNS, proxy, timeout, etc.)
    $err = ($probe.StdErr.Trim() + " " + $probe.StdOut.Trim()).Trim()
    Write-Error2 "Non-PKIX error: $err"
    $Report.Add([pscustomobject]@{
      Alias = $alias; Url = $url; Status = "ERROR"; Details = $err; Action = "Diagnose"; CrtPath = ""
    })
  }
}

# ------------------------- Local TXT report ---------------------------------
$lines = @()
$lines += "Check-And-Fix-Java-Trust.ps1 – Report"
$lines += "Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
$lines += "ZuluHome: $ZuluHome"
$lines += "cacerts:  $TrustStorePath"
if ($BackupPath) { $lines += "Backup:   $BackupPath" }
$lines += "Log:      $LogPath"
$lines += ""
$lines += "Results:"
$lines += "Alias;Status;Action;URL;Details;CRT"

foreach ($r in $Report) {
  $lines += "{0};{1};{2};{3};{4};{5}" -f $r.Alias,$r.Status,$r.Action,$r.Url,($r.Details -replace "`r?`n"," "),$r.CrtPath
}

$ReportPath = Join-Path $WorkDir ("report_" + $TimeStamp + ".txt")
$lines | Set-Content -Path $ReportPath -Encoding UTF8

Write-Host ""
Write-Info "Report saved to: $ReportPath"
Write-Info "Transcript at : $LogPath"

# ------------------------- Emails ------------------------------------------
$summaryHtml = Build-HtmlReport -Title "Cert Checker – Execution report" `
  -Report $Report -ZuluHome $ZuluHome -TrustStorePath $TrustStorePath `
  -LogPath $LogPath -ReportPath $ReportPath -BackupPath $BackupPath

function Maybe-Send-Summary {
  param([string]$htmlBody)
  if ($NoEmail) { return }
  $anyFixed  = ($Report | Where-Object { $_.Status -eq "FIXED" }).Count -gt 0
  $subject   = Build-DynamicSubject -Report $Report -Prefix "[Cert Checker]"
  if ($NotifyOnAll) {
    Send-EmailReport -Subject $subject -HtmlBody $htmlBody -Attachments @($ReportPath)
  } else {
    if ($anyFixed) {
      Send-EmailReport -Subject $subject -HtmlBody $htmlBody -Attachments @($ReportPath)
    } else {
      Write-Info "NotifyOnAll=false and no issues fixed: not sending summary."
    }
  }
}

Maybe-Send-Summary -htmlBody $summaryHtml

$pendingFailures = $FailuresDetail.Count -gt 0
if ($pendingFailures -and -not $NoEmail) {
  $failHtml   = Build-HtmlFailure -FailuresDetail $FailuresDetail -TrustStorePath $TrustStorePath -LogPath $LogPath
  $failCount  = $FailuresDetail.Count
  $failSubj   = "[Cert Checker] Action required – auto-fix failed ($failCount)"
  Send-EmailReport -Subject $failSubj -HtmlBody $failHtml -Attachments @($ReportPath)
}

Stop-Transcript | Out-Null
