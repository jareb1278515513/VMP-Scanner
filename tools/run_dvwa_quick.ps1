param(
  [string]$Target = "http://127.0.0.1/dvwa/",
    [string]$AllowedDomain = "127.0.0.1",
    [string]$Mode = "attack",
  [int]$MaxDepth = 10,
    [string]$LoginUrl = "/dvwa/login.php",
    [string]$Username = "admin",
    [string]$Password = "password",
    [string]$ReportDir = "reports"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$outDir = Join-Path $ReportDir "dvwa-quick-$timestamp"
New-Item -Path $outDir -ItemType Directory -Force | Out-Null

$jsonReport = Join-Path $outDir "risk-report.json"
$mdReport = Join-Path $outDir "risk-report.md"
$htmlReport = Join-Path $outDir "risk-report.html"

Write-Host "[vmp] Running DVWA full pipeline..."
Write-Host "[vmp] Profile: full DVWA vulnerabilities"
Write-Host "[vmp] Target: $Target"
Write-Host "[vmp] Output: $outDir"

uv run main.py `
  --target "$Target" `
  --mode $Mode `
  --max-depth $MaxDepth `
  --allowed-domain $AllowedDomain `
  --auto-login `
  --auth-login-url $LoginUrl `
  --auth-username $Username `
  --auth-password $Password `
  --auth-submit-field Login `
  --auth-submit-value Login `
  --auth-success-keyword logout.php `
  --auth-extra security=low `
  --report-json "$jsonReport" `
  --report-markdown "$mdReport" `
  --report-html "$htmlReport" `
  --log-level INFO

if ($LASTEXITCODE -ne 0) {
    throw "vmp-scanner failed with exit code $LASTEXITCODE"
}

Write-Host ""
Write-Host "[vmp] Done. Reports generated:"
Write-Host "  JSON: $jsonReport"
Write-Host "  Markdown: $mdReport"
Write-Host "  HTML: $htmlReport"
Write-Host ""
Write-Host "[vmp] Open HTML report quickly:"
Write-Host ('  start "" "{0}"' -f $htmlReport)
