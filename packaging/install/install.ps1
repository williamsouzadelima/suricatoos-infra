<#
  Suricatoos Agent — instalador one-shot (Windows x64).

  Baixa o binário do GitHub Release, verifica o SHA-256, instala, enrola no
  control-plane e registra o serviço SCM. Pensado para o fluxo sem fricção:

    irm https://scanner.suricatoos.com/install.ps1 | iex; `
    Install-SuricatoosAgent -Server https://scanner.suricatoos.com/agent/v1 -Token <TOKEN> -CaPin <PIN>

  Ou direto:
    powershell -ExecutionPolicy Bypass -File install.ps1 -Server <URL> -Token <TOKEN> -CaPin <PIN>
#>
param(
  [Parameter(Mandatory = $true)][string]$Server,
  [Parameter(Mandatory = $true)][string]$Token,
  [string]$CaPin = "",
  [string]$Version = "",
  [string]$Repo = "williamsouzadelima/suricatoos-infra",
  [switch]$NoService
)

$ErrorActionPreference = "Stop"

# Requer Administrador (instalar serviço + Program Files).
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
  ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) { throw "Rode como Administrador." }

$binName = "suricatoos-agent-windows-amd64.exe"

# Resolve a versão (default: último release agent-v*).
if (-not $Version) {
  $rels = Invoke-RestMethod "https://api.github.com/repos/$Repo/releases" -Headers @{ "User-Agent" = "suricatoos-install" }
  $tag = ($rels | Where-Object { $_.tag_name -like "agent-v*" } | Select-Object -First 1).tag_name
  if (-not $tag) { throw "Não consegui resolver a versão; passe -Version." }
  $Version = $tag -replace '^agent-v', ''
}
$base = "https://github.com/$Repo/releases/download/agent-v$Version"

Write-Host ">> Suricatoos Agent $Version (windows/amd64)"
$tmp = New-Item -ItemType Directory -Path ([IO.Path]::Combine($env:TEMP, "suricatoos-" + [guid]::NewGuid()))
try {
  $bin = Join-Path $tmp $binName
  Write-Host ">> baixando $binName"
  Invoke-WebRequest "$base/$binName" -OutFile $bin -UseBasicParsing
  $sumsFile = Join-Path $tmp "sums"
  Invoke-WebRequest "$base/SHA256SUMS-bin" -OutFile $sumsFile -UseBasicParsing

  # Verifica SHA-256.
  $want = (Get-Content $sumsFile | Where-Object { $_ -match [regex]::Escape($binName) + '$' } |
    ForEach-Object { ($_ -split '\s+')[0] }) | Select-Object -First 1
  $got = (Get-FileHash $bin -Algorithm SHA256).Hash.ToLower()
  if (-not $want -or $want.ToLower() -ne $got) { throw "sha256 não confere ($got != $want)" }
  Write-Host ">> sha256 verificado"

  # Instala.
  $dir = Join-Path $env:ProgramFiles "Suricatoos Agent"
  New-Item -ItemType Directory -Force -Path $dir | Out-Null
  $exe = Join-Path $dir "suricatoos-agent.exe"
  Copy-Item $bin $exe -Force
  Write-Host ">> instalado em $exe"

  $state = Join-Path $env:ProgramData "Suricatoos\agent"
  New-Item -ItemType Directory -Force -Path $state | Out-Null

  # Enroll.
  Write-Host ">> enroll no control-plane"
  $enrollArgs = @("enroll", "--state", $state, "--server", $Server, "--token", $Token)
  if ($CaPin) { $enrollArgs += @("--ca-pin", $CaPin) }
  & $exe @enrollArgs
  if ($LASTEXITCODE -ne 0) { throw "enroll falhou ($LASTEXITCODE)" }

  # Serviço.
  if (-not $NoService) {
    Write-Host ">> registrando serviço SCM"
    & $exe install
    Write-Host ">> pronto — agente instalado, enrolado e rodando."
  } else {
    Write-Host ">> pronto — agente instalado e enrolado (serviço não registrado)."
  }
}
finally {
  Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}
