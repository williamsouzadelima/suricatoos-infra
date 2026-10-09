<#
  Suricatoos Agent - instalador one-shot (Windows x64).

  Baixa o binario do GitHub Release, verifica o SHA-256, instala, enrola no
  control-plane e registra o servico SCM. Pensado para o fluxo sem friccao:

    irm https://scanner.suricatoos.com/install.ps1 | iex; `
    Install-SuricatoosAgent -Server https://scanner.suricatoos.com/agent/v1 -Token <TOKEN> -CaPin <PIN>

  Ou direto:
    powershell -ExecutionPolicy Bypass -File install.ps1 -Server <URL> -Token <TOKEN> -CaPin <PIN>

  NOTA: este arquivo e deliberadamente ASCII-only. O Windows PowerShell 5.1 le um
  script sem BOM na codepage ANSI, entao qualquer acento em UTF-8 sairia corrompido
  quando servido por 'irm | iex' ou salvo e executado.
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

# Requer Administrador (instalar servico + Program Files).
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
  ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) { throw "Rode como Administrador." }

$binName = "suricatoos-agent-windows-amd64.exe"

# Resolve a versao (default: ultimo release agent-v*).
if (-not $Version) {
  $rels = Invoke-RestMethod "https://api.github.com/repos/$Repo/releases" -Headers @{ "User-Agent" = "suricatoos-install" }
  $tag = ($rels | Where-Object { $_.tag_name -like "agent-v*" } | Select-Object -First 1).tag_name
  if (-not $tag) { throw "Nao consegui resolver a versao; passe -Version." }
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
  if (-not $want -or $want.ToLower() -ne $got) { throw "sha256 nao confere ($got != $want)" }
  Write-Host ">> sha256 verificado"

  # Instala.
  $dir = Join-Path $env:ProgramFiles "Suricatoos Agent"
  New-Item -ItemType Directory -Force -Path $dir | Out-Null
  $exe = Join-Path $dir "suricatoos-agent.exe"
  # Se o agente ja esta instalado como servico, pare-o antes de sobrescrever o
  # exe: um upgrade/reinstalacao por cima do servico em execucao travaria o
  # Copy-Item ("arquivo em uso por outro processo").
  $svc = Get-Service -Name "SuricatoosAgent" -ErrorAction SilentlyContinue
  if ($svc -and $svc.Status -ne "Stopped") {
    Write-Host ">> parando o servico existente para atualizar o binario"
    Stop-Service -Name "SuricatoosAgent" -Force -ErrorAction SilentlyContinue
    try { $svc.WaitForStatus("Stopped", [TimeSpan]::FromSeconds(20)) } catch {}
  }
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

  # Servico. --state aponta p/ a identidade recem-enrolada; o install herda dela a
  # URL de ingest (persistida no enroll), evitando exigir --ingest manualmente.
  if (-not $NoService) {
    if (Get-Service -Name "SuricatoosAgent" -ErrorAction SilentlyContinue) {
      # Ja registrado (upgrade): o exe no mesmo caminho foi atualizado acima;
      # apenas religa o servico, sem re-registrar (CreateService falharia se o
      # servico ja existe).
      Write-Host ">> reiniciando o servico existente (upgrade)"
      Start-Service -Name "SuricatoosAgent"
      Write-Host ">> pronto - agente atualizado e servico reiniciado."
    } else {
      Write-Host ">> registrando servico SCM"
      & $exe install --state $state
      if ($LASTEXITCODE -ne 0) { throw "registro do servico falhou ($LASTEXITCODE) - veja a mensagem acima" }
      Write-Host ">> pronto - agente instalado, enrolado e servico registrado."
    }
    Write-Host ">> confira com: & '$exe' service-status"
  } else {
    Write-Host ">> pronto - agente instalado e enrolado (servico nao registrado)."
  }
}
finally {
  Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}
