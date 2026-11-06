$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
$versionHerramienta = '8.30.1'
$directorioHerramienta = Join-Path $PSScriptRoot '.herramientas'
New-Item -ItemType Directory -Path $directorioHerramienta -Force | Out-Null
$archivoZip = Join-Path $directorioHerramienta "gitleaks_${versionHerramienta}_windows_x64.zip"
$urlHerramienta = "https://github.com/gitleaks/gitleaks/releases/download/v${versionHerramienta}/gitleaks_${versionHerramienta}_windows_x64.zip"
Invoke-WebRequest -Uri $urlHerramienta -OutFile $archivoZip
$esperado = 'D29144DEFF3A68AA93CED33DDDF84B7FDC26070ADD4AA0F4513094C8332AFC4E'
if ((Get-FileHash -LiteralPath $archivoZip -Algorithm SHA256).Hash -ne $esperado) {
    throw 'El archivo descargado no coincide con la suma de integridad verificada.'
}
Expand-Archive -LiteralPath $archivoZip -DestinationPath $directorioHerramienta -Force
& (Join-Path $directorioHerramienta 'gitleaks.exe') version
