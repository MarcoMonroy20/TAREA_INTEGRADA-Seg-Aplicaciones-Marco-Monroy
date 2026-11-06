$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
$pythonLocal = Join-Path $PSScriptRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $pythonLocal)) {
    if (Get-Command py -ErrorAction SilentlyContinue) {
        & py -3 -m venv '.venv'
    } else {
        & python -m venv '.venv'
    }
    if ($LASTEXITCODE -ne 0) { throw 'Se necesita una instalacion de Python 3.12 o posterior para crear el entorno.' }
}
& $pythonLocal -c "import importlib.util, sys; sys.exit(0 if all(importlib.util.find_spec(n) for n in ('flask', 'argon2', 'cryptography')) else 1)"
if ($LASTEXITCODE -ne 0) {
    & $pythonLocal -m pip install -r requirements.txt
    if ($LASTEXITCODE -ne 0) { throw 'No fue posible instalar las dependencias.' }
}
& $pythonLocal preparar.py
if ($LASTEXITCODE -ne 0) { throw 'Revise el mensaje de preparacion antes de continuar.' }
$datosLocal = Join-Path $PSScriptRoot 'datos_locales'
$usuarioSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
& icacls $datosLocal /inheritance:r /grant:r "*$($usuarioSid):(OI)(CI)F" '*S-1-5-18:(OI)(CI)F' /Q
if ($LASTEXITCODE -ne 0) { throw 'No se pudieron restringir los permisos de datos_locales.' }
& icacls (Join-Path $datosLocal '*') /reset /T /Q
if ($LASTEXITCODE -ne 0) { throw 'No se pudieron heredar los permisos de la carpeta privada.' }
Write-Host 'Consulte datos_locales\accesos.txt para conocer las cuentas ficticias.'
Write-Host 'Abra https://127.0.0.1:8443 en su navegador.'
& $pythonLocal ejecutar.py
exit $LASTEXITCODE
