@echo off
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
  echo Ejecute primero INICIAR_LABORATORIO.cmd para preparar las dependencias.
  pause
  exit /b 1
)
".venv\Scripts\python.exe" pruebas.py
pause
