@echo off
title ServiceZone Upload Server
cd /d "%~dp0"

set PY=
where python >nul 2>nul && set PY=python
if "%PY%"=="" (
  where py >nul 2>nul && set PY=py
)
if "%PY%"=="" (
  echo Python n'est pas installe. Installez-le d'abord avec "Add Python to PATH".
  pause
  exit /b
)

%PY% -c "import flask" >nul 2>nul
if errorlevel 1 (
  echo Installation de Flask...
  %PY% -m pip install flask
)

where cloudflared >nul 2>nul
if errorlevel 1 (
  echo cloudflared introuvable: le serveur demarre en reseau local seulement.
) else (
  start "Cloudflare Tunnel" cmd /k cloudflared tunnel --url http://localhost:8000
)

echo.
echo === Serveur en marche. NE FERMEZ PAS cette fenetre ===
echo.
%PY% app.py
pause
