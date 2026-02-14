@echo off
title IoT Threat Analyzer - Instalacja

echo.
echo ================================================================
echo.
echo              IoT THREAT ANALYZER v1.0
echo                      INSTALACJA
echo.
echo ================================================================
echo.

echo [1/3] Sprawdzanie Pythona...
python --version > nul 2>&1
if errorlevel 1 (
    echo [BLAD] Python nie jest zainstalowany!
    echo Pobierz: https://www.python.org/downloads/
    pause
    exit /b 1
)
echo       Python - OK
echo.

echo [2/3] Instalowanie zaleznosci...
cd /d "%~dp0"
pip install -r requirements.txt
if errorlevel 1 (
    echo [BLAD] Instalacja nie powiodla sie!
    pause
    exit /b 1
)
echo.

echo [3/3] Weryfikacja...
python -c "import flask" > nul 2>&1
if errorlevel 1 (
    echo [BLAD] Flask nie zainstalowany!
    pause
    exit /b 1
)
echo       Flask - OK

if exist "%~dp0app.py" (
    echo       app.py - OK
) else (
    echo [BLAD] Brak pliku app.py!
    pause
    exit /b 1
)

if exist "%~dp0IoTThreatAnalyzer_v1.py" (
    echo       Analizator - OK
) else (
    echo [BLAD] Brak pliku IoTThreatAnalyzer_v1.py!
    pause
    exit /b 1
)

echo.
echo ================================================================
echo.
echo   INSTALACJA ZAKONCZONA!
echo.
echo   Uruchom: start.bat
echo.
echo ================================================================
echo.

pause
