@echo off
REM Launcher for netcap.
REM
REM Python is often not on PATH on Windows: the "python" that ships with
REM Windows is a Microsoft Store stub that does nothing when run. This finds a
REM real interpreter and runs the tool with it.
REM
REM     netcap.cmd -c 40
REM     netcap.cmd -a examples\sample.pcap -v
REM     netcap.cmd -L
REM
REM All arguments are passed straight through to netcap.

setlocal enabledelayedexpansion

set "PYTHON="

REM 1. An interpreter already on PATH. Skip the Store stub, which exits 9009.
for %%I in (python.exe python3.exe py.exe) do (
    if not defined PYTHON (
        %%I -c "import sys" >nul 2>&1
        if not errorlevel 1 set "PYTHON=%%~$PATH:I"
    )
)

REM 2. The per-user install created by python.org.
if not defined PYTHON (
    for /d %%D in ("%LOCALAPPDATA%\Programs\Python\Python3*") do (
        if exist "%%D\python.exe" if not defined PYTHON set "PYTHON=%%D\python.exe"
    )
)

REM 3. The machine-wide install.
if not defined PYTHON (
    for /d %%D in ("C:\Program Files\Python3*") do (
        if exist "%%D\python.exe" if not defined PYTHON set "PYTHON=%%D\python.exe"
    )
)

if not defined PYTHON (
    echo Python was not found.
    echo.
    echo Install it from https://www.python.org/downloads/ and tick
    echo "Add python.exe to PATH", then from this folder run:
    echo.
    echo     python -m pip install -r requirements.txt
    echo.
    echo npcap is also needed for live capture on Windows: https://npcap.com/
    exit /b 1
)

pushd "%~dp0"
"%PYTHON%" -m netcap %*
set "RC=%ERRORLEVEL%"
popd
exit /b %RC%
