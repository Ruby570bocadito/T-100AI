@echo off
REM T-100AI - AI-Powered Offensive Security Terminal
REM Lanzador para Windows
REM Compatible con Windows 10/11, PowerShell y CMD

cd /d "%~dp0"

REM Activar entorno virtual si existe
if exist "venv\Scripts\activate.bat" (
    call venv\Scripts\activate.bat
)

REM Configurar codificacion UTF-8 para PowerShell
chcp 65001 >nul 2>&1

REM Asegurar que el paquete (src/) es importable sin necesidad de pip install -e .
set "PYTHONPATH=%~dp0src;%PYTHONPATH%"

REM Ejecutar T-100AI
python -m t100ai.cli.main %*

REM Pausar si hubo error
if errorlevel 1 (
    echo.
    echo Presiona cualquier tecla para salir...
    pause >nul
)
