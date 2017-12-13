@echo off
set BAT_PATH=%~dp0
set PYTHONPATH=%BAT_PATH%

python -O -m libs.main %*