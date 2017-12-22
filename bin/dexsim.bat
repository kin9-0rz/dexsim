@echo off
set BAT_PATH=%~dp0
set PYTHONPATH=%BAT_PATH:~0,-5%

python -O -m dexsim.main %*
