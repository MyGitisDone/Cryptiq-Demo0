@echo off
REM Thin wrapper for Windows — all the real logic lives in run_demo.py.
cd /d "%~dp0\.."
python run_demo.py pqc
