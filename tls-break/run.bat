@echo off
REM Thin wrapper for Windows — all the real logic lives in run.py.
cd /d "%~dp0"
python run.py
