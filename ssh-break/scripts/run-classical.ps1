# Thin wrapper for Windows PowerShell — all the real logic lives in run_demo.py.
Set-Location -Path (Join-Path $PSScriptRoot "..")
python run_demo.py classical
