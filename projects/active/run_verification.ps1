# PowerShell script to run Python lint verification
Set-Location "C:\Users\Corbin\development"
python verify_lint_fixes.py
exit $LASTEXITCODE