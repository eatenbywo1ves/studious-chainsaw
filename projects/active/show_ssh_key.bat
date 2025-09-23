@echo off
echo Checking for SSH public keys...
echo.

if exist "%USERPROFILE%\.ssh\id_rsa.pub" (
    echo Found RSA public key:
    echo ========================================
    type "%USERPROFILE%\.ssh\id_rsa.pub"
    echo ========================================
    goto :end
)

if exist "%USERPROFILE%\.ssh\id_ed25519.pub" (
    echo Found Ed25519 public key:
    echo ========================================
    type "%USERPROFILE%\.ssh\id_ed25519.pub"
    echo ========================================
    goto :end
)

if exist "%USERPROFILE%\.ssh\id_ecdsa.pub" (
    echo Found ECDSA public key:
    echo ========================================
    type "%USERPROFILE%\.ssh\id_ecdsa.pub"
    echo ========================================
    goto :end
)

echo No SSH public keys found in %USERPROFILE%\.ssh\
echo.
echo To generate a new SSH key, run:
echo ssh-keygen -t ed25519 -C "your_email@example.com"

:end