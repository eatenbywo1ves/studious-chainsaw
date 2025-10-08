@echo off
echo ========================================
echo WSL2 DNS Fix and Checkpoint Installation
echo ========================================
echo.

echo Step 1: Fixing WSL2 DNS resolution...
echo.

REM Execute DNS fix commands in WSL
wsl -d Ubuntu -u root bash -c "rm -f /etc/resolv.conf && echo 'nameserver 8.8.8.8' > /etc/resolv.conf && echo 'nameserver 8.8.4.4' >> /etc/resolv.conf && cat /etc/resolv.conf"

echo.
echo Step 2: Testing DNS resolution...
echo.

wsl -d Ubuntu bash -c "ping -c 3 google.com"

if errorlevel 1 (
    echo.
    echo DNS test failed. Trying alternative approach...
    echo.

    REM Try with wsl.conf approach
    wsl -d Ubuntu -u root bash -c "mkdir -p /etc && cat > /etc/wsl.conf << EOF
[network]
generateResolvConf = false
EOF
"

    echo WSL needs to be restarted. Running: wsl --shutdown
    wsl --shutdown
    timeout /t 5 /nobreak > nul

    echo Restarting WSL and applying DNS settings...
    wsl -d Ubuntu -u root bash -c "rm -f /etc/resolv.conf && echo 'nameserver 8.8.8.8' > /etc/resolv.conf && echo 'nameserver 8.8.4.4' >> /etc/resolv.conf"

    echo Testing DNS again...
    wsl -d Ubuntu bash -c "ping -c 3 google.com"
)

echo.
echo Step 3: Running checkpoint installation...
echo.

wsl -d Ubuntu bash -c "cd /mnt/c/Users/Corbin/development/security/wiz-challenge && ./checkpoint-install.sh"

echo.
echo ========================================
echo Installation Complete!
echo ========================================
pause
