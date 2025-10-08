#!/bin/bash
# Fix WSL2 DNS Resolution

echo "=== Fixing WSL2 DNS Resolution ==="

# Remove old resolv.conf
echo "Step 1: Removing old resolv.conf..."
sudo rm -f /etc/resolv.conf

# Create new resolv.conf with Google DNS
echo "Step 2: Creating new resolv.conf with Google DNS..."
echo "nameserver 8.8.8.8" | sudo tee /etc/resolv.conf > /dev/null
echo "nameserver 8.8.4.4" | sudo tee -a /etc/resolv.conf > /dev/null

# Display the new configuration
echo "Step 3: New DNS configuration:"
cat /etc/resolv.conf

echo ""
echo "=== DNS Fix Complete ==="
echo "Testing DNS resolution..."
ping -c 3 google.com

exit_code=$?
if [ $exit_code -eq 0 ]; then
    echo ""
    echo "SUCCESS: DNS resolution is working!"
else
    echo ""
    echo "ERROR: DNS resolution still failing"
fi

exit $exit_code
