-- Wireshark Custom Configuration & Dissectors
-- Place this file in: %APPDATA%\Wireshark\plugins\

-- ============================================
-- Custom Protocol Dissectors
-- ============================================

-- 1. Custom TCP Stream Analyzer
local tcp_stream = Proto("tcp_stream", "TCP Stream Analyzer")
tcp_stream.fields.payload_size = ProtoField.uint32("tcp_stream.payload_size", "Payload Size", base.DEC)
tcp_stream.fields.flags = ProtoField.string("tcp_stream.flags", "TCP Flags")

function tcp_stream.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = "TCP_STREAM"
    local subtree = tree:add(tcp_stream, buffer(), "TCP Stream Analysis")
    subtree:add(tcp_stream.fields.payload_size, buffer:len())
end

-- Register with TCP port range
tcp_table = DissectorTable.get("tcp.port")
for port = 8000, 9000 do
    tcp_table:add(port, tcp_stream)
end

-- ============================================
-- 2. Cryptocurrency Traffic Detector
-- ============================================
local crypto_detect = Proto("crypto_detect", "Cryptocurrency Traffic Detector")
crypto_detect.fields.type = ProtoField.string("crypto_detect.type", "Crypto Type")
crypto_detect.fields.pool = ProtoField.string("crypto_detect.pool", "Mining Pool")

-- Common mining pool patterns
local mining_pools = {
    ["pool."] = "Mining Pool Detected",
    ["stratum"] = "Stratum Protocol",
    ["mining"] = "Mining Activity",
    ["nicehash"] = "NiceHash Pool",
    ["ethermine"] = "Ethermine Pool",
    ["f2pool"] = "F2Pool",
    ["slushpool"] = "SlushPool"
}

function crypto_detect.dissector(buffer, pinfo, tree)
    local data = buffer():string()
    for pattern, pool_name in pairs(mining_pools) do
        if string.find(data:lower(), pattern) then
            pinfo.cols.protocol = "CRYPTO"
            local subtree = tree:add(crypto_detect, buffer(), "Cryptocurrency Activity Detected")
            subtree:add(crypto_detect.fields.type, "Mining Traffic")
            subtree:add(crypto_detect.fields.pool, pool_name)
            return
        end
    end
end

-- Register for common Stratum ports
tcp_table:add(3333, crypto_detect)  -- Common mining port
tcp_table:add(4444, crypto_detect)  -- Alternative mining port
tcp_table:add(8333, crypto_detect)  -- Bitcoin

-- ============================================
-- 3. IOT Device Detector
-- ============================================
local iot_detect = Proto("iot_detect", "IOT Device Detector")
iot_detect.fields.device = ProtoField.string("iot_detect.device", "Device Type")
iot_detect.fields.vendor = ProtoField.string("iot_detect.vendor", "Vendor")

-- IOT device patterns
local iot_patterns = {
    ["alexa"] = {device = "Amazon Echo", vendor = "Amazon"},
    ["google-home"] = {device = "Google Home", vendor = "Google"},
    ["ring"] = {device = "Ring Doorbell", vendor = "Amazon"},
    ["nest"] = {device = "Nest Device", vendor = "Google"},
    ["hue"] = {device = "Philips Hue", vendor = "Philips"},
    ["sonos"] = {device = "Sonos Speaker", vendor = "Sonos"},
    ["roku"] = {device = "Roku Device", vendor = "Roku"}
}

function iot_detect.dissector(buffer, pinfo, tree)
    local data = buffer():string():lower()
    for pattern, info in pairs(iot_patterns) do
        if string.find(data, pattern) then
            pinfo.cols.protocol = "IOT"
            local subtree = tree:add(iot_detect, buffer(), "IOT Device Detected")
            subtree:add(iot_detect.fields.device, info.device)
            subtree:add(iot_detect.fields.vendor, info.vendor)
            return
        end
    end
end

-- Register on common IOT ports
udp_table = DissectorTable.get("udp.port")
udp_table:add(1900, iot_detect)  -- SSDP/UPnP
udp_table:add(5353, iot_detect)  -- mDNS

-- ============================================
-- 4. Malware C2 Detector
-- ============================================
local c2_detect = Proto("c2_detect", "C2 Traffic Detector")
c2_detect.fields.type = ProtoField.string("c2_detect.type", "C2 Type")
c2_detect.fields.pattern = ProtoField.string("c2_detect.pattern", "Pattern Detected")

-- Suspicious patterns
local c2_patterns = {
    ["cmd.exe"] = "Command Execution",
    ["powershell"] = "PowerShell Activity",
    ["base64"] = "Base64 Encoding",
    ["eval"] = "Code Evaluation",
    ["exec"] = "Remote Execution",
    ["/c2/"] = "C2 Path Pattern",
    ["/gate/"] = "Gate Pattern",
    ["/panel/"] = "Panel Access"
}

function c2_detect.dissector(buffer, pinfo, tree)
    local data = buffer():string():lower()
    for pattern, desc in pairs(c2_patterns) do
        if string.find(data, pattern) then
            pinfo.cols.protocol = "C2"
            pinfo.cols.info = "Suspicious: " .. desc
            local subtree = tree:add(c2_detect, buffer(), "Potential C2 Activity")
            subtree:add(c2_detect.fields.type, desc)
            subtree:add(c2_detect.fields.pattern, pattern)
            -- Mark packet with expert info
            subtree:add_expert_info(PI_SECURITY, PI_WARN, "Potential malicious activity detected")
            return
        end
    end
end

-- Register on common C2 ports
tcp_table:add(4444, c2_detect)
tcp_table:add(8080, c2_detect)
tcp_table:add(8443, c2_detect)

-- ============================================
-- 5. Data Exfiltration Detector
-- ============================================
local exfil_detect = Proto("exfil_detect", "Data Exfiltration Detector")
exfil_detect.fields.method = ProtoField.string("exfil_detect.method", "Exfiltration Method")
exfil_detect.fields.size = ProtoField.uint32("exfil_detect.size", "Data Size", base.DEC)

-- Track large transfers
local large_transfer_threshold = 10485760  -- 10MB

function exfil_detect.dissector(buffer, pinfo, tree)
    local len = buffer:len()

    if len > large_transfer_threshold then
        pinfo.cols.protocol = "EXFIL"
        pinfo.cols.info = "Large Data Transfer Detected"
        local subtree = tree:add(exfil_detect, buffer(), "Potential Data Exfiltration")
        subtree:add(exfil_detect.fields.method, "Large Transfer")
        subtree:add(exfil_detect.fields.size, len)
        subtree:add_expert_info(PI_SECURITY, PI_WARN, "Large data transfer detected")
    end
end

-- Register on common ports
tcp_table:add(443, exfil_detect)  -- HTTPS
tcp_table:add(22, exfil_detect)   -- SSH

-- ============================================
-- 6. DNS Tunneling Detector
-- ============================================
local dns_tunnel = Proto("dns_tunnel", "DNS Tunneling Detector")
dns_tunnel.fields.suspicious = ProtoField.bool("dns_tunnel.suspicious", "Suspicious")
dns_tunnel.fields.reason = ProtoField.string("dns_tunnel.reason", "Reason")

function dns_tunnel.dissector(buffer, pinfo, tree)
    local data = buffer():string()

    -- Check for unusually long DNS queries (potential tunneling)
    if buffer:len() > 100 then
        pinfo.cols.protocol = "DNS-TUNNEL"
        local subtree = tree:add(dns_tunnel, buffer(), "Potential DNS Tunneling")
        subtree:add(dns_tunnel.fields.suspicious, true)
        subtree:add(dns_tunnel.fields.reason, "Unusually long DNS query")
        subtree:add_expert_info(PI_SECURITY, PI_WARN, "Potential DNS tunneling detected")
    end

    -- Check for base64-like patterns in DNS
    if string.find(data, "[A-Za-z0-9+/=]{20,}") then
        pinfo.cols.protocol = "DNS-TUNNEL"
        local subtree = tree:add(dns_tunnel, buffer(), "Potential DNS Tunneling")
        subtree:add(dns_tunnel.fields.suspicious, true)
        subtree:add(dns_tunnel.fields.reason, "Base64-like pattern in DNS")
    end
end

udp_table:add(53, dns_tunnel)

-- ============================================
-- Helper Functions
-- ============================================

-- Function to highlight suspicious traffic
local function mark_suspicious(tree, reason)
    tree:add_expert_info(PI_SECURITY, PI_ERROR, "SUSPICIOUS: " .. reason)
end

-- ============================================
-- Custom Statistics
-- ============================================

-- Create custom statistics window
local function custom_stats()
    local tw = TextWindow.new("Custom Protocol Statistics")
    tw:append("=== Custom Protocol Analysis ===\n\n")
    tw:append("Protocols detected in this capture:\n")
    tw:append("- TCP Streams analyzed\n")
    tw:append("- IOT devices detected\n")
    tw:append("- Cryptocurrency traffic\n")
    tw:append("- Potential C2 communications\n")
    tw:append("- Data exfiltration attempts\n")
    tw:append("- DNS tunneling indicators\n")
end

-- Register menu
register_menu("Custom Stats", custom_stats, MENU_TOOLS_UNSORTED)

-- ============================================
-- Initialization
-- ============================================
print("Custom Wireshark dissectors loaded successfully!")
print("Monitoring for:")
print("  - Cryptocurrency mining traffic")
print("  - IOT device communications")
print("  - C2 traffic patterns")
print("  - Data exfiltration")
print("  - DNS tunneling")
print("  - Custom TCP stream analysis")