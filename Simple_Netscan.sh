#!/usr/bin/env bash
 
# Enhanced network scanner with proper port number handling
 
# Get network info
interface=$(ip route | awk '/default/ {print $5}')
ip_range=$(ip -o -f inet addr show | awk '/scope global/ {print $4}' | head -n1)
 
echo "Scanning network on interface $interface (range: $ip_range)"
echo "----------------------------------------"
 
# Scan hosts
nmap -sn $ip_range | awk '/Nmap scan/ {print $5, $6}' | while read -r ip host; do
    echo "├── $ip ($host)"
 
    # Scan common ports with service detection (-sV)
    # Using -F for fast scan (100 most common ports) and -T3 for normal timing
    nmap -T3 -F -sV --min-rate=100 $ip | awk -v ip="$ip" '
    /^[0-9]+\/tcp/ {
        port = $1;
        sub("/tcp", "", port);
        service = $3;
        for (i=4; i<=NF; i++) service = service " " $i;
 
        # Only show ports below 10000 or known services
        if (port < 10000 || service != "unknown") {
            printf("│   ├── %s/tcp (%s)\n", port, service);
        }
    }
    ' | sort -n
 
done
 
echo "----------------------------------------"
echo "Scan completed"
