#!/bin/bash

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

echo -e "${PURPLE}${BOLD}"
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║ 🔄 Source-Preserving Port Forwarding Setup By: Scav-engeR 🔄 ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

echo -e "${CYAN}📋 Enter configuration details:${NC}"
read -p "$(echo -e $YELLOW"Enter input interface (default: eth0): "$NC)" INPUT_IFACE
INPUT_IFACE=${INPUT_IFACE:-eth0}

read -p "$(echo -e $YELLOW"Enter output interface (default: wg0): "$NC)" OUTPUT_IFACE
OUTPUT_IFACE=${OUTPUT_IFACE:-wg0}

read -p "$(echo -e $YELLOW"Enter port to forward (default: 110): "$NC)" PORT
PORT=${PORT:-110}

read -p "$(echo -e $YELLOW"Enter destination IP (default: 10.7.0.104): "$NC)" DEST_IP
DEST_IP=${DEST_IP:-10.7.0.104}

echo -e "\n${BLUE}${BOLD}⚙️ Configuration Summary:${NC}"
echo -e "${GREEN}• Input interface:${NC} $INPUT_IFACE"
echo -e "${GREEN}• Output interface:${NC} $OUTPUT_IFACE"
echo -e "${GREEN}• Port to forward:${NC} $PORT"
echo -e "${GREEN}• Destination IP:${NC} $DEST_IP"

echo -e "\n${BLUE}${BOLD}🔥 Applying iptables rules...${NC}"

echo -e "${YELLOW}➡️ Setting up forwarding rule for new connections...${NC}"
iptables-legacy -A FORWARD -i $INPUT_IFACE -o $OUTPUT_IFACE -p tcp --syn --dport $PORT -m conntrack --ctstate NEW -j ACCEPT

echo -e "${YELLOW}➡️ Allowing established/related connections (input → output)...${NC}"
iptables-legacy -A FORWARD -i $INPUT_IFACE -o $OUTPUT_IFACE -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

echo -e "${YELLOW}➡️ Allowing established/related connections (output → input)...${NC}"
iptables-legacy -A FORWARD -i $OUTPUT_IFACE -o $INPUT_IFACE -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

echo -e "${YELLOW}➡️ Setting up DNAT rule to redirect incoming traffic...${NC}"
iptables-legacy -t nat -A PREROUTING -i $INPUT_IFACE -p tcp --dport $PORT -j DNAT --to-destination $DEST_IP

echo -e "${YELLOW}➡️ Setting up SNAT rule to preserve source IP...${NC}"
iptables-legacy -t nat -A POSTROUTING -o $OUTPUT_IFACE -p tcp --dport $PORT -d $DEST_IP -j SNAT --to-source $DEST_IP

if [ $? -eq 0 ]; then
    echo -e "\n${GREEN}${BOLD}✅ Port forwarding Setup Successfully! ${NC}"
    echo -e "${GREEN}Traffic on port $PORT is now forwarded to $DEST_IP while preserving source IP.${NC}"
    
    echo -e "\n${BLUE}${BOLD}🔍 Current forwarding rules:${NC}"
    iptables-legacy -L FORWARD -n -v | grep -E "$PORT|$DEST_IP"
else
    echo -e "\n${RED}${BOLD}❌ Failed to apply IPTables Rules. Check your Configuration.${NC}"
fi

echo -e "\n${PURPLE}${BOLD}🚀 Done! Happy Forwardin! 🚀${NC}"
