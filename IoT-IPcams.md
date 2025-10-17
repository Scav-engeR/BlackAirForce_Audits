## WORK IN PROGRESS
This is a spare-time project of our `Trainee` and currently incomplete. Thanks for your patience.

# IOT and Traffic Cams
Warning! This is for educational and cybersecurity purposes only, we do not recommend trying this at home!

Based on the work of Matt Brown: https://www.youtube.com/watch?v=0dUnY1641WM we took a closer look at IOT Devices like public traffic cam data feeds.

We only looked at Infromation that was publicly accessible without login, no protection was in place on any of these.

## Tools & Links
- https://www.shodan.io/
- https://search.censys.io
- https://www.youtube.com/watch?v=0dUnY1641WM
- https://bgpview.io

## Finding Traffic Cams
Matt Brown demonstrated to search for the typo "PLease" in  `http response bodies`, for example on search.censys.io.
```
services.http.response.body:"Not found your stream. PLease contact administrator to get correct stream name"
```

Of course, we tried to take this a step further and identify other unique values that would allow finding similar devices. 

### Search results
```
107.89.193.47
Ubuntu Linux ATT-MOBILITY-LLC-AS20057 (20057) New Jersey, United States

166.169.33.198 (198.sub-166-169-33.myvzw.com)
Ubuntu Linux CELLCO-PART (6167) Nebraska, United States

107.89.35.45
Ubuntu Linux ATT-MOBILITY-LLC-AS20057 (20057) Texas, United States

166.152.44.39 (39.sub-166-152-44.myvzw.com)
Ubuntu Linux CELLCO-PART (6167) Illinois, United States

107.90.73.129
Ubuntu Linux ATT-MOBILITY-LLC-AS20057 (20057) Texas, United States

166.139.39.202 (202.sub-166-139-39.myvzw.com)
Ubuntu Linux CELLCO-PART (6167) Pennsylvania, United States

166.157.15.90 (90.sub-166-157-15.myvzw.com)
Ubuntu Linux CELLCO-PART (6167) Massachusetts, United States

166.155.208.127 (127.sub-166-155-208.myvzw.com)
Ubuntu Linux CELLCO-PART (6167) Alabama, United States

66.37.249.170 (wsip-66-37-249-170.om.om.cox.net)
Linux ASN-CXA-ALL-CCI-22773-RDC (22773) Nebraska, United States

107.89.193.16
Ubuntu Linux ATT-MOBILITY-LLC-AS20057 (20057) New Jersey, United States

166.247.58.128 (128.sub-166-247-58.myvzw.com)
Ubuntu Linux CELLCO-PART (6167) Georgia, United States

63.41.66.232 (host232.sub-63-41-66.myvzw.com)
Ubuntu Linux CELLCO-PART (6167) Texas, United States

107.89.193.36
Ubuntu Linux ATT-MOBILITY-LLC-AS20057 (20057) New Jersey, United States

107.89.193.41
Ubuntu Linux ATT-MOBILITY-LLC-AS20057 (20057) New Jersey, United States

166.141.100.135 (135.sub-166-141-100.myvzw.com)
Ubuntu Linux CELLCO-PART (6167) Tennessee, United States

166.159.168.84 (84.sub-166-159-168.myvzw.com)
Ubuntu Linux CELLCO-PART (6167) Illinois, United States

166.139.89.20 (20.sub-166-139-89.myvzw.com)
Ubuntu Linux CELLCO-PART (6167) Florida, United States

63.41.53.233 (host233.sub-63-41-53.myvzw.com)
Ubuntu Linux CELLCO-PART (6167) Florida, United States

166.247.193.253 (253.sub-166-247-193.myvzw.com)
Ubuntu Linux CELLCO-PART (6167) North Carolina, United States

166.152.44.38 (38.sub-166-152-44.myvzw.com)
Ubuntu Linux CELLCO-PART (6167) Illinois, United States

166.168.53.164 (164.sub-166-168-53.myvzw.com)
Ubuntu Linux CELLCO-PART (6167) Texas, United States

166.156.61.155 (155.sub-166-156-61.myvzw.com)
Ubuntu Linux CELLCO-PART (6167) Florida, United States

107.89.193.4
Ubuntu Linux ATT-MOBILITY-LLC-AS20057 (20057) New Jersey, United States

107.89.193.35
Ubuntu Linux ATT-MOBILITY-LLC-AS20057 (20057) New Jersey, United States

166.139.42.206 (206.sub-166-139-42.myvzw.com)
Ubuntu Linux CELLCO-PART (6167) Ohio, United States
```

## How to access Video Feed
Open `VLC Media Player`, CTRL + N, then enter the IP address with http, port 8080, the number of the cam and ir/color:
```
http://?.?.?.?:8080/cam1color
```

## How to get Data Feed
Connect to the IP via `Netcat` and optionally filter for license plates:
```bash
$ nc -v ?.?.?.? 5001 
$ nc -v ?.?.?.? 5001 | strings | grep -P "^[A-Z0-9]+"
```

## Hosted on specific site
Many of the Traffic Cams are hosted on subdomains of `myvzw.com`, which is owend by `Verizon Communications`. Others are also hosted at `Cox Communications` or `AT&T Mobility LLC`, these subdomains look like this:
```
198.sub-166-169-33.myvzw.com
135.sub-166-141-100.myvzw.com
127.sub-166-155-208.myvzw.com

wsip-66-37-249-170.om.om.cox.net
```

## IP Ranges
```
Traffic Cams hosted by Verizon Communications: 166.128.0.0/9 & 63.40.0.0/13

Traffic Cams hosted by AT&T Mobility LLC: 107.64.0.0/10

Traffic Cams hosted by Cox Communications: 66.37.224.0/19
```

## Ports
The Traffic Cams seem to always have these or a slight variation of these 20 ports open:
```
22/SSH, 80/HTTP, 81/HTTP, 161/SNMP, 2000, 2001, 2002, 2003, 2004, 2005, 5000, 5001, 5002, 5003, 5004, 5005, 8000/HTTP, 8080/HTTP, 8081/HTTP, 8443/HTTP
```

### Port Details

### Example 1
#### 22 / tcp
1553582664 | 2025-01-07T09:33:27.925913
```
OpenSSH7.6p1 Ubuntu 4ubuntu0.3

SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.3

Encryption Algorithms:
	chacha20-poly1305@openssh.com

[...]

Compression Algorithms:
	none
	zlib@openssh.com
```

#### 80 / tcp
902101657 | 2024-12-27T21:00:17.025007
```
Apache httpd2.4.29
[...]

HTTP/1.1 404 Not Found
```

#### 81 / tcp
902101657 | 2025-01-07T17:08:08.608114
```
Apache httpd2.4.29

HTTP/1.1 404 Not Found
Server: Apache/2.4.29 (Ubuntu)
[...]
```
#### 88 / tcp
-570837630 | 2025-01-07T11:00:42.385489
```
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Basic realm="Protected"
Content-Length: 39
```

#### 161 / udp
-933711104 | 2025-01-07T05:42:41.860970
```
SNMP:
  Versions:
    1
```

#### 2000 / tcp
-1969777379 | 2025-01-07T16:58:40.271289
```
\x08\x04\x00\x00
```

#### 2003 / tcp
-1969777379 | 2025-01-06T14:21:07.017525
```
\x08\x04\x00\x00
```

#### 8000 / tcp
902101657 | 2025-01-07T15:31:04.562224
```
Apache httpd2.4.29
404 Not Found

HTTP/1.1 404 Not Found
Server: Apache/2.4.29 (Ubuntu)
[...]
```

#### 8080 / tcp
-901826308 | 2025-01-07T14:58:25.647165
```
404 Not Found

HTTP/1.1 404 NotFound
Accept-Ranges: bytes
Connection: close
WWW-Authenticate: Basic realm="/"
Content-Type: text/html; charset=ISO-8859-1
Content-Length: 180
```

#### 8081 / tcp
1630575852 | 2025-01-07T09:11:04.391538
```
HTTP/1.1 301 Moved Permanently
Server: CradlepointHTTPService/1.0.0
Location: /admin/
[...]
```

#### 8443 / tcp
1397055126 | 2025-01-07T11:14:31.160229
```
Login :: IBR600C-150M-D

HTTP/1.1 200 OK
Server: CradlepointHTTPService/1.0.0
Transfer-Encoding: chunked
[...]

SSL Certificate

Certificate:
    Data:
        Version: 3 (0x2)
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: O=Cradlepoint, Inc., OU=http:\/\/cradlepoint.com, CN=cp
        Subject: O=Cradlepoint, Inc., OU=http:\/\/cradlepoint.com, CN=cp
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (2048 bit)
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Basic Constraints: critical
                CA:TRUE
            X509v3 Subject Alternative Name: 
                URI:http://cradlepoint.com
    Signature Algorithm: sha256WithRSAEncryption
    [...]
```

### Example 2
#### 22 / tcp
1553582664 | 2025-01-06T21:18:53.133235
```
OpenSSH7.6p1 Ubuntu 4ubuntu0.3
SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.3

Encryption Algorithms:
	chacha20-poly1305@openssh.com

[...]

Compression Algorithms:
	none
	zlib@openssh.com
```

#### 80 / tcp
1242964962 | 2025-01-06T21:17:30.265124
```
Apache httpd2.4.29
404 Not Found

HTTP/1.1 404 Not Found
Server: Apache/2.4.29 (Ubuntu)
[...]
```

#### 81 / tcp
1242964962 | 2025-01-06T21:17:05.846081
```
Apache httpd2.4.29
404 Not Found

HTTP/1.1 404 Not Found
Server: Apache/2.4.29 (Ubuntu)
[...]
```

#### 88 / tcp
-570837630 | 2025-01-06T21:17:24.629639
```
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Basic realm="Protected"
Content-Length: 39
```

#### 161 / udp
-933711104 | 2025-01-06T21:17:27.431343
```
SNMP:
  Versions:
    1
```

#### 2000 / tcp
-1969777379 | 2025-01-06T21:17:23.227277
```
\x08\x04\x00\x00
```

#### 2003 / tcp
-1969777379 | 2025-01-06T21:18:22.020325
```
\x08\x04\x00\x00
```

#### 8080 / tcp
-901826308 | 2025-01-06T21:19:31.991376
```
404 Not Found

HTTP/1.1 404 NotFound
Accept-Ranges: bytes
Connection: close
WWW-Authenticate: Basic realm="/"
Content-Type: text/html; charset=ISO-8859-1
Content-Length: 180
```

#### 8081 / tcp
937724310 | 2025-01-06T21:19:34.303298
```
HTTP/1.1 301 Moved Permanently
Server: CradlepointHTTPService/1.0.0
Content-Type: text/html; charset=UTF-8
[...]
Location: /admin/
Content-Length: 0
```

#### 8443 / tcp
1892008180 | 2025-01-07T17:25:40.010782
```
Login :: IBR600C-150M-D

HTTP/1.1 200 OK
Server: CradlepointHTTPService/1.0.0
[...]
Transfer-Encoding: chunked


SSL Certificate

Certificate:
    Data:
        Version: 3 (0x2)
        Issuer: O=Cradlepoint, Inc., OU=http:\/\/cradlepoint.com, CN=cp
        Validity
            Not Before: Aug  4 18:25:27 2021 GMT
            Not After : Aug  3 18:25:27 2026 GMT
        Subject: O=Cradlepoint, Inc., OU=http:\/\/cradlepoint.com, CN=cp
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Basic Constraints: critical
                CA:TRUE
            X509v3 Subject Alternative Name: 
                URI:http://cradlepoint.com
    Signature Algorithm: sha256WithRSAEncryption
    [...]

```

### Example 3
#### 22 / tcp
1553582664 | 2025-01-07T19:29:20.318091
```
OpenSSH7.6p1 Ubuntu 4ubuntu0.3

SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.3

Encryption Algorithms:
	chacha20-poly1305@openssh.com

[...]

Compression Algorithms:
	none
	zlib@openssh.com
```

#### 80 / tcp
-132343779 | 2025-01-07T17:48:58.903399
```
Apache httpd2.4.29
404 Not Found

HTTP/1.1 404 Not Found
Server: Apache/2.4.29 (Ubuntu)
[...]
```

#### 2000 / tcp
-724604201 | 2025-01-07T16:58:56.746354
```
\xb9\x0b\x00\x00\xdb\xda\x03\x00\x01\x00\x00\x00\xa0\x05\x00\x008\x04\x00\x00\x02\x00\x00\x00\xffU`:\xb6\x01\x00\x00\xd1\x15\xa4\xfcYf\x00\x00\xff\xd8\xff\xdb\x00\x84\x00\x06\x04\x05\x06\x05\x04\x06\x06\x05\x06\x07\x07\x06\x08\n\x10\n\n\t\t\n\x14\x0e\x0f\x0c\x10\x17\x14\x18\x18\x17\x14\x16\x16\x1a\x1d%\x1f\x1a\x1b#\x1c\x16\x16 , #&\')*)\x19\x1f-0-(0%()(\x01\x07\x07\x07\n\x08\n\x13\n\n\x13(\x1a\x16\x1a((((((((((((((((((((((((((((((((((((((((((((((((((\xff\xc4\x01\xa2\x00\x00\x01\x05\x01\x01\x01\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x10\x00\x02\x01\x03\x03\x02\x04\x03\x05\x05\x04\x04\x00\x00\x01}\x01\x02\x03\x00\x04\x11\x05\x12!1A\x06\x13Qa\x07"q\x142\x81\x91\xa1\x08#B\xb1\xc1\x15R\xd1\xf0$3br\x82\t\n\x16\x17\x18\x19\x1a%&\'()*4JUdGzvrMFDWrUUwY3toJATSeNwjn54LkCnKBPRzDuhzi5vSepHfUckJNxRL2gjkNrSqtCoRUrEDAgRwsQvVCjZbRyFTLRNyDmT1a1boZVxa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\x01\x00\x03\x01\x01\x01\x01\x01\x01\x01\x01\x01\x00\x00\x00\x00\x00\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x11\x00\x02\x01\x02\x04\x04\x03\x04\x07\x05\x04\x04\x00\x01\x02w\x00\x01\x02\x03\x11\x04\x05!1\x06\x12AQ\x07aq\x13"2\x81\x08\x14B\x91\xa1\xb1\xc1\t#3R\xf0\x15br\xd1\n\x16$4\xe1%\xf1\x17\x18\x19\x1a&\'()*56789:CDEFGHIJSTUVWXYZcdefghijstuvwxyz\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x92\x93\x94\x95\x96\x97\x98\x99\x9a\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xff\xc0\x00\x11\x08\x048\x05\xa0\x03\x00"\x00\x01\x11\x01\x02\x11\x01\xff\xda\x00\x0c\x03\x00\x00\x01\x11\x02\x11\x00?\x00\xf9\xca\x8a(\xa0\x02\x92\x8a(\x00\xa2\x8a(\x00\xa2\x8a(\x00\xa2\x8a(\x00\xa2\x8a(\x00\xa2\x8a(\x00\xa2\x8a(\x00\xa3\xe9E\x14\x00QE\x14\x00QH)h\x01(\xa2\x8a\x00(\xa2\x8a\x00(\xa2\x8a\x00(\xa2\x8a\x00(\xa2\x8a\x00(\xa2\x8a\x00(\xa2\x8a\x00(\xa2\x92\x80\x16\x92\x8aZ\x00))i(\x01i)i(\x00\xa2\x8a(\x00\xa2\x8a(\x00\xa2\x8a(\x00\xa2\x8a(\x00\xa2\x8e\xd4P\x01E\x1d(\xa0\x02\x8a(\xa0\x02\x92\x96\x8a\x00(\xa2\x8a\x00(\xa2\x8a\x00))h\xa0\x02\x92\x8aZ\x00(\xa4\xa2\x80\x16\x8aJ(\x00\xa2\x8a(\x00\xa2\x8a(\x00\xa2\x8a(\x00\xa2\x8a(\x00\xefE\x14P\x01E\x14P\x01E\x14P\x01E\x14\xb4\x00\x94QE\x00\x14QE\x00\x14QE\x00\x14QE\x00\x14QE\x00\x14w\xa2\x8a\x00(\xa2\x8a\x00(\xa2\x8a\x00(\xa2\x8a\x00(4Q@\x05\x14Q@\x05\x14Q@\x05\x14Q@\x05\x14Q@\x05\x14Q@\x05\x14Q@\x05\x14Q@\x05\x14Q@\x05\x14Q@\x05\x14Q@\x05\x14Q@\x05-%\x14\x00QE-\x00%\x14\xb4\x94\x00QE\x14\x00\xb4QE\x00%-%-\x00\x14QE\x00\x14QE\x00\x14QE\x00\x14QE\x00\x14QE\x00\x14QE\x00\x14QA\xa0\x02\x8a(\xa0\x02\x8a(\xa0\x02\x8a(\xa0\x02\x96\x92\x8a\x00(\xa2\x96\x80\x12\x96\x92\x96\x80\x12\x96\x8a(\x00\xa2\x8aJ\x00ZJZ(\x00\xa2\x8a(\x00\xa2\x8a(\x00\xa2\x8a(\x01\xd4QI@\x0bE\x14\x94\x00QE\x14\x00QE\x14\x00QE\x14\x00QE\x14\x00QE\x14\x00QE\x14\x00QE\x14\x00QE\x14\x00Rv\xa5\xa4\xa0\x02\x8a(\xa0\x02\x8a(\xa0\x02\x8a(\xa0\x02\x8a(\xa0\x02\x8a(\xa0\x02\x8a(\xa0\x02\x8a(\xa0\x02\x83E\x14\x00QIK@\tE\x14P\x01E\x14P\x01E\x14P\x01E\x14P\x01E\x14P\x01E\x1d\xa8\xa0\x02\x8a(\xa0\x02\x8a(\xa0\x02\x8a(\xa0\x02\x8a(\xa0\x02\x8a(\xa0\x02\x8a(\xa0\x02\x8a)(\x01i(\xa2\x80\n(4P\x01KE%\x00\x14QE\x00\x14QE\x00\x14QE\x00\x14QE\x00\x14R\xd2P\x01E\x14P\x01E-%\x00\x14QE\x00\x14QE\x00\x14QE\x00\x14QE\x00\x14QE\x00\x14QE\x00\x14QE\x00\x14QE\x00\x14QE\x00\x14QE\x00\x14QE\x00\x14QE\x00\x14QE\x00\x14QE\x00\x14QE\x00\x14QE\x00\x14QE\x00\x14QE\x00\x14QE\x00\x14QE\x00\x14QE\x00\x1dh\xa2\x8a\x00(\xa2\x8a\x00(\xa5\xa4\xa0\x02\x8a(\xa0\x02\x8a(\xa0\x02\x8a(\xa0\x05\xe6\x8aJ(\x01h\xa2\x8a\x00(\xa2\x8a\x00(\xa2\x8a\x00(\xa2\x8a\x00(\xa2\x8a\x00(\xa2\x8a\x00(\xa2\x8a\x00(\xa2\x8a\x00(\xa0Q@\x05\x14Q@\x05\x14Q@\x05\x14Q@\x05\x14\xb4\x94\x00\xb4\x94\xb4P\x02QKE\x00\x14\x94\xb4P\x01E\x14P\x01E\x14P\x01E\x14P\x03\xa9)h\xa0\x04\xa2\x8aZ\x00J(\xa5\xa0\x04\xa2\x8a(\x00\xa2\x8a(\x00\xa2\x8a(\x00\xa2\x8a(\x00\xa2\x8a(\x00\xa2\x8a(\x00\xa2\x8a(\x00\xa4\xa5\xa4\xa0\x00\xd1E\x14\x00QE\x14\x00\x1a(\xa2\x80\n(\xa2\x80\n(\xa4\xa0\x05\xa2\x8a
```

#### 2003 / tcp
-1969777379 | 2025-01-07T06:07:35.829498
```
\x08\x04\x00\x00
```

#### 8000 / tcp
-132343779 | 2025-01-07T15:28:21.386207
```
Apache httpd2.4.29
404 Not Found

HTTP/1.1 404 Not Found
Server: Apache/2.4.29 (Ubuntu)
[...]
```

#### 8080 / tcp
-901826308 | 2025-01-07T13:59:46.901250
```
404 Not Found

HTTP/1.1 404 NotFound
Accept-Ranges: bytes
Connection: close
WWW-Authenticate: Basic realm="/"
[...]
```

## Other
Shodan listed some generic `CVEs`, likely they don't have much relevancy, we only list them for completeness. 
```
CVE-2024-38476; CVE-2024-38474; CVE-2023-25690; CVE-2022-36760; CVE-2022-31813; CVE-2022-28615; CVE-2022-23943; CVE-2022-22721; CVE-2022-22720; CVE-2021-44790; CVE-2021-40438; CVE-2021-39275; CVE-2021-26691; CVE-2019-10082; CVE-2018-131258
```
