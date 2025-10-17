# IP-Cams
Collection of Resources around IP Camera Finding and Pentesting

## Creds
- https://github.com/Network-Sec/Wordlists/blob/main/ip_cam_credentials.json

## Tools & Links
- http://www.insecam.org/
- https://www.shodan.io/
- https://github.com/Ullaakut/cameradar
- https://github.com/ThatNotEasy/RTSP-FindingSomeFun
- https://gist.github.com/r00t-3xp10it/413a942d4f967453b1c74f7a8501e47f (NMap Recon Script)
- https://www.hackers-arise.com/post/the-default-passwords-of-nearly-every-ip-camera
- https://www.hackers-arise.com/post/2019/05/31/open-source-intelligenceosint-part-4-google-hacking-to-find-unsecured-web-cams
- https://www.coresecurity.com/sites/default/files/private-files/publications/2016/05/corelabs-ipcams-research-falcon-riva.pdf

## Ports
```
80,81,82,83,84,85,86,92,4JUdGzvrMFDWrUUwY3toJATSeNwjn54LkCnKBPRzDuhzi5vSepHfUckJNxRL2gjkNrSqtCoRUrEDAgRwsQvVCjZbRyFTLRNyDmT1a1boZV55757,55758
```

## Nmap
Scans are usually painfully slow, so if you're just looking for "a night of fun" you're far better off with Google and Shodan.
```bash
$ sudo nmap -sS -v -Pn -n -T5 -iR 700 -p 8080-8086 --open --min-rate 1000 --max-retries 2 --script=http-headers.nse,AXISwebcam-recon.nse -oA webcams <IP Range or Address>
```

## Google Dorks & Shodan Searches

### Shodan.io Searches & HTTP Headers
You should start with a few generic searches and note down some models, `HTTP Headers` etc. We haven't found a list of headers yet, sadly. 

### Combine Terms 
with country (Germany: DE, Great Britain:UK, ...)
```
Dahua country:DE
country:RU RTSP/1.0 has_screenshot:true
port:554
port:37777
```

### Terms
```
webcamxp
Webcams
webcam authorized
webcam has_screenshot:true
Web cameras
Open Webcams
5k+ Unlocked Webcams
RTSP
Cam
Cam Webs
Cam-Webs
Camera Web Server
Cameras with image
Comelit Camera
Dahua Cameras
Digital Watching NVR
DVSS-HttpServer
High-def Web Cameras
IP Cam
IP Cam Screenshots
IP Cam Dork
Webcam 7 unsecured
Megapixel
live cameras
MJPG Streamer
SQ-WEBCAM
DVR Surveillance Camera
Network Card Manager
Network Camera
Network Cube
Good IP Cam
Arecont Vision
AXIS P1365 Mk II
AXIS P5512-E
Axis Camera
AXIS Cameras no login
Avigilion CCTV
Canon VBM40 Net Cam
Canon VB Cams
ExecqVision
Sony Network Camera
D-Link IP camera
d-Link Internet Camera
Defeway
cam D-Link
Geovision Products Loging
GS Camera
Toshiba Network Camera
Milestone Portals
Netwave
Netwave IP Camera
WVC210 Wireless-G PTZ Internet Camera
VMax Web Viewer
Lilin Cam
Megapixel
Megapixel 2
Megapixel 3
Mobotix Cameras
Number Plate Recognition Camera
Hikvision IP Cam
Samsung DVR Web Viewer
DCS-5300G
Linksys Camera
Inspire DVR
IQInvision No-Auth Cameras
NetCamXL Video Camera Stream
Chianet Nodinfo Camera
D-Link Internet Camera
PIPS AUTOPLATE
Yawcam
HIK VISION
Polycoms HTTP access
Malaysia HOME DVR
Avtech Camera Login
Mini Dome IP Camera
MotionEYE
Security Spy
EverFocus camera industrial
Home Cam
LNE3003 Wireless IP Camera
TeleEye Java Viewer
Foscam IP Camera
Foscam H.264 IP Cameras
IQeye Camera
IP video+camera
Heden
Hikvision NVRs
Netwave IP
Vilar IP Camera
Vivotek IP
TP-Link IP Camera
IP CAMERA Viewer
IP cam 2
IP Camera 3
Foscam
Foscam IP WiFi Cams
Foscam (IP Cameras)
Foscam H.264 IP Cameras
IP Cam Screenshot
Planet IP Camera
Apple store CA Camera
Airlink Camera
Blue Iris Open Webcams
Reecam
NetSurveillance servers
Cube ip camera httpd
Dedicated Micros camera system
Mobotix Camera
Red Light Camera
box ip camera httpd
Netwave IP Camera
Loxone Intercom video
Speco IP Cameras
Vivotek Network Camera
Pan-Tilt Cameras
Hipcam RealServer/V1.0
yawcam
uc-httpd 1.0.0
NETSurveillance
```

### Google Dorks
```
inurl:"view.shtml"
inurl:"/view.shtml"
inurl:"view/index.shtml"
inurl:"view/indexFrame.shtml"
inurl:"/view/view.shtml?id="
inurl:"live/cam.html"
inurl:"/view/viewer_index.shtml"
inurl:"cgi-bin/guestimage.html"
inurl:"CgiStart?page="
inurl:"ViewerFrame"
inurl:"/pda/index.html"
inurl:"camctrl.cgi"
inurl:"/cgi-bin/rtpd.cgi"
inurl:"ViewerFrame?mode=Refresh"
inurl:"live.htm" intext:"M-JPEG" | "System Log" | "Camera-1" | "View Control"
intitle:"EvoCam" inurl:"webcam.html"
intitle:"Live View - AXIS" OR inurl:"view/view.shtml" OR inurl:"view/indexFrame.shtml" OR intitle:"MJPG Live Demo"
inurl:"/viewer/live/ja/live.html" VB Viewer 
intext:"Select preset position"
inurl:"config/cam_portal.cgi"
intitle:"iliveapplet" inurl:"LvAppl"
inurl:"indexFrame.shtml" Axis
intitle:"NetCamXL*"
intitle:"NetCamXL*" inurl:"index.html"
intitle:"NetCamSC*" 
intitle:"i-Catcher Console"
intitle:"IP Webcam"
intitle:"IP CAMERA Viewer"
intext:"Client setting"
intitle:"Live View" AXIS 210"
tilt intitle:"Live View - AXIS" | inurl:view/view.shtml
intitle:"Veo Observer XT"
intitle:"liveapplet"
AXIS 206
AXIS 206M
AXIS 210
AXIS Camera
iaxis
axadmin
liveapplet
inurl:"axis-cgi/mjpg" motion-JPEG
intitle:"axis" intitle:"video server"
intitle:"axadmin"
inurl:"axis-cgi/jpg"
intitle:"Live View — AXIS"
intitle:"webcam" inurl:login
intitle:HomeSeer.Web.Control
intitle:"WEBDVR" -inurl:demo
Home.Status.Events.Log
intitle:"Intellinet"
intitle:"IP Camera Homepage"
intitle:"Videoconference Management System" ext:htm
intitle:"Network Camera"
intitle:"NetworkCamera"
intitle:"NetCam Live Image"
intitle:"supervisioncam protocol"
intext:"powered by webcamXP 5"
intitle:"WEBCAM 7"
intitle:"webcam 7" inurl:"8080" -intext:"8080"
intitle:"webcam 7" inurl:"/gallery.html"
intitle:"IP CAMERA Viewer
intitle:"live view"
inurl:"top.htm" inurl:"currenttime"
inurl:ViewerFrame intext:"Pan / Tilt"
inurl:shtml|php|htm|html|pl|js|asp|aspx|aspxm -intext:observer
inurl:8080 "Live"
intext:"Video Web Server"
intitle:"Weather Wing WS-2"
inurl:"MultiCameraFrame?Mode="
intitle:"netcam live image"
intitle:"IP Webcam" inurl:"greet.html"
intitle:"Toshiba Network Camera"
intitle:"Sony Network Camera"
intitle:"snc-ml" or intitle:"snc-pl"
site:.viewnetcam.com -www.viewnetcam.com
intitle:EyeSpyFX|OptiCamFX "go to camera" | inurl:"servlet/DetectBrowser"
intitle:"AXIS 240 Camera Server" intext:"server push" -help
intitle:"istart" inurl:"cgistart"
intitle:"Edr1680 remote viewer"
allintitle:EDR1600 login | Welcome
allintitle:Edr1680 remote viewer
allintitle:Axis 2.10 OR 2.12 OR 2.30 OR 2.31 OR 2.32 OR 2.33 OR 2.34 OR 2.40 OR 2.42 OR 2.43 "Network Camera"
allintitle:EverFocus | EDSR | EDSR400 Applet
intitle:"MOBOTIX"
intitle:"WJ-NTI 04 Main Page"
intitle:"BlueNet Video Viewer"
intitle:"iGuard Security"
intitle:"yawcam" inurl:":8081"
intitle:"isnc-220" inurl:"home"
intitle:"isnc-cs3" inurl:"home"
intitle:"isnc-r230" inurl:"home"
intitle:"SNC-RZ30" -demo
inurl:"MultiCameraFrame?Mode=Motion"
intitle:"--- VIDEO WEB SERVER ---"
intitle:"webcamXP 5"
intitle:"Live NetSnap Cam-Server feed"
inurl:"lvappl.htm"
intitle:"active webcam page"
inurl:control/camerainfo
"Any time & Any where"
```

## HTTP Title Tags
Some, not nearly exhaustive...
```
TL-WR740N
AXIS Video Server
Live View / - AXIS
AXIS 2400 Video Server
Network Camera TUCCAM1
AXIS 243Q(2) Blade 4.45
Network Camera Capitanía
AXIS P5514 Network Camera
AXIS Q1615 Network Camera
AXIS P1357 Network Camera
AXIS M5013 Network Camera
AXIS M3026 Network Camera
AXIS M1124 Network Camera
Network Camera Hwy285/cr43,
Login - Residential Gateway 
Axis 2420 Video Server 2.32
AXIS Q6045-E Network Camera
AXIS Q6044-E Network Camera
Network Camera NetworkCamera
AXIS P1435-LE Network Camera
AXIS P1425-LE Network Camera
Axis 2120 Network Camera 2.34
Axis 2420 Network Camera 2.30
Axis 2420 Network Camera 2.31
Axis 2420 Network Camera 2.32
AXIS P1365 Mk II Network Camera
AXIS F34 Network Camera 6.50.2.3
AXIS 214 PTZ Network Camera 4.49
Axis 2130 PTZ Network Camera 2.30
Axis 2130 PTZ Network Camera 2.31
Axis 2130 PTZ Network Camera 2.32
AXIS P5635-E Mk II Network Camera
AXIS Q7401 Video Encoder 5.51.5.1
AXIS Q6045-E Mk II Network Camera
AXIS P1353 Network Camera 6.50.2.3
AXIS M3004 Network Camera 5.51.5.1
AXIS M1145-L Network Camera 6.50.3
AXIS M2025-LE Network Camera 8.50.1
Live view / - AXIS 205 version 4.03
Live view  - AXIS 240Q Video Server
Live view  - AXIS 221 Network Camera
Live view  - AXIS 211 Network Camera
AXIS Q1765-LE Network Camera 5.55.2.3
Live view  - AXIS P1354 Network Camera 
Live view  - AXIS P1344 Network Camera
Live view  - AXIS M1114 Network Camera
Live view  - AXIS M1103 Network Camera
Live view  - AXIS M1025 Network Camera
AXIS P1354 Fixed Network Camera 6.50.3
AXIS P1354 Fixed Network Camera 5.60.1
AXIS V5914 PTZ Network Camera 5.75.1.11
Live view - AXIS P5534-E Network Camera
Live view  - AXIS 215 PTZ Network Camera
Live view  - AXIS 214 PTZ Network Camera
Live view  - AXIS 213 PTZ Network Camera
AXIS P5534 PTZ Dome Network Camera 5.51.5
AXIS Q6034-E PTZ Dome Network Camera 5.41.4
AXIS P3354 Fixed Dome Network Camera 5.40.17
AXIS Q6042-E PTZ Dome Network Camera 5.70.1.4
AXIS Q3505 Fixed Dome Network Camera 6.30.1.1
Live view - AXIS 206M Network
```
