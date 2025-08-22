# Nuclei-AI-Prompts
1️⃣ Recon
```bash
docker run -v $(pwd):/src projectdiscovery/subfinder:latest -dL /src/domains -silent -o /src/subdomains && \
docker run -v $(pwd):/src projectdiscovery/dnsx:latest -l /src/subdomains -t 500 -retry 5 -silent -o /src/dnsx && \
docker run -v $(pwd):/src projectdiscovery/naabu:latest -l /src/dnsx -tp 1000 -s s -ec -c 100 -rate 5000 -o /src/alive_ports && \
docker run -v $(pwd):/src projectdiscovery/httpx:latest -l /src/alive_ports -t 100 -rl 500 -o /src/targets.txt
```
2️⃣ Recon (Active Crawl Links)
```bash
katana -l targets.txt -aff -jc -iqp -hl -nos -c 50 -p 50 -j -o katana.jsonl
```
3️⃣ Recon (Active + Passive JS Links)
```bash
docker run -v $(pwd):/src secsi/getjs --input /src/targets.txt --complete --output /src/js_links && \
katana -u targets.txt -ps -em js,json >> js_links # katana version 1.1.0 -> go install -v github.com/projectdiscovery/katana/cmd/katana@v1.1.0
```
# Fast Info Gathering
```
nuclei -list targets.txt -ai "Extract page title, detech tech and versions"
nuclei -list targets.txt -ai "Extract email addresses from web pages"
nuclei -list targets.txt -ai "Extract all subdomains referenced in web pages"
nuclei -list targets.txt -ai "Extract all external resource URLs (CDNs, images, iframes, fonts) from HTML"
nuclei -list targets.txt -ai "Extract social media profile links from web pages"
nuclei -list targets.txt -ai "Extract links pointing to staging, dev, or beta environments from HTML"
nuclei -list targets.txt -ai "Extract all links pointing to PDF, DOCX, XLSX, and other downloadable documents"
```
# Low Hanging Fruits
```
nuclei -list targets.txt -ai "Find exposed AI/ML model files (.pkl, .h5, .pt) that may leak proprietary algorithms or sensitive training data"
nuclei -list targets.txt -ai "Find exposed automation scripts (.sh, .ps1, .bat) revealing internal tooling or credentials"
nuclei -list targets.txt -ai "Identify misconfigured CSP headers allowing 'unsafe-inline' or wildcard sources"
nuclei -list targets.txt -ai "Detect pages leaking JWT tokens in URLs or cookies"
nuclei -list targets.txt -ai "Identify overly verbose error messages revealing framework or library details"
nuclei -list targets.txt -ai "Find application endpoints with verbose stack traces or source code exposure"
nuclei -list targets.txt -ai "Find sensitive information in HTML comments (debug notes, API keys, credentials)"
nuclei -list targets.txt -ai "Find exposed .env files leaking credentials, API keys, and database passwords"
nuclei -list targets.txt -ai "Find exposed configuration files such as config.json, config.yaml, config.php, application.properties containing API keys and database credentials."
nuclei -list targets.txt -ai "Find exposed configuration files containing sensitive information such as credentials, API keys, database passwords, and cloud service secrets."  
nuclei -list targets.txt -ai "Find database configuration files such as database.yml, db_config.php, .pgpass, .my.cnf leaking credentials."  
nuclei -list targets.txt -ai "Find exposed Docker and Kubernetes configuration files such as docker-compose.yml, kubeconfig, .dockercfg, .docker/config.json containing cloud credentials and secrets."  
nuclei -list targets.txt -ai "Find exposed SSH keys and configuration files such as id_rsa, authorized_keys, and ssh_config."  
nuclei -list targets.txt -ai "Find exposed WordPress configuration files (wp-config.php) containing database credentials and authentication secrets."  
nuclei -list targets.txt -ai "Identify exposed .npmrc and .yarnrc files leaking NPM authentication tokens"
nuclei -list targets.txt -ai "Identify open directory listings exposing sensitive files"  
nuclei -list targets.txt -ai "Find exposed .git directories allowing full repo download"
nuclei -list targets.txt -ai "Find exposed .svn and .hg repositories leaking source code"  
nuclei -list targets.txt -ai "Identify open FTP servers allowing anonymous access"  
nuclei -list targets.txt -ai "Find GraphQL endpoints with introspection enabled"  
nuclei -list targets.txt -ai "Identify exposed .well-known directories revealing sensitive data"  
nuclei -list targets.txt -ai "Find publicly accessible phpinfo() pages leaking environment details"  
nuclei -list targets.txt -ai "Find exposed Swagger, Redocly, GraphiQL, and API Blueprint documentation"  
nuclei -list targets.txt -ai "Identify exposed .vscode and .idea directories leaking developer configs"  
nuclei -list targets.txt -ai "Detect internal IP addresses (10.x.x.x, 192.168.x.x, etc.) in HTTP responses"  
nuclei -list targets.txt -ai "Find exposed WordPress debug.log files leaking credentials and error messages"  
nuclei -list targets.txt -ai "Detect misconfigured CORS allowing wildcard origins ('*')"  
nuclei -list targets.txt -ai "Find publicly accessible backup and log files (.log, .bak, .sql, .zip, .dump)"  
nuclei -list targets.txt -ai "Find exposed admin panels with default credentials"
nuclei -list targets.txt -ai "Identify commonly used API endpoints that expose sensitive user data, returning HTTP status 200 OK."
nuclei -list targets.txt -ai "Detect web applications running in debug mode, potentially exposing sensitive system information."  
```

# Advanced Mixed Testing
```
nuclei -list targets.txt -ai "Detect debug endpoints revealing system information"  
nuclei -list targets.txt -ai "Identify test and staging environments exposed to the internet"  
nuclei -list targets.txt -ai "Find admin login endpoints, filter 404 response code"
nuclei -list targets.txt -ai "Find misconfigured CORS policies allowing wildcard origins"
nuclei -list targets.txt -ai "Detect exposed stack traces in error messages"
nuclei -list targets.txt -ai "Find misconfigured Apache and Nginx security headers"  
nuclei -list targets.txt -ai "Check for APIs allowing unauthenticated access to admin routes"  
nuclei -list targets.txt -ai "Identify exposed admin panels of popular CMS (WordPress, Joomla, Magent, Opencart, etc.)"
nuclei -list targets.txt -ai "Find forgotten admin panels under uncommon paths (/secret-admin/, /super-admin/, /superuser/)"
nuclei -list targets.txt -ai "Find login pages using default HTTP basic auth with common credentials"
nuclei -list targets.txt -ai "Identify misconfigured iframe policies allowing clickjacking"
```
# Sensitive Data Exposure
```
nuclei -list targets.txt -ai "Scan for exposed environment files (.env) containing credentials"
nuclei -list targets.txt -ai "Find open directory listings and publicly accessible files"
nuclei -list targets.txt -ai "Detect exposed .git repositories and sensitive files"
nuclei -list targets.txt -ai "Identify publicly accessible backup and log files (.log, .bak, .sql, .dump)"
nuclei -list targets.txt -ai "Detect exposed .htaccess and .htpasswd files"
nuclei -list targets.txt -ai "Check for SSH private keys leaked in web directories"
nuclei -list targets.txt -ai "Find exposed API keys and secrets in responses and URLs"
nuclei -list targets.txt -ai "Identify API endpoints leaking sensitive data"
nuclei -list targets.txt -ai "Scan for hardcoded credentials in source code comments"
nuclei -list targets.txt -ai "Identify sensitive endpoints leaking personal or internal data"
nuclei -list targets.txt -ai "Detect vulnerable API endpoints exposing user input or sensitive information"
nuclei -list targets.txt -ai "Find exposed server status pages (e.g., phpinfo, server-status)"
nuclei -list targets.txt -ai "Identify sensitive configuration files (.env, .config, application.properties, settings.py)"
nuclei -list targets.txt -ai "Scan for information leaks in HTTP responses and headers"
```
# Sensitive Data Exposure (Javascript Files)
```
docker run -v $(pwd):/src projectdiscovery/nuclei:latest -l /src/js_links -ai "Find leaked database credentials in JavaScript files"
docker run -v $(pwd):/src projectdiscovery/nuclei:latest -l /src/js_links -ai "Perform a full deep JavaScript security audit: API keys, secrets, internal endpoints, debug logs, authentication tokens, and misconfigurations"
docker run -v $(pwd):/src projectdiscovery/nuclei:latest -l /src/js_links -ai "Find hardcoded API keys, JWT tokens, OAuth credentials, and authentication secrets in JavaScript"
docker run -v $(pwd):/src projectdiscovery/nuclei:latest -l /src/js_links -ai "Identify hardcoded cloud service credentials (AWS, GCP, Azure) in JavaScript files"
docker run -v $(pwd):/src projectdiscovery/nuclei:latest -l /src/js_links -ai "Find internal API endpoints (REST, GraphQL, WebSockets) hidden in JavaScript files"
docker run -v $(pwd):/src projectdiscovery/nuclei:latest -l /src/js_links -ai "Detect API keys, JWT tokens, and passwords in JavaScript files"
docker run -v $(pwd):/src projectdiscovery/nuclei:latest -l /src/js_links -ai "Find AWS, Google Cloud, and Azure API keys exposed in JavaScript"
docker run -v $(pwd):/src projectdiscovery/nuclei:latest -l /src/js_links -ai "Detect OAuth, Facebook, Twitter, and Google API tokens in JavaScript files"
docker run -v $(pwd):/src projectdiscovery/nuclei:latest -l /src/js_links -ai "Find Firebase, MongoDB, and Elasticsearch credentials in JavaScript"
docker run -v $(pwd):/src projectdiscovery/nuclei:latest -l /src/js_links -ai "Detect hardcoded JWT tokens and secrets in JavaScript files"
docker run -v $(pwd):/src projectdiscovery/nuclei:latest -l /src/js_links -ai "Identify exposed payment API keys for Stripe, PayPal, and Square in JavaScript files"
docker run -v $(pwd):/src projectdiscovery/nuclei:latest -l /src/js_links -ai "Find debugging logs, internal API endpoints, and test credentials in JavaScript"
docker run -v $(pwd):/src projectdiscovery/nuclei:latest -l /src/js_links -ai "Analyze JavaScript code for security vulnerabilities (XSS, CSRF, SSRF, RCE, LFI, LFR, etc)"
docker run -v $(pwd):/src projectdiscovery/nuclei:latest -l /src/js_links -ai "Detect corporate email addresses, internal contacts and internal resource in JavaScript files"
docker run -v $(pwd):/src projectdiscovery/nuclei:latest -l /src/js_links -ai "Find exposed JavaScript source maps (.map files) revealing original source code"
```

# SQL Injection (SQLi)
```
nuclei -list katana.jsonl -im jsonl -ai "Perform fuzzing on all parameters and HTTP methods using DSL, focusing on detecting SQL Injection vulnerabilities with pre-conditions"
nuclei -list katana.jsonl -im jsonl -ai "Search for database error responses indicating SQL query issues"
nuclei -list katana.jsonl -im jsonl -ai "Detect SQL errors in response when injecting common payloads into GET and POST requests"  
nuclei -list katana.jsonl -im jsonl -ai "Find SQL injection in 'id', 'user', 'product', 'category', 'page' parameters"  
nuclei -list katana.jsonl -im jsonl -ai "Identify potential blind SQL injection by probing query-related parameters such as search, s, q, query, sort, and filter"
nuclei -list katana.jsonl -im jsonl -ai "Use time delay techniques to detect time-based SQLi in all request parameters"
nuclei -list katana.jsonl -im jsonl -ai "Probe JSON-based API endpoints for injectable fields susceptible to SQL injection"  
nuclei -list katana.jsonl -im jsonl -ai "Inject SQL payloads into HTTP headers to detect header-based injection points (e.g. User-Agent, Referer, X-Forwarded-For, X-Forwarded-Host)" 
```
# Cross-Site Scripting (XSS)
```
nuclei -list katana.jsonl -im jsonl -ai "Fuzz all parameters and HTTP methods using DSL to detect XSS vulnerabilities, including reflected, stored, and DOM-based variants, applying context-aware pre-conditions"
nuclei -list katana.jsonl -im jsonl -ai "Test for reflected XSS in user-controllable parameters such as q, search, s, redirect, return, and url by injecting JavaScript payloads and observing output"
nuclei -list katana.jsonl -im jsonl -ai "Attempt stored XSS injection across all form fields and request parameters, analyzing persistent payload reflections in responses"
nuclei -list katana.jsonl -im jsonl -ai "Identify stored XSS in comment fields, usernames, profile descriptions"  
nuclei -list katana.jsonl -im jsonl -ai "Detect DOM-based XSS in JavaScript variables using common sources like location.href, document.URL, and referrer"  
nuclei -list katana.jsonl -im jsonl -ai "Fuzz AJAX or dynamic endpoints to identify reflected or stored XSS triggered via asynchronous responses"
nuclei -list katana.jsonl -im jsonl -ai "Inject XSS payloads into JSON fields of API requests and responses to find injection points vulnerable to script execution"
nuclei -list katana.jsonl -im jsonl -ai "Perform comprehensive scan for reflected XSS by injecting scripts into URL parameters"
```
# Server-Side Request Forgery (SSRF)
```
nuclei -list katana.jsonl -im jsonl -ai "Perform fuzzing on all HTTP parameters and methods using DSL, focusing on detecting SSRF vulnerabilities with pre-condition checks like internal IP ranges, URL redirects, and response behaviors."
nuclei -list katana.jsonl -im jsonl -ai "Accurately detect SSRF vulnerabilities in web applications by testing injection points, including headers, query, body parameters, and uncommon vectors."
nuclei -list katana.jsonl -im jsonl -ai "Identify SSRF vulnerabilities in query parameters"
nuclei -list katana.jsonl -im jsonl -ai "Identify SSRF vulnerabilities in most common parameters"
nuclei -list katana.jsonl -im jsonl -ai "Detect SSRF in common URL-related parameters like 'url', 'link', 'redirect', 'next', 'feed', and 'callback' by injecting payloads targeting internal services and metadata endpoints."
nuclei -list katana.jsonl -im jsonl -ai "Detect SSRF by injecting known internal IP ranges such as 127.0.0.1, 169.254.169.254, 10.0.0.0/8, 172.16.0.0/12, and 192.168.0.0/16 and analyzing server responses."
nuclei -list katana.jsonl -im jsonl -ai "Identify SSRF in API endpoints that fetch external resources, including indirect references such as file uploads, image fetchers, and URL previews."
nuclei -list katana.jsonl -im jsonl -ai "Detect blind SSRF by injecting unique external DNS and HTTP callbacks to monitor asynchronous server requests."
nuclei -list katana.jsonl -im jsonl -ai "Scan for blind SSRF by injecting webhooks and external DNS resolver payloads"
```
# Local & Remote File Inclusion (LFI/RFI)
```
nuclei -list katana.jsonl -im jsonl -ai "Fuzz all HTTP methods and parameters using DSL to detect Local and Remote File Inclusion (LFI/RFI) vulnerabilities, with context-aware pre-conditions"
nuclei -list katana.jsonl -im jsonl -ai "Search for LFI in parameters like file, path, template, inc, lang, and page using traversal payloads and file read probes"
nuclei -list katana.jsonl -im jsonl -ai "Test for Remote File Inclusion (RFI) by injecting remote HTTP/HTTPS URLs into parameters such as file and load"
nuclei -list katana.jsonl -im jsonl -ai "Identify Local File Inclusion by injecting payloads like /etc/passwd, ../../etc/passwd, php://filter, and php://input into suspect parameters"
nuclei -list katana.jsonl -im jsonl -ai "Detect file inclusion vulnerabilities based on verbose error messages or path disclosures revealing local file structure"
```
# Command Injection (RCE)
```
nuclei -list katana.jsonl -im jsonl -ai "Perform fuzzing on all parameters and HTTP methods using DSL, focusing on detecting Remote Code Execution (Command Injection) vulnerabilities with pre-conditions."
nuclei -list katana.jsonl -im jsonl -ai "Perform fuzzing on all parameters and HTTP methods using DSL, focusing on detecting Remote Code Execution (RCE) vulnerabilities on Linux and Windows."
nuclei -list katana.jsonl -im jsonl -ai "Detect command injection in 'cmd', 'exec', 'ping', 'query', 'shell' parameters"
nuclei -list katana.jsonl -im jsonl -ai "Scan for OS command injection via HTTP headers (X-Forwarded-For, X-Forwarded-Host, User-Agent, Referer)"
nuclei -list katana.jsonl -im jsonl -ai "Identify RCE vulnerabilities in file upload functionalities"
```
# XXE
```
nuclei -list katana.jsonl -im jsonl -ai "Fuzz all XML-based input fields using DSL to identify XXE injection points, with pre-conditions for triggering external entity processing or OOB interaction"
nuclei -list katana.jsonl -im jsonl -ai "Detect XXE by injecting malicious DTDs into XML inputs and analyzing responses for local file reads or error-based disclosures"
nuclei -list katana.jsonl -im jsonl -ai "Check for XXE vulnerabilities via POST requests with Content-Type: application/xml"
nuclei -list katana.jsonl -im jsonl -ai "Identify blind XXE using OOB techniques (DNS pingbacks, remote file loading)"
nuclei -list katana.jsonl -im jsonl -ai "Fuzz SOAP and XML-RPC endpoints for external entity injection vectors"
nuclei -list katana.jsonl -im jsonl -ai "Detect XXE in file upload or API endpoints that parse XML documents internally"
nuclei -list katana.jsonl -im jsonl -ai "Search for misconfigured XML parsers vulnerable to external entity expansion (XXE) or Billion Laughs attack"
nuclei -list katana.jsonl -im jsonl -ai "Test for base64-encoded XML content fields that may be parsed and exploited via XXE after decoding"
nuclei -list katana.jsonl -im jsonl -ai "Check for error-based XXE via injected <!DOCTYPE> declarations and malformed entity references"
```
# Host Header Injection
```
nuclei -list targets.txt -ai "Detect Host Header Injection"
nuclei -list targets.txt -ai "Test for web cache poisoning using manipulated Host headers"
nuclei -list targets.txt -ai "Identify password reset or login bypass via spoofed Host headers"
nuclei -list targets.txt -ai "Detect SSRF vectors triggered by altered Host headers"
nuclei -list targets.txt -ai "Check for insecure redirect or link generation using untrusted Host headers"
nuclei -list targets.txt -ai "Scan for Host-based access control bypass via alternate or poisoned headers"
nuclei -list targets.txt -ai "Detect cloud-based misrouting or virtual host misconfigurations through Host manipulation"
```
# Cloud Security Issues
```
nuclei -list targets.txt -ai "Scan for open Docker Engine API endpoints that permit remote control or container enumeration"
nuclei -list targets.txt -ai "Identify unauthenticated Kubernetes API servers accessible over the internet"
nuclei -list targets.txt -ai "Locate publicly accessible Kubernetes Dashboard interfaces with weak or missing authentication"
nuclei -list targets.txt -ai "Detect misconfigured Kubernetes dashboards or API endpoints exposed externally"
nuclei -list targets.txt -ai "Search for cloud provider metadata endpoints (e.g., AWS, Azure, GCP) that respond from web-facing services"
nuclei -list targets.txt -ai "Identify exposed S3 buckets, GCP buckets, and Azure blobs with insecure permissions (public read/write or misconfigured ACLs)"
nuclei -list targets.txt -ai "Extract Azure Storage access keys leaked in HTTP responses, reducing false positives"
nuclei -list targets.txt -ai "Extract AWS access keys or secrets found in HTTP responses with precision filters"
nuclei -list targets.txt -ai "Detect Google Cloud credentials exposed in HTTP responses and filter false positives using key structure"
nuclei -list targets.txt -ai "Check for public-facing Jenkins servers with unauthenticated script consoles"
nuclei -list targets.txt -ai "Detect public etcd instances leaking Kubernetes configuration and secrets"
nuclei -list targets.txt -ai "Identify web apps leaking Terraform or CloudFormation configurations"
nuclei -list targets.txt -ai "Detect exposed CI/CD configurations (GitHub Actions, GitLab CI, CircleCI) in .yml files"
nuclei -list targets.txt -ai "Find IAM policy documents or AWS assume-role tokens exposed in HTTP responses"
nuclei -list targets.txt -ai "Scan for cloud-specific SSRF via internal metadata access from response behaviors"
nuclei -list targets.txt -ai "Locate Kubernetes pods or service names leaked via headers, JS, or response bodies"
nuclei -list targets.txt -ai "Identify exposed Helm charts or Kustomize manifests with sensitive defaults"
nuclei -list targets.txt -ai "Detect exposed AWS Lambda function endpoints that execute code without proper auth"
```
# Web Cache Poisoning
```
nuclei -list targets.txt -ai "Test for web cache poisoning via manipulation of 'Host', 'X-Forwarded-Host', and 'X-Forwarded-For' headers, using multi-step validation (e.g. second/third request analysis)"
nuclei -list targets.txt -ai "Detect cache poisoning using 'X-Original-URL' and 'X-Rewrite-URL' headers by analyzing changes in response behavior across multiple requests"
nuclei -list targets.txt -ai "Inject payloads into 'Referer' and 'User-Agent' headers to identify cache poisoning issues, confirmed through response discrepancies over repeated requests"
nuclei -list targets.txt -ai "Scan for cache poisoning via malformed or non-standard HTTP headers with follow-up request comparison for response anomalies"
nuclei -list targets.txt -ai "Detect cache poisoning on CDN platforms like Fastly and Cloudflare through inconsistent response patterns with altered header values"
nuclei -list targets.txt -ai "Identify Varnish cache misconfigurations that leak private data by triggering caching of user-specific responses"
nuclei -list targets.txt -ai "Find cache poisoning issues in Squid proxy servers by injecting headers and analyzing cache behavior across sequential requests"
nuclei -list targets.txt -ai "Check for cache poisoning using path parameter variations and query parameter shadowing techniques"
nuclei -list targets.txt -ai "Test for variation in response caching when altering HTTP method from GET to HEAD or OPTIONS"
nuclei -list targets.txt -ai "Scan for cache poisoning via Accept-Encoding, Content-Type, or Language headers affecting response caching logic"
nuclei -list targets.txt -ai "Detect edge-case poisoning using duplicated headers (e.g., multiple Host headers) and non-standard capitalization"
```
