---
title: "CrownJewel 2 - Sherlocks"
date: 2024-09-14 08:00:00 - 0500
categories: [Hack The Box, Sherlocks]
tags: [htb, challenge, sherlocks, NTDS, Windows Event, DFIR]
image: 
  path: /assets/img/posts/htb/htb.png
---

**Scenario**: Forela's Domain environment is pure chaos. Just got another alert from the Domain controller of `NTDS.dit` database being exfiltrated. Just one day prior you responded to an alert on the same domain controller where an attacker dumped NTDS.dit via vssadmin utility. However, you managed to delete the dumped files kick the attacker out of the DC, and restore a clean snapshot. Now they again managed to access DC with a domain admin account with their persistent access in the environment. This time they are abusing ntdsutil to dump the database. Help Forela in these chaotic times!!

## Task 1

![Task 1](/assets/img/posts/htb/crownjewel2/task1.png){: width="972" height="589" }

At the start of the challenge, I will be given a zip file named `crownjewel2.zip`. When I unzip this file, I will obtain three event log files: `APPLICATION`, `SECURITY`, and `SYSTEM` logs. 

![log files](/assets/img/posts/htb/crownjewel2/artifact.png){: width="972" height="589" }

I used [Evtxcmd tool](https://github.com/EricZimmerman/evtx) to parse the event log into CSV file.

```bash
PS: ⥑01:41:00⥏ ∺ ﹝Hunting﹞ ▹ evtxECmd.exe -d .\Artifacts\ --csv crownjewel2
```
{: .nolineno }

![Evtxcmd](/assets/img/posts/htb/crownjewel2/5U4BhGRetM.png){: width="972" height="589" }

According to the information in question 1, when using ntdsutil.exe to dump the NTDS (Active Directory) database to disk, it also uses the Microsoft Shadow Copy Service.

System logs in Windows provide information about service-related events (`stoped`, `started`, `restarted`). Filter for Event ID 7036 which mean   `Description
Service started or stopped` and look for `Microsoft Shadow Copy Service`

![Evtxcmd](/assets/img/posts/htb/crownjewel2/dMWMZOTHKq.png){: width="972" height="589" }

**Answer**: `2024-05-15 05:39:55`
## Task 2

![Evtxcmd](/assets/img/posts/htb/crownjewel2/task2.png){: width="972" height="589" }

As we already know that Shadow Copy service will enter running state before NTDS file was dumped so we can filter for Event ID 325 (The database engine created a new database) and 327 (The database engine detached a database)

In Application Event Log, filter for Event ID 325. This Event ID is recorded whenever a new database (new copy of NTDS.dit database) is created by the database engine and will logged location of a new file so you can get the full path of the dumped NTDS file.

![Filter event id 325](/assets/img/posts/htb/crownjewel2/a1D0xv0eB6.png){: width="972" height="589" }

![](/assets/img/posts/htb/crownjewel2/NX2LiHJVXU.png){: width="972" height="589" }

**Answer**: `C:\Windows\Temp\dump_tmp\Active Directory\ntds.dit`

## Task 3

![task3](/assets/img/posts/htb/crownjewel2/task3.png){: width="972" height="589" }

This would be the time of the same event when the NTDS file was dumped (Event ID 325), so you should look at the creation time and use this time for the answer.

**Answer**: `2024-05-15 05:39:56`

## Task 4

![task3](/assets/img/posts/htb/crownjewel2/task4.png){: width="972" height="589" }

As I mentioned in the previous task, Event ID 325 indicates that `NTDS the database engine created a new database`, while Event ID 327 indicates that `NTDS the database engine detached a database`.

In the Application Event Log, filter for Event ID 327, which indicates when a newly created database is detached by the database engine and marked as ready to use.

![task3](/assets/img/posts/htb/crownjewel2/UEGHpqfcan.png){: width="972" height="589" }

**Answer**: `2024-05-15 05:39:58`

## Task 5

![task3](/assets/img/posts/htb/crownjewel2/task5.png){: width="972" height="589" }

Event logs use event sources to track events coming from different sources and you can see Event ID 325, 327 came from the same source which is `ESENT`

**Answer**: `ESENT`

## Task 6

![task3](/assets/img/posts/htb/crownjewel2/task6.png){: width="972" height="589" }

When ntdsutil.exe is used to dump the database, it enumerates certain user groups to validate the privileges of the account being used. 

So, I need to open Security log for this task, filter for Event ID 4799 (A security-enabled local group membership was enumerated) and look for Events in between the timeframe of incident identified so far.

![ntdsutil enumerate](/assets/img/posts/htb/crownjewel2/t13iQKmWOD.png){: width="972" height="589" }

**Answer**: `Administrators, Backup Operators, 0x8DE3D`

## Task 7

![task3](/assets/img/posts/htb/crownjewel2/task7.png){: width="972" height="589" }

In this task, you can take the LoginID `0x8DE3D` in the previous task and go to the Security logs as those login/logout events of users.

Initially, I thought I had to search for Event ID 4624 to find successful user logons to the system, but I did not find any Event ID 4624 entries.

Since this is a domain environment, I must to find Kerberos Events such as 4768 and 4769. From here identify the Event Where Account Name is a user account name and not any service or machine account (Starting with a $) in the event 4768

![Kerberos login](/assets/img/posts/htb/crownjewel2/Pn0mRGb3WG.png){: width="972" height="589" }

**Answer**: `2024-05-15 05:36:31`

## References
[1] - [NTDS dumping attack detection](https://www.hackthebox.com/blog/ntds-dumping-attack-detection)<br>
[2] - [Event types in Windows Event Log](https://learn.microsoft.com/en-us/windows/win32/eventlog/event-types)<br>
[3] - [Complete Guide to Checking Window Logs](https://signoz.io/guides/windows-logs/)<br>
[4] - [4799(S): A security-enabled local group membership was enumerated](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4799)