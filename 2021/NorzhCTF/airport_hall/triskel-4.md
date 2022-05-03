# Triskel 4 : Going deeper

## Pentest & Misc, 20 points

### Description

Well done, you broke it! I guess it's really the end of your journey this time haha!

by Remsio

### Solution

From Triskel 3, we have a stable reverse shell on the `Werkzeug` machine. We need to `go deeper`. 

At first, we thought to discover other machines and maybe exploit some CVE as the challenge was tagged with the `pentest` tag. We got a RCE on a few machines via PHP-FPM with this exploit https://gist.github.com/phith0n/9615e2420f31048f7e30f3937356cf75 and injecting some code this way:
```bash
root@kontammadur_klanvour:/app# python fpm.py -c code IP /usr/local/lib/php/System.php
```

Ẁe didn't find anything interesting with this path. 

Then we thought to attack the production machine from within the internal network, from the dev machine. We found nothing interesting too.

We were asking ourselves why is there a `misc` tag to this challenge. We noticed at the very beginning that we were in a Docker container, but didn't went down this path.

Finally, after reading some documentation (_cf_. https://book.hacktricks.xyz/linux-unix/privilege-escalation/docker-breakout), we tried to escape our Docker container to get access to the host file system. Among other approaches, we tried the `capabilities`. We listed the host capabilities easily as we were `root` with the following command:
```bash
root@kontammadur_klanvour:/app# capsh --print | grep cap_sys_admin
[...]
cap_sys_admin
[...]
```

We are able to mount the file system with a simple `mount` command then. Also, we knew from a `linPEAS` analysis (_cf_. https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) that the container was launched with the `privileged` attribute, this is why we are able to see the host drive with `fdisk -l` command. Thereby, we know that we have to mount `dev/sda1`. Let's do it:
```bash
root@kontammadur_klanvour:/app# mount /dev/sda1 /mnt
```

Bingo! - we got it, we can access the host file system. This way, we finish this series of Triskel challenges with the final flag: 

```bash
root@kontammadur_klanvour:/app# cat /mnt/root/flag
NORZH{pr1v1l363d_c0n741n3r_15_u53l355_0fd4b3a18e2191e483ef224f55b1bc7d}
```
