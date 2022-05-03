# Ordiphone0

## Forensic, 42 points

### Description


Un nouvel apprenti vient d'effectuer une capture mémoire mais a oublié de noter la date du lancement de celle-ci.

Pour valider cette première étape, vous devez retrouver la date à laquelle le processus permettant la capture a été lancé. Le flag est au format `FCSC{sha256(date)}`, avec la date au format `YYYY-MM-DD HH:MM` en UTC.

`lime.dump.7z` (180M) : https://files.france-cybersecurity-challenge.fr/dl/android/lime.dump.7z

SHA256(`lime.dump`) = `21575c12bcb8d67e6ca269bac6c3d360847b16922f2f44b0b360790862afe46d`.

### Solution

At first, I noticed `lime` in the file name, which made me think directly of `LiME` as in `Linux Memory Extractor` (https://github.com/504ensicsLabs/LiME). I guessed then it was a Linux memory dump. Let's have more information about it:
```bash
$ strings lime.dump | grep -i "linux version" | uniq 

Kernel: Linux version 3.18.91+ (android-build@wphr1.hot.corp.google.com) (gcc version 4.9 20140827 (prerelease) (GCC) ) #1 SMP PREEMPT Tue Jan 9 20:30:51 UTC 2018
Linux version 4.4.124+ (forensics@fcsc2021) (gcc version 4.9.x 20150123 (prerelease) (GCC) ) #3 SMP PREEMPT Sun Mar 21 19:15:33 CET 2021
Could not get linux version: %s
Kernel: Linux version 3.18.91+ (android-build@wphr1.hot.corp.google.com) (gcc version 4.9 20140827 (prerelease) (GCC) ) #1 SMP PREEMPT Tue Jan 9 20:30:51 UTC 2018
Linux version 4.4.124+ (forensics@fcsc2021) (gcc version 4.9.x 20150123 (prerelease) (GCC) ) #3 SMP PREEMPT Sun Mar 21 19:15:33 CET 2021
```

Even though I had no experience at all with Android memory forensics, I considered it similar as a Linux memory forensics case. According to this article https://resources.infosecinstitute.com/topic/obtaining-information-dumping-memory/ and with my digital forensics knowledge, I searched for `insmod` entries which is used in association with `LiME` to dump linux memory. I guessed it could be found in the `lime.dump` file, like it could be found on a Linux case with, for instance, `linux_bash` command in `volatility`. For this reason, I pulled out `strings` again:
```bash
$ strings lime.dump | grep "insmod"

insmod /sdcard/lime.ko "path=/sdcard/lime.dump format=lime"
[...]
```

Our guess was right, `insmod` is indeed used with `LiME`. Let's search for 5 lines before and after every matches, maybe I will get something interesting:
```bash
$ strings lime.dump | grep 'insmod /sdcard/lime.ko "path=/sdcard/lime.dump format=lime"' -B 5 -A 5

p33larudsb0jrflbmr90l6ikdbb4lcdaym7k5s3a6u28rx8sut7kp1347h6c4v78
mkdir /sdcard/very_secret
mount /dev/mapper/secrets /sdcard/very_secret
cd /sdcard/very_secret
sh script.sh
insmod /sdcard/lime.ko "path=/sdcard/lime.dump format=lime"
audit(1616526782.263:7186): avc:  denied  { write } for  pid=1849 comm="system_server" name="timerslack_ns" dev="proc" ino=32400 scontext=u:r:system_server:s0 tcontext=u:r:untrusted_app:s0:c512,c768 tclass=file permissive=0ive=0
Using -iter or -pbkdf2 would be better.
generic_x86_64:/sdcard/very_secret # insmod /sdcard/lime.ko "path=/sdcard/lime.dump format=lime"
[...]
```

The first matches are quite interesting, I have the bash history, a weird string on the first line, an `audit` with a timestamp and two matches for our `grep`. We assume this timestamp can fit, as I only need to be accurate to the minute to flag. Moreover, it is just before or after the memory extraction and with our `grep`, I have no other `audit`, hence timestamp entry. 

We might have a chance there, let's go: I go on https://www.epochconverter.com/, submit `1616526782.263` and get `Tuesday 23 March 2021 19:13:02.263` which would make as a potential date flag `2021-03-23 19:13`. We use a sha256 function to it, add our `FCSC{}` wrapper, and submit our flag: `FCSC{b7dc08558ee16d1acbf54db67263c1d92e9a9d9603e6a1345550c825527adc06}`.

Turns out, I flagged!