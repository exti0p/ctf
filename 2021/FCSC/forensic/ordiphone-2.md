# Ordiphone2

## Forensic, 197 points

### Description

Pour avancer sur cette investigation, vous devez analyser cette capture mémoire et une copie du stockage interne d'un téléphone Android utilisé par un cybercriminel.

Votre mission est de retrouver les secrets que ce dernier stocke sur son téléphone.

`lime.dump.7z` (180MB) : https://files.france-cybersecurity-challenge.fr/dl/android/lime.dump.7z

`sdcard.zip` (17MB) : https://files.france-cybersecurity-challenge.fr/dl/android/sdcard.zip

* SHA256(`lime.dump`) = `21575c12bcb8d67e6ca269bac6c3d360847b16922f2f44b0b360790862afe46d`.
* SHA256(`sdcard.zip`) = `e19e449c3bc7a9d04cc7f665fb494d857b9f019d8fec2ba08ab40c117fa2f8d8`.


### Solution

Now I am looking for some `secrets`. Remember from [Ordiphone 0](ordiphone-0.md), I found some interesting bash history which includes a `very_secret` directory, and even a weird string which can possibly a password: 
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

After unzipping `sdcard.zip`, I want to have a look at the files in it:
```bash
$ tree -l

├── Alarms
├── Android
│   └── data
│       ├── com.google.android.apps.maps
│       │   ├── cache
│       │   │   └── cache_r.m
│       │   ├── files
│       │   └── testdata
│       ├── com.google.android.apps.nexuslauncher
│       │   └── files
│       ├── com.google.android.gms
│       │   └── files
│       ├── com.google.android.googlequicksearchbox
│       │   └── files
│       │       ├── download_cache
│       │       └── pending_blobs
│       └── com.google.android.youtube
│           ├── cache
│           │   └── exo
│           │       └── 6861aa5b4dd5f9fd.uid
│           └── files
├── DCIM
├── Download
├── Movies
├── Music
├── Notifications
├── Pictures
├── Podcasts
├── Ringtones
└── secrets

27 directories, 3 files
```

Let's get a bit more information about these 3 files:
* `6861aa5b4dd5f9fd.uid`: empty.
* `cache_r.m`: 20 Mo.
* `secrets`: 50 Mo.

The `secrets` file looks promising, but before getting to it, let's have a quick look on `cache_r.m`. I extracted from it several non null bytes:
```bash
0000 0000 0000 0000 0000 0000 0000 0000
ecbb 4b55 0000 0000 0000 0000 0000 0000
0000 0000 ecbb 4b55 0000 0000 0000 0000
0000 0000 0000 0000 ecbb 4b55 0000 0000
0000 0000 0000 0000 0000 0000 ecbb 4b55

ecbb 4b55

0000 0000 0000 0000 0000 0000 67bb af86

67bb af86

0000 0016 0000 002d 0000 2000 0000 0004
0000 0080 0000 0000 0000 0001 7860 7e73
c000 0265 6e00 0000 0095 7d31 7d00 0000

0016 002d 2000 004 0080 0001 7860 7e73 c000 0265 6e00 0095 7d31 7d00
```

Finally, it led me to nothing. Let's get back to `secrets`.

```bash
$ file secrets 

secrets: LUKS encrypted file, ver 2 [, , sha256] UUID: 26040e95-2800-4129-be0f-4879b4579f22
```

Interesting stuff, LUKS2 encrypted file, which is basically not bruteforceable, at least easily. I probably then have the password for it. I actually have a possible one `p33larudsb0jrflbmr90l6ikdbb4lcdaym7k5s3a6u28rx8sut7kp1347h6c4v78`, let's try it:

```bash
$ cryptsetup open --type luks secrets fcscSecrets
$ mount /dev/mapper/fcscSecrets /mnt
```

I successfully mounted the partition, I get two files:
* `flag.enc`.
* `script.sh`.

I directly want to know what kind of file is `flag.enc`:
```bash
$ file flag.enc

flag.enc: openssl enc'd data with salted password
``` 

Now I am sure that I can't use any rainbow tables.

Let's understand `script.sh` and how I could possibly decrypt this `flag.enc`:
```bash
aleatoire=$(cat /dev/urandom | head | xxd -p -l 30 | tr -d " ")
echo $aleatoire > /dev/kmsg
aleatoirebis="$aleatoire$(pidof adbd | tr -d ' ')$(pidof vold | tr -d ' ')$(pidof logd | tr -d ' ')"
echo $aleatoirebis | /data/data/com.termux/files/usr/bin/openssl aes-256-cbc -in flag -out flag.enc -pass stdin
/data/data/com.termux/files/usr/bin/shred flag
rm flag
```

After some reading and trying this out locally, I understand that `$aleatoire` is a 60 long hex digits char and and that it is concatenated with the PIDs of `abdb`,`vold` and `logd` processes to create the `flag.enc` encryption password. 

Thereby, I crafted a little regex to find `$aleatoire` matches in our dump: `[0-9a-f]{60}`. Let's catch some matches:
```bash
$ strings stringsOutput |grep -P '^[0-9a-f]{60}$'

387e8985bd75be1b922eddaadde934e70465424ab4b0c3da98763c094432
387e8985bd75be1b922eddaadde934e70465424ab4b0c3da98763c094432
4100038121f20004150605040710000041637469766174653a64743d3135
4100038121f20004150605040710000041637469766174653a64743d3135
4100038121f20004150605040710000041637469766174653a64743d3135
4100038121f20004150605040710000041637469766174653a64743d3135
4100038121f20004150605040710000041637469766174653a64743d3135
4100038121f20004150605040710000041637469766174653a64743d3135
4100038121f20004150605040710000041637469766174653a64743d3135
4100038121f20004150605040710000041637469766174653a64743d3135
4100038121f20004150605040710000041637469766174653a64743d3135
4100038121f20004150605040710000041637469766174653a64743d3135
```

After removing duplicates, I get:
```bash
387e8985bd75be1b922eddaadde934e70465424ab4b0c3da98763c094432
4100038121f20004150605040710000041637469766174653a64743d3135
```

I have two candidates then, it is sufficient enough. Let's catch these PIDs now! Let's search for `adbd` in the memory dump:
```bash
$ strings lime.dump | grep 'adbd'

[...]
to free 81580kB on behalf of 'adbd' (1581) because
[...]
```

This entry is interesting, let's now look around:
```bash
$ strings lime.dump | grep 'adbd' -B 5 -A 5

[...]
cache 26340kB is below limit 73728kB for oom_score_adj 0
to free 88060kB on behalf of 'cryptsetup' (4458) because
cache 17288kB is below limit 73728kB for oom_score_adj 0
to free 82352kB on behalf of 'cryptsetup' (4458) because
cache 15780kB is below limit 73728kB for oom_score_adj 0
to free 81580kB on behalf of 'adbd' (1581) because
adj 0
cache -5240kB is below limit 73728kB for oom_score_adj 0
to free 82576kB on behalf of 'adbd' (1581) because
_adj 0
cache -26472kB is below limit 73728kB for oom_score_adj 0
to free 74484kB on behalf of 'cryptsetup' (4458) because
cache -27304kB is below limit 73728kB for oom_score_adj 0
to free 77896kB on behalf of 'cryptsetup' (4458) because
[...]
```

It definitely is `adbd`'s PID. Let's look for `/proc/1581/` now:
```bash
$ strings lime.dump | grep '/proc/1581/' -B 5 -A 5

/proc/1586/cmdline
mdnsd
/proc/1586/stat
/proc/1586/task
adbd
/proc/1581/cmdline
adbd
/proc/1581/stat
/proc/1581/task
vold
/proc/1539/cmdline
vold
/proc/1539/stat
/proc/1539/task
```

I can assume that as `/proc/1581/cmdline` gives us `adbd`'s PID, that `/proc/1539/cmdline` is doing the same thing. Hence only `logd`'s PID left to go! Let's dig deeper after these lines:

```bash
$ strings lime.dump | grep '/proc/1539/' -A 30

[...]
/proc/1529/cmdline
logd
[...]
```

I retrieved the three PIDs! To sum up:
* `$aleatoire`: `387e8985bd75be1b922eddaadde934e70465424ab4b0c3da98763c094432` or `4100038121f20004150605040710000041637469766174653a64743d3135`.
* `adbd`: `1581`.
* `vold`: `1539`.
* `logd`: `1529`.

Which makes `387e8985bd75be1b922eddaadde934e70465424ab4b0c3da98763c094432158115391529` or `4100038121f20004150605040710000041637469766174653a64743d3135158115391529` our possible decryption key.

After trying the first one, I check the flag file format:
```bash
$ file flag

flag: PNG image data, 612 x 408, 8-bit/color RGBA, non-interlaced
```

And I flag `FCSC{ba5dc3f62c971c212133bb45b76084732c86936b76a026dc89c7b34fd3df29ae}`.
