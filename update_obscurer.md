need to change 


ARCH version from cowrie_cfg_dist

OS-Release

src/cowrie/ssh/userauth.py  >> accepts any user
cowrie/ssh/transport.py  >> connection behaviour >> add some mini random delays 
cowrie/ssh/keys.py  >> generate host keys via standard ssh-keygen command   (ensure correct format)


honeyfs/proc/version >> Unix version


cowrie/core/honeypot.py >> add some mini random delays 


./share/cowrie/cmdoutput.json >> listing processes


most used commands:
uname -a
cat /etc/os-release
ps, w, who
ifconfig or ip a
netstat or ss

and ensure these agree on:
hostname
OS version
kernel version / architecture
active network interfaces and IPs
running services matching the server “role”





CONSISTENCY:

put the same OS version in
cowrie.cfg
honeyfs/etc/issue and etc/motd
hostkey and type and sizes
/etc/os-release in honeyfs




IN COWRIE.CFG
change idle_timeout
change authentication_timeout


Add small random delays

in server.py /ssh.py >> session level delays 50ms to 500ms


in userauth.py  >> session level delays 50ms to 500ms


in shell.py or shell/interact.py >> character delays from 50 ms to 150ms

>> command level delays from 50ms to 800ms   for complex commands outputs





Kernel Build String >> uname -a

Nix version >> nix --version

debian OS profile / system info >> cat /etc/os-release


# ---------------------------------------------------------------------

### starting cowrie

```
>> sudo su - cowrie

>> source cowrie/cowrie-env/bin/activate
```


# COMMANDS AND RESULTS

### nc localhost 2222
> cowrie.cfg file : 
```
version = SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3 
```


### nmap -sV localhost
> cowrie.cfg file (service info is deduced form the banner response): 
```
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-01 10:01 EST
Nmap scan report for localhost (127.0.0.1)
Host is up (0.0000010s latency).
Other addresses for localhost (not scanned): ::1
Not shown: 999 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
2222/tcp open  ssh     OpenSSH 9.2p1 Debian 2+deb12u3 (protocol 2.0)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 0.24 seconds
```

### nmap -script=firewalk localhost
> ??? : 
```
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-01 10:15 EST
Nmap scan report for localhost (127.0.0.1)
Host is up (0.0000010s latency).
Other addresses for localhost (not scanned): ::1
Not shown: 999 closed tcp ports (reset)
PORT     STATE SERVICE
2222/tcp open  EtherNetIP-1

Nmap done: 1 IP address (1 host up) scanned in 0.19 seconds
```

### nmap -O localhost
> ??? : 
```
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-01 10:21 EST
Nmap scan report for localhost (127.0.0.1)
Host is up (0.00015s latency).
Other addresses for localhost (not scanned): ::1
Not shown: 999 closed tcp ports (reset)
PORT     STATE SERVICE
2222/tcp open  EtherNetIP-1
Device type: general purpose
Running: Linux 2.6.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:2.6.32 cpe:/o:linux:linux_kernel:5 cpe:/o:linux:linux_kernel:6
OS details: Linux 2.6.32, Linux 5.0 - 6.2
Network Distance: 0 hops

OS detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1.48 seconds
```


### nmap -A -p 2222 localhost
> cowrie/var/lib/cowrie  the keys are saved there  both private and pub.  Theya re created when cowrie gets installed the first time:

to replace them
```ssh-keygen -t rsa -b 2048 -f ~/cowrie/var/lib/cowrie/ssh_host_rsa_key -N "" ```
```
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-01 10:24 EST
Nmap scan report for localhost (127.0.0.1)
Host is up (0.000067s latency).
Other addresses for localhost (not scanned): ::1

PORT     STATE SERVICE VERSION
2222/tcp open  ssh     OpenSSH 9.2p1 Debian 2+deb12u3 (protocol 2.0)
| ssh-hostkey: 
|   2048 c9:be:1e:b4:54:be:63:9a:4c:f4:0c:f9:9d:83:e4:c5 (RSA)
|   256 09:10:05:e2:c0:84:7b:0e:68:01:9d:9d:df:a4:6f:39 (ECDSA)
|_  256 53:5e:63:f0:d4:b9:73:bd:ef:54:09:e8:3b:e1:77:92 (ED25519)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 2.6.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:2.6.32 cpe:/o:linux:linux_kernel:5 cpe:/o:linux:linux_kernel:6
OS details: Linux 2.6.32, Linux 5.0 - 6.2
Network Distance: 0 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1.94 seconds

```


### nmap --script ssh2-enum-algos -p 2222 localhost
> this depends on the twisted/conch library :
it doesn't support others, if the honeypot would be used as a proxy then we would be able to use the ssh kex algos of the host as well.  i could hardocde the answer but then the nmap would break the cowrie honeypot connection class when using the non supported kex, so in this case is just better to remove a couple from the config file so that at least it is not the same as a default honeypot
it could be overwritten everything,  
> both in cowrie.cfg file and  cowrie/src/cowrie/ssh/transoprt.py file by
```
class HoneyPotSSHTransport(transport.SSHServerTransport, TimeoutMixin):
    # ADD THIS:
    supportedKeyExchanges = [
        b"curve25519-sha256",
        b"curve25519-sha256@libssh.org",
        b"ecdh-sha2-nistp256",
        b"ecdh-sha2-nistp384",
        b"ecdh-sha2-nistp521",
        b"diffie-hellman-group-exchange-sha256",
        b"diffie-hellman-group16-sha512",
        b"diffie-hellman-group18-sha512",
        b"diffie-hellman-group14-sha256",
        b"diffie-hellman-group14-sha1",
    ]
```

OUTPUT BEFORE:
```
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-01 10:26 EST
Nmap scan report for localhost (127.0.0.1)
Host is up (0.000087s latency).
Other addresses for localhost (not scanned): ::1

PORT     STATE SERVICE
2222/tcp open  EtherNetIP-1
| ssh2-enum-algos: 
|   kex_algorithms: (9)
|       curve25519-sha256
|       curve25519-sha256@libssh.org
|       ecdh-sha2-nistp256
|       ecdh-sha2-nistp384
|       ecdh-sha2-nistp521
|       diffie-hellman-group-exchange-sha256
|       diffie-hellman-group-exchange-sha1
|       diffie-hellman-group14-sha1
|       ext-info-s
|   server_host_key_algorithms: (3)
|       ssh-rsa
|       ecdsa-sha2-nistp256
|       ssh-ed25519
|   encryption_algorithms: (8)
|       aes128-ctr
|       aes192-ctr
|       aes256-ctr
|       aes256-cbc
|       aes192-cbc
|       aes128-cbc
|       3des-cbc
|       cast128-cbc
|   mac_algorithms: (5)
|       hmac-sha2-512
|       hmac-sha2-384
|       hmac-sha2-256
|       hmac-sha1
|       hmac-md5
|   compression_algorithms: (3)
|       zlib@openssh.com
|       zlib
|_      none

Nmap done: 1 IP address (1 host up) scanned in 0.15 seconds

```

OUTPUT AFTER:
```
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-02 07:22 EST
Nmap scan report for localhost (127.0.0.1)
Host is up (0.00027s latency).
Other addresses for localhost (not scanned): ::1

PORT     STATE SERVICE
2222/tcp open  EtherNetIP-1
| ssh2-enum-algos: 
|   kex_algorithms: (4)
|       diffie-hellman-group18-sha512
|       diffie-hellman-group16-sha512
|       ecdh-sha2-nistp256
|       ext-info-s
|   server_host_key_algorithms: (3)
|       ssh-rsa
|       ecdsa-sha2-nistp256
|       ssh-ed25519
|   encryption_algorithms: (7)
|       aes128-ctr
|       aes192-ctr
|       aes256-ctr
|       aes256-cbc
|       chacha20-poly1305@openssh.com
|       aes256-gcm@openssh.com
|       cast128-cbc
|   mac_algorithms: (5)
|       hmac-sha2-512
|       hmac-sha2-384
|       hmac-sha2-256
|       umac-64@openssh.com
|       hmac-sha2-512-etm@openssh.com
|   compression_algorithms: (2)
|       zlib@openssh.com
|_      none

Nmap done: 1 IP address (1 host up) scanned in 0.18 seconds
```


### nmap --script ssh-hostkey -p 2222 localhost
> ??? : 
```
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-01 10:28 EST
Nmap scan report for localhost (127.0.0.1)
Host is up (0.00013s latency).
Other addresses for localhost (not scanned): ::1

PORT     STATE SERVICE
2222/tcp open  EtherNetIP-1
| ssh-hostkey: 
|   2048 c9:be:1e:b4:54:be:63:9a:4c:f4:0c:f9:9d:83:e4:c5 (RSA)
|   256 09:10:05:e2:c0:84:7b:0e:68:01:9d:9d:df:a4:6f:39 (ECDSA)
|_  256 53:5e:63:f0:d4:b9:73:bd:ef:54:09:e8:3b:e1:77:92 (ED25519)

Nmap done: 1 IP address (1 host up) scanned in 0.14 seconds
```


### nmap --script ssh-publickey-acceptance -p 2222 localhost
> ??? : 
```
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-01 10:32 EST
Nmap scan report for localhost (127.0.0.1)
Host is up (0.000098s latency).
Other addresses for localhost (not scanned): ::1

PORT     STATE SERVICE
2222/tcp open  EtherNetIP-1
| ssh-publickey-acceptance: 
|_  Accepted Public Keys: No public keys accepted

Nmap done: 1 IP address (1 host up) scanned in 0.18 seconds
```



### hping3 -S localhost -p 2222
> ??? : 
```
HPING localhost (lo 127.0.0.1): S set, 40 headers + 0 data bytes
len=44 ip=127.0.0.1 ttl=64 DF id=0 sport=2222 flags=SA seq=0 win=65495 rtt=7.5 ms
len=44 ip=127.0.0.1 ttl=64 DF id=0 sport=2222 flags=SA seq=1 win=65495 rtt=8.4 ms
len=44 ip=127.0.0.1 ttl=64 DF id=0 sport=2222 flags=SA seq=2 win=65495 rtt=3.2 ms
len=44 ip=127.0.0.1 ttl=64 DF id=0 sport=2222 flags=SA seq=3 win=65495 rtt=7.3 ms
len=44 ip=127.0.0.1 ttl=64 DF id=0 sport=2222 flags=SA seq=4 win=65495 rtt=6.6 ms
len=44 ip=127.0.0.1 ttl=64 DF id=0 sport=2222 flags=SA seq=5 win=65495 rtt=6.2 ms
len=44 ip=127.0.0.1 ttl=64 DF id=0 sport=2222 flags=SA seq=6 win=65495 rtt=1.9 ms
len=44 ip=127.0.0.1 ttl=64 DF id=0 sport=2222 flags=SA seq=7 win=65495 rtt=1.5 ms
len=44 ip=127.0.0.1 ttl=64 DF id=0 sport=2222 flags=SA seq=8 win=65495 rtt=5.3 ms
--- localhost hping statistic ---
9 packets transmitted, 9 packets received, 0% packet loss
round-trip min/avg/max = 1.5/5.3/8.4 ms

```


### uname -a
> ??? : 
```
Linux testserver1 3.2.0-4-amd64 #1 SMP Debian 3.2.68-1+deb7u1 x86_64 GNU/Linux
```




https://agrohacksstuff.io/posts/i-made-a-honeypot-with-cowrie/

https://hackertarget.com/cowrie-honeypot-analysis-24hrs/

https://hackertarget.com/cowrie-honeypot-analysis-24hrs/

https://labs.detectify.com/ethical-hacking/hakluke-creating-the-perfect-bug-bounty-automation/

https://labex.io/tutorials/hydra-deploy-a-honeypot-in-cowrie-549933


