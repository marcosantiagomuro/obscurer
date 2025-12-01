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