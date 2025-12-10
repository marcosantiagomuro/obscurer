# Installing the Cowrie Honeypot  
*(Full Step-by-Step Guide With User Context & Troubleshooting)*

This document explains how to correctly install **Cowrie**, including all system dependencies, users, virtual environments, configuration, and optional port-22 redirection.

Every step specifies **which user** should execute the command.

---

# Step 1 — Install System Dependencies  
**Run as:** `root` (or any sudo-enabled user)

Cowrie requires development headers, Python build tools, virtual environment support, and git.

On **Debian / Ubuntu**:

```bash
sudo apt-get update
sudo apt-get install git python3-pip python3-venv libssl-dev libffi-dev build-essential libpython3-dev python3-minimal authbind
```

If you encounter:
```
Unable to locate package <something>
```
run:
```bash
sudo apt-get update --fix-missing
```

---

# Step 2 — Create a Dedicated Cowrie User  

**Run as:** `root`  

Cowrie should never run as root. Create a dedicated user:

```bash
sudo adduser --disabled-password cowrie
```

Press ENTER through all prompts unless you want to set metadata.

Switch to the new user:

```bash
sudo su - cowrie
```

Now all future steps run as **cowrie**, unless otherwise specified.

---

# Step 3 — Download the Cowrie Source Code  
**Run as:** `cowrie` user

Clone the repository:

```bash
git clone https://github.com/cowrie/cowrie
```

Enter the directory:

```bash
cd cowrie
```

Troubleshooting:
- If you get `git: command not found`, return to step 1 and install git.
- If the clone is slow, try the SSH URL or add `--depth 1`.

---

# Step 4 — Create and Configure the Python Virtual Environment  
**Run as:** `cowrie` user

Check your location:

```bash
pwd
```
Expected:
```
/home/cowrie/cowrie
```

Create the virtual environment:

```bash
python3 -m venv cowrie-env
```

Activate it:

```bash
source cowrie-env/bin/activate
```

Once activated, your prompt should look like:
```
(cowrie-env) $
```

Upgrade pip and install Cowrie:

```bash
(cowrie-env) python -m pip install --upgrade pip
(cowrie-env) python -m pip install -e .
```

Troubleshooting:
- If you see `ERROR: Could not build wheels`, install missing build packages:
  ```bash
  sudo apt-get install build-essential libpython3-dev
  ```
- If the venv does not activate, confirm the folder exists:
  ```bash
  ls cowrie-env/bin/
  ```

---

# Step 5 — Configure Cowrie (Optional)  
**Run as:** `cowrie` user

Cowrie reads two config files from `cowrie/etc/`:

| File | Purpose |
|------|----------|
| `cowrie.cfg.dist` | Default config (overwritten on updates) |
| `cowrie.cfg` | Custom overrides (persistent) |

To enable a simple Telnet listener, create:

```bash
nano etc/cowrie.cfg
```

Add:

```ini
[telnet]
enabled = true
```

Save and exit.

Troubleshooting:
- If `nano` is not installed:  
  ```bash
  sudo apt-get install nano
  ```

---

# Step 6 — Start Cowrie  
**Run as:** `cowrie` user with virtual environment active**

Activate the environment if not already:

```bash
source cowrie-env/bin/activate
```

Start Cowrie:

```bash
(cowrie-env) cowrie start
```

You should see:

```
Starting cowrie with extra arguments [] ...
```

Check logs:

```bash
tail -f log/cowrie.log
```

Troubleshooting:
- If you get `cowrie: command not found`, reinstall:
  ```bash
  (cowrie-env) python -m pip install -e .
  ```
- If port 2222 is already in use:
  ```bash
  ss -tulpn | grep 2222
  ```

---

# Step 7 — (Optional) Make Cowrie Listen on Port 22  

By default:
- OpenSSH = port 22  
- Cowrie = port 2222  

To attract more attacks, Cowrie can listen on port 22, replacing or redirecting traffic normally handled by OpenSSH.

There are **three supported methods**:

---

## Method 1 — Using iptables (Recommended for Testing)

**Run as:** `root`

Forward port 22 → 2222:

```bash
sudo iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222
```

To make persistent on Debian/Ubuntu:

```bash
sudo apt-get install iptables-persistent
sudo netfilter-persistent save
```

---

## Method 2 — Using authbind  

Allows non-root programs to bind to privileged ports (<1024).

**Run as root:**
```bash
sudo touch /etc/authbind/byport/22
sudo chown cowrie:cowrie /etc/authbind/byport/22
sudo chmod 755 /etc/authbind/byport/22
```

**Run as cowrie:**
```bash
authbind --deep cowrie-env/bin/cowrie start
```

---

## Method 3 — Using setcap  
Give Python permission to bind to lower ports.

**Run as root:**

```bash
sudo setcap 'cap_net_bind_service=+ep' /home/cowrie/cowrie-env/bin/python3
```

Then start Cowrie normally as cowrie.

---

# Troubleshooting

---

## ❗ Cowrie fails to start: “Address already in use”
Most likely another SSH server is using port 22 or 2222.

Check:
```bash
ss -tulpn | grep :22
ss -tulpn | grep :2222
```

Move OpenSSH to another port:

```bash
sudo nano /etc/ssh/sshd_config
```

Change:
```
Port 22222
```

Restart:
```bash
sudo systemctl restart ssh
```

---

## ❗ Permission errors while binding to port 22
Use **one** of the three port-22 methods: iptables, authbind, or setcap.

---

## ❗ Virtual environment will not activate
Ensure `bash` is being used:

```bash
bash
source cowrie-env/bin/activate
```

---

## ❗ “cowrie command not found”
Reinstall inside the venv:

```bash
(cowrie-env) python -m pip install -e .
```

---

# End of File






# Removing a Cowrie Honeypot Installation  
*(Full Step-by-Step Removal & Troubleshooting Guide)*

This document explains how to **fully delete a Cowrie honeypot** from a Linux system, including:
- Stopping the service  
- Removing virtual environments, users, directories  
- Cleaning firewall rules (optional)  
- Troubleshooting common errors  

Every command includes the **user account that should run it**.

---

# 1. Identify Your Cowrie Installation Path

Most commonly:
```
/home/cowrie/cowrie
```

If unsure, run (as **root**):
```bash
ps aux | grep cowrie
```
or:
```bash
systemctl status cowrie
```

---

# 2. Stop Cowrie Service

### If Cowrie is installed as a systemd service:
Run as **root**:
```bash
systemctl stop cowrie
systemctl disable cowrie
```

### If Cowrie is started manually (no service):
Run as **cowrie user**:
```bash
./bin/cowrie stop
```
or just activate the cowrie env and use the stop command.
```
cd home/cowrie/cowrie
source cowrie-env/bin/activate
(cowrie-env) cowrie status
(cowrie-env) cowrie stop
```


If the `bin/cowrie` path is unknown, check:
```bash
ls /home/cowrie/cowrie/bin/
```

---

# 3. Remove Cowrie User (Optional but Recommended)

If Cowrie was installed under a dedicated user such as `cowrie`:
Remember to 
```exit```
any bash window that is running under cowrie user first.
Run as **root**:
```bash
userdel -r cowrie
```

This deletes:
- The user  
- Home directory (`/home/cowrie`)  
- Cowrie installation folder (if inside that directory)

If the system reports:
```
userdel: cowrie is currently logged in
```
Then run:
```bash
pkill -u cowrie
userdel -r cowrie
```

---

# 4. Manually Remove Cowrie Directory (If You Did Not Delete the User)

If you prefer not to delete the user and only remove the installation:

Run as **root**:
```bash
rm -rf /home/cowrie/cowrie
```

If Cowrie is elsewhere:
```bash
rm -rf /opt/cowrie
rm -rf /srv/cowrie
```

---

# 5. Clean Virtual Environment (If Still Present)

Sometimes the venv is outside the Cowrie folder.

As **root** or the user who owns the directory:
```bash
rm -rf /home/cowrie/cowrie-env
```

Common names:
```
cowrie-env
cowrie-venv
env
venv
```

---

# 6. Remove Cowrie systemd Service Definition (If It Exists)

As **root**:
```bash
rm -f /etc/systemd/system/cowrie.service
systemctl daemon-reload
```

Verify removal:
```bash
systemctl status cowrie
```
You should see:
```
Unit cowrie.service could not be found.
```

---

# 7. Remove Cowrie Log Files (Optional)

As **root**:
```bash
rm -rf /var/log/cowrie
rm -rf /var/log/cowrie/*.log
```

---

# 8. Remove Firewall or Port Redirection Rules (If Cowrie Used Port 22 → 2222)

Cowrie often uses 2222 internally. Many installations add an iptables redirect.

### Check for rules:
Run as **root**:
```bash
iptables -t nat -L PREROUTING --line-numbers
```

Look for something like:
```
REDIRECT tcp -- anywhere anywhere tcp dpt:ssh redir ports 2222
```

### Remove the rule:
```bash
iptables -t nat -D PREROUTING <number>
```

### If using ufw:
List rules:
```bash
ufw status numbered
```
Delete:
```bash
ufw delete <number>
```

---

# 9. Verify Nothing Is Running

As **root**:
```bash
ps aux | grep cowrie
```

If processes remain:
```bash
pkill -f cowrie
```

Check port 22 or 2222:
```bash
ss -tulpn | grep 2222
ss -tulpn | grep 22
```

Nothing related to Cowrie should appear.

---

# 10. Common Troubleshooting

---

## ❗ Error: “permission denied” when deleting files
This occurs when commands are accidentally run as a normal user.

**Fix:** rerun as **root**:
```bash
sudo rm -rf /home/cowrie/cowrie
```

---

## ❗ userdel: cannot remove home directory
Often caused by files owned by root.

Fix (as **root**):
```bash
chown -R cowrie:cowrie /home/cowrie
userdel -r cowrie
```

---

## ❗ systemctl: Unit cowrie.service not found
Cowrie may have been installed manually without a service.

Just skip the service removal step.

---

## ❗ “rm -rf: device or resource busy”
Cowrie is still running in the background.

As **root**:
```bash
pkill -f cowrie
rm -rf /home/cowrie/cowrie
```

---

## ❗ Redirect from port 22 persists after uninstall
Means your firewall rule is still active.

As **root**:
```bash
iptables -t nat -L PREROUTING --line-numbers
iptables -t nat -D PREROUTING <number>
```

or remove ufw redirection if present.

---

# 11. Full Quick-Delete Script (Run as root)

If you are confident you want to completely remove Cowrie:

```bash
systemctl stop cowrie 2>/dev/null
systemctl disable cowrie 2>/dev/null
pkill -f cowrie 2>/dev/null

rm -f /etc/systemd/system/cowrie.service
systemctl daemon-reload

rm -rf /var/log/cowrie
rm -rf /home/cowrie/cowrie
rm -rf /home/cowrie/cowrie-env

iptables -t nat -L PREROUTING --line-numbers | grep 2222 | awk '{print $1}' | xargs -I{} iptables -t nat -D PREROUTING {}

userdel -r cowrie 2>/dev/null
```

---

# 12. Confirmation Checklist

| Item | Check |
|------|-------|
| No directory `/home/cowrie/cowrie` | ✔ |
| No `cowrie` system user (if removed) | ✔ |
| No service `cowrie.service` | ✔ |
| No processes `ps aux | grep cowrie` | ✔ |
| No port redirection to 2222 | ✔ |

Once all these are confirmed, **Cowrie is fully removed**.

---

# End of File
