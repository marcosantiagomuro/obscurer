#!/usr/bin/python3
# changes by marcosantiagomuro
# the COWRIE filesystem can be found here: https://github.com/cowrie/cowrie


import urllib.request
import random
import crypt
import csv
import string
import re
from random import randint
import time
from optparse import OptionParser
import sys
import os
import shutil

SCRIPT_VERSION = "1.1.0"


def rand_hex():
    return '{0}{1}'.format(random.choice('0123456789ABCDEF'), random.choice('0123456789ABCDEF'))


def random_int(len):
    return random.randint()


usernames = ['admin', 'support', 'guest',
             'user', 'service', 'tech', 'administrator', 'root', 'ubuntu']
passwords = ['system', 'enable', 'password',
             'shell', 'root', 'support', 'toor', '123456']
services = ['syslog', 'mongodb', 'statd', 'pulse']

hostnames = ['web', 'db', 'nas', 'dev', 'backups', 'dmz']
hostnames_suffixes = ['0a', '-01', '-srv', '-01a', '01', '001']

KERNELS = {
    "rhel-2.6.32": {
        "proc_version": (
            "Linux version 2.6.32-042stab116.2 "
            "(root@kbuild-rh6-x64.eng.sw.ru) "
            "(gcc version 4.4.6 20120305 (Red Hat 4.4.6-4) (GCC) ) "
            "#1 SMP Fri Jun 24 15:33:57 MSK 2016"
        ),
        "uname_template": (
            "Linux {hostname} 2.6.32-042stab116.2 "
            "#1 SMP Fri Jun 24 15:33:57 MSK 2016 x86_64 x86_64 x86_64 GNU/Linux"
        ),
        "arch_choices": ["linux-x64-lsb", "linux-x86-lsb"],
    },

    "ubuntu-1404-4.4.0-62": {
        "proc_version": (
            "Linux version 4.4.0-62-generic (buildd@lcy01-33) "
            "(gcc version 4.8.4 (Ubuntu 4.8.4-2ubuntu1~14.04.3) ) "
            "#83~14.04.1-Ubuntu SMP Wed Jan 18 18:10:30 UTC 2017"
        ),
        "uname_template": (
            "Linux {hostname} 4.4.0-62-generic "
            "#83~14.04.1-Ubuntu SMP Wed Jan 18 18:10:30 UTC 2017 "
            "x86_64 x86_64 x86_64 GNU/Linux"
        ),
        "arch_choices": ["linux-x64-lsb", "linux-x86-lsb"],
    },

    "ubuntu-1404-4.4.0-36": {
        "proc_version": (
            "Linux version 4.4.0-36-generic (buildd@lgw01-20) "
            "(gcc version 4.8.4 (Ubuntu 4.8.4-2ubuntu1~14.04.3) ) "
            "#55~14.04.1-Ubuntu SMP Fri Aug 12 11:49:30 UTC 2016"
        ),
        "uname_template": (
            "Linux {hostname} 4.4.0-36-generic "
            "#55~14.04.1-Ubuntu SMP Fri Aug 12 11:49:30 UTC 2016 "
            "x86_64 x86_64 x86_64 GNU/Linux"
        ),
        "arch_choices": ["linux-x64-lsb", "linux-x86-lsb"],
    },

    "ubuntu-1404-4.4.0-59": {
        "proc_version": (
            "Linux version 4.4.0-59-generic (buildd@lcy01-32) "
            "(gcc version 4.8.4 (Ubuntu 4.8.4-2ubuntu1~14.04.3) ) "
            "#80~14.04.1-Ubuntu SMP Fri Jan 6 18:02:02 UTC 2017"
        ),
        "uname_template": (
            "Linux {hostname} 4.4.0-59-generic "
            "#80~14.04.1-Ubuntu SMP Fri Jan 6 18:02:02 UTC 2017 "
            "x86_64 x86_64 x86_64 GNU/Linux"
        ),
        "arch_choices": ["linux-x64-lsb", "linux-x86-lsb"],
    },

    "debian-4.6.0-nix": {
        "proc_version": (
            "Linux version 4.6.0-nix-amd64 (devel@kgw92.org) "
            "(gcc version 5.4.0 20160609 (Debian 5.4.0-6) ) "
            "#1 SMP Debian 4.6.4-1nix1 (2016-07-21)"
        ),
        "uname_template": (
            "Linux {hostname} 4.6.0-nix1-amd64 "
            "#1 SMP Debian 4.6.4-1nix1 (2016-07-21) x86_64 GNU/Linux"
        ),
        "arch_choices": ["linux-x64-lsb", "linux-x86-lsb"],
    },

    "ubuntu-1404-3.13.0-108": {
        "proc_version": (
            "Linux version 3.13.0-108-generic (buildd@lgw01-60) "
            "(gcc version 4.8.4 (Ubuntu 4.8.4-2ubuntu1~14.04.3) ) "
            "#155-Ubuntu SMP Wed Jan 11 16:58:52 UTC 2017"
        ),
        "uname_template": (
            "Linux {hostname} 3.13.0-108-generic "
            "#155-Ubuntu SMP Wed Jan 11 16:58:52 UTC 2017 "
            "x86_64 x86_64 x86_64 GNU/Linux"
        ),
        "arch_choices": ["linux-x64-lsb", "linux-x86-lsb"],
    },
}

OS_PROFILES = {
    "ubuntu-1404": {
        "pretty_name": "Ubuntu 14.04.5 LTS",
        "kernel_ids": [
            "ubuntu-1404-3.13.0-108",
            "ubuntu-1404-4.4.0-36",
            "ubuntu-1404-4.4.0-59",
            "ubuntu-1404-4.4.0-62",
        ],
        "ssh_versions": [
            "SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13",
            "SSH-2.0-OpenSSH_5.3p1 Debian-3ubuntu6",
            "SSH-2.0-OpenSSH_5.5p1 Debian-6+squeeze2",
        ],
        "openssl_version": "OpenSSL 1.0.1f",
        "openssl_date": "06 Jan 2014",
        "arch_choices": ["linux-x64-lsb", "linux-x86-lsb"],
    },

    "ubuntu-1604": {
        "pretty_name": "Ubuntu 16.04 LTS",
        "kernel_ids": [
            "ubuntu-1404-4.4.0-36",
            "ubuntu-1404-4.4.0-59",
            "ubuntu-1404-4.4.0-62",
        ],
        "ssh_versions": [
            "SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13",
            "SSH-2.0-OpenSSH_7.4",
            "SSH-2.0-OpenSSH_8.0",
            "OpenSSH_7.4p1 Ubuntu-10ubuntu2.10",
        ],
        "openssl_version": "OpenSSL 1.0.2g",
        "openssl_date": "01 Mar 2016",
        "arch_choices": ["linux-x64-lsb"],
    },

    "ubuntu-1804": {
        "pretty_name": "Ubuntu 18.04 LTS",
        "kernel_ids": [
            "ubuntu-1404-4.4.0-59",
            "ubuntu-1404-4.4.0-62",
        ],
        "ssh_versions": [
            "SSH-2.0-OpenSSH_7.4",
            "SSH-2.0-OpenSSH_8.0",
            "OpenSSH_7.4p1 Ubuntu-10ubuntu2.10",
        ],
        "openssl_version": "OpenSSL 1.1.0g",
        "openssl_date": "02 Nov 2017",
        "arch_choices": ["linux-x64-lsb"],
    },

    "ubuntu-2004": {
        "pretty_name": "Ubuntu 20.04 LTS",
        "kernel_ids": [
            "ubuntu-1404-4.4.0-59",
            "ubuntu-1404-4.4.0-62",
        ],
        "ssh_versions": [
            "SSH-2.0-OpenSSH_7.4",
            "SSH-2.0-OpenSSH_8.0",
            "OpenSSH_7.4p1 Ubuntu-10ubuntu2.10",
        ],
        "openssl_version": "OpenSSL 1.1.1f",
        "openssl_date": "31 Mar 2020",
        "arch_choices": ["linux-x64-lsb"],
    },

    "debian-7": {
        "pretty_name": "Debian 7.11",
        "kernel_ids": [
            "rhel-2.6.32",
            "debian-4.6.0-nix",
        ],
        "ssh_versions": [
            "SSH-2.0-OpenSSH_5.1p1 Debian-5",
            "SSH-1.99-OpenSSH_4.7",
            "SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u1",
        ],
        "openssl_version": "OpenSSL 0.9.8zg",
        "openssl_date": "10 Jun 2015",
        "arch_choices": ["linux-x64-lsb", "linux-x86-lsb"],
    },

    "debian-8": {
        "pretty_name": "Debian 8.11",
        "kernel_ids": [
            "debian-4.6.0-nix",
        ],
        "ssh_versions": [
            "SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u1",
            "SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13",
        ],
        "openssl_version": "OpenSSL 1.0.1t",
        "openssl_date": "03 May 2016",
        "arch_choices": ["linux-x64-lsb"],
    },
}

processors = ['Intel(R) Core(TM) i7-2960XM CPU @ 2.70GHz', 'Intel(R) Core(TM) i5-4590S CPU @ 3.00GHz',
              'Intel(R) Core(TM) i3-4005U CPU @ 1.70GHz']
cpu_flags = ['rdtscp', 'arch_perfmon', 'nopl', 'xtopology', 'nonstop_tsc', 'aperfmperf', 'eagerfpu', 'pclmulqdq',
             'dtes64', 'pdcm', 'pcid',
             'sse4_2', 'x2apic', 'popcnt', 'tsc_deadline_timer', 'xsave', 'avx', 'epb', 'tpr_shadow', 'vnmi',
             'flexpriority', 'vpid', 'xsaveopt', 'dtherm', 'ida', 'arat', 'pln', 'pts']
physical_hd = ['sda', 'sdb', ]
mount_names = ['share', 'db', 'media', 'mount', 'storage']
mount_options = ['noexec', 'nodev', 'nosuid', 'relatime']
mount_additional = [
    'vmware-vmblock /run/vmblock-fuse fuse.vmware-vmblock rw,nosuid,nodev,relatime,user_id=0,group_id=0,default_permissions,allow_other 0 0',
    'gvfsd-fuse /run/user/1001/gvfs fuse.gvfsd-fuse rw,nosuid,nodev,relatime,user_id=1001,group_id=1001 0 0',
    'rpc_pipefs /run/rpc_pipefs rpc_pipefs rw,relatime 0 0']

ps_aux_sys = ['[acpi_thermal_pm]', '[ata_sff]', '[devfreq_wq]', '[ecryptfs-kthrea]', '[ext4-rsv-conver]',
              '[firewire_ohci]', '[fsnotify_mark]', '[hci0]', '[kdevtmpfs]', '[khugepaged]', '[khungtaskd]',
              '[kintegrityd]',
              '[ksoftirqd/0]', '[ksoftirqd/1]', '[ksoftirqd/2]', '[ksoftirqd/3]', '[ksoftirqd/4]', '[kvm-irqfd-clean]',
              '[kworker/0:0]', '[kworker/0:0H]', '[kworker/0:1H]', '[kworker/0:3]', '[kworker/1:0]',
              '[kworker/1:0H]', '[kworker/1:1H]', '[kworker/1:2]', '[kworker/2:0]', '[kworker/2:0H]', '[kworker/2:1]',
              '[migration/0]', '[migration/1]', '[migration/2]', '[migration/3]', '[migration/4]', '[migration/5]',
              '[netns]', '[nfsiod]', '[perf]', '[rcu_bh]', '[rcu_sched]', '[rpciod]', '[scsi_eh_0]', '[scsi_eh_1]',
              '[watchdog/0]', '[watchdog/1]', '[watchdog/2]', '[watchdog/3]', '[watchdog/4]', '[xfsalloc]',
              '[xfs_mru_cache]']
ps_aux_usr = ['/sbin/dhclient', '/sbin/getty', '/usr/lib/gvfs/gvfs-afc-volume-monitor', '/usr/lib/gvfs/gvfsd',
              '/usr/lib/gvfs/gvfsd-burn', '/usr/lib/gvfs/gvfsd-fuse', '/usr/lib/gvfs/gvfsd-http',
              '/usr/lib/gvfs/gvfsd-metadata', '/usr/lib/ibus/ibus-dconf', '/usr/lib/ibus/ibus-engine-simple',
              '/usr/lib/ibus/ibus-ui-gtk3', '/usr/lib/ibus/ibus-x11', '/usr/lib/rtkit/rtkit-daemon',
              '/usr/lib/telepathy/mission-control-5',
              '/usr/lib/xorg/Xorg', '/usr/sbin/cups-browsed', '/usr/sbin/cupsd', '/usr/sbin/dnsmasq',
              '/usr/sbin/irqbalance', '/usr/sbin/kerneloops', '/usr/sbin/ModemManager', '/usr/sbin/pcscd',
              '/usr/sbin/pptpd']


user_count = random.randint(1, 3)
users = []
password = []
service = []
i = 0
while i < user_count:
    rand_user = random.choice(usernames)
    users.append(rand_user)
    usernames.remove(rand_user)
    service.append(random.choice(services))
    passwd = random.choice(passwords)
    password.append(passwd)
    passwords.remove(passwd)
    i = i + 1


## Generate Host Profile ##
ram_size = 512 * random.choice(range(2, 16, 2))
hd_size = 61440 * random.choice(range(2, 16, 2))
processor = random.choice(processors)
ip_ranges = ['10.{0}.{1}.{2}'.format(random.randint(1, 255), random.randint(1, 255), random.randint(1, 255)),
             '172.{0}.{1}.{2}'.format(random.randint(
                 16, 31), random.randint(1, 255), random.randint(1, 255)),
             '192.168.{0}.{1}'.format(random.randint(1, 255), random.randint(1, 255))]
ip_address = random.choice(ip_ranges)
ipv6_number = list(map(int, ip_address.split('.')))


def make_hostname():
    return random.choice(hostnames) + random.choice(hostnames_suffixes)


def make_system_profile():
    hostname = make_hostname()

    # pick OS first
    os_key = random.choice(list(OS_PROFILES.keys()))
    os_profile = OS_PROFILES[os_key]

    # pick kernel compatible with that OS
    kernel_id = random.choice(os_profile["kernel_ids"])
    kernel_info = KERNELS[kernel_id]

    # pick architecture (intersection of OS + kernel choices if you want)
    arch_choices = list(
        set(os_profile["arch_choices"]) & set(kernel_info["arch_choices"])
    ) or os_profile["arch_choices"]
    arch = random.choice(arch_choices)

    # pick ssh version that fits that OS
    ssh_version = random.choice(os_profile["ssh_versions"])

    system_profile = {
        "hostname": hostname,
        "os_pretty_name": os_profile["pretty_name"],
        "os_key": os_key,
        "kernel_id": kernel_id,
        "proc_version": kernel_info["proc_version"],
        "uname": kernel_info["uname_template"].format(hostname=hostname),
        "arch": arch,
        "ssh_version": ssh_version,
        "openssl_version": os_profile["openssl_version"],
        "openssl_date": os_profile["openssl_date"],
    }

    return system_profile


SYSTEM_PROFILE = make_system_profile()


# ====================== getting MAC addresses =========================#

# Getting the list of OUIs and making a MAC Address list
# Prior to changing any values in the Cowrie, the following function below  downloads a sanitized OUI file from the website https://linuxnet.ca
# In the events the oui.txt file from the website is unavailable due (i.e. no internet conneciton) it will return with an exit code 1.
# This skips the generate_mac() and ifconfig_py() functions.
# This function is used if the user wishes to download a new oui.txt.file OR if the oui.txt does not exist in thje directory
def getoui():
    print("Retrieving a sanitized OUI file from \"https://standards-oui.ieee.org/\".")
    print("This may take a minute.")
    url = "https://standards-oui.ieee.org/oui/oui.csv"
    filename = "oui.csv"

    try:
        urllib.request.urlretrieve(url, filename)  # Download the OUI file.
        return 0
    except Exception as e:
        print("Could not retrieve the OUI file. Skipping MAC address changes.")
        print(f"Error: {e}")
        return 1


# The function below ustilizes the getoui() function to download list of valid OUI's.
# If the oui.txt file exists in the directory, it will then prompt the user to parse the file instead download a new one.
def generate_mac():
    filename = "oui.csv"
    mac_addresses = []
    # Check if the oui.csv file exists in the same directory as the script.
    if os.path.isfile(filename):
        parsebool = ""
        print(
            "An oui file has been found. Parse (p) this file or retrieve (r) a new one? p/r")
        while parsebool not in ('p', 'r'):
            parsebool = input("Input (p/r): ").strip().lower()
        if parsebool == 'r':
            if getoui() == 1:
                return 1
    else:
        if getoui() == 1:
            return 1

    print("Generating random MAC addresses.")
    ouiarray = []

    # Open the CSV file for reading.
    with open(filename, 'r', newline='') as ouifile:
        reader = csv.reader(ouifile)
        # Skip header: Registry,Assignment,Organization Name,Organization Address
        header = next(reader, None)

        for row in reader:
            if not row or len(row) < 2:
                continue

            # Assignment column is index 1, e.g. "286FB9"
            assignment = row[1].strip().strip('"')

            # Only accept 6 hex characters like 286FB9
            if len(assignment) != 6:
                continue
            if not all(c in string.hexdigits for c in assignment):
                continue

            # Turn 286FB9 into 28:6F:B9
            assignment = assignment.upper()
            prefix = ":".join(assignment[i:i+2] for i in range(0, 6, 2))

            ouiarray.append(prefix)

    # Build full MAC addresses by adding random last 3 bytes.
    mac_addresses = [
        f"{prefix}:{rand_hex()}:{rand_hex()}:{rand_hex()}"
        for prefix in ouiarray
    ]

    return mac_addresses


# ====================== cowrie.cfg file - MAIN CONFIGURATION =========================#

# The following functions below edits the main configuration of Cowrie under the filename etc/cowrie.cfg
# It checks if a copy of the configuraiton exists and  if not then it creatres a copy ofrom the directory etc/cowrie.cfg.dist.
# The functiones changes the hostnames as well as the fake ip  ip address to another value
def cowrie_cfg(cowrie_install_dir):
    print('Editing main configuration.')
    # Check if the cowrie.cfg file exists, otherwise, copy it from cowrie.cfg.dist.
    if not os.path.isfile("{0}{1}".format(cowrie_install_dir, "/etc/cowrie.cfg")):
        shutil.copyfile("{0}{1}".format(cowrie_install_dir, "/etc/cowrie.cfg.dist"),
                        "{0}{1}".format(cowrie_install_dir, "/etc/cowrie.cfg"))

    with open("{0}{1}".format(cowrie_install_dir, "/etc/cowrie.cfg"), "r+") as cowrie_cfg:
        cowrie_config = cowrie_cfg.read()
        cowrie_cfg.seek(0)
        refunc = "(?<=version ).*?(?= \()"
        proc_version = SYSTEM_PROFILE["proc_version"]
        uname_kernel = re.findall(refunc, proc_version)
        ssh_v_output = f"{SYSTEM_PROFILE['ssh_version']}, {SYSTEM_PROFILE['openssl_version']}  {SYSTEM_PROFILE['openssl_date']}"
        replacements = {
            "hostname = svr04": "hostname = {0}".format(SYSTEM_PROFILE["hostname"]),
            "#fake_addr = 192.168.66.254": "fake_addr = {0}".format(ip_address),
            "version = SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2": "version = {0}".format(SYSTEM_PROFILE["ssh_version"]),
            "#listen_port = 2222": "listen_port = 2222",
            "tcp:2222": "tcp:2222",
            "kernel_version = 3.2.0-4-amd64": "kernel_version = {0}".format(uname_kernel[0]),
            "kernel_build_string = #1 SMP Debian 3.2.68-1+deb7u1": "kernel_build_string = {0}".format(SYSTEM_PROFILE["kernel_build_string"]),
            "ssh_version = OpenSSH_7.9p1, OpenSSL 1.1.1a  20 Nov 2018": f"ssh_version = {ssh_v_output}",
            "macs = hmac-sha2-512,hmac-sha2-384,hmac-sha2-256,hmac-sha1,hmac-md5 ": "macs = hmac-sha2-512,hmac-sha2-384,hmac-sha2-256,umac-64@openssh.com,hmac-sha2-512-etm@openssh.com",
            "compression = zlib@openssh.com,zlib,none ": "compression = zlib@openssh.com,none",
            "ciphers = aes128-ctr,aes192-ctr,aes256-ctr,aes256-cbc,aes192-cbc,aes128-cbc,3des-cbc,cast128-cbc ": "ciphers = aes128-ctr,aes192-ctr,aes256-ctr,chacha20-poly1305@openssh.com,aes256-gcm@openssh.com"
        }
        substrs = sorted(replacements, key=len, reverse=True)
        regexp = re.compile('|'.join(map(re.escape, substrs)))
        config_update = regexp.sub(
            lambda match: replacements[match.group(0)], cowrie_config)
        cowrie_cfg.close()
        with open("{0}{1}".format(cowrie_install_dir, "/etc/cowrie.cfg"), "w+") as cowrie_cfg_update:
            cowrie_cfg_update.write(config_update)
            cowrie_cfg_update.truncate()
            cowrie_cfg_update.close()


# ====================== userdb.txt file - USER DATABASE for SSH ACCESS =========================#

# The following function below replaces the  users associated with direcotry etc/userdb.txt  by replacing the  usernames and passwords from the 'usernames' and 'passwords' array.
def userdb(cowrie_install_dir):
    print('Editing user database, replacing defaults users.')
    if not os.path.isfile("{0}{1}".format(cowrie_install_dir, "/etc/userdb.txt")):
        shutil.copyfile("{0}{1}".format(cowrie_install_dir, "/etc/userdb.example"),
                        "{0}{1}".format(cowrie_install_dir, "/etc/userdb.txt"))
    # Changed reading to just writing, removing all default values
    with open("{0}{1}".format(cowrie_install_dir, "/etc/userdb.txt"), "w") as userdb_file:
        for user in users:
            for p in password:
                userdb_file.write("\n{0}:x:{1}".format(user, p))
        userdb_file.truncate()
        userdb_file.close()


# ====================== userauth.py - COWRIE AUTHENTICATION =========================#

# The following changes below are made to the userauth.py file located in cowrie/ssh/userauth.py
# The changes will introduce randomised accepatble delays to Cowrie's userauth.py sendBanner() function
def add_random_delay_userauth(cowrie_install_dir):
    print("Editing userauth.py file to add randomized banner delay.")

    userauth_path = f"{cowrie_install_dir}/src/cowrie/core/userauth.py"
    backup_path = f"{userauth_path}.backup"

    # Make a backup copy if it doesn't exist
    if not os.path.isfile(backup_path):
        shutil.copyfile(userauth_path, backup_path)
        print("Backup created:", backup_path)

    # Read the original content
    with open(userauth_path, "r") as f:
        data = f.read()

    # ------------------------------------------------------------------
    # 1. Ensure required imports exist: random, reactor
    # ------------------------------------------------------------------
    if "import random" not in data:
        data = data.replace(
            "import struct",
            "import struct\nimport random"
        )

    if "from twisted.internet import reactor" not in data:
        data = data.replace(
            "from twisted.internet import defer",
            "from twisted.internet import defer\nfrom twisted.internet import reactor"
        )

    # ------------------------------------------------------------------
    # 2. Replace the existing sendBanner() with a delayed version
    # ------------------------------------------------------------------
    new_sendbanner = """
    def sendBanner(self):
        \"\"\"
        Modified sendBanner() that introduces a randomized delay using
        Twisted reactor.callLater() before sending the pre-login banner.
        \"\"\"
        if self.bannerSent:
            return
        self.bannerSent = True

        # Random delay (0.2s - 1.4s)
        delay = random.uniform(
            CowrieConfig.getfloat("ssh", "banner_delay_min", fallback=0.15),
            CowrieConfig.getfloat("ssh", "banner_delay_max", fallback=0.700),
        )

        # Schedule actual sending
        reactor.callLater(delay, self._sendBannerNow)
    

    def _sendBannerNow(self):
        \"\"\"
        Actual banner-sending code moved here so sendBanner() can delay it.
        \"\"\"
        if not getattr(self, "transport", None):
            return

        try:
            with open(
                "{}/etc/issue.net".format(
                    CowrieConfig.get("honeypot", "contents_path")
                ),
                encoding="ascii",
            ) as f:
                banner = f.read()
        except configparser.Error as e:
            log.msg(f"Loading default /etc/issue.net file: {e!r}")
            resources_path = importlib.resources.files(data)
            banner_path = resources_path.joinpath("honeyfs", "etc", "issue.net")
            banner = banner_path.read_text(encoding="utf-8")
        except OSError as e:
            log.err(e, "ERROR: Failed to load /etc/issue.net")
            return

        if not banner or not banner.strip():
            return

        try:
            self.transport.sendPacket(
                userauth.MSG_USERAUTH_BANNER,
                NS(banner) + NS(b"en"),
            )
        except Exception as e:
            log.err(e, "ERROR: Failed to send banner packet")
"""

    # Replace old sendBanner (naive but safe string match)
    if "def sendBanner" in data:
        start = data.index("def sendBanner")
        # crude but works: cut until next "def "
        end = data.find("\n    def ", start + 5)
        if end == -1:
            end = len(data)
        data = data[:start] + new_sendbanner + data[end:]

    # ------------------------------------------------------------------
    # 3. Write updated file
    # ------------------------------------------------------------------
    with open(userauth_path, "w") as f:
        f.write(data)

    print("Randomized delay successfully added to userauth.py")


# ====================== honeyfs - COWRIE EMULATED FILESYSTEM =========================#

##################### pre-login banner ##########################
# The following function below replaces the  identified operating system in the directory honeyfs/etc/issue.net file
# from Debian GNU/Linux 7 to any in the 'operatingsystem' array.
def issue(cowrie_install_dir):
    print('Changing issue.')
    with open("{0}{1}".format(cowrie_install_dir, "/honeyfs/etc/issue"), "r+") as issue_file:
        issue = issue_file.read()
        issue_file.seek(0)
        issue_file.write(issue.replace("Debian GNU/Linux 7",
                         SYSTEM_PROFILE["os_pretty_name"]))
        issue_file.truncate()
        issue_file.close()


##################### post-login banner ##########################
# The following function below replaces the  message of the day in the directory honeyfs/etc/motd file
def motd(cowrie_install_dir):
    print("Changing motd.")
    motd_path = f"{cowrie_install_dir}/honeyfs/etc/motd"

    motd_text = f"""
 ________________________________________________________________________
|                                                                        |
| UNAUTHORIZED ACCESS TO THIS SYSTEM IS PROHIBITED.                      |       
| All activities performed on this system are logged and monitored.      |
|________________________________________________________________________|

Welcome to {SYSTEM_PROFILE['hostname']}

Operating system: {SYSTEM_PROFILE['os_pretty_name']}                   
Kernel: {SYSTEM_PROFILE['uname']}
Architecture: {SYSTEM_PROFILE['arch']}

"""

    with open(motd_path, "w") as motd_file:
        motd_file.write(motd_text)


# The function below replaces the  default user phil  with a selection of other usernames randomly chosen in the script.
# It opens the group file in the directory cowrie/honeyfs/etc and replaces the string "phil" with other usernames.
def group(cowrie_install_dir):
    print('Editing group file.')
    y = 0
    num = 1001
    # Open the group file.
    with open("{0}{1}".format(cowrie_install_dir, "/honeyfs/etc/group"), "r+") as group_file:
        group = group_file.read()
        group_file.seek(0)
        group_update = ""
        while y < len(users):  # Using iteration to add users.
            if y == 0:
                new_user = "{0}:x:{1}:{2}:{3},,,:/home/{4}:/bin/bash".format(users[y], str(num), str(num), users[y],
                                                                             users[y])
                # Replace these strings with usernames.
                replacements = {"phil": users[y], "sudo:x:27:": "{0}{1}".format(
                    "sudo:x:27:", users[y])}
                substrs = sorted(replacements, key=len, reverse=True)
                regexp = re.compile('|'.join(map(re.escape, substrs)))
                group_update = regexp.sub(
                    lambda match: replacements[match.group(0)], group)
            elif y == 1:
                group_update += "{0}:x:{1}:".format(users[y], str(num))
                num = num + 1
            elif y > 1:
                group_update += "\n{0}:x:{1}:".format(users[y], str(num))
                num = num + 1
            y = y + 1
        group_file.write(group_update)
        group_file.truncate()
        group_file.close()


# The following function below makes changes to the passwd file in the directory cowrie/honeyfs/etc by replacing the user phil with a selection of random usernames
def passwd(cowrie_install_dir):
    print('Changing passwd file.')
    y = 1
    num = 1000
    # Open the passwd file.
    with open("{0}{1}".format(cowrie_install_dir, "/honeyfs/etc/passwd"), "r+") as passwd_file:
        passwd = passwd_file.read()
        passwd_file.seek(0)
        passwd_update = ""
        while y <= len(users):  # Using iteration to add users.
            if y == 1:
                new_user = "{0}:x:{1}:{2}:{3},,,:/home/{4}:/bin/bash".format(users[y-1], str(num), str(num), users[y-1],
                                                                             users[y-1])
                # replace the string with a new user.
                replacements = {
                    "phil:x:1000:1000:Phil California,,,:/home/phil:/bin/bash": new_user}
                substrs = sorted(replacements, key=len, reverse=True)
                regexp = re.compile('|'.join(map(re.escape, substrs)))
                passwd_update = regexp.sub(
                    lambda match: replacements[match.group(0)], passwd)
            elif y > 1:
                passwd_update += "{0}:x:{1}:{2}:{3},,,:/home/{4}:/bin/bash\n".format(
                    users[y-1], str(num), str(num), users[y-1], users[y-1])
            y = y + 1
            num = num + 1
        passwd_file.write(passwd_update)
        passwd_file.truncate()
        passwd_file.close()


# The following function below edits the shadow file in the directory cowrie/honeyfs/etc which removes the phil user in addition to adding new users with salted hash passwords
def shadow(cowrie_install_dir):
    print('Changing shadow file.')
    x = 1
    shadow_update = ""
    # Open the shadow file.
    with open("{0}{1}".format(cowrie_install_dir, "/honeyfs/etc/shadow"), "r+") as shadow_file:
        shadow = shadow_file.read()
        shadow_file.seek(0)
        shadow_update = ""
        days_since = random.randint(16000, 17200)
        # Using a salt to hash the passwords.
        salt = ''.join(random.choice(string.ascii_lowercase +
                       string.digits) for _ in range(8))
        while x <= len(users):  # Using iteration to add users.
            if x == 1:
                gen_pass = crypt.crypt(password[x-1], "$6$" + salt)
                salt = ''.join(random.choice(
                    string.ascii_lowercase + string.digits) for _ in range(8))
                new_user = "{0}:{1}:{2}:0:99999:7:::".format(
                    users[x-1], gen_pass, random.randint(16000, 17200))
                new_root_pass = crypt.crypt("password", "$6$" + salt)
                # Replace certain strings with new users.
                replacements = {"15800": str(days_since),
                                "phil:$6$ErqInBoz$FibX212AFnHMvyZdWW87bq5Cm3214CoffqFuUyzz.ZKmZ725zKqSPRRlQ1fGGP02V/WawQWQrDda6YiKERNR61:15800:0:99999:7:::\n": new_user,
                                "$6$4aOmWdpJ$/kyPOik9rR0kSLyABIYNXgg/UqlWX3c1eIaovOLWphShTGXmuUAMq6iu9DrcQqlVUw3Pirizns4u27w3Ugvb6": new_root_pass}
                substrs = sorted(replacements, key=len, reverse=True)
                regexp = re.compile('|'.join(map(re.escape, substrs)))
                shadow_update = regexp.sub(
                    lambda match: replacements[match.group(0)], shadow)
            elif x > 1:
                gen_pass = crypt.crypt(password[x-1], "$6$" + salt)
                shadow_update += "\n{0}:{1}:{2}:0:99999:7:::".format(
                    users[x-1], gen_pass, random.randint(16000, 17200))
            x = x + 1
        shadow_file.write(shadow_update)
        shadow_file.truncate()
        shadow_file.close()


# The following function below creates the directories of the user defined above in the directory cowrie/honeyfs/home
# After creating them we add belieavle files to each home directory like .bashrc, .profile and .ssh/authorized_keys
def home_dirs(cowrie_install_dir):
    print('Creating home directories.')
    for user in users:
        user_home_dir = "{0}{1}{2}{3}".format(
            cowrie_install_dir, "/honeyfs/home/", user, "/")
        if not os.path.exists(user_home_dir):
            os.makedirs(user_home_dir)
        # set up directory structure and files in home dir
        setup_ubuntu_home(user_home_dir)


# The follwing function below creates in the directory /honeyfs/etc the os-relase file if it does not already exist.
# The os-release file contains information about the operating system being simulated by the honeypot
def os_release(cowrie_install_dir):
    print('Creating os-release file.')
    path = f"{cowrie_install_dir}/honeyfs/etc/os-release"

    if os.path.isfile(path):
        return  # already exists, do nothing

    # e.g. "Ubuntu 18.04 LTS"
    os_pretty = SYSTEM_PROFILE["os_pretty_name"]
    os_key = SYSTEM_PROFILE["os_key"]                 # e.g. "ubuntu-1804"

    # -----------------------------
    #  Build correct os-release
    # -----------------------------
    if os_key.startswith("ubuntu"):
        # Extract version ID ("18.04") from the pretty name
        version_id = os_pretty.split()[1]   # e.g. "18.04"

        os_release_contents = f'''
NAME="Ubuntu"
VERSION="{os_pretty}"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="{os_pretty}"
VERSION_ID="{version_id}"
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
'''

    elif os_key.startswith("debian"):
        # Extract version ID ("7.11", "8.11")
        version_id = os_pretty.split()[1]   # e.g. "8.11"

        os_release_contents = f'''
NAME="Debian GNU/Linux"
VERSION="{os_pretty}"
ID=debian
ID_LIKE=debian
PRETTY_NAME="{os_pretty}"
VERSION_ID="{version_id}"
HOME_URL="https://www.debian.org/"
SUPPORT_URL="https://www.debian.org/support"
BUG_REPORT_URL="https://bugs.debian.org/"
'''

    else:
        # fallback if new OS types ever get added
        os_release_contents = f'''
NAME="{os_pretty}"
PRETTY_NAME="{os_pretty}"
VERSION="{os_pretty}"
'''

    # -----------------------------
    #   Write the file
    # -----------------------------
    with open(path, "w") as os_release_file:
        os_release_file.write(os_release_contents.strip() + "\n")


# The following function below replaces the  default hostname in the directory honeyfs/etc/hosts from "nas3" to any of the hostnames in the 'hostnames' array
def hosts(cowrie_install_dir):
    print('Replacing Hosts.')
    with open("{0}{1}".format(cowrie_install_dir, "/honeyfs/etc/hosts"), "r+") as host_file:
        hosts = host_file.read()
        host_file.seek(0)
        host_file.write(hosts.replace("nas3", SYSTEM_PROFILE["hostname"]))
        host_file.truncate()
        host_file.close()


# The function below makes changes to the  directory honeyfs/etc/hostname in which it replaces"svr04" to  any of the hostsnames in the  'hostnames' array
def hostname_py(cowrie_install_dir):
    print('Changing hostname.')
    with open("{0}{1}".format(cowrie_install_dir, "/honeyfs/etc/hostname"), "r+") as hostname_file:
        hostname_contents = hostname_file.read()
        hostname_file.seek(0)
        hostname_file.write(hostname_contents.replace(
            "svr04", SYSTEM_PROFILE["hostname"]))
        hostname_file.truncate()
        hostname_file.close()


# The following function below empties the inittab file located in the directory honeyfs/etc/inittab
def inittab(cowrie_install_dir):
    print('Emptying inittab.')
    inittab_path = f"{cowrie_install_dir}/honeyfs/etc/inittab"

    with open(inittab_path, "r+") as inittab_file:
        inittab_file.seek(0)
        inittab_file.truncate()   # clear file contents
        inittab_file.close()


# The following function below adds the nameserver to the resolv.conf file located in the directory honeyfs/etc/resolv.conf
def set_resolv_conf_nameserver(cowrie_install_dir):
    print('Updating resolv.conf.')
    resolv_path = f"{cowrie_install_dir}/honeyfs/etc/resolv.conf"

    with open(resolv_path, "r+") as resolv_file:
        contents = resolv_file.read()
        resolv_file.seek(0)

        # Only add if not already present
        if "nameserver 1.1.1.1" not in contents:
            if contents.endswith("\n"):
                contents += "nameserver 1.1.1.1\n"
            else:
                contents += "\nnameserver 1.1.1.1\n"

        resolv_file.write(contents)
        resolv_file.truncate()
        resolv_file.close()


# The following function below  checks whether or not  the fs.pickle file exist in the directory honeyfs/home.
# If the  file does not exist then the function below creates the "home" directory inside the honeyfs and using the command 'bin/createfs -l../honeyfs -o fs.piickle' to create the pickle file.
def fs_pickle(cowrie_install_dir):
    print('Creating filesystem.')
    try:
        os.mkdir("{0}{1}".format(cowrie_install_dir, "/honeyfs/home"))
    except FileExistsError:
        pass
    try:
        os.remove("{0}{1}".format(
            cowrie_install_dir, "/share/cowrie/fs.pickle"))
    except FileNotFoundError:
        pass
    os.system(
        "{0}/bin/createfs -l {0}/honeyfs -o {0}/share/cowrie/fs.pickle".format(cowrie_install_dir))


# The following function below creates believable files in the home directory of the ubuntu user inside the honeyfs/home/ubuntu directory.
# It creates the .bash_history, .profile and .ssh/authorized_keys files with believable content.
def setup_ubuntu_home(honeyfs_path="honeyfs/home/ubuntu"):
    # Ensure directory structure exists
    ssh_dir = os.path.join(honeyfs_path, ".ssh")
    os.makedirs(ssh_dir, exist_ok=True)

    # File paths
    bash_history_path = os.path.join(honeyfs_path, ".bash_history")
    authorized_keys_path = os.path.join(ssh_dir, "authorized_keys")
    profile_path = os.path.join(honeyfs_path, ".profile")

    # Contents
    bash_history_content = """sudo apt update
sudo apt upgrade -y
cd /var/log
ls -la
cat auth.log
ssh-keygen -t ed25519
sudo systemctl status ssh
nano /etc/ssh/sshd_config
htop
ps aux | grep python
journalctl -xe
sudo reboot
"""

    authorized_keys_content = """ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIC8UjdbiuWeEyPu5xwVuYorI0bmHfH1s7+3NQ0o2hkZL ubuntu@workstation
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC0K9adk7HYa8CvnfC/4VZkSN3WISjQqq2ySg9d+pbGfgH3Fbi8B0bn5NyxYQ9X6NxZGmbb70D5dS8YdwCXWFAw2rKMnWKXPc0i/SV6JiSJOHCOeG6heXpdMd0RySOyVJ964tXRBJSO7eayv1brUYS+vQH73SzvYFx8S9txPhKcM0BjwQNL63/Hz0MLTIvJqV0TeqcF1ByG30oovYRhgvUOAJN9DUhUQ1Tq2Pp0e2XK3DPHfiWE6VJwAEb3P63Uz9xaGVZm0ZW+BDwFh1nYz6Rs8QW4k9LGipSbrIbZdh+uTgowj8kTBySByUrQk88UJq6vjJhesC9dE4vR example@laptop
"""

    profile_content = """# ~/.profile: executed by the command interpreter for login shells.

if [ -n "$BASH_VERSION" ]; then
    # include .bashrc if it exists
    if [ -f "$HOME/.bashrc" ]; then
        . "$HOME/.bashrc"
    fi
fi

# set PATH so it includes user's private bin if it exists
if [ -d "$HOME/bin" ] ; then
    PATH="$HOME/bin:$PATH"
fi

# set PATH for local scripts
if [ -d "$HOME/scripts" ] ; then
    PATH="$HOME/scripts:$PATH"
fi
"""

    # Write files
    with open(bash_history_path, "w") as f:
        f.write(bash_history_content)

    with open(authorized_keys_path, "w") as f:
        f.write(authorized_keys_content)

    with open(profile_path, "w") as f:
        f.write(profile_content)

    print(f"Created ubuntu fake home directory at {honeyfs_path}")


# ====================== commands/xxx.py - COWRIE COMMANDS =========================#

# Within the Cowrie source code, the base_py() function changes a command in the cowrie/src/commands/base/py script.
# It contains many commands, particularly the 'ps' comand, which is emulated in the honeypot
# This function is now obsolete however as further review has shown the default base.py script in Cowrie is already obscured enough.
def base_py(cowrie_install_dir):
    print('Editing base.py')
    with open("{0}{1}".format(cowrie_install_dir, "/src/cowrie/commands/base.py"), "r+") as base_file:
        user = random.choice(users)
        base = base_file.read()
        base_file.seek(0)
        to_replace = re.findall(
            '(?<=output = \(\n)(.*)(?=for i in range)', base, re.DOTALL)
        new_base = "            ('USER      ', ' PID', ' %CPU', ' %MEM', '    VSZ', '   RSS', ' TTY      ', 'STAT ', 'START', '   TIME ', 'COMMAND',),\n"
        new_base += "            ('{0:<10}', '{1:>4}', '{2:>5}', '{3:>5}', '{4:>7}', '{5:>6}', '{6:<10}', '{7:<5}', '{8:>5}', '{9:>8}', '{10}',),\n".format(
            'root', '1', '0.0', '0.0', randint(10000, 25000), randint(
                500, 2500), '?', 'Ss', time.strftime('%b%d'),
            '0:00', '/sbin/init')
        new_base += "            ('{0:<10}', '{1:>4}', '{2:>5}', '{3:>5}', '{4:>7}', '{5:>6}', '{6:<10}', '{7:<5}', '{8:>5}', '{9:>8}', '{10}',),\n".format(
            'root', '2', '0.0', '0.0', '0', '0', '?', 'S', time.strftime('%b%d'), '0:00', '[kthreadd]')
        r = randint(15, 30)
        sys_pid = 3
        while r > 0:
            sys_pid = sys_pid + randint(1, 3)
            new_base += "            ('{0:<10}', '{1:>4}', '{2:>5}', '{3:>5}', '{4:>7}', '{5:>6}', '{6:<10}', '{7:<5}', '{8:>5}', '{9:>8}', '{10}',),\n".format(
                'root', sys_pid, '0.0', '0.0', '0', '0', '?', random.choice(
                    ['S', 'S<']), time.strftime('%b%d'), '0:00',
                random.choice(ps_aux_sys))
            r -= 1
        t = randint(4, 10)
        usr_pid = 1000
        while t > 0:
            usr_pid = usr_pid + randint(20, 70)
            minute = time.strftime('%m')
            hour = time.strftime('%')
            new_base += "            ('{0:<10}', '{1:>4}', '{2:>5}', '{3:>5}', '{4:>7}', '{5:>6}', '{6:<10}', '{7:<5}', '{8:>5}', '{9:>8}', '{10}',),\n".format(
                random.choice(['root', user]), usr_pid, '{0}.{1}'.format(
                    randint(0, 4), randint(0, 9)),
                '{0}.{1}'.format(randint(0, 4), randint(0, 9)), randint(
                    10000, 25000), randint(500, 2500),
                '?', random.choice(['S', 'S<', 'S+', 'Sl']), time.strftime('%H:%m'), '0:00', random.choice(ps_aux_usr))
            t -= 1
        new_base += "            ('{0:<10}', '{1:>4}', '{2:>5}', '{3:>5}', '{4:>7}', '{5:>6}', '{6:<10}', '{7:<5}', '{8:>5}', '{9:>8}', '{10},),\n".format(
            'root', usr_pid +
            randint(20, 100), '0.{0}'.format(
                randint(0, 9)), '0.{0}'.format(randint(0, 9)),
            randint(1000, 6000), randint(
                500, 2500), '?', random.choice(['S', 'S<', 'S+', 'Sl']),
            time.strftime('%H:%m'), '0:{0}{1}'.format(0, randint(0, 3)), '/usr/sbin/sshd: %s@pts/0\' % user')
        new_base += "            ({0:<10}, '{1:>4}', '{2:>5}', '{3:>5}', '{4:>7}', '{5:>6}', '{6:<10}', '{7:<5}', '{8:>5}', '{9:>8}', '{10}',),\n".format(
            '\'%s\'.ljust(8) % user', usr_pid + randint(20,
                                                        100), '0.{0}'.format(randint(0, 9)),
            '0.{0}'.format(randint(0, 9)), randint(1000, 6000), randint(
                    500, 2500), 'pts/{0}'.format(randint(0, 5)),
            random.choice(['S', 'S<', 'S+', 'Sl']), time.strftime('%H:%m'),
            '0:{0}{1}'.format(0, randint(0, 3)), '-bash')
        new_base += "            ({0:<10}, '{1:>4}', '{2:>5}', '{3:>5}', '{4:>7}', '{5:>6}', '{6:<10}', '{7:<5}', '{8:>5}', '{9:>8}', {10},),\n".format(
            '\'%s\'.ljust(8) % user', usr_pid + randint(20,
                                                        100), '0.{0}'.format(randint(0, 9)),
            '0.{0}'.format(randint(0, 9)), randint(1000, 6000), randint(
                    500, 2500), 'pts/{0}'.format(randint(0, 5)),
            random.choice(['S', 'S<', 'S+', 'Sl']),
            time.strftime('%H:%m'), '0:{0}{1}'.format(0, randint(0, 3)), '\'ps %s\' % \' \'.join(self.args)')
        new_base += "            )\n        "
        base_replacements = {to_replace[0]: new_base}
        substrs = sorted(base_replacements, key=len, reverse=True)
        regexp = re.compile('|'.join(map(re.escape, substrs)))
        base_update = regexp.sub(
            lambda match: base_replacements[match.group(0)], base)
        base_file.write(base_update)
        base_file.truncate()
        base_file.close()


# The following function below edits the free.py script in the directory cowrie/src/commands within the Cowrie source code.
# By default, Cowrie  grabs the memory information from the meminfo file located inside the proc directory of the honeyfs
# The function below shows the memory info rmation about the honeypot based on the meminfo_py() function
def free_py(cowrie_install_dir):
    print('Editing free.py')
    with open("{0}{1}".format(cowrie_install_dir, "/src/cowrie/commands/free.py"), "r+") as free_file:
        free = free_file.read()
        free_file.seek(0)
        total = int(ram_size - ((3 * ram_size) / 100.0))
        used_ram = int((randint(50, 75) * ram_size) / 100.0)
        free_ram = total - used_ram
        shared_ram = ram_size / 48
        buffers = ram_size / 36
        cached = used_ram - shared_ram - buffers
        buffers_cachev1 = used_ram - (buffers + cached)
        buffers_cachev2 = used_ram + (buffers + cached)
        free_replacements = {
            "Mem:          7880       7690        189          0        400       5171": "Mem:          {0}       {1}        {2}          {3}        {4}       {5}".format(
                total, used_ram, free_ram, shared_ram, buffers, cached),
            "-/+ buffers/cache:       2118       5761": "-/+ buffers/cache:       {0}       {1}".format(buffers_cachev1,
                                                                                                        buffers_cachev2),
            "Swap:         3675        129       3546": "Swap:         0        0       0",
            "Mem:       8069256    7872920     196336          0     410340    5295748": "Mem:       {0}    {1}     {2}          {3}     {4}    {5}".format(
                total * 1000, used_ram * 1000, free_ram * 1000, shared_ram * 1000, buffers * 1000, cached * 1000),
            "-/+ buffers/cache:    2166832    5902424": "-/+ buffers/cache:    {0}    {1}".format(
                buffers_cachev1 * 1000, buffers_cachev2 * 1000),
            "Swap:      3764220     133080    3631140": "Swap:      0     0    0".format(),
            "Mem:          7.7G       7.5G       189M         0B       400M       5.1G": "Mem:          {0}G       {1}G       {2}M         {3}B       {4}M       {5}G".format(
                total / 1000, round(used_ram / 1000.0, 1), free_ram / 1000, shared_ram, buffers, cached / 1000),
            "-/+ buffers/cache:       2.1G       5.6G": "-/+ buffers/cache:       {0}M       {1}G".format(
                round(buffers_cachev1 / 1000.0, 1), round(buffers_cachev2 / 1000.0, 1)),
            "Swap:         3.6G       129M       3.5G": "Swap:         0B       0B       0B"}
        substrs = sorted(free_replacements, key=len, reverse=True)
        regexp = re.compile('|'.join(map(re.escape, substrs)))
        free_update = regexp.sub(
            lambda match: free_replacements[match.group(0)], free)
        free_file.write(free_update)
        free_file.truncate()
        free_file.close()


# The following  function makes changes to the ifconfig.py file in the directory cowrie/src/commands within the Cowrie source code.
# In particular, it changes the  the MAC address in the directory cowrie/honeyfs/proc/net/arp which is related to the  generate_mac() and getoui() functions.
# It picks from an array of MAC addresses and writes it to  the ifconfig command and arp file
# By default, Cowrie assigns a fake MAC address by using using the randint (0,255) several times.
# # This was replaced with a string containing a legitimate MAC from the generate_mac() function.
def ifconfig_py(cowrie_install_dir):
    print("Editing ifconfig and arp file.")
    mac_addresses = generate_mac()
    # If the generate_mac() function couldn't generate MAC addresses, skip this function.
    if mac_addresses == 1:
        return
    macaddress = random.choice(mac_addresses)
    mac_addresses.remove(macaddress)
    macaddress2 = random.choice(mac_addresses)
    with open("{0}{1}".format(cowrie_install_dir, "/src/cowrie/commands/ifconfig.py"), "r+") as ifconfig_file:  # Open the ifconfig.py file
        ifconfig = ifconfig_file.read()
        ifconfig_file.seek(0)
        hwaddrstring = "HWaddr = \"{0}\"".format(macaddress)
        # Generate random number of bytes recieved
        eth_rx = randint(10000000000, 500000000000)
        # Generate random number of bytes transmitted
        eth_tx = randint(10000000000, 500000000000)
        lo_rxtx = randint(10000, 99999)  # Generate random number of bytes
        ifconfig_replacements = {"""HWaddr = \"%02x:%02x:%02x:%02x:%02x:%02x\" % (
    randint(0, 255), randint(0, 255), randint(0, 255), randint(0, 255), randint(0, 255), randint(0, 255))""": '{0}'.format(hwaddrstring),
                                 "self.protocol.kippoIP": '\"{0}\"'.format(ip_address)}  # Replace string with these values.
        substrs = sorted(ifconfig_replacements, key=len, reverse=True)
        regexp = re.compile('|'.join(map(re.escape, substrs)))
        ifconfig_update = regexp.sub(
            lambda match: ifconfig_replacements[match.group(0)], ifconfig)
        ifconfig_file.write(ifconfig_update)
        ifconfig_file.truncate()
        ifconfig_file.close()
    print("Editing arp file.")
    # Open the arp file.
    with open("{0}{1}".format(cowrie_install_dir, "/honeyfs/proc/net/arp"), "r+") as arp_file:
        arp = arp_file.read()
        arp_file.seek(0)
        base_ip = '.'.join(ip_address.split('.')[0:3])
        arp_replacements = {'192.168.1.27': '{0}.{1}'.format(base_ip, random.randint(1, 255)),
                            '192.168.1.1': '{0}.{1}'.format(base_ip, '1'),
                            '52:5e:0a:40:43:c8': '{0}'.format(macaddress),
                            # Replace strings with these values.
                            '00:00:5f:00:0b:12': '{0}'.format(macaddress2)}
        substrs = sorted(arp_replacements, key=len, reverse=True)
        regexp = re.compile('|'.join(map(re.escape, substrs)))
        arp_update = regexp.sub(
            lambda match: arp_replacements[match.group(0)], arp)
        arp_file.write(arp_update.strip("\n"))
        arp_file.truncate()
        arp_file.close()


# The following function below replaces the version file in the directory cowrie/honeyfs/proc with a randomised uname and version information.
def version_uname(cowrie_install_dir):
    print('Changing uname and version.')
    # Open the version file.
    with open("{0}{1}".format(cowrie_install_dir, "/honeyfs/proc/version"), "w") as version_file:
        version_file.write(SYSTEM_PROFILE["proc_version"])
        version_file.close()


# The following fuction replaces the meminfo file in  the directory cowrie/honeyfs/proc with randomised information about the memory of the simulated system.
# Similar to the format of the default file, a large string is  generated with randomised values.
# Most of these values use the same variable adnd have been divided  by certain integers as most of these values are proportional to each other
def meminfo_py(cowrie_install_dir):
    print('replacing meminfo_py values.')
    kb_ram = ram_size * 1000
    meminfo = \
        'MemTotal:        {0} kB\nMemFree:         {1} kB\nMemAvailable:    {2} kB\nCached:          {3} kB\nSwapCached:            0 kB\n' \
        'Active:          {4} kB\nInactive:        {5} kB\nActive(anon):     {6} kB\nInactive(anon):   {7} kB\nActive(file):    {8} kB\n' \
        'Inactive(file):  {9} kB\nUnevictable:          64 kB\nMlocked:              64 kB\nSwapTotal:             0 kB\nSwapFree:              0 kB\n' \
        'Dirty:              {10} kB\nWriteback:             0 kB\nAnonPages:        {11} kB\nMapped:            {12} kB\nShmem:             {13} kB\n' \
        'Slab:              {14} kB\nSReclaimable:      {15} kB\nSUnreclaim:        {16} kB\nKernelStack:       {17} kB\nPageTables:        {18} kB\n' \
        'NFS_Unstable:          0 kB\nBounce:                0 kB\nWritebackTmp:          0 kB\nCommitLimit:     {19} kB\nCommitted_AS:    {20} kB\n' \
        'VmallocTotal:   {21} kB\nVmallocUsed:           0 kB\nVmallocChunk:          0 kB\nHardwareCorrupted:     0 kB\nAnonHugePages:    {22} kB\n' \
        'HugePages_Total:       0\nHugePages_Free:        0\nHugePages_Rsvd:        0\nHugePages_Surp:        0\nHugepagesize:       2048 kB\n' \
        'DirectMap4k:      {23} kB\nDirectMap2M:      {24} kB'.format(kb_ram, '{0}'.format(kb_ram / 2), '{0}'.format(
            kb_ram - random.randint(100000, 400000)),
            '{0}'.format(
            kb_ram - random.randint(100000, 200000)),
            '{0}'.format(
            kb_ram / 2),
            '{0}'.format(
            kb_ram / 3),
            '{0}'.format(
            kb_ram / 24),
            '{0}'.format(
            kb_ram / 48),
            '{0}'.format(
            int(kb_ram / 2.75)),
            '{0}'.format(
            int(kb_ram / 3.1)),
            '{0}'.format(
            random.randint(1000, 4000)),
            '{0}'.format(
            int(kb_ram / 10.45)),
            '{0}'.format(
            int(kb_ram / 133)),
            '{0}'.format(
            int(kb_ram / 180)),
            '{0}'.format(
            int(kb_ram / 90)),
            '{0}'.format(
            int(kb_ram / 75)),
            '{0}'.format(
            int(kb_ram / 170)),
            '{0}'.format(
            int(kb_ram / 210)),
            '{0}'.format(
            int(kb_ram / 172)),
            '{0}'.format(
            int(kb_ram / 1.8)),
            '{0}'.format(
            int(kb_ram / 2.5)),
            '{0}'.format(
            int(kb_ram * 10.3)),
            '{0}'.format(
            int(kb_ram / 17)),
            '{0}'.format(
            int(kb_ram / 25)),
            '{0}'.format(int(kb_ram / 20)))
    # Open the meminfo file and write the memory information to it.
    with open("{0}{1}".format(cowrie_install_dir, "/honeyfs/proc/meminfo"), "w") as new_meminfo:
        new_meminfo.write(meminfo)
        new_meminfo.close()


# The function below replaces  information about mounted drives and disks  in the directory cowrie/honeyfs/proc/mounts.
# The mounts file contains a random number of storage drives with random names and random disks sizes assigned.
def mounts(cowrie_install_dir):
    print('Changing mounts.')
    # Open the mounts file.
    with open("{0}{1}".format(cowrie_install_dir, "/honeyfs/proc/mounts"), "r+") as mounts_file:
        mounts = mounts_file.read()
        mounts_file.seek(0)
        # Search for these strings to be replaced.
        mounts_replacements = {'rootfs / rootfs rw 0 0': '', '10240': '{0}'.format(random.randint(10000, 25000)),
                               '/dev/dm-0 / ext3': '/dev/{0}1 / ext4'.format(random.choice(physical_hd)),
                                                   '/dev/sda1 /boot ext2 rw,relatime 0 0': '/dev/{0}2 /{1} ext4 rw,nosuid,relatime 0 0'.format(
            random.choice(physical_hd), random.choice(mount_names)),
            'mapper': '{0}'.format(random.choice(usernames))}
        substrs = sorted(mounts_replacements, key=len, reverse=True)
        regexp = re.compile('|'.join(map(re.escape, substrs)))
        mounts_update = regexp.sub(
            lambda match: mounts_replacements[match.group(0)], mounts)
        mounts_update += random.choice(mount_additional)
        mounts_file.write(mounts_update.strip("\n"))
        mounts_file.truncate()
        mounts_file.close()


# The following function replaces the certain values of the cpuinfo file in the  directory cowre/honeyfs/proc.
# Values such as model name , vendor, speed and cache size are changed.
def cpuinfo(cowrie_install_dir):
    print('Replacing CPU Info.')
    with open("{0}{1}".format(cowrie_install_dir, "/honeyfs/proc/cpuinfo"), "r+") as cpuinfo_file:
        cpuinfo = cpuinfo_file.read()
        cpuinfo_file.seek(0)
        cpu_mhz = "{0}{1}".format(processor.split(
            "@ ")[1][:-3].replace(".", ""), "0.00")
        no_processors = processor.split("TM) i")[1].split("-")[0]
        cpu_replacements = {"Intel(R) Core(TM)2 Duo CPU     E8200  @ 2.66GHz": processor,
                            ": 23": ": {0}".format(random.randint(60, 69)), ": 2133.304": ": {0}".format(cpu_mhz),
                            ": 10": ": {0}".format(random.randint(10, 25)),
                            ": 4270.03": ": {0}".format(random.randint(4000.00, 7000.00)),
                            ": 6144 KB": ": {0} KB".format(1024 * random.choice(range(2, 16, 2))),
                            "lahf_lm": " ".join(random.sample(cpu_flags, random.randint(6, 14))),
                            "siblings	: 2": "{0}{1}".format("siblings	: ", no_processors)}
        substrs = sorted(cpu_replacements, key=len, reverse=True)
        regexp = re.compile('|'.join(map(re.escape, substrs)))
        cpuinfo_update = regexp.sub(
            lambda match: cpu_replacements[match.group(0)], cpuinfo)
        cpuinfo_file.write(cpuinfo_update)
        cpuinfo_file.truncate()
        cpuinfo_file.close()


# ====================== ssh/transport.py - COWRIE TWISTED OVERWRITE =========================#

#  The following function below  patches the transport.py file located in the cowrie/src/cowrie/ssh directory.
#  Modifies cowrie/src/cowrie/ssh/transport.py by inserting a supportedKeyExchanges array right after the class definition line.
def patch_transport_kex(cowrie_install_dir):
    print("Patching transport.py to add supportedKeyExchanges...")

    transport_path = os.path.join(
        cowrie_install_dir, "src/cowrie/ssh/transport.py"
    )

    if not os.path.exists(transport_path):
        print(f"ERROR: transport.py not found at: {transport_path}")
        return

    # The block we want to insert
    kex_block = (
        "    supportedKeyExchanges = [\n"
        "        b\"curve25519-sha256\",\n"
        "        b\"curve25519-sha256@libssh.org\",\n"
        "        b\"ecdh-sha2-nistp256\",\n"
        "        b\"ecdh-sha2-nistp384\",\n"
        "        b\"ecdh-sha2-nistp521\",\n"
        "        b\"diffie-hellman-group-exchange-sha256\",\n"
        "        b\"diffie-hellman-group16-sha512\",\n"
        "        b\"diffie-hellman-group18-sha512\",\n"
        "        b\"diffie-hellman-group14-sha256\",\n"
        "        b\"diffie-hellman-group14-sha1\",\n"
        "    ]\n\n"
    )

    with open(transport_path, "r+", encoding="utf-8") as f:
        original = f.read()

        # Check if it's already patched
        if "supportedKeyExchanges = [" in original:
            print("supportedKeyExchanges already present. Skipping patch.")
            return

        # Find class definition line
        class_def = "class HoneyPotSSHTransport(transport.SSHServerTransport, TimeoutMixin):"

        if class_def not in original:
            print("ERROR: Could not find class definition!")
            return

        # Create modified content
        modified = original.replace(
            class_def,
            class_def + "\n" + kex_block.rstrip("\n")
        )

        # Rewrite file
        f.seek(0)
        f.write(modified)
        f.truncate()

    print("Patch applied successfully.")


# ===============================================================#
# ====================== ALL THE THINGS =========================#
# ===============================================================#

# The following function below  executes the installations one at a time
# In the events of an error, it will prompt a message to check the file path and try again

def allthethings(cowrie_install_dir):
    try:
        # base_py(cowrie_install_dir)
        # free_py(cowrie_install_dir)
        ifconfig_py(cowrie_install_dir)
        version_uname(cowrie_install_dir)
        meminfo_py(cowrie_install_dir)
        mounts(cowrie_install_dir)
        cpuinfo(cowrie_install_dir)
        group(cowrie_install_dir)
        passwd(cowrie_install_dir)
        shadow(cowrie_install_dir)
        cowrie_cfg(cowrie_install_dir)
        hosts(cowrie_install_dir)
        hostname_py(cowrie_install_dir)
        issue(cowrie_install_dir)
        userdb(cowrie_install_dir)
        fs_pickle(cowrie_install_dir)
    except:
        e = sys.exc_info()[1]
        print("\nError: {0}\nCheck file path and try again.".format(e))
        pass


header = """\
            _
           | |
        __ | |__  ___  ___ _   _ _ __ ___ _ __
      / _ \| '_ \/ __|/ __| | | | '__/ _ \ '__|
     | (_) | |_) \__ \ (__| |_| | | |  __/ |
      \___/|_.__/|___/\___|\__,_|_|  \___|_|
      
      https://github.com/marcosantiagomuro/obscurer

              Cowrie Honeypot Obscurer
                   Version {1}

  Forked from https://github.com/boscutti939/obscurer

""".format(SCRIPT_VERSION)

output = """\

Cowrie Configuration Updated
----------------------------

Accepted Username(s): {0}
Accepted Password(s): {1}

Hostname: {2}
Operating System: {3}
SSH Version: {4}
SSH Listen Port: {5}
Internal IP: {6}

""".format(users, password, SYSTEM_PROFILE["hostname"], SYSTEM_PROFILE["os_pretty_name"], SYSTEM_PROFILE["ssh_version"], "2222", ip_address)

if __name__ == "__main__":
    parser = OptionParser(
        usage='usage: python3 %prog cowrie/install/dir [options]')
    parser.add_option("-a", "--allthethings", action='store_true',
                      default='False', help="Change all the things")
    (options, args) = parser.parse_args()

    if len(args) < 1:
        print(header)
        print("[!] Not enough Arguments, Need at least file path")
        parser.print_help()
        sys.exit()

    elif options.allthethings is True:
        filepath = args[0]
        if filepath[-1] == "/":
            filepath.rstrip('/')
        if os.path.isdir(filepath):
            print(header)
            allthethings(args[0])
            print(output)
        else:
            print("[!] Incorrect directory path. The path does not exist.")
        sys.exit()
