# Obscurer

## Cowrie Honeypot Obscurer (2020)

A Python script designed to remove (nearly) all default values from a Cowrie Honey Pot installation. 

A random host profile with new users, hostname, groups, file shares, harddrive(s) sizes, mounts, cpu, ram, OS version, IP address, MAC addresses and SSH version is created. In theory this makes it much harder to easily detect default cowrie honeypot installations.

This script will work best with new installations of Cowrie, with unedited configurations.

## Requirements

* Fresh Cowrie install (no edited configurations or files) (using virtualenv with python 3)
* Python 3

## Usage

To install it as a cowrie user, so then there will be no issues in writing the files inside the cowrie directory of the cowrie user

**Run as:** `cowrie` user
to switch (no cowrie-env needed):
```bash
sudo su - cowrie
```
Then
```bash
cd /home/cowrie
git clone https://github.com/marcosantiagomuro/obscurer.git obscurer-cowrie

```

the go to 

```bash
cd obscurer-cowrie
python3 -m venv obscurer-env
source obscurer-env/bin/activate
```
so it will show something like:
```
(obscurer-env)
```
then with the venv active
```bash
pip install --upgrade pip
pip install -r requirements.txt
```

Then run the script using the venv:


```bash
./obscurer.py [options] path/to/cowrie/directory

Options:
  -h, --help    Show this help message and exit
  -a, --allthethings  Change all of the default values
  
Example:
./obscurer.py -a /home/cowrie/cowrie/
```


Decativate the venv when done
```bash
deactivate
```

Once the script has completed, restart the Cowrie service and SSH to the host to confirm changes have been made.
