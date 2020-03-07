# IP Blacklist Check

![Generic badge](https://img.shields.io/badge/python-3.7-blue.svg) [![Twitter](https://img.shields.io/badge/Twitter-@pulsecode-blue.svg)](https://twitter.com/pulsecode)

```blacklist_check.py``` Simple script to download blacklists from various sources and check IP addresses against those blacklists.  Utilizes the FreeGeopIP Live service for IP geolocation. (ref: <https://freegeoip.live/)>

## Installation

```text
git clone https://github.com/dfirsec/blacklist_check.git
cd blacklist_check
pip install -r requirements.txt
```

## Usage

```console
        ____  __           __   ___      __     ________              __
       / __ )/ /___ ______/ /__/ (_)____/ /_   / ____/ /_  ___  _____/ /__
      / __  / / __ `/ ___/ //_/ / / ___/ __/  / /   / __ \/ _ \/ ___/ //_/
     / /_/ / / /_/ / /__/ ,< / / (__  ) /_   / /___/ / / /  __/ /__/ ,<
    /_____/_/\__,_/\___/_/|_/_/_/____/\__/   \____/_/ /_/\___/\___/_/|_|
     v2.0

usage: blacklist_check.py [-h] [-u] [-s] [-q query [query ...]] [-w] [-f file] [-i insert insert] [-r remove]

IP Blacklist Check

optional arguments:
  -h, --help            show this help message and exit
  -u                    Update set of Blacklisted IPs
  -s                    Show/Sort Blacklist Feeds by Name or Count
  -q query [query ...]  Query a single or list of IPs against Blacklist
  -w                    Perform IP whois lookup
  -f file               Blacklist check a list of IPs from file
  -i insert insert      Insert new Blacklist feed. Use comma-separated key-value pair: "Blacklist Name", "URL"
  -r remove             Remove Blacklist feed
  ```
  
### Download/update Blacklisted IPs from feeds

  ```text
  python blacklist_check.py -u

 [ Downloading ]
  ➜  Alien Vault Reputation
  ➜  Bambenek Consulting
  ➜  Bitcoin Nodes
  ➜  Blocklist DE
  ➜  Bot Scout IPs
  ➜  Brute Force Blocker
  ➜  CI Army Badguys
  ➜  Coin Blacklist Hosts
  ➜  CyberCrime
  ➜  Danger Rulez
  ➜  Darklist DE
  ➜  ET Compromised
  ➜  ET Tor Rules
  ➜  IP Spamlist
  ➜  MalC0de Blacklist
  ➜  Malware Army
  ➜  Malware Domains
  ➜  Mirai Security
  ➜  MyIP Blacklist
  ➜  SSL Abuse IP List
  ➜  SpamHaus Drop
  ➜  Stop Forum Spam
  ➜  Talos Intel
  ➜  Threat Crowd
  ➜  Threatweb Botnet IPs
  ➜  Threatweb Watchlist
  ➜  URL Haus
  ➜  WindowsSpyBlocker
```

### Show count of Blacklisted IPs

```text
python blacklist_check.py -s

LIST                      COUNT
-----------------------------------
Alien Vault Reputation   : 36112
Bambenek Consulting      : 564
Bitcoin Nodes            : 7762
Blocklist DE             : 25879
Bot Scout IPs            : 56
Brute Force Blocker      : 625
CI Army Badguys          : 14987
Coin Blacklist Hosts     : 7358
CyberCrime               : 2334
Danger Rulez             : 627
Darklist DE              : 7746
ET Compromised           : 622
ET Tor Rules             : 7114
IP Spamlist              : 50
MalC0de Blacklist        : 21
Malware Army             : 4383
Malware Domains          : 996
Mirai Security           : 999
MyIP Blacklist           : 1145
SSL Abuse IP List        : 86
SpamHaus Drop            : 48
Stop Forum Spam          : 178470
Talos Intel              : 1320
Threat Crowd             : 976
Threatweb Botnet IPs     : 313
Threatweb Watchlist      : 745
URL Haus                 : 96865
Windows SpyBlocker       : 358

➜  Last Modified: 2020-01-30 07:22:35
```

### Insert new Blacklist feed

```text
python blacklist_check.py" -i "Windows SpyBlocker", https://...WindowsSpyBlocker...

✔ Added feed: "Windows SpyBlocker": "https://...WindowsSpyBlocker..."
```

### Remove Blacklist feed

```text
python blacklist_check.py" -r "Windows SpyBlocker"

✔ Removed feed: "Windows SpyBlocker"
```

### Check if IP is blacklisted

#### Single

 ```text
python blacklist_check.py" -q 104.152.52.31
  
✘ BLACKLISTED  104.152.52.31   United States (US)             Blacklist: Alien Vault Reputation
```

#### Multiple inline

```text
python blacklist_check.py -q 5.255.250.96, 78.46.85.236, 46.229.168.146
  
✘ BLACKLISTED  46.229.168.146  Ashburn, Virginia (US)         Blacklist: MyIP Blacklist
✔ NOT LISTED   5.255.250.96    Moscow, Russia (RU)
✔ NOT LISTED   78.46.85.236    Germany (DE)
```

#### Multiple from file

```text
python blacklist_check.py -f ip_list.txt
  
✘ BLACKLISTED  46.229.168.146  Ashburn, Virginia (US)         Blacklist: MyIP Blacklist
✔ NOT LISTED   5.255.250.96    Moscow, Russia (RU)
✔ NOT LISTED   78.46.85.236    Germany (DE)
```

#### IP Whois Lookup

```text
python blacklist_check.py -q 75.62.69.12, 12.16.5.23, 87.56.25.4, 18.23.36.2 -w

..............................
[ Performing IP whois lookup ]

✔ NOT LISTED    75.62.69.12     Allen, Texas (US)    AT&T Corp.
✔ NOT LISTED    12.16.5.23      United States (US)   AT&T Services, Inc.
✔ NOT LISTED    87.56.25.4      Denmark (DK)         TDC BB-ADSL users
✔ NOT LISTED    18.23.36.2      United States (US)   Massachusetts Institute of Technology
```
