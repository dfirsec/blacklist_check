# IP Blacklist Check

![Generic badge](https://img.shields.io/badge/python-3.7-blue.svg) [![Twitter](https://img.shields.io/badge/Twitter-@pulsecode-blue.svg)](https://twitter.com/pulsecode)

Python script that downloads IP reputation blacklists from various sources and queries an IP address, or multiple IPs, against those lists. Utilizes the FreeGeopIP Live service for IP geolocation - ref: <https://freegeoip.live/>

API Key (add to `settings.ini` file) required for the following:

- AbuseIPDB
- Shodan
- VirusTotal

## Installation

```text
git clone https://github.com/dfirsec/blacklist_check.git
cd blacklist_check
pip install -r requirements.txt
```

## Usage

```text
        ____  __           __   ___      __     ________              __
       / __ )/ /___ ______/ /__/ (_)____/ /_   / ____/ /_  ___  _____/ /__
      / __  / / __ `/ ___/ //_/ / / ___/ __/  / /   / __ \/ _ \/ ___/ //_/
     / /_/ / / /_/ / /__/ ,< / / (__  ) /_   / /___/ / / /  __/ /__/ ,<
    /_____/_/\__,_/\___/_/|_/_/_/____/\__/   \____/_/ /_/\___/\___/_/|_|

usage: blacklist_check.py [-h] [-t [threads]] [-v] [-a] [-s] [-u | -fu | -sh] [-q query [query ...] | -f file | -i | -r]

IP Blacklist Check

optional arguments:
  -h, --help            show this help message and exit
  -t [threads]          threads for rbl check (default 25, max 50)
  -v                    check virustotal for ip info
  -a                    check abuseipdb for ip info
  -s                    check shodan for ip info
  -u                    update blacklist feeds
  -fu                   force update of all feeds
  -sh                   show blacklist feeds
  -q query [query ...]  query a single or multiple ip addrs
  -f file               query a list of ip addresses from file
  -i                    insert a new blacklist feed
  -r                    remove an existing blacklist feed
```

### Example Run

![alt text](imgs/blacklist_check.gif)
