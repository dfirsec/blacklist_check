


import concurrent.futures
blacklists = {
    "Alien Vault Reputation": "http://reputation.alienvault.com/reputation.data",
    "Bambenek Consulting": "https://osint.bambenekconsulting.com/feeds/c2-masterlist.txt",
    "Bitcoin Nodes": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/bitcoin_nodes.ipset",
    "Blocklist DE": "http://www.blocklist.de/lists/all.txt",
    "Bot Scout IPs": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/botscout.ipset",
    "Brute Force Blocker": "https://panwdbl.appspot.com/lists/bruteforceblocker.txt",
    "CI Army Badguys": "http://www.ciarmy.com/list/ci-badguys.txt",
    "Coin Blacklist Hosts": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/coinbl_hosts.ipset",
    "CyberCrime": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/cybercrime.ipset",
    "Danger Rulez": "http://danger.rulez.sk/projects/bruteforceblocker/blist.php",
    "Darklist DE": "https://www.darklist.de/raw.php",
    "ET Compromised": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
    "ET Tor Rules": "https://rules.emergingthreats.net/blockrules/emerging-tor.rules",
    "GreenSnow": "https://blocklist.greensnow.co/greensnow.txt",
    "IP Spamlist": "http://www.ipspamlist.com/public_feeds.csv",
    "MalC0de Blacklist": "http://malc0de.com/bl/IP_Blacklist.txt",
    "Malware Army": "https://malware.army/api/honey_iplist",
    "Malware Domains": "http://www.malwaredomainlist.com/hostslist/ip.txt",
    "Mirai Security": "https://mirai.security.gives/data/ip_list.txt",
    "MyIP Blacklist": "https://www.myip.ms/files/blacklist/csf/latest_blacklist.txt",
    "OpenPhish": "https://openphish.com/feed.txt",
    "PhishTank": "http://data.phishtank.com/data/online-valid.csv",
    "SSL Abuse IP List": "https://panwdbl.appspot.com/lists/sslabuseiplist.txt",
    "SpamHaus Drop": "https://panwdbl.appspot.com/lists/shdrop.txt",
    "Stop Forum Spam": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/stopforumspam.ipset",
    "Talos Intel": "https://talosintelligence.com/documents/ip-blacklist",
    "Threat Crowd": "https://www.threatcrowd.org/feeds/ips.txt",
    "Threatweb Botnet IPs": "https://www.threatweb.com/access/Botnet-IPs-High_Confidence_BL.txt",
    "Threatweb Watchlist": "https://www.threatweb.com/access/SIEM/OPTIV_HIGH_CONFIDENCE_SIEM_IP_WATCHLIST.txt",
    "URL Haus": "https://urlhaus.abuse.ch/downloads/csv_recent/",
    "Windows SpyBlocker": "https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/firewall/extra.txt"
}


def myfunc(elem):
    elem['ascii'] = ord(elem['name'])


mylist = [
    {'name': 'a'},
    {'name': 'b'},
    {'name': 'c'},
    {'name': 'd'},
    {'name': 'e'}
]

with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
    future_to_url = {executor.submit(myfunc, elem): elem for elem in mylist}
    for future in concurrent.futures.as_completed(future_to_url):
        try:
            future.result()
        except Exception as exc:
            print(exc)

print(mylist)


for k, v in blacklists.items():
    print(k, v)