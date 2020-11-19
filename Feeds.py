'''Python sctipt that extracts, writes and parses known malicious URL's, Domains, IP addresses and Hash's (SHA 256) from uniqe sources, listed in the "urls_list" list object.
 DO NOT change without permission from CyberDome Team !!
The code does the following :
At first, the script generates a uniqe "cryptolaemus link" and adds it to the list .
cryptolaemus updates their data every day, with a link : https://paste.cryptolaemus.com/emotet/DAY/MONTH/YEAR/emotet-malware-IoCs_DAY-MONTH-YEAR.html" !
1. Retrieving HTML code from sources using a uniqe HTTP packet.
2. Parsing the relevant data and appending it into global lists.
3.When the for loop ends, the lists turns into a set data type, to remove duplicates.
4. Writing the data into the .txt files

Daniel B
 '''

#----------IMPORTS----------

import requests
from datetime import datetime
import re, os, csv
import time

#----------CONSTS----------

urls_list = [
            'https://lists.blocklist.de/lists/all.txt',
            'https://www.dan.me.uk/torlist/?exit',
            'https://www.dan.me.uk/torlist/',
            'https://raw.githubusercontent.com/stamparm/ipsum/master/levels/1.txt',
            'https://raw.githubusercontent.com/stamparm/ipsum/master/levels/2.txt',
            'https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt',
            'https://raw.githubusercontent.com/stamparm/ipsum/master/levels/4.txt',
            'https://raw.githubusercontent.com/stamparm/ipsum/master/levels/5.txt',
            'https://raw.githubusercontent.com/stamparm/ipsum/master/levels/6.txt',
            'https://raw.githubusercontent.com/stamparm/ipsum/master/levels/7.txt',
            'https://raw.githubusercontent.com/stamparm/ipsum/master/levels/8.txt',
            'https://mirai.security.gives/data/ip_list.txt',
            'https://api.cybercure.ai/feed/get_ips?type=csv',
            'https://api.cybercure.ai/feed/get_url?type=csv',
            'https://api.cybercure.ai/feed/get_hash?type=csv',
            'https://blocklist.greensnow.co/greensnow.txt',
            'https://dataplane.org/vncrfb.txt',
            'https://dataplane.org/sshpwauth.txt',
            'https://dataplane.org/sipregistration.txt',
            'https://dataplane.org/sipquery.txt',
            'https://dataplane.org/sipinvitation.txt',
            'https://cinsscore.com/list/ci-badguys.txt',
            'https://raw.githubusercontent.com/ktsaou/blocklist-ipsets/master/firehol_level1.netset',
            'https://raw.githubusercontent.com/pan-unit42/iocs/master/diamondfox/diamondfox_panels.txt',
            'https://data.phishtank.com/data/online-valid.csv',
            'https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset',
            'https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level2.netset',
            'https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level3.netset',
            'http://sanyalnet-cloud-vps.freeddns.org/mirai-ips.txt',
            'https://feodotracker.abuse.ch/downloads/ipblocklist.csv',
            'https://cybercrime-tracker.net/all.php',
            'https://cybercrime-tracker.net/ccamgate.php',
            'https://cybercrime-tracker.net/ccamgate.php',
            'https://cybercrime-tracker.net/ccamlist.php',
            'https://phishstats.info/phish_score.csv',
            'https://bazaar.abuse.ch/export/txt/md5/full/',
            'https://benkow.cc/export_rat.php',
            'https://benkow.cc/export.php',
            'http://www.ipspamlist.com/public_feeds.csv',
            'https://raw.githubusercontent.com/phishfort/phishfort-lists/master/blacklists/domains.json',
            'https://pastebin.com/quYGaugQ',
            'https://udurrani.com/0fff/bad_hashes.html'
            ]

#REGEX Consts
SHA256_RE = '[A-Fa-f0-9]{64}'
IP_PORT_RE = r"(?:\d{1,3}\.){3}\d{1,3}"
DOMAIN_RE = 'https?://([A-Za-z_0-9.-]+).*'
LINK_REGEX = 'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+'

#FILES consts
CURRENT_PATH = os.path.abspath(os.getcwd())

LOG_FILE = CURRENT_PATH + "/log.txt"

PATH_SHA265 = CURRENT_PATH  + "/SHA265_{}.txt".format(datetime.now().strftime('%Y-%m-%d'))
PATH_IP = CURRENT_PATH + "/IP_{}.txt".format(datetime.now().strftime('%Y-%m-%d')) 
PATH_URL = CURRENT_PATH + "/URL_{}.txt".format(datetime.now().strftime('%Y-%m-%d'))
PATH_DOMAIN = CURRENT_PATH + "/DOMAIN_{}.txt".format(datetime.now().strftime('%Y-%m-%d'))

#Global Variables
all_ips = []
all_domains = []
all_urls = []
all_sha = []

#----------Functions----------
#Function is responsible for writing data into the LOG file.
def write_to_logFile(log):

    with open(LOG_FILE,'a') as logfile:
        logfile.write(log + '\n')

#Function generates a cryptolaemus link, according to the current day
def genereate_cryptolaemus_link():

    now = datetime.now()
    year = now.strftime("%Y")
    month = now.strftime("%m")
    day = now.strftime("%d")
    link = "https://paste.cryptolaemus.com/emotet/{}/{}/{}/emotet-malware-IoCs_{}-{}-{}.html".format(year, month, day, month, day, year[2:])
    write_to_logFile("Generated the link : {}".format(link) +'\n')

    return link

#Function gets a URL and retunes the HTML code as a string.
def fetch_html_from_url(url):

    try:
        time.sleep(0.5)
        #Chenge the packet headers because some of the websites dont like bots..
        headers = {"User-Agent":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.97 Safari/537.36"}
        page = requests.get(url, headers=headers, verify = True)
        if page:
            write_to_logFile("The html code was successfully granted from : {}".format(url) + '\n')
            return page.text
        else:
            write_to_logFile("The page {} returned an ERROR : {}, try again tomorrow".format(page, error) + '\n')
            return False
    except Exception as error:
        write_to_logFile("An error was written: {} ".format(error) +'\n')
        return False

#Function writes data to the file.
def write_to_file(file_path, data_list):
    try:
        with open(file_path,'a', newline = '') as f:

            for val in set(data_list):
                f.write(str(val) + '\n')
            write_to_logFile("written to {}".format(file_path))
                
    except IOError as err:
        write_to_logFile("I/O Error" + '\n')
        return False
    except Exception as err:
        write_to_logFile("Unknown Error when trying to write to file {}, the error is {}".format(file_path,err) + '\n')
        return False

#Function gets html code and extraces the releveant data.
def parse_data(html_code):
    
    try:    

        time.sleep(0.5)
        sha_265 = re.findall(SHA256_RE,html_code)
        for file_hash in sha_265:
            all_sha.append(file_hash)
        
        time.sleep(0.5)
        ips = re.findall(IP_PORT_RE,html_code)
        for ip in ips:
            all_ips.append(ip)
        time.sleep(0.5)

        urls = re.findall(LINK_REGEX,html_code)
        domains = []
        for url in urls:
            all_urls.append(url)
            tmp_data = re.search(DOMAIN_RE,str(url))
            domains.append(tmp_data.group(1))

        for domain in domains:
            all_domains.append(domain)

    except Exception as err:        
        write_to_logFile("parsing error: {}".format(err))
        return False

def main():

    c_link = genereate_cryptolaemus_link()
    urls_list.append(c_link)
    for idx, url in enumerate(urls_list):
        try:
            time.sleep(1)
            write_to_logFile("working on : {}".format(url) + '\n')
            parse_data(fetch_html_from_url(url))
            print("Working on url number: {}, {}".format(idx,url))
            write_to_logFile("##### Finished working on URL : {} #####".format(idx) + '\n')
        except Exception as err:
            write_to_logFile("An Unknown error : {}".format(err))
    write_to_logFile("There Are {} IPS, {} Hashes, {} Urls and {} Domains !".format(len(set(all_ips)),len(set(all_sha)),len(set(all_urls)),len(set(all_domains))))
            
    write_to_file(PATH_SHA265,set(all_sha))
    write_to_file(PATH_IP,set(all_ips))
    write_to_file(PATH_DOMAIN,set(all_domains))
    write_to_file(PATH_URL,set(all_urls))

if __name__ == '__main__':
    main()