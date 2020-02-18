#python script to search IOC via free APIs
import requests
import validators
import argparse
import os
import pulsedive
import base64

parser = argparse.ArgumentParser()
parser.add_argument("ioc", help="Enter the ioc youd like to query")
args = parser.parse_args()

ioc = args.ioc.strip()
print('Searching the IOC %s...' % ioc)

keys = {}
headers = {}
#read apis from config file
with open("keys.cfg", "r") as keys_c:
    next(keys_c)
    for line in keys_c:
        (key, val) = line.split(":")
        keys[key.strip()] = val.strip()

#set pulsedive key and start object
if keys['pulsedive']:
    pud = pulsedive.Pulsedive(keys['pulsedive'])
else:
    pud = pulsedive.Pulsedive()
    
#check_ip
def check_ip(ioc):
    #vt check ip
    headers['x-apikey'] = keys['vt']
    vt_ip_api = "https://www.virustotal.com/api/v3/ip_addresses/%s" % ioc
    vt_ip = requests.get(url=vt_ip_api,headers=headers)
    vt_data = vt_ip.json()
    vtowner = vt_data['data']['attributes']['as_owner']
    vtcountry = vt_data['data']['attributes']['country']
    vtrep = vt_data['data']['attributes']['reputation']
    print('--VirusTotal--')
    print('Owner: %s' % vtowner)
    print('Country: %s' % vtcountry)
    print('Reputation: %s\n' % vtrep)    
    
    #pulsedive
    print('--PulseDive--')
    try:
        ind = pud.indicator(value=ioc)
        if ind['risk'] == 'none':
            print('Verdict Unknown')
        else:
            print(ind['risk'])        
    except pulsedive.exceptions.PulsediveException as e:
        if 'Indicator not found' in str(e):
            print('Indicator not found')
            #maybe add option to upload ioc to pulsedive

#check_url
def check_url(ioc):
    #vt
    headers['x-apikey'] = keys['vt']
    vt_url_api = "https://www.virustotal.com/api/v3/urls/%s" % base64.urlsafe_b64encode(ioc.encode()).strip(b'=').decode()
    vt_url = requests.get(url=vt_url_api,headers=headers)
    vt_data = vt_url.json()
    vtrep = vt_data['data']['attributes']['reputation']
    print('--VirusTotal--')
    print('Reputation: %s\n' % vtrep)
    
    #pulsedive
    print('--PulseDive--')
    try:
        ind = pud.indicator(value=ioc)
        if ind['risk'] == 'none':
            print('Verdict Unknown')
        else:
            print(ind['risk'])        
    except pulsedive.exceptions.PulsediveException as e:
        if 'Indicator not found' in str(e):
            print('Indicator not found')
            #maybe add option to upload ioc to pulsedive
    exit()

def check_domain(ioc):
        print('it bad!')
#detect ioc, check if hash,ip, domain, or url
def check_ioc(ioc):
    pass
    if validators.ip_address.ipv4(ioc) or validators.ip_address.ipv6(ioc):
        check_ip(ioc)
    #hash
    elif validators.url(ioc):
        check_url(ioc)
    elif validators.domain(ioc):
        check_domain(ioc)
    else:
        print("The IOC:'%s' cannot be searched. The script only searches IPs, hashes, URLs, and domains" % ioc)
        exit()

check_ioc(ioc)
