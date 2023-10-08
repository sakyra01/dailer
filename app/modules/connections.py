import requests
import time
from pyExploitDb import PyExploitDb
from dotenv import load_dotenv
import logging
import os
from datetime import datetime


# Settings to turn on Logger + updating db pyExploitDB
timestamp = datetime.today().strftime("%Y-%m-%d")
year = datetime.today().strftime("%Y")

pEdb = PyExploitDb()
load_dotenv()
pEdb.debug = False
Log_Format = "%(levelname)s %(asctime)s - %(message)s"
logging.basicConfig(filename=f"logs/logfile.log", filemode="w", format=Log_Format, level=logging.INFO)
logger = logging.getLogger()

# Network default settings
url = os.getenv('URL')
token = os.getenv('Token')

proxies = {
   'https': 'http://10.67.50.74:8888',
}


# Function which check update and connection to database of vulnerabilities
def check_connection_pedb():
    pEdb.openFile()


# Function get findings from DefectDojo
def get_findings_data(offset):
    path = f'{url}?limit=1000&offset={offset}/'
    headers = {'content-type': 'application/json', 'Authorization': token}

    try:
        r = requests.get(path, headers=headers, verify=True)    # set verify to False if ssl cert is self-signed
        r.raise_for_status()
        # Check content for data
        full_content = r.json()
        count = full_content["count"]
        content = full_content['results']
        # Checking count of findings for timeout problem working of program
        if count > 50000:
            message = f"Alert! There are {count} findings in DefectDojo"
            print(message)
            debug_message(message)
        # Condition to exit from loop of requests
        if offset > count:
            content = 0
        return content
    except requests.exceptions.RequestException:
        message = f"Unreached DefectDojo source. File - (connections.py); Function - (get_findings_data)"
        print(message)
        debug_message(message)
        exit(1)


# Function connect to NIST API and get data
def nist_connection(cve_id):
    api_key = os.getenv('NIST_API_KEY')
    nist_url = os.getenv('NIST_URL')
    nist_new_path = f"{nist_url}{cve_id}"
    headers = {"apiKey": api_key}

    try:
        time.sleep(0.8)
        response = requests.get(nist_new_path, headers=headers, proxies=proxies, timeout=5)
        cve_data = response.json()
        return cve_data
    except requests.exceptions.RequestException:
        message = f"Unreached NIST source. File - (connections.py); Function - (nist_connection)"
        print(message)
        debug_message(message)
        exit(1)


# Functon send new tags on DefectDojo in obvious finding tags field
def post_new_tags(tags_list, finding_id):
    uri = url                                   # path to api finding id + tags
    uri = f'{uri}{finding_id}/tags/'            # sum full path
    body = {
        "tags": tags_list
    }
    headers = {'content-type': 'application/json', 'Authorization': token}

    try:
        requests.post(uri, headers=headers, verify=True, json=body)
    except requests.exceptions.ConnectionError:
        message = f"Error to add new tags in finding for finding - {finding_id}. File - (connections.py); Function - (post_new_tags)"
        logger.error(message)
        print(message)
        debug_message(message)
        exit(1)


# Function delete vpr tag from finding
def delete_tag(tag, f_id):
    path = url
    new_path = f"{path}{f_id}/remove_tags/"
    headers = {'content-type': 'application/json', 'Authorization': token}
    body = {
        "tags": [
            tag
        ]
    }

    response = requests.patch(new_path, headers=headers, verify=True, json=body)
    status_code = response.status_code

    if status_code == 400:
        message = f"Connection error to DefectDojo. Bad request. Status code - {status_code}. Finding - {f_id}. File - (connections.py); Function - (delete_tag)"
        logger.error(message)
        print(message)
        debug_message(message)
    else:
        logger.info(f"Successfully remove tag {tag}. Finding - {f_id}")


def get_products(finding_id):
    path = f"https://defectdojo.x5food.tech/api/v2/findings/{finding_id}/?related_fields=true&engagement=%"
    headers = {'content-type': 'application/json', 'Authorization': token}
    r = requests.get(path, headers=headers, verify=True)
    product = r.json()
    return product


# Get information about cve from cisa and adding in file app/cisa/cisa_list
def get_cisa_cve():
    cisa_path = os.getenv('Cisa_URL')
    headers = {'content-type': 'application/json'}

    try:
        response = requests.get(cisa_path, headers=headers, proxies=proxies)
        cisa_cve_list = response.json()['vulnerabilities']
        return cisa_cve_list
    except requests.exceptions.ConnectionError:
        message = f"Error connect to CISA. File - (connections.py); Function - (get_cisa_cve)"
        logger.error(message)
        print(message)
        debug_message(message)
        exit(1)


def get_epss(cve):
    epss_path = os.getenv('EPSS_URL')
    epss_cve_patch = f"{epss_path}{cve}"
    headers = {'content-type': 'application/json'}

    try:
        response = requests.get(epss_cve_patch, headers=headers, proxies=proxies)
        epss_data = response.json()
        return epss_data
    except requests.exceptions.ConnectionError:
        message = f"Error connect to EPSS. File - (connections.py); Function - (get_epss)"
        logger.error(message)
        print(message)
        debug_message(message)
        exit(1)


# Send debug problem message by web hook on chanel in rocketchat (report option)
def debug_message(message):
    uri = os.getenv('Web_Hook_Debug')
    data = {
        "alias": "Dailer framework",
        "text": f"Something go wrong. Debug problem!\n {message}"
    }
    requests.post(uri, headers={'content-type': 'application/json'}, json=data)


# Send statistic message by web hook on chanel in rocketchat (report option)
def statistic_message(message):
    uri = os.getenv('Web_Hook_Debug')
    data = {
        "alias": "Dailer framework",
        "text": f"Framework performance statistics. Status-[Successfully Ended].\n {message}"
    }
    requests.post(uri, headers={'content-type': 'application/json'}, json=data)


def send_alerts_messages(message):
    uri = os.getenv('Web_Hook_Alert')
    data = {
        "alias": "Dailer framework",
        "text": "Framework performance statistics about critical vulnerabilities in DefectDojo.",
        "attachments": [
            {
                "title": "Payload sources",
                "text": message,
                "status": "collapsed"
            }
        ]
    }
    requests.post(uri, headers={'content-type': 'application/json'}, json=data)
