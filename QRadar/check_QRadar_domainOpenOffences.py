#!/usr/bin/python
#Author:  611096119
#Created: 20/03/2019
#Description: This script uses a http get request to retrieve the number of Default Domain open offenses in a QRadar instance. This is to warn us when the amount of open offenses is 1 or more.
#==========================================
#
# Import
#
#==========================================

import requests #to use http requests
import json #to read json data
import sys #used for command line arguments
import re #used for regex

from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Suppress request warnings "InsecureRequestWarning: Unverified HTTPS request is being made."

#==========================================
#
# Variables
#
#==========================================

domain = sys.argv[1]
authKey = sys.argv[2]
warn = sys.argv[3]

#==========================================
#
# Validation
#
#==========================================

if re.match("^https:\/\/|^http:\/\/", domain) is None:
    print "Domain name must start with http:// or https://"
    exit(2)

if re.match("^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$", authKey) is None:
    print "Incorrect authorisation key format"
    exit(2)

if re.match("^[0-9]{1,4}$", warn) is None:
    print "Warning input is not an integer, or above 9999"
    exit(2)

#==========================================
#
# Main Code
#
#==========================================

url = domain + "/api/siem/offenses?fields=id&filter=domain_id%3D0%20and%20status%3D%22open%22"
headers = {'SEC': ''+ authKey +'', 'Version': 9.0, 'content-type':'application/json'}
r = requests.get(url, headers=headers, verify=False)
httpCode = r.status_code

if httpCode == 200:

    data = json.loads(r.content)

    if len(data) >= int(warn):
        statustxt = "WARNING: " + str(len(data)) + " open offences|openoffences=" + str(len(data)) + ";" + str(warn) + ";" + ";0"
        print statustxt
        exit(1)
    elif type(len(data)) != int or len(data) < 0:
        statustxt = "UNKNOWN: " + str(len(data)) + " open offences|openoffences=" + str(len(data)) + ";" + str(warn) + ";" + ";0"
        print statustxt
        exit(3)
    else:
        statustxt = "OK: " + str(len(data)) + " open offences|openoffences=" + str(len(data)) + ";" + str(warn) + ";" +  ";0"
        print statustxt
        exit(0)
else:
    statustxt = "HTTP Code: " + str(httpCode)
    print statustxt
    exit(2)

