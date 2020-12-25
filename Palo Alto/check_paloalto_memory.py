#!/usr/bin/python
# check_paloalto_memory.py 
# HOST-RESOURCES-MIB::hrStorageIndex 1.3.6.1.2.1.25.2.3 https://knowledgebase.paloaltonetworks.com/KCSArticleDetail?id=kA10g000000ClaSCAS
# Original Author/date: Bilal H, 2020-12-19

import argparse
import subprocess
import re
import sys
from decimal import Decimal
from threading import Timer

PATTERN=r"^HOST-RESOURCES-MIB::hrStorage(\w+).(\d+)\s(.*?)$"
NAGIOS="Memory usage : {Used} used for a total of {Size} ({usedPercentage}%) {AllocationUnits}"
DESCRIPTION="Checks Palo Alto physical memory snmpv2."

def nagios(msg, code):
    status = 'OKAY' if code == 0 else 'WARN' if code == 1 else 'CRIT' if code == 2 else 'UNKNOWN'
    print('{} - {}'.format(status, msg))
    exit(code)

def percentage(part, whole):
    return 100 * float(part)/float(whole)

def get_mem(community, hostname, timeout):
    kill = lambda process: process.kill()
    cmd = ['/usr/bin/snmpwalk', '-OqE', '-v2c', '-c', str(community), str(hostname), 'hrStorageTable']
    proc = subprocess.Popen(cmd, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    my_timer = Timer(timeout, kill, [proc])
    try:
        my_timer.start()
        stdout, stderr = proc.communicate()
    finally:
        my_timer.cancel()
    
    if stderr:
        nagios('Unable to get SNMP result {}'.format(stderr), 3)
    
    if not stdout:
        nagios('Unable to get SNMP result. Timed out ({}s)'.format(timeout), 3)

    try:
        return stdout.rstrip('\n')
    except Exception:
        nagios('Unable to processes SNMP result {}'.format(stdout), 3)

def parse_args():
    parser = argparse.ArgumentParser(description=DESCRIPTION)
    parser.add_argument('--hostname','-H', nargs=1, metavar='str', required=True)
    parser.add_argument('--community','-c', nargs=1, default='public', metavar='str', required=True)
    parser.add_argument('--timeout', '-t', nargs=1, type=int, metavar='N', default=[10], help='Please specify SNMP timeout')
    parser.add_argument('--warning', '-W', nargs=1, type=int, metavar='N', default=[80], help='Please specify Warning')
    parser.add_argument('--critical', '-C', nargs=1, type=int, metavar='N', default=[95], help='Please specify Critical')
    return parser.parse_args()

def main():
    # Get user input
    args = parse_args()
    # Get SNMP data
    result = get_mem(args.community[0], args.hostname[0], args.timeout[0])

    # Sort through SNMP data
    d={}
    for x in result.split('\n'):
        name, ids, value = re.match(PATTERN, x).groups()
        try:
            d[int(ids)][name] = value 
        except Exception:
            d[int(ids)] = {name:value}

    # If physical memory is available continue 
    try:
        for x in d:
            if 'hrStorageRam' in str(d[x]['Type']):
                memoryId = x
        
        d[memoryId]['usedPercentage'] = int(percentage(d[memoryId]['Used'], d[memoryId]['Size']))
        d[memoryId].pop('Index',None)
        d[memoryId].pop('AllocationFailures',None)
        d[memoryId].pop('Type',None)
    except Exception as e:
        nagios('Unable to calculate memory percentage {}'.format(e), 3)

    # If warning is provided
    if args.warning:
        if int(d[memoryId]['usedPercentage']) > args.warning[0]:
            nagios(NAGIOS.format(**d[memoryId]), 1)

    # If critical is provided
    if args.critical:
        if int(d[memoryId]['usedPercentage']) > args.critical[0]:
            nagios(NAGIOS.format(**d[memoryId]), 2)

    # No thresholds provided
    nagios(NAGIOS.format(**d[memoryId]), 0)

if __name__ == '__main__':
    main()