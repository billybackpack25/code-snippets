#!/usr/bin/python
# check_paloalto_bandwidth.py
# Original Author/date: Bilal H, 2020-12-19
# https://www.cisco.com/c/en/us/support/docs/ip/simple-network-management-protocol-snmp/8141-calculate-bandwidth-snmp.html
from time import sleep
from threading import Timer
import argparse
import subprocess
import re

PATTERN=r"^[^:]+::(\w+).(\d+)\s(.*?)$" # Filter out SNMP results
PATTERN2=r"^SNMPv2-MIB::sysDescr.0 Palo Alto Networks ([^\s]+) series firewall$" # Get device version
TYPES=['PA-3200','PA-5200','PA-800']
DESCRIPTION="Checks Palo Alto bandwidth snmpv2. Compatable with: {}".format(', '.join(TYPES))
NAGIOS='{ifIpOrName}({speed}): {bandwidth}, errorIn ({errorIn}) errorOut ({errorOut}) Mtu ({mtuPackets}) ({ipStatus}) {perf}'
SNMPINTERVAL=5
TIMEOUT=10

# Print nagios expected output 
def nagios(msg, code, statusP=True):
    if statusP:
        status = 'OKAY - ' if code == 0 else 'WARN - ' if code == 1 else 'CRIT - ' if code == 2 else 'UNKNOWN - '
    else:
        status = ''
    print('{}{}'.format(status, msg))
    exit(code)

# Get SNMP data using linux's snmpbulkwalk command
def get_snmpOid(community, hostname, timeout, snmpP=''):
    kill = lambda process: process.kill()
    if snmpP != '':
        cmd = ['/usr/bin/snmpbulkwalk', '-OqE', '-v2c', '-c', str(community), str(hostname), str(snmpP)]
    else:
        cmd = ['/usr/bin/snmpbulkwalk', '-OqE', '-v2c', '-c', str(community), str(hostname)]
    proc = subprocess.Popen(cmd, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    my_timer = Timer(timeout, kill, [proc])
    try:
        my_timer.start()
        stdout, stderr = proc.communicate()
    finally:
        my_timer.cancel()
    # Check for errors
    if stderr:
        nagios('Unable to get SNMP result {} {}'.format(stdout, stderr), 3)
    # Check for empty result
    if not stdout:
        nagios('Unable to get SNMP result. Timed out ({}s)'.format(timeout), 3)
    # Return output
    try:
        return stdout.rstrip('\n')
    except Exception:
        nagios('Unable to processes SNMP result {}'.format(stdout), 3)

# Sort through the SNMP data returned
def sortSNMP(result):
    # Sort through SNMP data
    d={}
    y = ['ifType','ifMtu','ifSpeed','ifOperStatus','ifInOctets','ifOutOctets','ifDescr','ifName','ifInDiscards','ifInErrors','ifOutDiscards','ifOutErrors','ifHighSpeed','ifAlias']
    for x in result.split('\n'):
        # Try to run the regex pattern, find the name, ids and values
        try:
            name, ids, value = re.match(PATTERN, x).groups()
        except Exception:
            pass

        # Make sure I only format the information I want
        if not 0 in [name.find(string) for string in y]:
            continue

        # Add the values to the dictionary
        try:
            d[int(ids)][name] = value
            #print(name, value)
        except Exception:
            d[int(ids)] = {name:value}
            #print(name, value)
    
    # Variables missing
    try:
        for x in y:
            d[int(ids)][x]
    except Exception:
        nagios('Unable to pull back all the SNMP variables required. Try increasing the timeout -t', 3)

    return d

# Parse the user arguments
def parse_args():
    parser = argparse.ArgumentParser(description=DESCRIPTION)
    parser.add_argument('--hostname','-H', nargs=1, metavar='str', required=True)
    parser.add_argument('--community','-c', nargs=1, default='public', metavar='str', required=True)
    parser.add_argument('--interface', '-i', nargs=1, type=int, metavar='N',help='Please specify interface')
    parser.add_argument('--print_interfaces', '-pi', action='store_true', help='Print all interface')
    parser.add_argument('--skipError', '-sE', action='store_true', help='Skip version mismatch error')
    parser.add_argument('--timeout', '-t', nargs=1, type=int, metavar='N', default=[TIMEOUT], help='Please specify SNMP timeout in seconds. Default: 10')
    parser.add_argument('--warning', '-W', nargs=1, type=int, metavar='N', help='Please specify Warning. e.g. 80')
    parser.add_argument('--critical', '-C', nargs=1, type=int, metavar='N', help='Please specify Critical. e.g. 90')
    return parser.parse_args()

# Calculate the bandwidth used
def halfDuplex(d1, d2, diffSeconds):
    diffInOctetc = int(d1['ifInOctets']) + int(d2['ifInOctets'])
    diffOutOctet = int(d1['ifOutOctets']) + int(d2['ifOutOctets'])
    ifSpeed = int(d1['ifSpeed'])
    return float(((diffInOctetc + diffOutOctet) * 8 * 100) / (diffSeconds * ifSpeed)) / float(100)

# Translate the bps into Mbps and Gbps for bandwidth
def speedP(x):
    if int(x) >= 1000000000:
        speed='{} Gbps'.format((int(x) / 1000000000))
    elif int(x) >= 1000000:
        speed='{} Mbps'.format((int(x) / 1000000))
    else:
        speed=x
    return speed

# Print the SNMP interfaces
def printInterfaces(d1, returnInterface=False):
    if returnInterface:
        array, perf =[], []
        for k, v in d1.items():
            speed=speedP(v['ifSpeed'])
            array.append('{}: {} ({})'.format(v['ifName'], speed, v['ifOperStatus']))
            perf.append('"{}({})"={}'.format(v['ifName'], v['ifAlias'], 1 if v['ifOperStatus'] == 'up' else 0))
        print('OKAY - {}/{} interfaces up/down. {} | {}'.format(
            len([x for x in array if '(up)' in x]),
            len([x for x in array if '(down)' in x]),
            ', '.join(array),
            ' '.join(perf)
            )
        )
        exit(0)
    try:
        lenOfIndex = [k for k in d1]
        lenOfIndex.sort()
        printFormat='| {:%s}  | {:15}|  {:10}|  {:6} | {:15} |' % len(str(lenOfIndex[-1]))
        printFormatHeader='| {:%s}  | {:15}|  {:10}|  {:6} | {:15} |' % len(str(lenOfIndex[-1]))
        print('------------------------------------------------------------------------')
        print(printFormatHeader.format('Interface','Name','Speed','Status','Alias'))
        print('------------------------------------------------------------------------')
        for k, v in d1.items():
            speed=speedP(v['ifSpeed'])
            print(printFormat.format(k, v['ifName'], speed, v['ifOperStatus'], v['ifAlias']))
        print('------------------------------------------------------------------------')
        exit(0)
    except Exception:
        print('UNKOWN - Something went wrong and I cannot print the interfaces')
        exit(3)

def main():
    # Get user input
    args = parse_args()

    # Check device type
    deviceType = get_snmpOid(args.community[0], args.hostname[0], args.timeout[0], 'sysDescr.0')
    try:
        device = re.match(PATTERN2, deviceType).groups()[0]
    except Exception:
        nagios('Device description doesn\'t match a Palo Alto Firewall. Instead returned: {}'.format(deviceType[23:]),3)
    
    if device not in TYPES:
        if not args.skipError:
            print('Your device: {}'.format(device))
            nagios('Device type doesn\'t match compatible type: {}. To override this error, add the flag -sE or --skipError'.format(', '.join(TYPES)),3)
    
    # Get SNMP data
    result1 = get_snmpOid(args.community[0], args.hostname[0], args.timeout[0])
    d1 = sortSNMP(result1) # Sort through SNMP data

    # Check print interfaces
    if args.print_interfaces:
        printInterfaces(d1)
    
    # Wait for next poll
    sleep(SNMPINTERVAL)

    # Get the SNMP result again
    result2 = get_snmpOid(args.community[0], args.hostname[0], args.timeout[0])
    d2 = sortSNMP(result2) # Sort through SNMP data

    if args.interface:
        # Manual interface selection
        bandwidth=halfDuplex(d1[args.interface[0]], d2[args.interface[0]], SNMPINTERVAL)

        # data
        data = dict(
            ifIpOrName=d1[args.interface[0]]['ifName'],
            speed=speedP(d1[args.interface[0]]['ifSpeed']),
            bandwidth='{}%'.format(bandwidth),
            errorIn=int(d2[args.interface[0]]['ifInErrors']) - int(d1[args.interface[0]]['ifInErrors']),
            errorOut=int(d2[args.interface[0]]['ifOutErrors']) - int(d1[args.interface[0]]['ifOutErrors']),
            mtuPackets=d1[args.interface[0]]['ifMtu'],
            ipStatus=d1[args.interface[0]]['ifOperStatus']
        )

        # Performace data
        data['perf'] = '| bandwidth={} errorIn={} errorOut={} Mtu={}'.format(data['bandwidth'], data['errorIn'], data['errorOut'], data['mtuPackets'])

        # If interface is down
        if data['ipStatus'] != 'up':
            nagios(NAGIOS.format(**data),2)
        
        # If critical is provided
        try:
            args.critical[0]
            if bandwidth >= args.critical[0]:
                nagios(NAGIOS.format(**data),2)
        except Exception:
            pass
        
        # If warning is provided
        try:
            args.warning[0]
            if bandwidth >= args.warning[0]:
                nagios(NAGIOS.format(**data),1)
        except Exception:
            pass

        # No thresholds provided
        nagios(NAGIOS.format(**data),0)
    else:
        # Initialise variables
        interfaces={}
        bandwidth={}
        lan_ids, wan_ids, perf, begin, down = [], [], [], [], []

        # Loop through the interfaces and try to find LAN/WAN
        for x, k in d1.items():
            if 'LAN' in k['ifAlias']:
                lan_ids.append(x)
            if 'WAN' in k['ifAlias']:
                wan_ids.append(x)
            
            if 'LAN' in k['ifAlias'] or 'WAN' in k['ifAlias']:
                try:
                    interfaces[x]['ifAlias'] = k['ifAlias']
                except Exception:
                    interfaces[x] = {}
                    interfaces[x]['ifAlias'] = k['ifAlias']
        
        # If no interfaces were found the user will need to specify an interface 
        if not interfaces:
            printInterfaces(d1, returnInterface=True)
        
        # Loop through the interfaces and retireve the attributes
        for x in interfaces:
            alias=d1[x]['ifAlias'].replace(' ','_')
            bandwidth[x] = {}
            bandwidth[x]['bandwidth']=halfDuplex(d1[x], d2[x], SNMPINTERVAL)
            begin.append('{}({}): {}% {}'.format(alias,speedP(d1[x]['ifSpeed']),bandwidth[x]['bandwidth'], d1[x]['ifOperStatus']))
            perf.append('{}_bandwidth={}%'.format(alias,bandwidth[x]['bandwidth']))
            if d1[x]['ifOperStatus'] != 'up':
                down.append(True)
            #perf.append('{}_errorIn={}'.format(alias, int(d2[x]['ifInErrors']) - int(d1[x]['ifInErrors'])))
            #perf.append('{}_errorOut={}'.format(alias, int(d2[x]['ifOutErrors']) - int(d1[x]['ifOutErrors'])))
            #perf.append('{}_Mtu={}'.format(alias, d1[x]['ifMtu']))
        
        msg = '{} | {}'.format(', '.join(begin), ' '.join(perf))

        # Try looking for LAN connections
        try:   
            bandwidth_lan=[bandwidth[x]['bandwidth'] for x in lan_ids]
            calc_lan=sum(bandwidth_lan) / len(bandwidth_lan)
            perf.append('LAN={}%'.format(calc_lan))
        except Exception:
            pass
        
        # Try looking for WAN connections
        try:
            bandwidth_wan=[bandwidth[x]['bandwidth'] for x in wan_ids]
            calc_wan=sum(bandwidth_wan) / len(bandwidth_wan)
            perf.append('WAN={}%'.format(calc_wan))
        except Exception:
            pass

        # Catch if interface is down
        if down:
            nagios(msg,2)

        # If critical is provided
        try:
            args.critical[0]
            if calc_wan >= args.critical[0] or calc_lan >= args.critical[0]:
                nagios(msg,2)
        except Exception:
            pass
        
        # If warning is provided
        try:
            args.warning[0]
            if calc_wan >= args.warning[0] or calc_lan >= args.warning[0]:
                nagios(msg,1)
        except Exception:
            pass
        
        # Finish
        nagios(msg,0)
         
    

if __name__ == '__main__':
    main()