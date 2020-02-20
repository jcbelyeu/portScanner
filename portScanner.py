#!/usr/bin/python

from sys import argv
import os.path
import argparse
import ipaddress
from scapy.all import*
from scapy import route
from scapy.layers.inet import Ether,IP,UDP
from scapy.layers.inet import TCP
from scapy.layers.inet import IP
from scapy.layers.inet import UDP
from scapy.layers.inet import ICMP

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

def get_user_defined_ips(argument):
    destination_list = []
    if ',' in argument:
        for x in argument.split(','):
            if '/' in x:
                for y in ipaddress.IPv4Network(x, strict=False):
                    destination_list.append(str(y))
            elif '-' in x:
                for y in find_hyphen_ip_addresses(x):
                    destination_list.append(y)
            else:
                destination_list.append(x)
    return destination_list

def port_handle_commas(argument):
    argument = ''.join(argument.split())
    port_list = []
    extra_symbols = []
    if ',' in argument:
        for y in argument.split(','):
            port_list.append(y)
    for y in port_list:
        if '-' in y:
            extra_symbols.append(y)
            for z in port_handle_dashes(y):
                port_list.append(z)
    for i in extra_symbols:
        port_list.remove(i)
    return port_list

def port_handle_dashes(argument):
    port_list = []
    temp_list = []
    if '-' in argument:
        for y in argument.split('-'):
            temp_list.append(y)
        if len(temp_list) != 2:
            raise NameError('Bad syntax in ports specified')
        else:
            for z in range(int(temp_list[0]), int(temp_list[1])):
                port_list.append(str(z))
    return port_list

def find_hyphen_ip_addresses(argument):
    parsed_list = []
    addr_list = []
    first_octet = 0
    second_octet = 1
    third_octet = 2
    fourth_octet = 3
    range_modifier = 4
    for x in argument.split('-'):
        for y in x.split('.'):
            parsed_list.append(y)
    for x in range(int(parsed_list[fourth_octet]), int(parsed_list[range_modifier]) + 1):
        addr_list.append(str(parsed_list[first_octet]) + "." + str(parsed_list[second_octet])
                         + "." + str(parsed_list[third_octet]) + "." + str(x))
    return addr_list

def run_tcp_scan(list_hosts, list_ports):
    for ip in list_hosts:
        print("Performing TCP scan on host " + ip)
        dst_ip = ip
        for target_port in list_ports:
            src_port = RandShort()
            dst_port = int(target_port)
            timeout = 10;
            tcp_syn_req = sr1(IP(dst=dst_ip)/TCP(sport=src_port, dport=dst_port, flags="S"), timeout=timeout, verbose=0)
            if "NoneType" in str(type(tcp_syn_req)):
                print("Port " + str(dst_port) + " Closed")
            elif tcp_syn_req.haslayer(TCP):
                if tcp_syn_req.getlayer is None:
                    print("Port " + str(dst_port) + " Closed")
                elif tcp_syn_req.getlayer(TCP).flags == 0x12:
                    send_rst = sr(IP(dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags="AR"), timeout=timeout, verbose=0)
                    print("Port " + str(dst_port) + " Open")
                elif tcp_syn_req.getlayer(TCP).flags == 0x14:
                    print("Port " + str(dst_port) + " Closed")
            else:
                print("Error, improper state for port " + str(dst_port))

def run_udp_scan(list_hosts, list_ports):
    for ip in list_hosts:
        print("Performing UDP scan on host " + ip)
        dst_ip = ip
        for target_port in list_ports:
            src_port = RandShort()
            dst_port = int(target_port)
            timeout = 10;
            udp_pkg = sr1(IP(dst=dst_ip)/UDP(sport=src_port,dport=dst_port),timeout=timeout, verbose=0)
            if udp_pkg is None:
                print("Port " + str(dst_port) + " is Open/filtered")
            else:
                if udp_pkg.haslayer(ICMP):
                    print("Port " + str(dst_port) + " is Closed")
                elif udp_pkg.haslayer(UDP):
                    print("Port " + str(dst_port) + " is Open/filtered")
                else:
                    print("Port " + str(dst_port) + " is Unknown")

def run_icmp_scan(list_hosts):
    timeout = 2;
    for ip in list_hosts:
        icmp_pkt = sr1(IP(dst=str(ip))/ICMP(),timeout=timeout, verbose=0,)
        if icmp_pkt is None:
            print("Host " + str(ip) + " may not exist or isn't responding")
        elif int(icmp_pkt.getlayer((ICMP).type)==3 and int(icmp_pkt.getlayer(ICMP).code) in [1,2,3,9,10,13]):
            print("Host " + str(ip) + " is blocking ICMP")
        else:
            print("Host " + str(ip) + " is alive")

#parse out all flags accepted when script is run
parser = argparse.ArgumentParser()
parser.add_argument('-d','--destination', type=str, help='Specify target destinations (IP addresses) for scan')
parser.add_argument('-p', '--port', type=str, help='Specify ports to scan')
parser.add_argument('-hf', '--hostFile', type=str, help='Pass in file of hosts to scan')
parser.add_argument('-t','--tcp', action='store_true', help='Specify to perform TCP scan on targets')
parser.add_argument('-u','--udp', action='store_true', help='Specify to perform UDP scan on targets')
parser.add_argument('-i','--icmp', action='store_true', help='Specify to perform ICMP scan on targets')
args = parser.parse_args()
#helpful link, introduced me to argparse https://stackoverflow.com/questions/32286403/how-to-implement-command-line-switches-to-my-script

#Catch no hosts specified
if not args.hostFile and not args.destination:
    raise NameError('No hosts specified. Please specify hosts to scan with with -hf or -d')

#Gather all IP addresses to be scanned into set
allHostsToScan = set()
userDefinedHosts = ""
if args.destination:
    userDefinedHosts = args.destination
if args.hostFile:
    print("hosts file being read...")
    with open(args.hostFile, 'r') as file:
        if not userDefinedHosts == "":
            userDefinedHosts = userDefinedHosts + "," + file.read().replace(" ","")
        else:
            userDefinedHosts = file.read().replace(" ","")
userDefinedHosts =''.join(userDefinedHosts.split())
if "," in userDefinedHosts:
    for addr in get_user_defined_ips(userDefinedHosts):
        allHostsToScan.add(addr)
elif "/" in userDefinedHosts:
    for addr in ipaddress.IPv4Network(userDefinedHosts, strict=False):
        allHostsToScan.add(str(addr))
elif "-" in userDefinedHosts:
    for addr in find_hyphen_ip_addresses(userDefinedHosts):
        allHostsToScan.add(addr)
else:
    allHostsToScan.add(userDefinedHosts)
if args.destination or args.hostFile:
    print("host(s) specified " + userDefinedHosts)


#Parse out all user-defined ports, and store in set
if args.port:
    print("Destination port(s) " + args.port)
allPortsToScan = set()
userDefinedPorts = args.port
if "," in userDefinedPorts:
    for port in port_handle_commas(userDefinedPorts):
        allPortsToScan.add(port)
elif '-' in userDefinedPorts:
    userDefinedPorts = ''.join(userDefinedPorts.split())
    for port in port_handle_dashes(userDefinedPorts):
        allPortsToScan.add(port)
else:
    allPortsToScan.add(userDefinedPorts)

#run scans as specified by user
if len(userDefinedHosts) > 0 and len(userDefinedPorts) > 0:
    if args.tcp:
        print("TCP scan")
        run_tcp_scan(allHostsToScan, allPortsToScan)
    if args.udp:
        print("UDP scan")
        run_udp_scan(allHostsToScan, allPortsToScan)
if len(userDefinedHosts) > 0 and args.icmp:
    print("ICMP scan")
    run_icmp_scan(allHostsToScan)