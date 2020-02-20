# portScanner

Simple PortScanning (Python 3.7)

portScanner.py provides basic scanning functionality for the follow protocols:
- ICMP
- UDP
- TCP

Port scanner is called from the terminal, and accepts commandline arguments through flags.

# CLI Flags

'-d', '--destination': Specify target destinations (ip addresses of hosts you would like to scan). Acceptable synax for input are ip addresses seperated by commas (e.g., x.x.x.x,x.x.x.x,...), ip addresses within quotes separated by commas and spaces ("x.x.x.x, x.x.x.x, x.x.x.x"), / style addresses (x.x.x.x/24), ip ranges in the last quartet (x.x.x.100-150), and combinations of these methods ("x.x.x.x, x.x.x.x/24, x.x.x.6-60").

'-p', '--port': Specify which ports to scan on a target host. Acceptable formats for passing in ports include: ports as a comma-separated list (80,443,66,8080 or "80, 443, 66, 8080"), a range (200-250), or a combination ("80, 443, 60-99, 8080").

'-hf', '--hostFile': Specify the path to a file containing host IPs, instead of or in addition to specifying hosts with --destination. This file should follow the same syntax as described for --destination.

'-t','--tcp': flag to require TCP scan of all ports and IP combinations.

'-u','--udp': flag to require UDP scan of all ports and IP combinations.

'-i','--icmp': flag to require ICMP scan of all IP addresses.

'-h', '--help': flag to show help comments for all flags.

Example commands: 

portScanner.py -d 192.168.100.44 -p 80,443,8080 -t -u

Scan TCP and UDP ports 80,443, and 8080 for host 192.168.100.44.

portScanner.py -d 192.168.100.3/24 -p 8080-10000 -t -i

Scan hosts in the 192.168.100.0/24 subnet (.0 on the last quartet is not strictly enforced) on all ports from 8080-10000 for listening TCP ports (not recommended, would be extremely time-consuming) and ping all these hosts with ICMP packets. 

portScanner.py -hf hosts.txt -u -p 22,2000,3030

Scan all hosts listed in the file hosts.txt for listening UDP ports on 22, 2000, and 3030. 
