#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This software must not be used by military or secret service organisations.
# License: TODO
# TODO: PEP 8

import sys, argparse
from libnmap.parser import NmapParser

greeter = '''
 ▐ ▄ • ▌ ▄ ·.  ▄▄▄·  ▄▄▄·    .▄▄▄  ▄• ▄▌▄▄▄ .▄▄▄   ▄· ▄▌    ▐▄• ▄ • ▌ ▄ ·. ▄▄▌  
•█▌▐█·██ ▐███▪▐█ ▀█ ▐█ ▄█    ▐▀•▀█ █▪██▌▀▄.▀·▀▄ █·▐█▪██▌     █▌█▌▪·██ ▐███▪██•  
▐█▐▐▌▐█ ▌▐▌▐█·▄█▀▀█  ██▀·    █▌·.█▌█▌▐█▌▐▀▀▪▄▐▀▀▄ ▐█▌▐█▪     ·██· ▐█ ▌▐▌▐█·██▪  
██▐█▌██ ██▌▐█▌▐█ ▪▐▌▐█▪·•    ▐█▪▄█·▐█▄█▌▐█▄▄▌▐█•█▌ ▐█▀·.    ▪▐█·█▌██ ██▌▐█▌▐█▌▐▌ NEW VERSION
▀▀ █▪▀▀  █▪▀▀▀ ▀  ▀ .▀       ·▀▀█.  ▀▀▀  ▀▀▀ .▀  ▀  ▀ •     •▀▀ ▀▀▀▀  █▪▀▀▀.▀▀▀ '''
for c in "█▐▌▄▀":
    greeter = greeter.replace(c, "\u001b[32m" + c + "\u001b[0m")
version = "0.0.3#beta"
url = "https://github.com/honze-net/nmap-query-xml"

help="""Pattern for output mkdir -p ~/project/{ip}/{protocol}/{port}
{hostname} - The first hostname of a list of hostnames (nmap could have detected more via rDNS). If no hostname was detected, the IP will be used.
{hostnames} - Comma separated list of all hostnames. If no hostname was detected, the IP will be used.
{ip} - The IP address of the host.
{port} - The port number.
{protocol} - The protocol used (mostly tcp or udp).
{s} - This a flag for SSL/TLS tunnel usage. It is s if SSL/TLS is used and  otherwise.
{service} - The service name discovered by nmap. Sometimes https is discovered as http with the SSL/TLS flag. Use {service}{s} then.
{state} - The port state nmap discovered (open, closed, filtered, etc.).
{xmlfile} - The file name (supplied as argument). Great for searching a lot of xml files for a specific host for example.
{scripts_results} - All script result
{baner} - Service banner
Default: %(default)s"""


help="""


"""

parser = argparse.ArgumentParser(description="", epilog="Full documentation: %s\nThis software must not be used by military or secret service organisations." % url, formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument("xml", help="path to Nmap XML file", nargs='+')
parser.add_argument("--service", help="Nmap service name to filter for. Default: Empty", default="", dest="service")
parser.add_argument("--pattern", help="Output tipe {service}{s}://{ip}:{port} {os}", default="{service}{s}://{ip}:{port}", dest="pattern")
parser.add_argument("--state", help="Select a port state. Use \"all\" for all. Default: %(default)s", default="open", dest="state")
parser.add_argument("--ports", help="Nmap ports to filter for. Default: Empty", default="", dest="ports")
parser.add_argument("--os", help="Nmap os summary Default: Empty", default="", dest="os")


if len(sys.argv) == 1: # If no arguments are specified, print greeter, help and exit.
    print(greeter)
    print(("version %s %s\n" % (version, url)).center(80))
    parser.print_help()
    sys.exit(0) 
args = parser.parse_args()

check_list = isinstance(args.xml, list)


mparsers=[]

if check_list:
    for i in args.xml:
        r1 = NmapParser.parse_fromfile(i)
        mparsers.append(r1)
    for i in mparsers:
        print(i.hosts[0].address)


else:
    try:
        r1 = NmapParser.parse_fromfile(args.xml)
        mparsers.append(r1)
    except IOError:
        print("Error: File %s not found." % args.xml)
        sys.exit(1)




#print("Host total: ",report.hosts_total)
#print("Host up: ",report.hosts_up)
#print(report.summary)

for report in mparsers:
    for host in report.hosts:    
        for service in host.services:
            if (args.service == "" or service.service in args.service.split(",")) and (args.ports == "" or str(service.port) in args.ports.split(",")) and (service.port != ""): # TODO: Test if this is precise enough
                line = args.pattern
                line = line.replace("{hostname}", host.address if not host.hostnames else host.hostnames[0]) # TODO: Fix naive code.
                line = line.replace("{hostnames}", host.address if not host.hostnames else ", ".join(list(set(host.hostnames)))) # TODO: Fix naive code.
                line = line.replace("{ip}", host.address)
                line = line.replace("{service}", service.service)
                line = line.replace("{s}", "s" if service.tunnel == "ssl" else "")
                line = line.replace("{protocol}", service.protocol)
                line = line.replace("{banner}", service.banner.replace("product:",""))
                line = line.replace("{port}", str(service.port))
                line = line.replace("{state}", str(service.state))
                print("%s" % line)

