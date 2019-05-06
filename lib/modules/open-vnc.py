#!/usr/bin/env python3

# by TheTechromancer

import sys
import ipaddress
from .base_module import *
import subprocess as sp
from shutil import which
from datetime import datetime
import xml.etree.cElementTree as xml # for parsing Nmap output



class Module(BaseModule):

    name            = 'check_open_vnc'
    csv_headers     = ['Open VNC']
    required_ports  = [5900, 5902]
    required_progs  = ['nmap', 'vncsnapshot']

    def __init__(self, inventory):

        super().__init__(inventory)


    def run(self, inventory):

        # run nmap, once for each required port

        # {ip: [ports, with, open, vnc]}
        vulnerable_hosts = dict()

        for port in self.required_ports:

            valid_targets = 0

            targets_file = str(self.work_dir / 'open_vnc_targets_{}_{date:%Y-%m-%d_%H-%M-%S}'.format(port, date=datetime.now()))
            output_file = str(self.work_dir / 'open_vnc_nmap_{}_{date:%Y-%m-%d_%H-%M-%S}'.format(port, date=datetime.now()))

            with open(targets_file, mode='w') as f:
                for host in inventory:
                    if port in host.open_ports:
                        try:
                            if host['Open VNC'].lower() in ['yes', 'no']:
                                continue
                        except KeyError:
                            pass

                        f.write(host['IP Address'] + '\n')
                        valid_targets += 1
        
            if valid_targets <= 0:
                print('\n[+] No systems to scan for open VNC on port {}'.format(port))

            else:
                print('\n[+] Scanning {:,} systems for open VNC on port {}\n'.format(valid_targets, port))

                command = ['nmap', '-p{}'.format(port), '-T4', '-n', '-Pn', '-v', '-sV', \
                    '--script=vnc-info', '-oA', output_file, \
                    '-iL', targets_file]

                try:
                    self.process = sp.run(command, check=True)
                except sp.CalledProcessError as e:
                    sys.stderr.write('[!] Error launching Nmap: {}\n'.format(str(e)))
                    sys.exit(1)

                # parse xml
                tree = xml.parse(output_file + '.xml')

                for host in tree.findall('host'):

                    ip = None
                    for address in host.findall('address'):
                        if address.attrib['addrtype'] == 'ipv4':
                            try:
                                ip = ipaddress.ip_address(address.attrib['addr'])
                            except ValueError:
                                continue
                            break

                    if ip is None:
                        continue

                    else:
                        for nmap_ports in host.findall('ports'):
                            for nmap_port in nmap_ports.findall('port'):
                                for script in nmap_port.findall('script'):
                                    if script.attrib['id'] == 'vnc-info':
                                        if 'does not require auth' in script.attrib['output']:
                                            inventory.hosts[ip].update({'Open VNC': 'Yes'})
                                            try:
                                                vulnerable_hosts[ip].add(port)
                                            except KeyError:
                                                vulnerable_hosts[ip] = {port,}

                print('[+] Saved Nmap VNC results to {}.*'.format(output_file))


        if vulnerable_hosts:
            # try and take a screenshot of each one
            print('\n[+] Attempting VNC screenshots:')

            for ip, ports in vulnerable_hosts.items():
                for port in ports:

                    filename = self.work_dir / 'vnc_{}_{}_screenshot.jpg'.format(ip, port)

                    vnc_command = ['vncsnapshot', '-allowblank', '-cursor', '-quality', '75', '{}::{}'.format(ip, port), str(filename)]                    
                    print('\t> {}'.format(' '.join(vnc_command)))

                    try:
                        process = sp.run(vnc_command, stdout=sp.DEVNULL, stderr=sp.DEVNULL, timeout=15)

                    except sp.TimeoutExpired:
                        sys.stderr.write('[!] VNC screenshot timed out on {}\n'.format(ip))

                    if filename.is_file():
                        print('[+] Screenshot saved to {}'.format(filename))



    def report(self, inventory):

        vulnerable_hosts = []
        for host in inventory:
            try:
                if host['Open VNC'].lower().startswith('y'):
                    vulnerable_hosts.append(host)
            except KeyError:
                pass

        if vulnerable_hosts:
            print('[+] {:,} system(s) with Open VNC:\n\t'.format(len(vulnerable_hosts)), end='')
            print('\n\t'.join([str(h) for h in vulnerable_hosts]))
        else:
            print('[+] No systems found with open VNC')
        print('')



    def read_host(self, csv_line, host):

        vulnerable = 'N/A'
        try:
            c = csv_line['Open VNC'].strip()
            if c:
                vulnerable = c
        except KeyError:
            pass

        host.update({'Open VNC': vulnerable})