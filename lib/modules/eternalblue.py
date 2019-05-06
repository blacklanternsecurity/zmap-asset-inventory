#!/usr/bin/env python3.7

import string
import ipaddress
from .base_module import *
import subprocess as sp
from datetime import datetime
import xml.etree.cElementTree as xml # for parsing Nmap output

# by TheTechromancer

class Module(BaseModule):

    name            = 'eternalblue'
    csv_headers     = ['Vulnerable to EternalBlue']
    required_ports  = [445]
    required_progs  = ['nmap']

    def __init__(self, inventory):

        super().__init__(inventory)

        self.process            = None
        self.targets_file       = str(self.work_dir / 'eternalblue_targets_{date:%Y-%m-%d_%H-%M-%S}'.format(date=datetime.now()))
        self.output_file        = str(self.work_dir / 'eternalblue_results_{date:%Y-%m-%d_%H-%M-%S}'.format(date=datetime.now()))


    def run(self, inventory):

        targets = 0
        with open(self.targets_file, mode='w') as f:
            for host in inventory:
                ip = host.ip
                try:
                    vulnerable = host['Vulnerable to EternalBlue']
                except KeyError:
                    vulnerable = 'N/A'
                inventory.hosts[ip].update({'Vulnerable to EternalBlue': vulnerable})

                if 445 in host.open_ports and not vulnerable.strip().lower() in ['yes', 'no']:
                    targets += 1
                    f.write(str(ip) + '\n')

        if targets <= 0:
            print('\n[!] No valid targets for EternalBlue scan')

        else:

            command = ['nmap', '-p445', '-T4', '-n', '-Pn', '-v', '-sV', \
                '--script=smb-vuln-ms17-010', '-oA', self.output_file, \
                '-iL', self.targets_file]

            print('\n[+] Scanning {:,} systems for EternalBlue:\n\t> {}\n'.format(targets, ' '.join(command)))

            try:
                self.process = sp.run(command, check=True)
            except sp.CalledProcessError as e:
                sys.stderr.write('[!] Error launching EternalBlue Nmap: {}\n'.format(str(e)))
                sys.exit(1)

            print('\n[+] Finished EternalBlue Nmap scan')

            # parse xml
            tree = xml.parse(self.output_file + '.xml')

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
                    for hostscript in host.findall('hostscript'):
                        for script in hostscript.findall('script'):
                            if script.attrib['id'] == 'smb-vuln-ms17-010':
                                if 'VULNERABLE' in script.attrib['output']:
                                    inventory.hosts[ip].update({'Vulnerable to EternalBlue': 'Yes'})
                                else:
                                    inventory.hosts[ip].update({'Vulnerable to EternalBlue': 'No'})

            print('[+] Saved Nmap EternalBlue results to {}.*'.format(self.output_file))


    def report(self, inventory):

        vulnerable_hosts = []
        for host in inventory:
            try:
                if host['Vulnerable to EternalBlue'].lower().startswith('y'):
                    vulnerable_hosts.append(host)
            except KeyError:
                pass

        if vulnerable_hosts:
            print('[+] {} system(s) vulnerable to EternalBlue:\n\t'.format(len(vulnerable_hosts)), end='')
            print('\n\t'.join([str(h) for h in vulnerable_hosts]))
        else:
            print('[+] No systems found vulnerable to EternalBlue')
        print('')


    def read_host(self, csv_line, host):

        try:
            vulnerable = csv_line['Vulnerable to EternalBlue']
        except KeyError:
            vulnerable = 'N/A'

        host.update({'Vulnerable to EternalBlue': vulnerable})