#!/usr/bin/env python3.7

from lib.host import *
import subprocess as sp
import xml.etree.cElementTree as xml # for parsing Nmap output

# by TheTechromancer

class Nmap:

    def __init__(self, targets_file, work_dir):

        self.process            = None
        self.output_file        = str(work_dir / 'nmap_ms17-010')
        self.finished           = False
        self.targets_file       = str(targets_file)

        self.hosts              = dict()


    def __iter__(self):
        '''
        Yields IP and boolean representing whether or not it's vulnerable
        '''

        if not self.finished:

            command = ['nmap', '-p445', '-T5', '-n', '-Pn', '-v', '-sV', \
                '--script=smb-vuln-ms17-010', '-oA', self.output_file, \
                '-iL', self.targets_file]

            print('\n[+] Running nmap:\n\t> {}\n'.format(' '.join(command)))

            try:
                self.process = sp.run(command, check=True)
            except sp.CalledProcessError as e:
                sys.stderr.write('[!] Error launching nmap: {}\n'.format(str(e)))
                sys.exit(1)

            print('\n[+] Finished Nmap scan')

            # parse xml
            tree = xml.parse(self.output_file + '.xml')

            for host in tree.findall('host'):
                pass

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
                    self.hosts[ip] = Host(ip)
                    for hostscript in host.findall('hostscript'):
                        for script in hostscript.findall('script'):
                            if script.attrib['id'] == 'smb-vuln-ms17-010' and 'VULNERABLE' in script.attrib['output']:
                                self.hosts[ip]['Vulnerable to EternalBlue'] = 'Yes'
                                yield (ip, True)
                            else:
                                self.hosts[ip]['Vulnerable to EternalBlue'] = 'No'
                                yield (ip, False)

            self.finished = True

        else:
            for ip, host in self.hosts.items():
                yield (ip, host['Vulnerable to EternalBlue'] == 'Yes')

        print('[+] Saved Nmap results to {}.*'.format(self.output_file))
