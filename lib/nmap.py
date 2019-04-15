#!/usr/bin/env python3.7

import string
from lib.host import *
import subprocess as sp
import xml.etree.cElementTree as xml # for parsing Nmap output

# by TheTechromancer

class Nmap:

    def __init__(self, targets_file, work_dir, check='eternalblue'):

        self.check              = ''.join([c for c in check.strip().lower() if c in string.ascii_lowercase + string.digits])
        if not self.check in ['eternalblue', 'vnc']:
            raise ValueError('invalid nmap scan type "{}", please specify either "eternalblue" or "vnc"'.format(str(self.check)))

        self.process            = None
        self.finished           = False
        self.targets_file       = str(targets_file)
        self.output_file        = str(work_dir / 'nmap_{}_{date:%Y-%m-%d_%H-%M-%S}'.format(check, date=datetime.now()))

        self.hosts              = dict()


    def __iter__(self):
        '''
        Yields IP and boolean representing whether or not it's vulnerable
        '''

        if self.check == 'eternalblue':
            for i in self.check_eternal_blue():
                yield i
        elif self.check == 'vnc':
            for i in self.check_vnc():
                yield i

        print('[+] Saved Nmap results to {}.*'.format(self.output_file))


    def check_eternal_blue(self):

        if not self.finished:

            command = ['nmap', '-p445', '-T5', '-n', '-Pn', '-v', '-sV', \
                '--script=smb-vuln-ms17-010', '-oA', self.output_file, \
                '-iL', self.targets_file]

            print('\n[+] Checking for EternalBlue with Nmap:\n\t> {}\n'.format(' '.join(command)))

            try:
                self.process = sp.run(command, check=True)
            except sp.CalledProcessError as e:
                sys.stderr.write('[!] Error launching Nmap: {}\n'.format(str(e)))
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


    def check_vnc(self):

        # check to make sure script is installed
        vncsnapshot_url = 'https://raw.githubusercontent.com/eelsivart/vnc-screenshot/master/vnc-screenshot.nse'
        vncsnapshot_script = Path('/usr/share/nmap/scripts/vnc-screenshot.nse')

        if not vncsnapshot_script.is_file():
            vncsnapshot_install_command = ['wget', '-O', str(vncsnapshot_script), vncsnapshot_url]
            print('[+] Installing vncsnapshot NSE script:\n\t> {}\n'.format(' '.join(vncsnapshot_install_command)))
            sp.run(vncsnapshot_install_command)


        update_nmap_scripts_command = ['nmap', '--script-updatedb']
        print('[+] Updating Nmap script database:\n\t> {}\n'.format(' '.join(update_nmap_scripts_command)))
        sp.run(update_nmap_scripts_command)        

        if not self.finished:

            command = ['nmap', '-p5900,5902', '-T5', '-n', '-Pn', '-v', '-sV', \
                '--script=vnc-screenshot', '-oA', self.output_file, \
                '-iL', self.targets_file]

            print('\n[+] Checking for open VNC with Nmap:\n\t> {}\n'.format(' '.join(command)))

            try:
                self.process = sp.run(command, check=True)
            except sp.CalledProcessError as e:
                sys.stderr.write('[!] Error launching Nmap: {}\n'.format(str(e)))
                sys.exit(1)

            print('\n[+] Finished VNC Nmap scan')

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
                    self.hosts[ip] = Host(ip)
                    for hostscript in host.findall('hostscript'):
                        for script in hostscript.findall('script'):
                            if script.attrib['id'] == 'vnc-screenshot' and 'saved to' in script.attrib['output']:
                                print('[+] {}'.format(script.attrib['output']))
                                self.hosts[ip]['Open VNC'] = 'Yes'
                                yield (ip, True)
                            else:
                                self.hosts[ip]['Open VNC'] = 'No'
                                yield (ip, False)

            self.finished = True

        else:
            for ip, host in self.hosts.items():
                yield (ip, host['Open VNC'] == 'Yes')