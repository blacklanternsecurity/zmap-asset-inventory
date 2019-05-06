#!/usr/bin/env python3.7

import io
import ipaddress
from .base_module import *
from time import sleep
import subprocess as sp
from pathlib import Path
from signal import SIGINT
from datetime import datetime

patator_default_work_dir = (Path.home() / '.asset_inventory/cache/patator').resolve()


class Module(BaseModule):

    name            = 'default_ssh'
    csv_headers     = ['Default SSH Login']
    required_ports  = [22]
    required_progs  = ['patator']

    def __init__(self, inventory):

        super().__init__(inventory)

        self.port = 22
        self.threads = 80
        self.num_targets = 0

        # file containing usernames and passwords to try (colon-delimited)
        self.creds_file = Path(__file__).resolve().parent / 'ssh_creds.txt'

        # log file for patator stdout
        patator_log_filename = 'patator_log_{date:%Y-%m-%d_%H-%M-%S}'.format(date=datetime.now())
        self.patator_log_file = self.work_dir / patator_log_filename

        # file for patator valid username/password pairs
        patator_valid_creds = 'patator_valid_creds_{date:%Y-%m-%d_%H-%M-%S}'.format(date=datetime.now())
        self.patator_valid_creds = self.work_dir / patator_valid_creds

        # file containing target IPs
        targets_filename = 'patator_targets_{date:%Y-%m-%d_%H-%M-%S}'.format(date=datetime.now())
        self.targets_file = self.work_dir / targets_filename

        # variable for running patator process
        self.patator_process = None


    def run(self, inventory):

        # write targets to file
        with open(self.targets_file, 'w') as f:
            for host in inventory:
                if self.port in host.open_ports:
                    self.num_targets += 1
                    f.write(host['IP Address'] + '\n')

        if self.num_targets <= 0:
            print('\n[+] No valid targets for Patator scan')

        else:

            try:

                patator_command = ['patator', 'ssh_login', '--threads={}'.format(self.threads), \
                    'user=COMBO00', 'password=COMBO01', 'host=FILE1', 
                    '--max-retries=2', '0={}'.format(self.creds_file),\
                    '1={}'.format(self.targets_file)]

                print('\n[+] Running patator against {:,} targets:\n\t> {}\n'.format(self.num_targets, ' '.join(patator_command)))

                if self.patator_process is None:
                    self.patator_process = sp.Popen(patator_command, stdout=sp.PIPE, stderr=sp.PIPE)
                    sleep(2)

                    with open(self.patator_valid_creds, 'w') as valid_creds_file:
                        with open(self.patator_log_file, 'w') as log_file:
                            for line in io.TextIOWrapper(self.patator_process.stderr, encoding='utf-8'):
                                # pass through stdout to log
                                log_file.write(line)
                                line = ''.join(line.split('patator')[1:]).strip()
                                print('\r{}'.format(line), end='')
                                if 'INFO - 0' in line:
                                    valid_creds_file.write(line)
                                    print('\r' + line)
                                    #try:
                                    cred_str = line.split()[6]
                                    creds = ':'.join(cred_str.split(':')[:2])
                                    ip = ipaddress.ip_address(cred_str.split(':')[-1])
                                    inventory.hosts[ip].update({'Default SSH Login': creds})
                                    #except ValueError:
                                    #    continue

                    self.patator_process = None

                else:
                    raise PatatorError('Patator is already running')

            except KeyboardInterrupt:
                print('\n\n[!] Cancelling Patator scan, please wait')
                try:
                    self.patator_process.send_signal(SIGINT)
                    sleep(1)
                    self.patator_process.send_signal(SIGINT)
                    sleep(1)
                    self.patator_process.terminate()
                except AttributeError:
                    pass



    def report(self, inventory):

        valid_creds = dict()
        for host in inventory:
            try:
                creds = host['Default SSH Login']
                if ':' in creds:
                    valid_creds[host.ip] = creds
            except KeyError:
                pass

        if valid_creds:
            print('[+] {:,} system(s) with default SSH logins:\n\t'.format(len(valid_creds)), end='')
            print('\n\t'.join(['{} - {}'.format(ip, cred) for ip, cred in list(valid_creds.items())]))
        else:
            print('[+] No systems found with default SSH credentials')
        print('')



    def read_host(self, csv_line, host):

        try:
            vulnerable = csv_line['Default SSH Login']
        except KeyError:
            vulnerable = ''

        host.update({'Default SSH Login': vulnerable})