#!/usr/bin/env python3

import os
import json
import configparser
from time import sleep
import subprocess as sp
from shutil import which
from pathlib import Path
import concurrent.futures
from datetime import datetime


def parse_service_config(config_file):

    try:

        config = configparser.ConfigParser()
        config.read(config_file)

        if not config:
            raise KeyError('Error parsing config file')

        # make sure we have credentials
        if not config['CREDENTIALS']['username'] or not config['CREDENTIALS']['password']:
            try:
                ticket_var = Path(os.environ['KRB5CCNAME'])
                ticket = True
            except KeyError:
                print('[!] Username or password missing and no KRB5CCNAME variable found.')
                return

        return config

    except (KeyError, TypeError) as e:
        print('[!] Problem with config file at {}'.format(str(config_file)))
        print('\t' + str(e))



class wmiexec:

    def __init__(self, target, config):

        self.target   = target
        self.username = config['CREDENTIALS']['username']
        self.password = config['CREDENTIALS']['password']
        self.domain   = config['CREDENTIALS']['domain'] 
        self.services = config['SERVICES']

        self.ticket = False
        if not self.username:
            try:
                os.environ['KRB5CCNAME']
                self.ticket = True
            except KeyError:
                raise ValueError('Kerberos ticket not found, please export "KRB5CCNAME" variable')


    def get_services(self):
        '''
        enumerates requested services
        returns tuple (os_name: { service_fname: True|False ... } )
        returns None if no unreachable
        returns empty string if no results
        '''

        service_keywords = set()
        for service_name in self.services.values():
            [service_keywords.add(word) for word in service_name.split()]

        canary = '!@#'
        canary_cmd = 'echo {}'.format(canary)

        win_commands = ['(', canary_cmd, '&', \
        '''reg query "hklm\\software\\microsoft\\windows nt\\currentversion" /v productname''', '&',
        canary_cmd, '&', '''sc query | findstr /i "{}"'''.format(' '.join(service_keywords)), ')']

        stdout,stderr = self.run_wmiexec(' '.join(win_commands))

        if not canary in stdout:
            return None

        else:
            try:
                os_str, svc_str = [[line.strip() for line in chunk.split('\r\n') if line.strip()] for chunk in stdout.split(canary)[1:3]]
            except ValueError:
                return None
            '''
            print('=' * 20)
            print('\n'.join(os_str))
            print('=' * 20)
            print('\n'.join(svc_str))
            print('=' * 20)
            '''

        os_name = ' '.join(os_str[-1].split()[2:])

        services_detected = dict()
        for (fname, sname) in self.services.items():
            sname = sname.upper()

            services_detected[fname] = 'No'

            for s in svc_str:
                svc_name = s.split(':')[-1].strip().upper()
                if sname == svc_name:
                    services_detected[fname] = 'Yes'
                    break

        # print(os_name, services_detected)
        return (os_name, services_detected)

        # echo !@# && reg query "hklm\software\microsoft\windows nt\currentversion" /v productname && echo !@# && sc query | findstr /i data


    def run_wmiexec(self, command, timeout=10):

        if which('wmiexec'):
            wmiexec_script = 'wmiexec'
        elif which('wmiexec.py'):
            wmiexec_script = 'wmiexec.py'
        else:
            print('[+] Unable to find wmiexec in $PATH')
            return

        wmiexec_command = [wmiexec_script, '{}{}:{}@{}'.format( \
            ('{}/'.format(self.domain) if self.domain else ''), \
            self.username, self.password, self.target), command]

        print(' >> ' + ' '.join(wmiexec_command))
        wmiexec_process = sp.run(wmiexec_command, stdout=sp.PIPE, stderr=sp.PIPE)
        return (wmiexec_process.stdout.decode(), wmiexec_process.stderr.decode())

"""
# some random tests

start_time = datetime.now()

c = parse_service_config('services.config')
w = wmiexec('10.0.0.119', c)
print(w.get_services())

'''
with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
    futures = [executor.submit(wmiexec, '1.2.3.4', c, 'Admin', 'asdf') for c in commands]

    for future in concurrent.futures.as_completed(futures):
        print(future.result())
'''

end_time = datetime.now()

print('Time elapsed: {date}'.format( date=(end_time-start_time)))

'''
start_time = datetime.now()
for c in commands:
    print(wmiexec('10.0.0.119', c, 'Admin', 'asdf'))

end_time = datetime.now()
print('Time elapsed: {date}'.format( date=(end_time-start_time)))
'''
"""