#!/usr/bin/env python3.7

import io
from time import sleep
import subprocess as sp
from pathlib import Path
from signal import SIGINT
from datetime import datetime

patator_default_work_dir = (Path.home() / '.asset_inventory/cache/patator').resolve()

class PatatorError(Exception):
    pass


class Patator:

    def __init__(self, targets, port=22, threads=80, work_dir=patator_default_work_dir):

        self.threads = threads
        self.num_targets = len(targets)

        # file containing usernames and passwords to try (colon-delimited)
        self.creds_file = str(Path(__file__).resolve().parent / 'ssh_creds.txt')

        # log file for patator stdout
        patator_log_filename = 'patator_log_{}_{date:%Y-%m-%d_%H-%M-%S}'.format(str(port), date=datetime.now())
        self.patator_log_file = str(Path(work_dir) / patator_log_filename)

        # file for patator valid username/password pairs
        patator_valid_creds = 'patator_valid_creds_{}_{date:%Y-%m-%d_%H-%M-%S}'.format(str(port), date=datetime.now())
        self.patator_valid_creds = str(Path(work_dir) / patator_valid_creds)

        # file containing target IPs
        targets_filename = 'targets_port_{}_{date:%Y-%m-%d_%H-%M-%S}'.format(str(port), date=datetime.now())
        self.targets_file = str(Path(work_dir) / targets_filename)

        # write targets to file
        with open(self.targets_file, 'w') as f:
            for target in targets:
                f.write(str(target) + '\n')

        # make sure patator is installed
        try:
            if sp.run(['patator', 'ssh_login', '--help'], check=True, stdout=sp.DEVNULL, stderr=sp.DEVNULL).returncode != 0:
                raise CalledProcessError
        except (FileNotFoundError, sp.CalledProcessError):
            raise PatatorError('Patator is not installed')

        # variable for running patator process
        self.patator_process = None



    def scan(self):

        try:

            valid_creds_found = False

            patator_command = ['patator', 'ssh_login', '--threads={}'.format(self.threads), \
                'user=COMBO10', 'password=COMBO11', 'host=FILE0', 
                '--max-retries=2', '1={}'.format(self.creds_file),\
                '0={}'.format(self.targets_file)]

            print('\n[+] Running patator against {:,} targets:\n\t> {}\n'.format(self.num_targets, ' '.join(patator_command)))

            if self.patator_process is None:
                self.patator_process = sp.Popen(patator_command, stdout=sp.PIPE, stderr=sp.PIPE)
                sleep(2)

                with open(self.patator_valid_creds, 'w') as valid_creds:
                    with open(self.patator_log_file, 'w') as log_file:
                        for line in io.TextIOWrapper(self.patator_process.stderr, encoding='utf-8'):
                            log_file.write(line)
                            line = '\r' + ''.join(line.split('patator')[1:]).strip()
                            print('\r{}'.format(line), end='')
                            if 'INFO - 0' in line:
                                valid_creds_found = True
                                valid_creds.write(line)
                                print(line)

                self.patator_process = None

            else:
                raise PatatorError('Patator is already running')

        except KeyboardInterrupt:
            print('\n\n[!] Patator interrupted')
            try:
                self.patator_process.send_signal(SIGINT)
                sleep(2)
                self.patator_process.send_signal(SIGINT)
                self.patator_process.terminate()
            except AttributeError:
                pass

        finally:
            if valid_creds_found:
                print('\n\n[+] Valid SSH creds found, see {}'.format(str(self.patator_valid_creds)))
            return valid_creds_found