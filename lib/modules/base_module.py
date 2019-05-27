#!/usr/bin/env python3.7

# by TheTechromancer

from shutil import which


class BaseModule():

    # string used for creating temp directory
    name            = 'tmp'
    csv_headers     = []
    required_ports  = []
    required_progs  = []

    def __init__(self, inventory):

        # create working directory
        self.work_dir = inventory.work_dir / 'modules' / self.name
        self.work_dir.mkdir(mode=0o755, parents=True, exist_ok=True)


    def check_progs(self):

        progs_to_install = []
        for prog in self.required_progs:
            if not which(prog):
                progs_to_install.append(prog)

        return progs_to_install


    def run(self, inventory):

        for host in inventory:
            if 22 in host.open_ports:
                pass



    def report(self, inventory):

        vulnerable_hosts = []
        '''
        for host in inventory:
            try:
                if host['Vulnerable to EternalBlue'].lower().startswith('y'):
                    vulnerable_hosts.append(host)
            except KeyError:
                pass

        if vulnerable_hosts:
            print('[+] Vulnerable to EternalBlue:\n\n\t')
            print('\n\t'.join([str(h) for h in vulnerable_hosts]))
        else:
            print('[+] No systems found vulnerable to EternalBlue')
        '''



    def read_host(self, csv_line, host):
        '''
        hook for loading state from CSV
        takes a CSV line and modifies Host() appropriately
        '''

        pass
        '''
        try:
            pass
            vulnerable = csv_line['Vulnerable to EternalBlue']
        except KeyError:
            vulnerable = 'N/A'
            pass

        host.update({'Vulnerable to EternalBlue': vulnerable})
        '''