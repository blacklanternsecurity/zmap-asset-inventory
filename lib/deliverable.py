#!/usr/bin/env python3

# by TheTechromancer

import csv
import ipaddress

class Deliverable:

	def __init__(self, inventory, csv_files):

		self.inventory = inventory
		self.csv_files = csv_files


	def generate_xlsx(self, filename):
	    '''
	    takes a list of asset inventory CSV files and combines them
	    writes to a new CSV file in the current directory
	    '''

	    try:
	        import openpyxl
	    except ImportError:
	        sys.stderr.write('\n[!] Please run "python3 -m pip install openpyxl"\n\n')
	        return

	    hosts = dict()
	    fieldnames = []

	    for file in self.csv_files:
	        try:
	            with open(file, newline='') as f:

	                c = csv.DictReader(f)

	                if not fieldnames:
	                    fieldnames = ['IP Address', 'Hostname', 'Open Ports']

	                for field in c.fieldnames:
	                    if not field in fieldnames and not field.lower().endswith('/tcp'):
	                        fieldnames.append(field)

	                for row in c:

	                    row = dict(row)
	                    ports = set()
	                    ip = ipaddress.ip_address(row['IP Address'])

	                    for k in list(row):
	                        if k.lower().endswith('/tcp'):
	                            try:
	                                port = int(k.split('/')[0])
	                                ports.add(port)
	                                row.pop(k)
	                            except ValueError:
	                                continue

	                    try:
	                        ports.update(hosts[ip]['Open Ports'])
	                        for k,v in row.items():
	                            if v and not v.lower() in ['unknown', 'n/a', 'closed']:
	                                # skip if the cell isn't empty
	                                if k in hosts[ip]:
	                                    if hosts[ip][k] and not hosts[ip][k].lower() in ['unknown', 'n/a', 'closed']:
	                                        continue
	                                hosts[ip].update({k: v})

	                    except KeyError:
	                        hosts[ip] = row

	                    finally:
	                        hosts[ip].update({'Open Ports': ports})

	        except KeyError:
	            sys.stderr.write('[!] Error combining {}\n'.format(file))
	            continue
	        
	    print('[+] Writing combined list to {}'.format(filename))
	    with open(filename, newline='', mode='w') as f:
	        c = csv.DictWriter(f, fieldnames=fieldnames)
	        c.writeheader()
	        hosts = list(hosts.items())
	        hosts.sort(key=lambda x: x[0])
	        for ip, host in hosts:
	            host['Open Ports'] = list(host['Open Ports'])
	            host['Open Ports'].sort()
	            host['Open Ports'] = ', '.join([str(p) for p in host['Open Ports']])
	            c.writerow(host)