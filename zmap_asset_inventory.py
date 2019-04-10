#!/usr/bin/env python3.7

# by TheTechromancer

'''
TODO:
    
    - whitelist doesn't work when -Pn is specified
    - check domain when getting services
    - make backup of nmap output before overwriting

    - output "{num} services found on {system}" instead of "Successful Authentication on {system}"
'''

import os
import csv
import sys
import queue
import random
import argparse
import ipaddress
import subprocess as sp
from pathlib import Path
import concurrent.futures
from datetime import datetime
from lib.service_enum import *
from lib.scan import Nmap, Zmap
from lib.host import *
from lib.brute_ssh import *



def main(options):

    if os.geteuid() != 0:
        sys.stderr.write('[!] Must be root\n')
        sys.exit(2)

    # make sure blacklist and whitelist exist
    if options.blacklist:
        assert Path(options.blacklist).resolve().is_file(), 'Problem reading blacklist file "{}"'.format(str(options.blacklist))
    if options.whitelist:
        assert Path(options.whitelist).resolve().is_file(), 'Problem reading whitelist file "{}"'.format(str(options.whitelist))

    # resolve symlinks
    options.work_dir = options.work_dir.resolve()

    cache_dir = options.work_dir / 'cache'
    nmap_dir = cache_dir / 'nmap'
    zmap_dir = cache_dir / 'zmap'
    temp_dir = options.work_dir / 'tmp'
    patator_dir = cache_dir / 'patator'

    # if starting fresh, rename working directory to ".bak"
    if options.start_fresh:
        backup_cache_dir = Path(str(cache_dir) + '_{date:%Y-%m-%d_%H-%M-%S}.bak'.format( date=datetime.now() ))
        try:
            old_dir = str(cache_dir)
            cache_dir.rename(backup_cache_dir)
            print('[+] Backed up {} to {}'.format(old_dir, str(backup_cache_dir)))
        except FileNotFoundError:
            pass

    # create directories if they don't exist
    nmap_dir.mkdir(mode=0o755, parents=True, exist_ok=True)
    zmap_dir.mkdir(mode=0o755, parents=True, exist_ok=True)
    temp_dir.mkdir(mode=0o755, parents=True, exist_ok=True)
    patator_dir.mkdir(mode=0o755, parents=True, exist_ok=True)

    # add port 445 if check_services is requested
    if options.check_services or options.check_eternal_blue:
        if not options.ports:
            options.ports = [445]
        elif not 445 in options.ports:
            options.ports.append(445)


    if options.csv_file is None:
        options.csv_file = options.work_dir / 'asset_inventory_{date:%Y-%m-%d_%H-%M-%S}.csv'.format( date=datetime.now() )


    if options.combine_all_assets:
        print('[+] Combining all assets discovered to date')

        csv_files = []
        try:
            for csv_file in next(os.walk(options.work_dir))[2]:
                if csv_file.startswith('asset_inventory') and csv_file.endswith('.csv'):
                    print('[+] Found asset inventory CSV: {}'.format(csv_file))
                    csv_files.append(options.work_dir / csv_file)

        except StopIteration:
            pass

        combine_csv(csv_files)


    else:

        z = Zmap(options.targets, options.bandwidth, resolve=(not options.dont_resolve), \
            work_dir=cache_dir, skip_ping=options.skip_ping, blacklist=options.blacklist, \
            whitelist=options.whitelist, interface=options.interface, \
            gateway_mac=options.gateway_mac)

        # do host discovery
        for host in z:
            pass

        # check for default SSH creds
        if options.ssh:
            try:
                z.brute_ssh()
            except PatatorError as e:
                sys.stderr.write('\n[!] {}\n'.format(str(e)))

        # scan additional ports if requested
        # only alive hosts are scanned
        if options.ports:
            for port in options.ports:
                zmap_out_file, new_hosts_found = z.scan_online_hosts(port)
                if new_hosts_found:
                    print('\n[+] Port scan results for {}/TCP written to {}'.format(port, zmap_out_file))


        # check for EternalBlue
        if options.check_eternal_blue:
            z.check_eternal_blue()


        # if service enumeration is enabled
        # run wmiexec
        if options.check_services:
            print('[+] Retrieving service information for Windows hosts')

            # generate whitelist
            whitelist = []
            if options.whitelist is not None:
                with open(options.whitelist) as f:
                    for line in f.readlines():
                        try:
                            whitelist.append(ipaddress.ip_network(line.strip()))
                        except ValueError:
                            continue

            lockout_queue = queue.Queue()
            lockout_counter = 0

            wmiexec_output = dict()
            config = parse_service_config('services.config')

            # parse services.config
            try:
                if config is None:
                    print('[!] Error with config')
                else:
                    z.services = list(config['SERVICES'].keys())
                    if z.services:
                        z.services = ['OS'] + z.services
                        # set up threading
                        wmi_futures = []
                        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as wmi_executor:
                            shuffled_hosts = random.sample(list(z.hosts.values()), len(z.hosts))
                            for host in shuffled_hosts:
                                if 445 in host.open_ports:
                                    if whitelist:
                                        # make sure host is in whitelist
                                        host_ip = ipaddress.ip_address(host.ip)
                                        if not any([host_ip in entry for entry in whitelist]):
                                            continue

                                    try:
                                        # this is terrible
                                        # fix so that lockout_queue entries specify the host
                                        while 1:
                                            failed_login = lockout_queue.get_nowait()
                                            if failed_login == 1:
                                                lockout_counter += 1
                                                #print('[!] LOGON FAILURE ON {}'.format(str(host)))
                                            else:
                                                print('[+] Successful authentication on {}'.format(str(host)))
                                                lockout_counter = 0

                                    except queue.Empty:
                                        pass

                                    assert lockout_counter < options.ufail_limit
                                    wmi_futures.append(wmi_executor.submit(host.get_services, config, lockout_queue))
                                    sleep(.75)
                                    #host.get_services(config)

                            wmi_executor.shutdown(wait=True)

                        for host in z:
                            if host.raw_wmiexec_output:
                                wmiexec_output[host['IP Address']] = host.raw_wmiexec_output

                        #for f in wmi_futures:
                        #    print(f.result())

                    else:
                        print('[!] No services specified')

            except AssertionError:
                print('[!] Logon failure limit reached ({limit}/{limit})'.format(limit=options.ufail_limit))
            finally:
                try:
                    raw_output_file = str(cache_dir / 'raw_wmiexec_output_{date:%Y-%m-%d_%H-%M-%S}.txt'.format( date=datetime.now() ))
                    print('[+] Writing raw command output to {}'.format(raw_output_file))
                    with open(raw_output_file, 'w') as f:
                        for ip, output in wmiexec_output.items():
                            f.write('=' * 10 + '\n')
                            f.write(str(ip) + '\n')
                            f.write('=' * 5 + '\n')
                            f.write(str(output) + '\n')
                except:
                    pass
                try:
                    print('=' * 60)
                    print(wmiexec.report(config, z.hosts_sorted()))
                    print('=' * 60)
                except:
                    pass

        # write CSV file
        z.write_csv(csv_file=options.csv_file)

        # print summary
        z.report(netmask=options.netmask)
        if options.check_eternal_blue and z.eternal_blue_count <= 0:
            print('[+] No systems found vulnerable to EternalBlue')
            print('')

        # calculate deltas if requested
        if options.diff:
            stray_hosts = []
            stray_networks = []

            stray_networks = z.get_network_delta(options.diff, netmask=options.netmask)
            stray_networks_csv = './network_diff_{date:%Y-%m-%d_%H-%M-%S}.csv'.format( date=datetime.now())
            print('')
            print('[+] {:,} active network(s) not found in {}'.format(len(stray_networks), str(options.diff)))
            print('[+] Full report written to {}'.format(stray_networks_csv))
            print('=' * 60)

            with open(stray_networks_csv, 'w', newline='') as f:
                csv_file = csv.DictWriter(f, fieldnames=['Network', 'Host Count'])
                csv_file.writeheader()

                max_display_count = 20
                for network in stray_networks:
                    #print('\t{:<16}{}'.format(str(network[0]), network[1]))
                    print('\t{:<19}{:<10}'.format(str(network[0]), ' ({:,})'.format(network[1])))
                    max_display_count -= 1
                    if max_display_count <= 0:
                        print('\t...')
                        break

                for network in stray_networks:
                    csv_file.writerow({'Network': str(network[0]), 'Host Count': str(network[1])})

            stray_hosts = z.get_host_delta(options.diff)
            stray_hosts_csv = './host_diff_{date:%Y-%m-%d_%H-%M-%S}.csv'.format( date=datetime.now())
            print('')
            print('[+] {:,} alive host(s) not found in {}'.format(len(stray_hosts), str(options.diff)))
            print('[+] Full report written to {}'.format(stray_hosts_csv))
            print('=' * 60)

            max_display_count = 20
            for host in stray_hosts:
                print('\t{}'.format(str(host)))
                max_display_count -= 1
                if max_display_count <= 0:
                    print('\t...')
                    break

            z.write_csv(csv_file=stray_hosts_csv, hosts=stray_hosts)

            # if more than 5 percent of hosts are strays, or you have more than one stray network
            if len(z.hosts) > 0:
                if len(stray_hosts)/len(z.hosts) > .05 or len(stray_networks) > 1:
                    print('')
                    print(' "Your asset management is bad and you should feel bad"')
                    print('\n')

        print('[+] CSV file written to {}'.format(options.csv_file))

        z.stop()
        z.dump_scan_cache()




def parse_target_args(targets):
    '''
    takes 
    '''

    networks = set()

    for network_list in targets:
        for network in network_list:
            networks.add(network)

    networks = list(networks)
    networks.sort()
    return networks



def combine_csv(csv_files):
    '''
    takes a list of asset inventory CSV files and combines them
    writes to a new CSV file in the current directory
    '''

    hosts = dict()
    fieldnames = []

    for file in csv_files:
        try:
            with open(file, newline='') as f:
                c = csv.DictReader(f)
                for field in c.fieldnames:
                    if not field in fieldnames:
                        fieldnames.append(field)
                for row in c:
                    row = dict(row)
                    ip = ipaddress.ip_address(row['IP Address'])
                    if not ip in hosts:
                        hosts[ip] = row
                    else:
                        for k,v in row.items():
                            if v and not v.lower() in ['unknown', 'n/a', 'closed']:
                                # skip if the cell isn't empty
                                if k in hosts[ip]:
                                    if hosts[ip][k] and not hosts[ip][k].lower() in ['unknown', 'n/a', 'closed'`]:
                                        continue
                                hosts[ip].update({k: v})

        except KeyError:
            sys.stderr.write('[!] Error combining {}\n'.format(file))
            continue
        
    out_filename = 'combined_asset_inventory_{date:%Y-%m-%d_%H-%M-%S}.csv'.format( date=datetime.now() )
    print('[+] Writing combined list to {}'.format(out_filename))
    with open(out_filename, newline='', mode='w') as f:
        c = csv.DictWriter(f, fieldnames=fieldnames)
        c.writeheader()
        hosts = list(hosts.items())
        hosts.sort(key=lambda x: x[0])
        for ip, host in hosts:
            c.writerow(host)



if __name__ == '__main__':

    default_bandwidth = '600K'
    default_work_dir = Path.home() / '.asset_inventory'
    default_cidr_mask = 24
    default_networks = [[ipaddress.ip_network(n)] for n in ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16']]

    parser = argparse.ArgumentParser(description="Assess the security posture of an internal network")
    parser.add_argument('-t', '--targets', type=str_to_network, nargs='+',      default=default_networks, help='target network(s) to scan', metavar='STR')
    parser.add_argument('-n', '--dont-resolve',         action='store_true',    help='do not perform reverse DNS lookups')
    parser.add_argument('-B', '--bandwidth', default=default_bandwidth,         help='max egress bandwidth (default {})'.format(default_bandwidth), metavar='STR')
    parser.add_argument('-i', '--interface',                                    help='interface from which to scan (e.g. eth0)', metavar='IFC')
    parser.add_argument('-G', '--gateway-mac',                                  help='MAC address of default gateway', metavar='MAC')
    parser.add_argument('--blacklist',                                          help='a file containing hosts to exclude from scanning', metavar='FILE')
    parser.add_argument('--whitelist',                                          help='only these hosts (those which overlap with targets) will be scanned', metavar='FILE')
    parser.add_argument('-w', '--csv-file',                                     help='output CSV file', metavar='CSV_FILE')
    parser.add_argument('-f', '--start-fresh',          action='store_true',    help='don\'t load results from previous scans')
    parser.add_argument('-p', '--ports', nargs='+', type=int,                   help='port-scan online hosts')
    parser.add_argument('-Pn', '--skip-ping', action='store_true',              help='skip zmap host-discovery')
    parser.add_argument('-e', '--check-eternal-blue',   action='store_true',    help='scan for EternalBlue')
    parser.add_argument('-s', '--check-services',       action='store_true',    help='enumerate select services with wmiexec (see services.config)')
    parser.add_argument('--work-dir', type=Path, default=default_work_dir,      help='custom working directory', metavar='DIR')
    parser.add_argument('-d', '--diff',             type=Path,                  help='show differences between scan results and IPs/networks from file', metavar='FILE')
    parser.add_argument('--netmask',       type=int, default=default_cidr_mask, help='summarize networks with this CIDR mask (default {})'.format(default_cidr_mask))
    parser.add_argument('--ssh',                        action='store_true',    help='scan for default SSH creds (see lib/ssh_creds.txt)')
    parser.add_argument('--ufail-limit',   type=int, default=3,                 help='limit consecutive wmiexec failed logins (default: 3)')
    parser.add_argument('--combine-all-assets',         action='store_true',    help='combine all previous results and save in current directory')

    try:

        options = parser.parse_args()
        options.targets = parse_target_args(options.targets)
        if not options.targets:
            sys.stderr.write('\n[!] No valid targets\n')
            sys.exit(1)

        assert 0 <= options.netmask <= 32, "Invalid netmask"

        main(options)


    except (argparse.ArgumentError, AssertionError) as e:
        sys.stderr.write('\n[!] {}\n'.format(str(e)))
        sys.exit(2)

    except KeyboardInterrupt:
        sys.stderr.write('\n[!] Interrupted\n')
        sys.exit(1)