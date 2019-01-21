#!/usr/bin/env python3.7

# by TheTechromancer

import os
import csv
import sys
import queue
import argparse
import ipaddress
import subprocess as sp
from pathlib import Path
import concurrent.futures
from datetime import datetime
from lib.service_enum import *
from lib.scan import Nmap, Zmap



def main(options):

    if os.geteuid() != 0:
        sys.stderr.write('[!] Must be root\n')
        sys.exit(2)

    # resolve symlinks
    options.work_dir = options.work_dir.resolve()

    cache_dir = options.work_dir / 'cache'
    nmap_dir = cache_dir / 'nmap'

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

    # add port 445 if check_services is requested
    if options.check_services:
        if not options.ports:
            options.ports = [445]
        elif not 445 in options.ports:
            options.ports.append(445)


    if options.csv_file is None:
        options.csv_file = options.work_dir / 'asset_inventory_{date:%Y-%m-%d_%H-%M-%S}.csv'.format( date=datetime.now() )

    z = Zmap(options.targets, options.bandwidth, work_dir=cache_dir, \
        skip_ping=options.skip_ping, blacklist=options.blacklist, \
        interface=options.interface, gateway_mac=options.gateway_mac)

    # jdo host discovery
    for host in z:
        pass

    # check for EternalBlue
    if options.check_eternal_blue:
        z.check_eternal_blue()

    # scan additional ports if requested
    # only alive hosts are scanned
    if options.ports:
        for port in options.ports:
            zmap_out_file = z.scan_online_hosts(port)
            if zmap_out_file is not None:
                print('\n[+] Port scan results for {}/TCP written to {}'.format(port, str(zmap_out_file)))


    # if service enumeration is enabled
    # run wmiexec
    if options.check_services:
        print('[+] Retrieving service information for Windows hosts')

        lockout_queue = queue.Queue()
        lockout_counter = 0

        # parse services.config
        try:
            config = parse_service_config('services.config')
            if config is None:
                print('[!] Error with config')
            else:
                z.services = list(config['SERVICES'].keys())
                if z.services:
                    z.services = ['OS'] + z.services
                    # set up threading
                    wmi_futures = []
                    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as wmi_executor:
                        for host in z:
                            #for i in range(4): # testing
                            if 445 in host.open_ports:
                                try:
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
                                sleep(1)
                                #host.get_services(config)

                        wmi_executor.shutdown(wait=True)

                    #for f in wmi_futures:
                    #    print(f.result())

                    print('=' * 60)
                    print(wmiexec.report(config, z.hosts_sorted()))
                    print('=' * 60)

                else:
                    print('[!] No services specified')

        except AssertionError:
            print('[!] Logon failure limit reached ({limit}/{limit})'.format(limit=options.ufail_limit))

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
                csv_file.writerow({'Network': str(network[0]), 'Host Count': str(network[1])})
                #print('\t{:<16}{}'.format(str(network[0]), network[1]))
                print('\t{:<19}{:<10}'.format(str(network[0]), ' ({:,})'.format(network[1])))
                max_display_count -= 1
                if max_display_count <= 0:
                    print('\t...')
                    break

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




def str_to_network(s):
    '''
    takes either CIDR or range notation as string
    generates ip_network objects
    '''

    try:
        if '-' in s:
            if s.count('-') == 1:
                start, end = [p.strip() for p in s.split('-')[:2]]
                for i in ipaddress.summarize_address_range(ipaddress.ip_address(start), ipaddress.ip_address(end)):
                    yield i
            else:
                raise ValueError()
        else:
            yield ipaddress.ip_network(s, strict=False)

    except ValueError:
        print('[!] Cannot create host/network from "{}"'.format(str(s)))
        print('     Accepted formats are:')
        print('      192.168.0.0/24')
        print('      192.168.0.0-192.168.0.255')

        #raise ValueError('Cannot create host/network from "{}"'.format(str(s)))


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



if __name__ == '__main__':

    default_bandwidth = '1M'
    default_work_dir = Path.home() / '.asset_inventory'
    default_cidr_mask = 24

    parser = argparse.ArgumentParser("Scan private IP ranges, output to CSV")
    parser.add_argument('-t', '--targets', type=str_to_network, nargs='+', default=[['10.0.0.0/8'], ['172.16.0.0/12'], ['192.168.0.0/16']], help='target network(s) to scan', metavar='STR')
    parser.add_argument('-B', '--bandwidth', default=default_bandwidth,         help='max egress bandwidth (default {})'.format(default_bandwidth), metavar='STR')
    parser.add_argument('-i', '--interface',                                    help='interface from which to scan (e.g. eth0)', metavar='IFC')
    parser.add_argument('-G', '--gateway-mac',                                  help='MAC address of default gateway', metavar='MAC')
    parser.add_argument('--blacklist',                                          help='a file containing hosts to exclude from scanning', metavar='FILE')
    parser.add_argument('-w', '--csv-file',                                     help='output CSV file', metavar='CSV_FILE')
    parser.add_argument('-f', '--start-fresh',          action='store_true',    help='don\'t load results from previous scans')
    parser.add_argument('-p', '--ports', nargs='+', type=int,                   help='port-scan online hosts')
    parser.add_argument('-Pn', '--skip-ping', action='store_true',              help='skip zmap host-discovery')
    parser.add_argument('-e', '--check-eternal-blue',   action='store_true',    help='scan for EternalBlue')
    parser.add_argument('-s', '--check-services',       action='store_true',    help='enumerate select services with wmiexec (see services.config)')
    parser.add_argument('--work-dir', type=Path, default=default_work_dir,      help='custom working directory', metavar='DIR')
    parser.add_argument('-d', '--diff',             type=Path,                  help='show differences between scan results and IPs/networks from file', metavar='FILE')
    parser.add_argument('-n', '--netmask', type=int, default=default_cidr_mask, help='summarize networks with this CIDR mask (default {})'.format(default_cidr_mask))
    parser.add_argument('--ufail-limit',   type=int, default=3,                 help='limit consecutive failed logins (default: 3)')

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