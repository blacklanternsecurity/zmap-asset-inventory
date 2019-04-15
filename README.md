# zmap-asset-inventory
Python script which takes internal asset inventory at scale using zmap.  Outputs to a nicely-formatted CSV for delivery to the customer.


## Features:
* Scans entire private IP space (by default)
    * Bandwidth, by default, is capped at 1Mbps
* Automatic reverse-DNS lookups
* Ability to calculate delta between scan results and another list
    * Great for finding stray hosts
* Outputs to CSV
* Can check for EternalBlue, default SSH creds, and open VNC (optional)
* Automatic caching of scan results
    * Run additional port scans without waiting for host discovery or DNS lookups 
    * Saves lots of time if scanning > thousands of hosts


## Typical usage scenario:

**zmap ping scan &rarr; zmap port scan(s) &rarr; Service/EternalBlue/SSH/VNC scans (optional) &rarr; CSV**

1. **Host Discovery**
  1. Ensure your /etc/hosts contains the correct DNS information for reverse lookups
  2. Run a ping sweep (defaults to entire private IP range):
    - `$ ./zmap_asset_inventory.py`
  3. Tip #1: You can specify a `--blacklist`
  4. Tip #2: All raw output is saved in `~/.asset_inventory`
2. **Port Scans**
  - Multiple ports can be scanned in one go:
    - `$ ./zmap_asset_inventory.py -p 21 22 23 80 443 445`
  - Note: Only alive hosts (discovered during the ping sweep) will be scanned unless `--skip-ping` is specified
3. **Service Enumeration**
  - Useful for enumerating host-based controls such as AV on Windows systems
  - Note: Requires an account which can execute code on target systems (e.g. a Domain Admin)
  - To enumerate services:
    1. Edit `services.config` and ensure credentials are valid
      - Fill out any 
      - Note: Impacket's wmiexec is used for execution, and it must be in your path:
        - `$ export PATH=/root/Downloads/impacket/examples:$PATH`
      - Tip: You can pass the hash or use a golden ticket.  A password or hash is recommended; golden tickets can be a bit buggy, and only work on systems with a resolvable hostname.
    2. Ensure credentials are valid (seriously)
    3. Dew it.  All systems with 445 open are scanned by default:
      - `$ ./zmap_asset_inventory.py --check-services`
      - Tip: You can specify a whitelist 
4. **Additional Checks**
  - To check for EternalBlue:
    - `$ ./zmap_asset_inventory.py --check-eternal-blue`
  - To check for default SSH creds:
    - `$ ./zmap_asset_inventory.py --check-default-ssh`
  - To check for default open VNC:
    - `$ ./zmap_asset_inventory.py --check-open-vnc`
5. **Combine all results into deliverable CSV**
  - `$ ./zmap_asset_inventory.py --combine`
  - A CSV file will be created in the current directory


## Usage:
~~~
# ./zmap_asset_inventory.py --help
usage: zmap_asset_inventory.py [-h] [-t STR [STR ...]] [-n] [-B STR] [-i IFC]
                               [-G MAC] [--blacklist FILE] [--whitelist FILE]
                               [-w CSV_FILE] [-f] [-p PORTS [PORTS ...]] [-Pn]
                               [-e] [-v] [-s] [--work-dir DIR] [-d FILE]
                               [--netmask NETMASK] [--ssh]
                               [--ufail-limit UFAIL_LIMIT]
                               [--combine-all-assets]

Assess the security posture of an internal network

optional arguments:
  -h, --help            show this help message and exit
  -t STR [STR ...], --targets STR [STR ...]
                        target network(s) to scan
  -n, --dont-resolve    do not perform reverse DNS lookups
  -B STR, --bandwidth STR
                        max egress bandwidth (default 600K)
  -i IFC, --interface IFC
                        interface from which to scan (e.g. eth0)
  -G MAC, --gateway-mac MAC
                        MAC address of default gateway
  --blacklist FILE      a file containing hosts to exclude from scanning
  --whitelist FILE      only these hosts (those which overlap with targets)
                        will be scanned
  -w CSV_FILE, --csv-file CSV_FILE
                        output CSV file
  -f, --start-fresh     don't load results from previous scans
  -p PORTS [PORTS ...], --ports PORTS [PORTS ...]
                        port-scan online hosts
  -Pn, --skip-ping      skip zmap host-discovery
  -e, --check-eternal-blue
                        scan for EternalBlue
  -v, --vnc             scan for open VNC
  -s, --check-services  enumerate select services with wmiexec (see
                        services.config)
  --work-dir DIR        custom working directory
  -d FILE, --diff FILE  show differences between scan results and IPs/networks
                        from file
  --netmask NETMASK     summarize networks with this CIDR mask (default 24)
  --ssh                 scan for default SSH creds (see lib/ssh_creds.txt)
  --ufail-limit UFAIL_LIMIT
                        limit consecutive wmiexec failed logins (default: 3)
  --combine-all-assets  combine all previous results and save in current
                        directory
~~~


## Example:
~~~
# ./zmap_asset_inventory.py -t 192.168.1.0/24 --check-eternal-blue
[+] No state found at /home/user/.asset_inventory/192.168.1.0-24/.state, starting fresh

[+] Running zmap:
    > zmap --blacklist-file=/home/user/.asset_inventory/192.168.1.0-24/.zmap_blacklist_tmp --bandwidth=1M --probe-module=icmp_echoscan 192.168.1.0/24

Dec 07 14:31:49.556 [INFO] zmap: output module: csv
Dec 07 14:31:49.556 [INFO] csv: no output file selected, will use stdout
 0:00 0%; send: 0 0 p/s (0 p/s avg); recv: 0 0 p/s (0 p/s avg); drops: 0 p/s (0 p/s avg); hitrate: 0.00%
[+] 192.168.1.216    lt_14.evilcorp.local
[+] 192.168.1.198    lt_13.evilcorp.local
[+] 192.168.1.1      gateway.evilcorp.local
[+] 192.168.1.228    git.evilcorp.local
[+] 192.168.1.197    lt_15.evilcorp.local
[+] 192.168.1.196    lt_74.evilcorp.local
[+] 192.168.1.203    lt_12.evilcorp.local
[+] 192.168.1.214    lt_63.evilcorp.local
[+] 192.168.1.222    lt_24.evilcorp.local
[+] 192.168.1.204    lt_97.evilcorp.local
[+] 192.168.1.227    lt_10.evilcorp.local
[+] 192.168.1.218    lt_86.evilcorp.local
[+] 192.168.1.213    lt_84.evilcorp.local
[+] 192.168.1.212    lt_70.evilcorp.local
[+] 192.168.1.210    ldap.evilcorp.local
[+] 192.168.1.200    lt_66.evilcorp.local
[+] 192.168.1.220    lt_73.evilcorp.local
[+] 192.168.1.230    ras.evilcorp.local
 0:08 96% (1s left); send: 256 done (589 p/s avg); recv: 18 0 p/s (2 p/s avg); drops: 0 p/s (0 p/s avg); hitrate: 7.03%
Dec 07 14:31:58.621 [INFO] zmap: completed

[+] Scanning for EternalBlue
[+] Scanning 18 hosts on port 445

[+] Running zmap:
    > zmap --whitelist-file=/home/user/.asset_inventory/192.168.1.0-24/zmap_online_hosts.txt --bandwidth=1M --target-port=445

Dec 07 14:31:59.260 [INFO] zmap: output module: csv
Dec 07 14:31:59.260 [INFO] csv: no output file selected, will use stdout
 0:00 0%; send: 0 0 p/s (0 p/s avg); recv: 0 0 p/s (0 p/s avg); drops: 0 p/s (0 p/s avg); hitrate: 0.00%
[+] 192.168.1.216:445    lt_14.evilcorp.local
[+] 192.168.1.198:445    lt_13.evilcorp.local
[+] 192.168.1.197:445    lt_15.evilcorp.local
[+] 192.168.1.196:445    lt_74.evilcorp.local
[+] 192.168.1.203:445    lt_12.evilcorp.local
[+] 192.168.1.214:445    lt_63.evilcorp.local
[+] 192.168.1.222:445    lt_24.evilcorp.local
[+] 192.168.1.204:445    lt_97.evilcorp.local
[+] 192.168.1.227:445    lt_10.evilcorp.local
[+] 192.168.1.218:445    lt_86.evilcorp.local
[+] 192.168.1.213:445    lt_84.evilcorp.local
[+] 192.168.1.212:445    lt_70.evilcorp.local
[+] 192.168.1.210:445    ldap.evilcorp.local
[+] 192.168.1.200:445    lt_66.evilcorp.local
[+] 192.168.1.220:445    lt_73.evilcorp.local
 0:08 100% (1s left); send: 18 done (170 p/s avg); recv: 14 0 p/s (0 p/s avg); drops: 0 p/s (0 p/s avg); hitrate: 77.78%
Dec 07 14:32:08.328 [INFO] zmap: completed

[+] Running nmap:
    > nmap -p445 -T5 -n -Pn -v -sV --script=smb-vuln-ms17-010 -oA /home/user/.asset_inventory/192.168.1.0-24/nmap_output -iL /home/user/.asset_inventory/192.168.1.0-24/zmap_port_445.txt

[+] Finished Nmap scan
[+] Saved Nmap results to /home/user/.asset_inventory/192.168.1.0-24/nmap_output.*


[+] RESULTS:
==================================================
[+] Total Online Hosts: 18
[+] Summary of Subnets:
    192.168.X.X      (18)     

[+] Vulnerable to EternalBlue: 2
        192.168.1.227    lt_10.evilcorp.local 
        192.168.1.218    lt_86.evilcorp.local

[+] CSV file written to /home/user/.asset_inventory/192.168.1.0-24/asset_inventory.csv
~~~