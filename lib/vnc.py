#!/usr/bin/env python3

# by TheTechromancer

import sys
import subprocess as sp
from shutil import which


def check_vnc(ip, work_dir, port=5900):

    if not which('vncsnapshot'):
        sys.stderr.write('[!] Please ensure "vncsnapshot" is installed and in $PATH\n')
        return

    filename = work_dir / 'vnc_{}_{}_screenshot.jpg'.format(ip, port)

    vnc_command = ['vncsnapshot', '-allowblank', '-cursor', '-quality', '75', '{}::{}'.format(ip, port), str(filename)]
    #print('[+] Attempting VNC screenshot:')
    print('[i] > {}'.format(' '.join(vnc_command)))
    try:
        sp.run(vnc_command, stdout=sp.PIPE, stderr=sp.PIPE, timeout=5)
        if filename.is_file():
            print('[+] Screenshot saved to {}'.format(filename))
            return True
    except sp.TimeoutExpired:
        sys.stderr.write('[!] VNC screenshot timed out on {}\n'.format(ip))

    return False