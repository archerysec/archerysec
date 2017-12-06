#!/usr/bin/env python
import os
import platform
import subprocess
from zapv2 import ZAPv2
import json
import sys


def start_zap():
    api_key_path = os.getcwd() + '/' + 'apidata.json'
    with open(api_key_path, 'r+') as f:
        data = json.load(f)
        zap_path = data['zap_path']
        zap_port = data['zap_port']

    if platform.system() == 'Windows' or platform.system().startswith('CYGWIN'):
        executable = 'zap.bat'
    else:
        executable = 'zap.sh'

    executable_path = os.path.join(zap_path, executable)
    zap_command = [executable_path, '-daemon', '-port', zap_port]

    log_path = os.getcwd() + '/' + 'zap.log'

    with open(log_path, 'w+') as log_file:
        subprocess.Popen(zap_command, cwd=zap_path, stdout=log_file, stderr=subprocess.STDOUT)

    print "zap started"


def stop_zap():
    api_key_path = os.getcwd() + '/' + 'apidata.json'
    with open(api_key_path, 'r+') as f:
        data = json.load(f)
        apikey = data['zap_api_key']
    zap = ZAPv2(apikey=apikey,
                proxies={'http': 'http://127.0.0.1:'+'zap_port', 'https': 'http://127.0.0.1:'+'zap_port'})
    p = zap.core.shutdown()
    print p

if __name__ == "__main__":
    try:
        if sys.argv[1] == "start":
            start_zap()
        if sys.argv[1] == "stop":
            stop_zap()
    except Exception as e:
        print e
        print "Please input start or stop"
