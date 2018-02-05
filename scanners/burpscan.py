#!/usr/bin/env python
import os
import platform
import subprocess
from PyBurprestapi import burpscanner
import json
import sys
from django.core import signing


def burp_start():
    api_key_path = os.getcwd() + '/' + 'apidata.json'
    with open(api_key_path, 'r+') as f:
        data = json.load(f)
        burp_path_f = data['burp_path']
        burp_port = data['burp_port']

    burp_path = burp_path_f

    if platform.system() == 'Windows' or platform.system().startswith('CYGWIN'):
        executable = 'burp-rest-api-1.0.0.jar'
    else:
        executable = 'burp-rest-api-1.0.0.jar'

    executable_path = os.path.join(burp_path, executable)
    print executable_path

    burp_cmd = ['java', '-jar', executable_path, '--burp.edition=free']

    log_path = os.getcwd() + '/' + 'burp_log.log'

    with open(log_path, 'w+') as log_file:
        subprocess.Popen(burp_cmd, cwd=burp_path, stdout=log_file, stderr=subprocess.STDOUT)

    print "Burp Started"


def burp_stop():
    host = 'http://localhost:8090'

    bi = burpscanner.BurpApi(host)

    out = bi.burp_stop()

    resp = out.message

    if resp == "OK":
        print "Burp Stopped"


if __name__ == "__main__":
    try:
        if sys.argv[1] == "start":
            burp_start()
        if sys.argv[1] == "stop":
            burp_stop()
    except Exception as e:
        print e
        print "Please input start or stop"