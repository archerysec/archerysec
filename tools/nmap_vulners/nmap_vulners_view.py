# -*- coding: utf-8 -*-
#                    _
#     /\            | |
#    /  \   _ __ ___| |__   ___ _ __ _   _
#   / /\ \ | '__/ __| '_ \ / _ \ '__| | | |
#  / ____ \| | | (__| | | |  __/ |  | |_| |
# /_/    \_\_|  \___|_| |_|\___|_|   \__, |
#                                     __/ |
#                                    |___/
# Copyright (C) 2017 Anand Tiwari
#
# Email:   anandtiwarics@gmail.com
# Twitter: @anandtiwarics
#
# This file is part of ArcherySec Project.

from itertools import starmap

from django.shortcuts import render, HttpResponseRedirect

from tools.models import nmap_vulners_port_result_db, nmap_scan_db, nmap_result_db
from tools.nmap_vulners.nmap_vulners_scan import run_nmap_vulners
from notifications.signals import notify


def nmap_vulners_scan(request):
    """

    :return:
    """
    all_nmap = nmap_scan_db.objects.all()

    return render(request,
                  'nmap_scan.html',
                  {'all_nmap': all_nmap,
                   'is_vulners': True
                  }
                  )


def nmap_vulners(request):
    """

    :return:
    """
    user = request.user

    if request.method == 'POST':
        ip_address = request.POST.get('ip')
        project_id = request.POST.get('project_id')

        try:
            run_nmap_vulners(ip_addr=ip_address, project_id=project_id)
            notify.send(user, recipient=user, verb='NMAP Scan Completed')
        except Exception as e:
            print('Error in nmap_vulners scan:', e)

        return HttpResponseRedirect('/tools/nmap_scan/')

    elif request.method == 'GET':
        ip_address = request.GET.get('ip')

        all_nmap = nmap_result_db.objects.filter(ip_address=ip_address)

    return render(request,
                  'nmap_vulners_list.html',
                  {'all_nmap': all_nmap}

                  )


def nmap_vulners_port(request):
    ip_address = request.GET.get('ip')
    port = request.GET.get('port')
    if not (ip_address and port):
        raise ValueError('Nmap Vulners Port info: both IP and port must be present.')

    port_info = nmap_vulners_port_result_db.objects.filter(ip_address=ip_address, port=port)

    cve_info = list()
    if port_info.first().vulners_extrainfo:
        info = port_info.first().vulners_extrainfo.split('\n\t')[1:]
        info_gen = starmap(lambda x: x.split('\t\t'), info)

        names = ('cve', 'cvss', 'link',)
        cve_info = (dict(zip(names, info)) for info in info_gen)

    return render(request,
                  'nmap_vulners_port_list.html',
                  {
                      'ip': ip_address,
                      'port': port,
                      'cve_info': cve_info
                  }
                  )
