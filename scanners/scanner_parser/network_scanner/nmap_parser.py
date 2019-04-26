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

from __future__ import print_function
from __future__ import print_function
import hashlib
import datetime
import uuid
from tools.models import nmap_result_db, nmap_scan_db

ip_address = None
port = None
protocol = None
used_state = None
used_portid = None
used_proto = None
state = None
reason = None
reason_ttl = None
version = None
extrainfo = None
name = None
conf = None
method = None
cpe = None
type_p = None
osfamily = None
vendor = None
osgen = None
accuracy = None


def xml_parser(root, project_id, scan_id):
    """

    :param root:
    :param project_id:
    :param scan_id:
    :return:
    """
    global ip_address, \
        port, \
        protocol, \
        used_state, \
        used_portid, \
        used_proto, \
        state, \
        reason, \
        reason_ttl, \
        version, \
        extrainfo, \
        name, \
        conf, \
        method, \
        cpe, \
        type_p, \
        osfamily, \
        vendor, \
        osgen, \
        accuracy

    for nmap in root:
        for scaninfo in nmap:
            if scaninfo.tag == 'address':
                ip = scaninfo.attrib
                for key, value in ip.items():
                    if key == 'addrtype':
                        if value == 'ipv4':
                            for key, value in ip.items():
                                if key == 'addr':
                                    ip_address = value
            for s in scaninfo:
                # print s.tag
                if s.tag == 'port':
                    p = s.attrib
                    for key, value in p.items():
                        # print key
                        if key == 'portid':
                            port = value
                            print(port)
                        if key == 'protocol':
                            protocol = value

                if s.tag == 'portused':
                    p = s.attrib
                    for key, value in p.items():
                        # print key, value
                        if key == 'state':
                            used_state = value
                        if key == 'portid':
                            used_portid = value
                        if key == 'proto':
                            used_proto = value

                for ss in s:
                    sat = ss.attrib
                    for key, value in sat.items():
                        if key == 'state':
                            state = value
                        if key == 'reason':
                            reason = value
                        if key == 'reason_ttl':
                            reason_ttl = value
                        if key == 'version':
                            version = value
                        if key == 'extrainfo':
                            extrainfo = value
                        if key == 'name':
                            name = value
                        if key == 'conf':
                            conf = value
                        if key == 'method':
                            method = value
                        if key == 'type':
                            type_p = value
                        if key == 'osfamily':
                            osfamily = value
                        if key == 'vendor':
                            vendor = value
                        if key == 'osgen':
                            osgen = value
                        if key == 'accuracy':
                            accuracy = value

                    for sss in ss:
                        cpe = sss.text
                # print(ip_address)
                print("------")

                dump_data = nmap_result_db(
                    scan_id=scan_id,
                    ip_address=ip_address,
                    port=port,
                    state=state,
                    reason=reason,
                    reason_ttl=reason_ttl,
                    version=version,
                    extrainfo=extrainfo,
                    name=name,
                    conf=conf,
                    method=method,
                    type_p=type_p,
                    osfamily=osfamily,
                    vendor=vendor,
                    osgen=osgen,
                    accuracy=accuracy,
                    cpe=cpe,
                    used_state=used_state,
                    used_portid=used_portid,
                    used_proto=used_proto,
                )
                dump_data.save()

    for nmap in root:
        for scaninfo in nmap:
            # print scaninfo.tag, scaninfo.attrib
            if scaninfo.tag == 'address':
                ip = scaninfo.attrib
                for key, value in ip.items():
                    if key == 'addrtype':
                        if value == 'ipv4':
                            for key, value in ip.items():
                                if key == 'addr':
                                    ip_address = value

                                    all_data = nmap_result_db.objects.filter(ip_address=ip_address)
                                    # for a in all_data:
                                    #     global total_ports, ports_p
                                    #     ports_p = a.port
                                    total_ports = len(all_data)
                                    # print(total_ports)

                                    all_open_p = nmap_result_db.objects.filter(ip_address=ip_address,
                                                                               state='open')
                                    # for p in all_open_p:
                                    #     global total_open_p
                                    total_open_p = len(all_open_p)
                                    # print(total_open_p)

                                    all_close_p = nmap_result_db.objects.filter(ip_address=ip_address,
                                                                                state='closed')
                                    total_close_p = len(all_close_p)

                                    save_scan = nmap_scan_db(scan_id=scan_id,
                                                             project_id=project_id,
                                                             scan_ip=ip_address,
                                                             total_ports=total_ports,
                                                             total_open_ports=total_open_p,
                                                             total_close_ports=total_close_p,
                                                             )
                                    save_scan.save()
