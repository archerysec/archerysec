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

from openvas_lib import VulnscanManager, VulnscanException
from networkscanners.models import openvas_scan_db, ov_scan_result_db
from django.utils import timezone
import time
import os
import uuid
from archerysettings.models import openvas_setting_db
import hashlib
from datetime import datetime
from scanners.scanner_parser.network_scanner import OpenVas_Parser

name = ''
creation_time = ''
modification_time = ''
host = ''
port = ''
threat = ''
severity = ''
description = ''
family = ''
cvss_base = ''
cve = ''
bid = ''
xref = ''
tags = ''
banner = ''
vuln_color = None
false_positive = ''
duplicate_hash = ''
duplicate_vuln = ''
ov_host = ''
ov_user = ''
ov_pass = ''
ov_port = ''


class OpenVAS_Plugin:
    """
    OpenVAS plugin Class
    """

    def __init__(self, scan_ip, project_id, sel_profile, username):
        """

        :param scan_ip:
        :param project_id:
        :param sel_profile:
        """

        self.scan_ip = scan_ip
        self.project_id = project_id
        self.sel_profile = sel_profile
        self.username = username

    def connect(self):
        """
        Connecting with OpenVAS
        :return:
        """

        global ov_host, ov_user, ov_pass, ov_port
        all_openvas = openvas_setting_db.objects.filter(username=self.username)

        for openvas in all_openvas:
            ov_user = openvas.user
            ov_pass = openvas.password
            ov_host = openvas.host
            ov_port = openvas.port

        scanner = VulnscanManager(str(ov_host),
                                  str(ov_user),
                                  str(ov_pass),
                                  int(ov_port))
        time.sleep(5)

        return scanner

    def scan_launch(self, scanner):
        """
        Scan Launch Plugin
        :param scanner:
        :return:
        """
        profile = None
        if profile is None:
            profile = "Full and fast"

        else:
            profile = self.sel_profile
        scan_id, target_id = scanner.launch_scan(target=str(self.scan_ip),
                                                 profile=str(profile))
        return scan_id, target_id

    def scan_status(self, scanner, scan_id):
        """
        Get the scan status.
        :param scanner:
        :param scan_id:
        :return:
        """

        previous = ''
        while float(scanner.get_progress(str(scan_id))) < 100.0:
            current = str(scanner.get_scan_status(str(scan_id))) + str(scanner.get_progress(str(scan_id)))
            if current != previous:
                print('[Scan ID ' + str(scan_id) + '](' + str(
                    scanner.get_scan_status(str(scan_id))) + ') Scan progress: ' + str(
                    scanner.get_progress(str(scan_id))) + ' %')
                status = float(scanner.get_progress(str(scan_id)))
                openvas_scan_db.objects.filter(scan_id=scan_id).update(scan_status=status)
                previous = current
            time.sleep(5)

        status = "100"
        openvas_scan_db.objects.filter(scan_id=scan_id).update(scan_status=status)

        return status


def vuln_an_id(scan_id, project_id, username):
    """
    The function is filtering all data from OpenVAS and dumping to Archery database.
    :param scan_id:
    :return:
    """
    global name, host, severity, port, creation_time, modification_time, threat, severity, description, family, cvss_base, cve, bid, xref, tags, banner, date_time, false_positive, duplicate_hash, duplicate_vuln, ov_ip, ov_user, ov_pass

    all_openvas = openvas_setting_db.objects.filter(username=username)

    scan_status = "100"
    date_time = datetime.now()

    for openvas in all_openvas:
        ov_user = openvas.user
        ov_pass = openvas.password
        ov_ip = openvas.host

    scanner = VulnscanManager(str(ov_ip),
                              str(ov_user),
                              str(ov_pass))
    openvas_results = scanner.get_raw_xml(str(scan_id))

    hosts = OpenVas_Parser.get_hosts(openvas_results)

    del_old = openvas_scan_db.objects.filter(scan_id=scan_id)
    del_old.delete()

    for host in hosts:
        scan_dump = openvas_scan_db(scan_ip=host,
                                    scan_id=host,
                                    date_time=date_time,
                                    project_id=project_id,
                                    scan_status=scan_status,
                                    username=username
                                    )
        scan_dump.save()
    OpenVas_Parser.updated_xml_parser(project_id=project_id,
                                      scan_id=scan_id,
                                      root=openvas_results,
                                      username=username
                                      )
