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
from networkscanners.models import scan_save_db, ov_scan_result_db
from django.utils import timezone
from archerysettings import load_settings
from django.core import signing
import time
import os
import uuid
from archerysettings.models import openvas_setting_db

# openvas_data = os.getcwd() + '/' + 'apidata.json'
# openvas_setting = load_settings.ArcherySettings(openvas_data)
import hashlib


class OpenVAS_Plugin:
    """
    OpenVAS plugin Class
    """

    def __init__(self, scan_ip, project_id, sel_profile):
        """

        :param scan_ip:
        :param project_id:
        :param sel_profile:
        """

        self.scan_ip = scan_ip
        self.project_id = project_id
        self.sel_profile = sel_profile

    def connect(self):
        """
        Connecting with OpenVAS
        :return:
        """

        all_openvas = openvas_setting_db.objects.all()

        for openvas in all_openvas:
            ov_user = openvas.user
            ov_pass = openvas.password
            ov_host = openvas.host
            ov_port = openvas.port

        # ov_user = openvas_setting.openvas_username()
        # ov_pass = openvas_setting.openvas_pass()
        # ov_host = openvas_setting.openvas_host()

        lod_ov_user = ov_user
        lod_ov_pass = ov_pass
        lod_ov_host = ov_host
        lod_ov_port = ov_port

        scanner = VulnscanManager(str(lod_ov_host),
                                  str(lod_ov_user),
                                  str(lod_ov_pass),
                                  int(lod_ov_port))
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
                scan_save_db.objects.filter(scan_id=scan_id).update(scan_status=status)
                previous = current
            time.sleep(5)

        status = "100"
        scan_save_db.objects.filter(scan_id=scan_id).update(scan_status=status)

        return status


def vuln_an_id(scan_id, project_id):
    """
    The function is filtering all data from OpenVAS and dumping to Archery database.
    :param scan_id:
    :return:
    """
    # ov_user = openvas_setting.openvas_username()
    # ov_pass = openvas_setting.openvas_pass()
    # ov_ip = openvas_setting.openvas_host()
    #
    # lod_ov_user = signing.loads(ov_user)
    # lod_ov_pass = signing.loads(ov_pass)
    # lod_ov_ip = signing.loads(ov_ip)

    all_openvas = openvas_setting_db.objects.all()

    for openvas in all_openvas:
        ov_user = openvas.user
        ov_pass = openvas.password
        ov_ip = openvas.host

    lod_ov_user = ov_user
    lod_ov_pass = ov_pass
    lod_ov_ip = ov_ip

    scanner = VulnscanManager(str(lod_ov_ip),
                              str(lod_ov_user),
                              str(lod_ov_pass))
    openvas_results = scanner.get_raw_xml(str(scan_id))

    for openvas in openvas_results.findall(".//result"):
        for r in openvas:
            if r.tag == "name":
                global name
                if r.text is None:
                    name = "NA"
                else:
                    name = r.text

            if r.tag == "creation_time":
                global creation_time
                if r.text is None:
                    creation_time = "NA"
                else:
                    creation_time = r.text

            if r.tag == "modification_time":
                global modification_time
                if r.text is None:
                    modification_time = "NA"
                else:
                    modification_time = r.text
            if r.tag == "host":
                global host
                if r.text is None:
                    host = "NA"
                else:
                    host = r.text

            if r.tag == "port":
                global port
                if r.text is None:
                    port = "NA"
                else:
                    port = r.text
            if r.tag == "threat":
                global threat
                if r.text is None:
                    threat = "NA"
                else:
                    threat = r.text
            if r.tag == "severity":
                global severity
                if r.text is None:
                    severity = "NA"
                else:
                    severity = r.text
            if r.tag == "description":
                global description
                if r.text is None:
                    description = "NA"
                else:
                    description = r.text

            for rr in r.getchildren():
                if rr.tag == "family":
                    global family
                    if rr.text is None:
                        family = "NA"
                    else:
                        family = rr.text
                if rr.tag == "cvss_base":
                    global cvss_base
                    if rr.text is None:
                        cvss_base = "NA"
                    else:
                        cvss_base = rr.text
                if rr.tag == "cve":
                    global cve
                    if rr.text is None:
                        cve = "NA"
                    else:
                        cve = rr.text
                if rr.tag == "bid":
                    global bid
                    if rr.text is None:
                        bid = "NA"
                    else:
                        bid = rr.text

                if rr.tag == "xref":
                    global xref
                    if rr.text is None:
                        xref = "NA"
                    else:
                        xref = rr.text

                if rr.tag == "tags":
                    global tags
                    if rr.text is None:
                        tags = "NA"
                    else:
                        tags = rr.text
                if rr.tag == "type":
                    global banner
                    if rr.text is None:
                        banner = "NA"
                    else:
                        banner = rr.text

        date_time = timezone.now()
        vul_id = uuid.uuid4()

        dup_data = name + host + severity + port
        duplicate_hash = hashlib.sha256(dup_data.encode('utf-8')).hexdigest()

        match_dup = ov_scan_result_db.objects.filter(
            vuln_duplicate=duplicate_hash).values('vuln_duplicate').distinct()
        lenth_match = len(match_dup)

        if lenth_match == 1:
            duplicate_vuln = 'Yes'
        elif lenth_match == 0:
            duplicate_vuln = 'No'
        else:
            duplicate_vuln = 'None'

        false_p = ov_scan_result_db.objects.filter(
            false_positive_hash=duplicate_hash)
        fp_lenth_match = len(false_p)

        if fp_lenth_match == 1:
            false_positive = 'Yes'
        else:
            false_positive = 'No'

        save_all = ov_scan_result_db(scan_id=scan_id,
                                     vul_id=vul_id,
                                     name=name,
                                     creation_time=creation_time,
                                     modification_time=modification_time,
                                     host=host,
                                     port=port,
                                     threat=threat,
                                     severity=severity,
                                     description=description,
                                     family=family,
                                     cvss_base=cvss_base,
                                     cve=cve,
                                     bid=bid,
                                     xref=xref,
                                     tags=tags,
                                     banner=banner,
                                     date_time=date_time,
                                     false_positive=false_positive,
                                     vuln_status='Open',
                                     dup_hash=duplicate_hash,
                                     vuln_duplicate=duplicate_vuln,
                                     project_id=project_id,

                                     )
        save_all.save()

        openvas_vul = ov_scan_result_db.objects.filter(scan_id=scan_id)

        total_high = len(openvas_vul.filter(threat="High"))
        total_medium = len(openvas_vul.filter(threat="Medium"))
        total_low = len(openvas_vul.filter(threat="Low"))
        log_total = len(openvas_vul.filter(threat="Log"))
        total_duplicate = len(openvas_vul.filter(vuln_duplicate='Yes'))
        total_vul = total_high + total_medium + total_low

        scan_save_db.objects.filter(scan_id=scan_id). \
            update(total_vul=total_vul,
                   high_total=total_high,
                   medium_total=total_medium,
                   log_total=log_total,
                   low_total=total_low,
                   total_dup=total_duplicate,

                   )

        for row in ov_scan_result_db.objects.all():
            if ov_scan_result_db.objects.filter(name=row.name, port=row.port, scan_id=scan_id).count() > 1:
                row.delete()
