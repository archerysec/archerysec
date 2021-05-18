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

from staticscanners.models import debcvescan_scan_db, debcvescan_scan_results_db
import uuid
import hashlib
from datetime import datetime
import json
from dashboard.views import trend_update
from webscanners.zapscanner.views import email_sch_notify

vul_col = ''
Target = ''
VulnerabilityID = ''
PkgName = ''
InstalledVersion = ''
FixedVersion = ''
Title = ''
Description = ''
Severity = ''
References = ''


def debcvescan_report_json(data, project_id, scan_id, username):
    """

    :param data:
    :param project_id:
    :param scan_id:
    :return:
    """
    date_time = datetime.now()
    vul_col = ''

    vuln = data['vulnerabilities']

    for vuln_data in vuln:
        try:
            description = vuln_data['description']
        except Exception as e:
            description = "Not Found"

        try:
            cve = vuln_data['cve']
        except Exception as e:
            cve = "Not Found"

        try:
            severity = vuln_data['severity']
        except Exception as e:
            severity = "Not Found"

        try:
            package = vuln_data['package']
        except Exception as e:
            package = "Not Found"

        try:
            package_ver = vuln_data['installed_version']
        except Exception as e:
            package_ver = "Not Found"

        try:
            fix_ver = vuln_data['fixed_version']
        except Exception as e:
            fix_ver = "Not Found"

        if severity == 3:
            severity = "High"
            vul_col = "danger"

        elif severity == 2:
            vul_col = "warning"
            severity = "Medium"

        elif severity == 1:
            vul_col = "info"
            severity = "Low"

        elif severity == 'Unknown':
            severity = "Low"
            vul_col = "info"

        else:
            severity = "No"
            vul_col = "info"

        vul_id = uuid.uuid4()

        dup_data = str(cve) + str(severity) + str(package)

        duplicate_hash = hashlib.sha256(dup_data.encode('utf-8')).hexdigest()

        match_dup = debcvescan_scan_results_db.objects.filter(username=username,
                                                                       dup_hash=duplicate_hash).values('dup_hash')
        lenth_match = len(match_dup)

        if lenth_match == 0:
            duplicate_vuln = 'No'

            false_p = debcvescan_scan_results_db.objects.filter(username=username,
                                                                    false_positive_hash=duplicate_hash)
            fp_lenth_match = len(false_p)

            if fp_lenth_match == 1:
                false_positive = 'Yes'
            else:
                false_positive = 'No'

            save_all = debcvescan_scan_results_db(
                vuln_id=vul_id,
                scan_id=scan_id,
                date_time=date_time,
                project_id=project_id,
                description=description,
                cve=cve,
                package=package,
                package_ver=package_ver,
                fix_ver=fix_ver,
                Severity=severity,
                vul_col=vul_col,
                vuln_status='Open',
                dup_hash=duplicate_hash,
                vuln_duplicate=duplicate_vuln,
                false_positive=false_positive,
                username=username,
            )
            save_all.save()
        else:
            duplicate_vuln = 'Yes'

            save_all = debcvescan_scan_results_db(
                vuln_id=vul_id,
                scan_id=scan_id,
                date_time=date_time,
                project_id=project_id,
                description=description,
                cve=cve,
                package=package,
                package_ver=package_ver,
                fix_ver=fix_ver,
                Severity=severity,
                vul_col=vul_col,
                vuln_status='Duplicate',
                dup_hash=duplicate_hash,
                vuln_duplicate=duplicate_vuln,
                false_positive='Duplicate',
                username=username,
            )
            save_all.save()

    all_findbugs_data = debcvescan_scan_results_db.objects.filter(username=username, scan_id=scan_id,
                                                                           false_positive='No')

    duplicate_count = debcvescan_scan_results_db.objects.filter(username=username, scan_id=scan_id, vuln_duplicate='Yes')

    total_vul = len(all_findbugs_data)
    total_high = len(all_findbugs_data.filter(Severity="High"))
    total_medium = len(all_findbugs_data.filter(Severity="Medium"))
    total_low = len(all_findbugs_data.filter(Severity="Low"))
    total_duplicate = len(duplicate_count.filter(vuln_duplicate='Yes'))

    debcvescan_scan_db.objects.filter(scan_id=scan_id).update(username=username,
                                                                       total_vul=total_vul,
                                                                       high_vul=total_high,
                                                                       medium_vul=total_medium,
                                                                       low_vul=total_low,
                                                                       total_dup=total_duplicate
                                                                       )
    trend_update(username=username)
    subject = 'Archery Tool Scan Status - Debian CVE Scan Report Uploaded'
    message = 'Debian CVE Scan has completed the scan ' \
              '  %s <br> Total: %s <br>High: %s <br>' \
              'Medium: %s <br>Low %s' % (Target, total_vul, total_high, total_medium, total_low)

    email_sch_notify(subject=subject, message=message)
