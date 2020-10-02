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

from staticscanners.models import semgrepscan_scan_db, semgrepscan_scan_results_db
import uuid
import hashlib
from datetime import datetime
import json

from webscanners.zapscanner.views import email_sch_notify

vul_col = ''
Target = ''
PkgName = ''
InstalledVersion = ''
FixedVersion = ''
Title = ''
Description = ''
Severity = ''
References = ''


def semgrep_report_json(data, project_id, scan_id, username):
    """

    :param data:
    :param project_id:
    :param scan_id:
    :return:
    """
    vul_col = ''

    vuln = data['results']

    for vuln_data in vuln:
        try:
            check_id = vuln_data['check_id']
        except Exception as e:
            check_id = 'Not Found'

        try:
            path = vuln_data['path']
        except Exception as e:
            path = 'Not Found'

        try:
            start = vuln_data['start']
        except Exception as e:
            start = 'Not Found'

        try:
            end = vuln_data['end']
        except Exception as e:
            end = 'Not Found'

        try:
            message = vuln_data['extra']['message']
        except Exception as e:
            message = 'Not Found'

        try:
            metavars = vuln_data['extra']['metavars']
        except Exception as e:
            metavars = 'Not Found'

        try:
            metadata = vuln_data['extra']['metadata']
        except Exception as e:
            metadata = 'Not Found'

        try:
            severity = vuln_data['extra']['severity']
        except Exception as e:
            severity = 'Not Found'

        try:
            lines = vuln_data['extra']['lines']
        except Exception as e:
            lines = 'Not Found'

        if severity == "ERROR":
            severity = "High"
            vul_col = "danger"

        elif severity == 'WARNING':
            severity = 'Medium'
            vul_col = "warning"

        elif severity == 'INFORMATION':
            severity = 'Low'
            vul_col = "info"

        vul_id = uuid.uuid4()

        dup_data = str(check_id) + str(severity) + str(path)

        duplicate_hash = hashlib.sha256(dup_data.encode('utf-8')).hexdigest()

        match_dup = semgrepscan_scan_results_db.objects.filter(username=username,
                                                               dup_hash=duplicate_hash).values('dup_hash')
        lenth_match = len(match_dup)

        if lenth_match == 0:
            duplicate_vuln = 'No'

            false_p = semgrepscan_scan_results_db.objects.filter(username=username,
                                                                 false_positive_hash=duplicate_hash)
            fp_lenth_match = len(false_p)

            if fp_lenth_match == 1:
                false_positive = 'Yes'
            else:
                false_positive = 'No'

            save_all = semgrepscan_scan_results_db(
                vuln_id=vul_id,
                scan_id=scan_id,
                project_id=project_id,
                vul_col=vul_col,
                vuln_status='Open',
                dup_hash=duplicate_hash,
                vuln_duplicate=duplicate_vuln,
                false_positive=false_positive,
                check_id=check_id,
                path=path,
                severity=severity,
                message=message,
                end=end,
                metavars=metavars,
                metadata=metadata,
                lines=lines,
                username=username,
            )
            save_all.save()

        else:
            duplicate_vuln = 'Yes'

            save_all = semgrepscan_scan_results_db(
                vuln_id=vul_id,
                scan_id=scan_id,
                project_id=project_id,
                vul_col=vul_col,
                vuln_status='Duplicate',
                dup_hash=duplicate_hash,
                vuln_duplicate=duplicate_vuln,
                false_positive='Duplicate',
                check_id=check_id,
                path=path,
                severity=severity,
                message=message,
                end=end,
                metavars=metavars,
                metadata=metadata,
                lines=lines,
                username=username,
            )
            save_all.save()

    all_findbugs_data = semgrepscan_scan_results_db.objects.filter(username=username, scan_id=scan_id,
                                                                   false_positive='No')

    duplicate_count = semgrepscan_scan_results_db.objects.filter(username=username, scan_id=scan_id,
                                                                 vuln_duplicate='Yes')

    total_vul = len(all_findbugs_data)
    total_high = len(all_findbugs_data.filter(severity="High"))
    total_medium = len(all_findbugs_data.filter(severity="Medium"))
    total_low = len(all_findbugs_data.filter(severity="Low"))
    total_duplicate = len(duplicate_count.filter(vuln_duplicate='Yes'))

    semgrepscan_scan_db.objects.filter(username=username, scan_id=scan_id).update(
        total_vuln=total_vul,
        SEVERITY_HIGH=total_high,
        SEVERITY_MEDIUM=total_medium,
        SEVERITY_LOW=total_low,
        total_dup=total_duplicate
    )
    subject = 'Archery Tool Scan Status - semgrep Report Uploaded'
    message = 'semgrep Scanner has completed the scan ' \
              '  %s <br> Total: %s <br>High: %s <br>' \
              'Medium: %s <br>Low %s' % ("semgrep", total_vul, total_high, total_medium, total_low)

    email_sch_notify(subject=subject, message=message)
