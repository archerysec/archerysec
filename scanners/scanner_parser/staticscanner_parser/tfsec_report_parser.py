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

from staticscanners.models import tfsec_scan_db, tfsec_scan_results_db
import uuid
import hashlib
from datetime import datetime
import json

from webscanners.zapscanner.views import email_sch_notify

vul_col = ''
severity = ''


def tfsec_report_json(data, project_id, scan_id, username):
    """

    :param data:
    :param project_id:
    :param scan_id:
    :return:
    """

    global vul_col
    for vuln in data['results']:
        rule_id = vuln['rule_id']
        link = vuln['link']
        filename = vuln['location']['filename']
        start_line = vuln['location']['start_line']
        end_line = vuln['location']['end_line']
        description = vuln['description']
        severity = vuln['severity']

        if severity == "ERROR":
            severity = 'High'
            vul_col = "danger"

        elif severity == 'WARNING':
            severity = 'Medium'
            vul_col = "warning"

        elif severity == 'INFO':
            severity = 'Info'
            vul_col = "info"

        vul_id = uuid.uuid4()

        dup_data = str(rule_id) + str(severity) + str(filename)

        duplicate_hash = hashlib.sha256(dup_data.encode('utf-8')).hexdigest()

        match_dup = tfsec_scan_results_db.objects.filter(username=username,
                                                         dup_hash=duplicate_hash).values('dup_hash')
        lenth_match = len(match_dup)

        if lenth_match == 0:
            duplicate_vuln = 'No'

            false_p = tfsec_scan_results_db.objects.filter(username=username,
                                                           false_positive_hash=duplicate_hash)
            fp_lenth_match = len(false_p)

            if fp_lenth_match == 1:
                false_positive = 'Yes'
            else:
                false_positive = 'No'

            save_all = tfsec_scan_results_db(
                vuln_id=vul_id,
                scan_id=scan_id,
                project_id=project_id,
                vul_col=vul_col,
                vuln_status='Open',
                dup_hash=duplicate_hash,
                vuln_duplicate=duplicate_vuln,
                false_positive=false_positive,
                rule_id=rule_id,
                filename=filename,
                severity=severity,
                description=description,
                link=link,
                start_line=start_line,
                end_line=end_line,
                username=username,
            )
            save_all.save()

        else:
            duplicate_vuln = 'Yes'

            save_all = tfsec_scan_results_db(
                vuln_id=vul_id,
                scan_id=scan_id,
                project_id=project_id,
                vul_col=vul_col,
                vuln_status='Duplicate',
                dup_hash=duplicate_hash,
                vuln_duplicate=duplicate_vuln,
                false_positive='Duplicate',
                rule_id=rule_id,
                filename=filename,
                severity=severity,
                description=description,
                link=link,
                start_line=start_line,
                end_line=end_line,
                username=username,
            )
            save_all.save()

    all_findbugs_data = tfsec_scan_results_db.objects.filter(username=username, scan_id=scan_id, false_positive='No')

    duplicate_count = tfsec_scan_results_db.objects.filter(username=username, scan_id=scan_id,
                                                           vuln_duplicate='Yes')

    total_vul = len(all_findbugs_data)
    total_high = len(all_findbugs_data.filter(severity="High"))
    total_medium = len(all_findbugs_data.filter(severity="Medium"))
    total_low = len(all_findbugs_data.filter(severity="Low"))
    total_duplicate = len(duplicate_count.filter(vuln_duplicate='Yes'))

    tfsec_scan_db.objects.filter(username=username, scan_id=scan_id).update(
        total_vuln=total_vul,
        SEVERITY_HIGH=total_high,
        SEVERITY_MEDIUM=total_medium,
        SEVERITY_LOW=total_low,
        total_dup=total_duplicate
    )
    subject = 'Archery Tool Scan Status - tfsec Report Uploaded'
    message = 'tfsec Scanner has completed the scan ' \
              '  %s <br> Total: %s <br>High: %s <br>' \
              'Medium: %s <br>Low %s' % ("tfsec", total_vul, total_high, total_medium, total_low)

    email_sch_notify(subject=subject, message=message)
