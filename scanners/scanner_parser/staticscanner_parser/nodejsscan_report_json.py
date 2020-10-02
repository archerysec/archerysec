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

from staticscanners.models import nodejsscan_scan_db, nodejsscan_scan_results_db
import uuid
import hashlib
from datetime import datetime
import json

from webscanners.zapscanner.views import email_sch_notify

vul_col = ''
severity = ''


def nodejsscan_report_json(data, project_id, scan_id, username):
    """

    :param data:
    :param project_id:
    :param scan_id:
    :return:
    """
    global vul_col, severity
    for vuln in data['sec_issues']:
        for vuln_dat in (data['sec_issues'][vuln]):
            with open('scanners/scanner_parser/staticscanner_parser/nodejsscan_vuln.json') as f:
                vuln_name = json.load(f)
                for v in (vuln_name['vuln']):
                    if v['name'] == vuln_dat['title']:
                        severity = v['severity']
            title = vuln_dat['title']
            filename = vuln_dat['filename']
            path = vuln_dat['path']
            sha2 = vuln_dat['sha2']
            tag = vuln_dat['tag']
            description = vuln_dat['description']

            line = vuln_dat['line']
            lines = vuln_dat['lines']

            if severity == "High":
                vul_col = "danger"

            elif severity == 'Medium':
                vul_col = "warning"

            elif severity == 'Low':
                vul_col = "info"

            vul_id = uuid.uuid4()

            dup_data = str(title) + str(severity) + str(filename) + str(line)
            print(dup_data)

            duplicate_hash = hashlib.sha256(dup_data.encode('utf-8')).hexdigest()
            print(duplicate_hash)

            match_dup = nodejsscan_scan_results_db.objects.filter(username=username,
                                                                  dup_hash=duplicate_hash).values('dup_hash')
            lenth_match = len(match_dup)

            if lenth_match == 0:
                duplicate_vuln = 'No'

                false_p = nodejsscan_scan_results_db.objects.filter(username=username,
                                                                    false_positive_hash=duplicate_hash)
                fp_lenth_match = len(false_p)

                if fp_lenth_match == 1:
                    false_positive = 'Yes'
                else:
                    false_positive = 'No'

                save_all = nodejsscan_scan_results_db(
                    vuln_id=vul_id,
                    scan_id=scan_id,
                    project_id=project_id,
                    vul_col=vul_col,
                    vuln_status='Open',
                    dup_hash=duplicate_hash,
                    vuln_duplicate=duplicate_vuln,
                    false_positive=false_positive,
                    title=title,
                    filename=filename,
                    severity=severity,
                    path=path,
                    sha2=sha2,
                    tag=tag,
                    description=description,
                    line=line,
                    lines=lines,
                    username=username,
                )
                save_all.save()

            else:
                duplicate_vuln = 'Yes'

                save_all = nodejsscan_scan_results_db(
                    vuln_id=vul_id,
                    scan_id=scan_id,
                    project_id=project_id,
                    vul_col=vul_col,
                    vuln_status='Duplicate',
                    dup_hash=duplicate_hash,
                    vuln_duplicate=duplicate_vuln,
                    false_positive='Duplicate',
                    title=title,
                    filename=filename,
                    severity=severity,
                    path=path,
                    sha2=sha2,
                    tag=tag,
                    description=description,
                    line=line,
                    lines=lines,
                    username=username,
                )
                save_all.save()

        all_findbugs_data = nodejsscan_scan_results_db.objects.filter(username=username, scan_id=scan_id,
                                                                      false_positive='No')

        duplicate_count = nodejsscan_scan_results_db.objects.filter(username=username, scan_id=scan_id,
                                                                             vuln_duplicate='Yes')

        total_vul = len(all_findbugs_data)
        total_high = len(all_findbugs_data.filter(severity="High"))
        total_medium = len(all_findbugs_data.filter(severity="Medium"))
        total_low = len(all_findbugs_data.filter(severity="Low"))
        total_duplicate = len(duplicate_count.filter(vuln_duplicate='Yes'))

        nodejsscan_scan_db.objects.filter(username=username, scan_id=scan_id).update(
            total_vuln=total_vul,
            SEVERITY_HIGH=total_high,
            SEVERITY_MEDIUM=total_medium,
            SEVERITY_LOW=total_low,
            total_dup=total_duplicate
        )
        subject = 'Archery Tool Scan Status - Trivy Report Uploaded'
        message = 'Trivy Scanner has completed the scan ' \
                  '  %s <br> Total: %s <br>High: %s <br>' \
                  'Medium: %s <br>Low %s' % ("Nodejsscan", total_vul, total_high, total_medium, total_low)

        email_sch_notify(subject=subject, message=message)
