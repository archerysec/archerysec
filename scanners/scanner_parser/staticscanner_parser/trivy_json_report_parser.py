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

from staticscanners.models import trivy_scan_db, trivy_scan_results_db
import uuid
import hashlib
from datetime import datetime
import json

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


def trivy_report_json(data, project_id, scan_id):
    """

    :param data:
    :param project_id:
    :param scan_id:
    :return:
    """
    vul_col = ''
    for vuln_data in data:
        Target = vuln_data['Target']

        for vuln in data:
            vulnerbilities = vuln['Vulnerabilities']
            try:
                for dat_vuln in vulnerbilities:
                    try:
                        VulnerabilityID = dat_vuln['VulnerabilityID']
                    except Exception as e:
                        VulnerabilityID = "Not Found"
                        print(e)
                    try:
                        PkgName = dat_vuln['PkgName']
                    except Exception as e:
                        PkgName = "Not Found"
                        print(e)
                    try:
                        InstalledVersion = dat_vuln['InstalledVersion']
                    except Exception as e:
                        InstalledVersion = "Not Found"
                        print(e)
                    try:
                        FixedVersion = dat_vuln['FixedVersion']
                    except Exception as e:
                        FixedVersion = "Not Found"
                        print(e)
                    try:
                        Title = dat_vuln['Title']
                    except Exception as e:
                        Title = "Not Found"
                        print(e)
                    try:
                        Description = dat_vuln['Description']
                    except Exception as e:
                        Description = "Not Found"
                        print(e)
                    try:
                        Severity = dat_vuln['Severity']
                    except Exception as e:
                        Severity = "Not Found"
                        print(e)
                    try:
                        References = dat_vuln['References']
                    except Exception as e:
                        References = "Not Found"
                        print(e)

                    if Severity == "HIGH":
                        Severity = 'High'
                        vul_col = "danger"

                    elif Severity == 'MEDIUM':
                        Severity = 'Medium'
                        vul_col = "warning"

                    elif Severity == 'LOW':
                        Severity = 'Low'
                        vul_col = "info"

                    vul_id = uuid.uuid4()

                    dup_data = VulnerabilityID + Severity

                    duplicate_hash = hashlib.sha256(dup_data.encode('utf-8')).hexdigest()

                    match_dup = trivy_scan_results_db.objects.filter(
                        dup_hash=duplicate_hash).values('dup_hash')
                    lenth_match = len(match_dup)

                    if lenth_match == 1:
                        duplicate_vuln = 'Yes'
                    elif lenth_match == 0:
                        duplicate_vuln = 'No'
                    else:
                        duplicate_vuln = 'None'

                    false_p = trivy_scan_results_db.objects.filter(
                        false_positive_hash=duplicate_hash)
                    fp_lenth_match = len(false_p)

                    if fp_lenth_match == 1:
                        false_positive = 'Yes'
                    else:
                        false_positive = 'No'

                    save_all = trivy_scan_results_db(
                        vuln_id=vul_id,
                        scan_id=scan_id,
                        project_id=project_id,
                        Target=Target,
                        VulnerabilityID=VulnerabilityID,
                        PkgName=PkgName,
                        InstalledVersion=InstalledVersion,
                        FixedVersion=FixedVersion,
                        Title=Title,
                        Description=Description,
                        Severity=Severity,
                        References=References,
                        vul_col=vul_col,
                        vuln_status='Open',
                        dup_hash=duplicate_hash,
                        vuln_duplicate=duplicate_vuln,
                        false_positive=false_positive,
                    )
                    save_all.save()
            except Exception as e:
                print(e)

        all_findbugs_data = trivy_scan_results_db.objects.filter(scan_id=scan_id, false_positive='No')

        total_vul = len(all_findbugs_data)
        total_high = len(all_findbugs_data.filter(Severity="High"))
        total_medium = len(all_findbugs_data.filter(Severity="Medium"))
        total_low = len(all_findbugs_data.filter(Severity="Low"))
        total_duplicate = len(all_findbugs_data.filter(vuln_duplicate='Yes'))

        trivy_scan_db.objects.filter(scan_id=scan_id).update(
            total_vuln=total_vul,
            SEVERITY_HIGH=total_high,
            SEVERITY_MEDIUM=total_medium,
            SEVERITY_LOW=total_low,
            total_dup=total_duplicate
        )
    subject = 'Archery Tool Scan Status - Trivy Report Uploaded'
    message = 'Trivy Scanner has completed the scan ' \
              '  %s <br> Total: %s <br>High: %s <br>' \
              'Medium: %s <br>Low %s' % (Target, total_vul, total_high, total_medium, total_low)

    email_sch_notify(subject=subject, message=message)
