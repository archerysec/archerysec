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

from staticscanners.models import gitlabcontainerscan_scan_db, gitlabcontainerscan_scan_results_db
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


def gitlabcontainerscan_report_json(data, project_id, scan_id, username):
    """

    :param data:
    :param project_id:
    :param scan_id:
    :return:
    """
    vul_col = ''

    vuln = data['vulnerabilities']

    for vuln_data in vuln:
        try:
            name = vuln_data['name']
        except Exception as e:
            name = "Not Found"

        try:
            message = vuln_data['message']
        except Exception as e:
            message = "Not Found"

        try:
            description = vuln_data['description']
        except Exception as e:
            description = "Not Found"

        try:
            cve = vuln_data['cve']
        except Exception as e:
            cve = "Not Found"

        try:
            scanner = vuln_data['scanner']
        except Exception as e:
            scanner = "Not Found"

        try:
            location = vuln_data['location']
        except Exception as e:
            location = "Not Found"

        try:
            identifiers = vuln_data['identifiers']
        except Exception as e:
            identifiers = "Not Found"

        try:
            severity = vuln_data['severity']
        except Exception as e:
            severity = "Not Found"

        try:
            file = vuln_data['location']['file']
        except Exception as e:
            file = "Not Found"

        if severity == "Critical":
            severity = 'High'
            vul_col = "danger"

        if severity == "High":
            vul_col = "danger"

        elif severity == 'Medium':
            vul_col = "warning"

        elif severity == 'Low':
            vul_col = "info"

        elif severity == 'Unknown':
            severity = "Low"
            vul_col = "info"

        elif severity == 'Everything else':
            severity = "Low"
            vul_col = "info"

        vul_id = uuid.uuid4()

        dup_data = str(message) + str(severity) + str(file)

        duplicate_hash = hashlib.sha256(dup_data.encode('utf-8')).hexdigest()

        match_dup = gitlabcontainerscan_scan_results_db.objects.filter(username=username,
                                                                       dup_hash=duplicate_hash).values('dup_hash')
        lenth_match = len(match_dup)

        if lenth_match == 0:
            duplicate_vuln = 'No'

            false_p = gitlabcontainerscan_scan_results_db.objects.filter(username=username,
                                                                         false_positive_hash=duplicate_hash)
            fp_lenth_match = len(false_p)

            if fp_lenth_match == 1:
                false_positive = 'Yes'
            else:
                false_positive = 'No'

            save_all = gitlabcontainerscan_scan_results_db(
                vuln_id=vul_id,
                scan_id=scan_id,
                project_id=project_id,
                name=name,
                message=message,
                description=description,
                cve=cve,
                gl_scanner=scanner,
                location=location,
                file=file,
                Severity=severity,
                identifiers=identifiers,
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

            save_all = gitlabcontainerscan_scan_results_db(
                vuln_id=vul_id,
                scan_id=scan_id,
                project_id=project_id,
                name=name,
                message=message,
                description=description,
                cve=cve,
                gl_scanner=scanner,
                location=location,
                file=file,
                Severity=severity,
                identifiers=identifiers,
                vul_col=vul_col,
                vuln_status='Duplicate',
                dup_hash=duplicate_hash,
                vuln_duplicate=duplicate_vuln,
                false_positive='Duplicate',
                username=username,
            )
            save_all.save()

    all_findbugs_data = gitlabcontainerscan_scan_results_db.objects.filter(username=username, scan_id=scan_id,
                                                                           false_positive='No')

    duplicate_count = gitlabcontainerscan_scan_results_db.objects.filter(username=username, scan_id=scan_id, vuln_duplicate='Yes')

    total_vul = len(all_findbugs_data)
    total_high = len(all_findbugs_data.filter(Severity="High"))
    total_medium = len(all_findbugs_data.filter(Severity="Medium"))
    total_low = len(all_findbugs_data.filter(Severity="Low"))
    total_duplicate = len(duplicate_count.filter(vuln_duplicate='Yes'))

    gitlabcontainerscan_scan_db.objects.filter(scan_id=scan_id).update(username=username,
                                                                       total_vuln=total_vul,
                                                                       SEVERITY_HIGH=total_high,
                                                                       SEVERITY_MEDIUM=total_medium,
                                                                       SEVERITY_LOW=total_low,
                                                                       total_dup=total_duplicate
                                                                       )
    subject = 'Archery Tool Scan Status - GitLab Container Scan Report Uploaded'
    message = 'GitLab Container Scan has completed the scan ' \
              '  %s <br> Total: %s <br>High: %s <br>' \
              'Medium: %s <br>Low %s' % (Target, total_vul, total_high, total_medium, total_low)

    email_sch_notify(subject=subject, message=message)
