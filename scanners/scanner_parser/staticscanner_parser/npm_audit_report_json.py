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

from staticscanners.models import npmaudit_scan_db, npmaudit_scan_results_db
import uuid
import hashlib
from datetime import datetime
import json

from webscanners.zapscanner.views import email_sch_notify

vul_col = ''


def npmaudit_report_json(data, project_id, scan_id, username):
    """

    :param data:
    :param project_id:
    :param scan_id:
    :return:
    """
    global vul_col
    for vuln in data['advisories']:
        title = data['advisories'][vuln]['title']
        found_by = data['advisories'][vuln]['found_by']
        reported_by = data['advisories'][vuln]['reported_by']
        module_name = data['advisories'][vuln]['module_name']
        cves = data['advisories'][vuln]['cves']
        vulnerable_versions = data['advisories'][vuln]['vulnerable_versions']
        patched_versions = data['advisories'][vuln]['patched_versions']
        overview = data['advisories'][vuln]['overview']
        recommendation = data['advisories'][vuln]['recommendation']
        references = data['advisories'][vuln]['references']
        access = data['advisories'][vuln]['access']
        severity = data['advisories'][vuln]['severity']
        cwe = data['advisories'][vuln]['cwe']
        metadata = data['advisories'][vuln]['metadata']
        url = data['advisories'][vuln]['url']

        findings = (data['advisories'][vuln]['findings'])
        vuln_versions = {}
        for find in findings:
            vuln_versions[find['version']] = [find['paths']]

        if not title:
            title = "not found"
        if not found_by:
            found_by = "not found"
        if not reported_by:
            reported_by = "not found"
        if not module_name:
            module_name = "not found"
        if not cves:
            cves = "not found"
        if not vulnerable_versions:
            vulnerable_versions = "not found"
        if not patched_versions:
            patched_versions = "not found"
        if not recommendation:
            recommendation = "not found"
        if not overview:
            overview = "not found"
        if not references:
            references = "not found"
        if not access:
            access = "not found"
        if not severity:
            severity = "not found"
        if not cwe:
            cwe = "not found"
        if not url:
            url = "not found"

        if severity == "critical":
            severity = 'High'
            vul_col = "danger"

        if severity == "high":
            severity = 'High'
            vul_col = "danger"

        elif severity == 'moderate':
            severity = 'Medium'
            vul_col = "warning"

        elif severity == 'low':
            severity = 'Low'
            vul_col = "info"

        elif severity == 'info':
            severity = 'Low'
            vul_col = "info"

        vul_id = uuid.uuid4()

        dup_data = str(title) + str(severity) + str(module_name)

        duplicate_hash = hashlib.sha256(dup_data.encode('utf-8')).hexdigest()

        match_dup = npmaudit_scan_results_db.objects.filter(username=username,
            dup_hash=duplicate_hash).values('dup_hash')
        lenth_match = len(match_dup)

        if lenth_match == 0:
            duplicate_vuln = 'No'

            false_p = npmaudit_scan_results_db.objects.filter(username=username,
                                                              false_positive_hash=duplicate_hash)
            fp_lenth_match = len(false_p)

            if fp_lenth_match == 1:
                false_positive = 'Yes'
            else:
                false_positive = 'No'

            save_all = npmaudit_scan_results_db(
                vuln_id=vul_id,
                scan_id=scan_id,
                project_id=project_id,
                vul_col=vul_col,
                vuln_status='Open',
                dup_hash=duplicate_hash,
                vuln_duplicate=duplicate_vuln,
                false_positive=false_positive,
                version=vuln_versions,
                title=title,
                found_by=found_by,
                reported_by=reported_by,
                module_name=module_name,
                cves=cves,
                vulnerable_versions=vulnerable_versions,
                patched_versions=patched_versions,
                overview=overview,
                recommendation=recommendation,
                references=references,
                access=access,
                severity=severity,
                cwe=cwe,
                url=url,
                username=username,
            )
            save_all.save()

        else:
            duplicate_vuln = 'Yes'

            save_all = npmaudit_scan_results_db(
                vuln_id=vul_id,
                scan_id=scan_id,
                project_id=project_id,
                vul_col=vul_col,
                vuln_status='Duplicate',
                dup_hash=duplicate_hash,
                vuln_duplicate=duplicate_vuln,
                false_positive='Duplicate',
                version=vuln_versions,
                title=title,
                found_by=found_by,
                reported_by=reported_by,
                module_name=module_name,
                cves=cves,
                vulnerable_versions=vulnerable_versions,
                patched_versions=patched_versions,
                overview=overview,
                recommendation=recommendation,
                references=references,
                access=access,
                severity=severity,
                cwe=cwe,
                url=url,
                username=username,
            )
            save_all.save()

    all_findbugs_data = npmaudit_scan_results_db.objects.filter(username=username, scan_id=scan_id, false_positive='No')

    duplicate_count = npmaudit_scan_results_db.objects.filter(username=username, scan_id=scan_id,
                                                                         vuln_duplicate='Yes')

    total_vul = len(all_findbugs_data)
    total_high = len(all_findbugs_data.filter(severity="High"))
    total_medium = len(all_findbugs_data.filter(severity="Medium"))
    total_low = len(all_findbugs_data.filter(severity="Low"))
    total_duplicate = len(duplicate_count.filter(vuln_duplicate='Yes'))

    npmaudit_scan_db.objects.filter(username=username, scan_id=scan_id).update(
        total_vuln=total_vul,
        SEVERITY_HIGH=total_high,
        SEVERITY_MEDIUM=total_medium,
        SEVERITY_LOW=total_low,
        total_dup=total_duplicate
    )
    subject = 'Archery Tool Scan Status - Trivy Report Uploaded'
    message = 'Trivy Scanner has completed the scan ' \
              '  %s <br> Total: %s <br>High: %s <br>' \
              'Medium: %s <br>Low %s' % ("npm-audit", total_vul, total_high, total_medium, total_low)

    email_sch_notify(subject=subject, message=message)
