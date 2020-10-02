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

from staticscanners.models import whitesource_scan_db, whitesource_scan_results_db
import uuid
import hashlib
from datetime import datetime
import json

from webscanners.zapscanner.views import email_sch_notify

vul_col = ''
severity = ''
project = ''


def whitesource_report_json(data, project_id, scan_id, username):
    """

    :param data:
    :param project_id:
    :param scan_id:
    :return:
    """

    global vul_col, project
    vuln = data['vulnerabilities']

    for issues in vuln:
        name = issues['name']
        severity = issues['severity']
        score = issues['score']
        cvss3_severity = issues['cvss3_severity']
        cvss3_score = issues['cvss3_score']
        publishDate = issues['publishDate']
        lastUpdatedDate = issues['lastUpdatedDate']
        scoreMetadataVector = issues['scoreMetadataVector']
        url = issues['url']
        description = issues['description']
        project = issues['project']
        product = issues['product']
        cvss3Attributes = issues['cvss3Attributes']
        library = issues['library']
        topFix = issues['topFix']
        #allFixes = issues['allFixes']
        filename = issues['library']['filename']
        sha1 = issues['library']['sha1']
        version = issues['library']['version']
        groupId = issues['library']['groupId']
        if severity == "high":
            severity = 'High'
            vul_col = "danger"
        elif severity == 'medium':
            severity = 'Medium'
            vul_col = "warning"
        elif severity == 'low':
            severity = 'Low'
            vul_col = "info"
        vul_id = uuid.uuid4()
        dup_data = str(name) + str(severity) + str(project)
        duplicate_hash = hashlib.sha256(dup_data.encode('utf-8')).hexdigest()
        match_dup = whitesource_scan_results_db.objects.filter(username=username,
                                                               dup_hash=duplicate_hash).values('dup_hash')
        lenth_match = len(match_dup)
        if lenth_match == 0:
            duplicate_vuln = 'No'

            false_p = whitesource_scan_results_db.objects.filter(username=username,
                                                                 false_positive_hash=duplicate_hash)
            fp_lenth_match = len(false_p)
            if fp_lenth_match == 1:
                false_positive = 'Yes'
            else:
                false_positive = 'No'
            save_all = whitesource_scan_results_db(
                vuln_id=vul_id,
                scan_id=scan_id,
                project_id=project_id,
                vul_col=vul_col,
                vuln_status='Open',
                dup_hash=duplicate_hash,
                vuln_duplicate=duplicate_vuln,
                false_positive=false_positive,

                name=name,
                severity=severity,
                score=score,
                cvss3_severity=cvss3_severity,
                cvss3_score=cvss3_score,
                publishDate=publishDate,
                lastUpdatedDate=lastUpdatedDate,
                scoreMetadataVector=scoreMetadataVector,
                url=url,
                description=description,
                project=project,
                product=product,
                cvss3Attributes=cvss3Attributes,
                library=library,
                topFix=topFix,
                # allFixes=allFixes,
                filename=filename,
                sha1=sha1,
                version=version,
                groupId=groupId,
                username=username,
            )
            save_all.save()

        else:
            duplicate_vuln = 'Yes'

            save_all = whitesource_scan_results_db(
                vuln_id=vul_id,
                scan_id=scan_id,
                project_id=project_id,
                vul_col=vul_col,
                vuln_status='Duplicate',
                dup_hash=duplicate_hash,
                vuln_duplicate=duplicate_vuln,
                false_positive='Duplicate',

                name=name,
                severity=severity,
                score=score,
                cvss3_severity=cvss3_severity,
                cvss3_score=cvss3_score,
                publishDate=publishDate,
                lastUpdatedDate=lastUpdatedDate,
                scoreMetadataVector=scoreMetadataVector,
                url=url,
                description=description,
                project=project,
                product=product,
                cvss3Attributes=cvss3Attributes,
                library=library,
                topFix=topFix,
                # allFixes=allFixes,
                filename=filename,
                sha1=sha1,
                version=version,
                groupId=groupId,
                username=username,
            )
            save_all.save()

    all_findbugs_data = whitesource_scan_results_db.objects.filter(username=username, scan_id=scan_id, false_positive='No')

    duplicate_count = whitesource_scan_results_db.objects.filter(username=username, scan_id=scan_id,
                                                                         vuln_duplicate='Yes')

    total_vul = len(all_findbugs_data)
    total_high = len(all_findbugs_data.filter(severity="High"))
    total_medium = len(all_findbugs_data.filter(severity="Medium"))
    total_low = len(all_findbugs_data.filter(severity="Low"))
    total_duplicate = len(duplicate_count.filter(vuln_duplicate='Yes'))

    whitesource_scan_db.objects.filter(username=username, scan_id=scan_id).update(
        project_name=project,
        total_vuln=total_vul,
        SEVERITY_HIGH=total_high,
        SEVERITY_MEDIUM=total_medium,
        SEVERITY_LOW=total_low,
        total_dup=total_duplicate
    )
    subject = 'Archery Tool Scan Status - whitesource Report Uploaded'
    message = 'whitesource Scanner has completed the scan ' \
              '  %s <br> Total: %s <br>High: %s <br>' \
              'Medium: %s <br>Low %s' % ("whitesource", total_vul, total_high, total_medium, total_low)

    email_sch_notify(subject=subject, message=message)
