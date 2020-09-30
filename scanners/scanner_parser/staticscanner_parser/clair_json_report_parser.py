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

from staticscanners.models import clair_scan_db, clair_scan_results_db
import uuid
import hashlib
from datetime import datetime

from webscanners.zapscanner.views import email_sch_notify

vul_col = ''

def clair_report_json(data, project_id, scan_id, username):
    """

    :param data:
    :param project_id:
    :param scan_id:
    :return:
    """

    # d = data['Vulnerabilities']['Medium']
    #
    # for dd in d:
    #     print dd['Name']

    global vul_col
    try:
        high = data['Vulnerabilities']['High']
        for vuln in high:
            vul_id = uuid.uuid4()
            try:
                Name = vuln['Name']

            except Exception:
                Name = "Not Found"

            try:
                NamespaceName = vuln['NamespaceName']
            except Exception:
                NamespaceName = "Not Found"

            try:
                Description = vuln['Description']
            except Exception:
                Description = "Not Found"

            try:
                Link = vuln['Link']
            except Exception:
                Link = "Not Found"

            try:
                Severity = vuln['Severity']
            except Exception:
                Severity = "Not Found"
            try:
                Metadata = vuln['Metadata']
            except Exception:
                Metadata = "Not Found"

            try:
                FeatureName = vuln['FeatureName']
            except Exception:
                FeatureName = "Not Found"

            try:
                FeatureVersion = vuln['FeatureVersion']
            except Exception:
                FeatureName = "Not Found"

            if Severity == "High":
                vul_col = "danger"

            dup_data = Name + Severity + NamespaceName

            duplicate_hash = hashlib.sha256(dup_data.encode('utf-8')).hexdigest()

            match_dup = clair_scan_results_db.objects.filter(username=username,
                dup_hash=duplicate_hash).values('dup_hash')
            lenth_match = len(match_dup)

            if lenth_match == 0:
                duplicate_vuln = 'No'

                false_p = clair_scan_results_db.objects.filter(username=username,
                                                               false_positive_hash=duplicate_hash)
                fp_lenth_match = len(false_p)

                if fp_lenth_match == 1:
                    false_positive = 'Yes'
                else:
                    false_positive = 'No'

                save_all = clair_scan_results_db(
                    vuln_id=vul_id,
                    scan_id=scan_id,
                    project_id=project_id,
                    Name=Name,
                    NamespaceName=NamespaceName,
                    Description=Description,
                    Link=Link,
                    Severity=Severity,
                    Metadata=Metadata,
                    FeatureName=FeatureName,
                    FeatureVersion=FeatureVersion,
                    vuln_status='Open',
                    dup_hash=duplicate_hash,
                    vuln_duplicate=duplicate_vuln,
                    false_positive=false_positive,
                    vul_col=vul_col,
                    username=username
                )
                save_all.save()

            else:
                duplicate_vuln = 'Yes'

                save_all = clair_scan_results_db(
                    vuln_id=vul_id,
                    scan_id=scan_id,
                    project_id=project_id,
                    Name=Name,
                    NamespaceName=NamespaceName,
                    Description=Description,
                    Link=Link,
                    Severity=Severity,
                    Metadata=Metadata,
                    FeatureName=FeatureName,
                    FeatureVersion=FeatureVersion,
                    vuln_status='Duplicate',
                    dup_hash=duplicate_hash,
                    vuln_duplicate=duplicate_vuln,
                    false_positive='Duplicate',
                    vul_col=vul_col,
                    username=username
                )
                save_all.save()


    except Exception:
        print("High Vulnerability Not Found")
        # pass

    try:

        medium = data['Vulnerabilities']['Medium']
        for vuln in medium:
            vul_id = uuid.uuid4()
            try:
                Name = vuln['Name']
            except Exception:
                Name = "Not Found"

            try:
                NamespaceName = vuln['NamespaceName']
            except Exception:
                NamespaceName = "Not Found"

            try:
                Description = vuln['Description']
            except Exception:
                Description = "Not Found"

            try:
                Link = vuln['Link']
            except Exception:
                Link = "Not Found"

            try:
                Severity = vuln['Severity']
            except Exception:
                Severity = "Not Found"
            try:
                Metadata = vuln['Metadata']
            except Exception:
                Metadata = "Not Found"

            try:
                FeatureName = vuln['FeatureName']
            except Exception:
                FeatureName = "Not Found"

            try:
                FeatureVersion = vuln['FeatureVersion']
            except Exception:
                FeatureName = "Not Found"

            if Severity == "Medium":
                vul_col = "warning"

            dup_data = Name + Severity + NamespaceName

            duplicate_hash = hashlib.sha256(dup_data.encode('utf-8')).hexdigest()

            match_dup = clair_scan_results_db.objects.filter(username=username,
                dup_hash=duplicate_hash).values('dup_hash')
            lenth_match = len(match_dup)

            if lenth_match == 0:

                duplicate_vuln = 'No'

                false_p = clair_scan_results_db.objects.filter(username=username,
                                                               false_positive_hash=duplicate_hash)
                fp_lenth_match = len(false_p)

                if fp_lenth_match == 1:
                    false_positive = 'Yes'
                else:
                    false_positive = 'No'

                save_all = clair_scan_results_db(
                    vuln_id=vul_id,
                    scan_id=scan_id,
                    project_id=project_id,
                    Name=Name,
                    NamespaceName=NamespaceName,
                    Description=Description,
                    Link=Link,
                    Severity=Severity,
                    Metadata=Metadata,
                    FeatureName=FeatureName,
                    FeatureVersion=FeatureVersion,
                    vuln_status='Open',
                    dup_hash=duplicate_hash,
                    vuln_duplicate=duplicate_vuln,
                    false_positive=false_positive,
                    vul_col=vul_col,
                    username=username,
                )
                save_all.save()

            else:
                duplicate_vuln = 'Yes'

                save_all = clair_scan_results_db(
                    vuln_id=vul_id,
                    scan_id=scan_id,
                    project_id=project_id,
                    Name=Name,
                    NamespaceName=NamespaceName,
                    Description=Description,
                    Link=Link,
                    Severity=Severity,
                    Metadata=Metadata,
                    FeatureName=FeatureName,
                    FeatureVersion=FeatureVersion,
                    vuln_status='Duplicate',
                    dup_hash=duplicate_hash,
                    vuln_duplicate=duplicate_vuln,
                    false_positive='Duplicate',
                    vul_col=vul_col,
                    username=username,
                )
                save_all.save()

    except Exception:
        print("Medium Vulnerability not found.")
        # pass

    try:
        low = data['Vulnerabilities']['Low']

        for vuln in low:
            vul_id = uuid.uuid4()
            try:
                Name = vuln['Name']
            except Exception:
                Name = "Not Found"

            try:
                NamespaceName = vuln['NamespaceName']
            except Exception:
                NamespaceName = "Not Found"

            try:
                Description = vuln['Description']
            except Exception:
                Description = "Not Found"

            try:
                Link = vuln['Link']
            except Exception:
                Link = "Not Found"

            try:
                Severity = vuln['Severity']
            except Exception:
                Severity = "Not Found"
            try:
                Metadata = vuln['Metadata']
            except Exception:
                Metadata = "Not Found"

            try:
                FeatureName = vuln['FeatureName']
            except Exception:
                FeatureName = "Not Found"

            try:
                FeatureVersion = vuln['FeatureVersion']
            except Exception:
                FeatureName = "Not Found"

            if Severity == "Low":
                vul_col = "info"

            dup_data = Name + Severity + NamespaceName

            duplicate_hash = hashlib.sha256(dup_data.encode('utf-8')).hexdigest()

            match_dup = clair_scan_results_db.objects.filter(
                dup_hash=duplicate_hash).values('dup_hash')
            lenth_match = len(match_dup)

            if lenth_match == 0:
                duplicate_vuln = 'No'

                false_p = clair_scan_results_db.objects.filter(username=username,
                                                               false_positive_hash=duplicate_hash)
                fp_lenth_match = len(false_p)

                if fp_lenth_match == 1:
                    false_positive = 'Yes'
                else:
                    false_positive = 'No'

                save_all = clair_scan_results_db(
                    vuln_id=vul_id,
                    scan_id=scan_id,
                    project_id=project_id,
                    Name=Name,
                    NamespaceName=NamespaceName,
                    Description=Description,
                    Link=Link,
                    Severity=Severity,
                    Metadata=Metadata,
                    FeatureName=FeatureName,
                    FeatureVersion=FeatureVersion,
                    vuln_status='Open',
                    dup_hash=duplicate_hash,
                    vuln_duplicate=duplicate_vuln,
                    false_positive=false_positive,
                    vul_col=vul_col,
                    username=username,
                )
                save_all.save()

            else:
                duplicate_vuln = 'Yes'

                save_all = clair_scan_results_db(
                    vuln_id=vul_id,
                    scan_id=scan_id,
                    project_id=project_id,
                    Name=Name,
                    NamespaceName=NamespaceName,
                    Description=Description,
                    Link=Link,
                    Severity=Severity,
                    Metadata=Metadata,
                    FeatureName=FeatureName,
                    FeatureVersion=FeatureVersion,
                    vuln_status='Duplicate',
                    dup_hash=duplicate_hash,
                    vuln_duplicate=duplicate_vuln,
                    false_positive='Duplicate',
                    vul_col=vul_col,
                    username=username,
                )
                save_all.save()

    except Exception:
        print("Low Vulnerability Not found")
        low = data['vulnerabilities']

        for vuln in low:
            vul_id = uuid.uuid4()
            try:
                Name = vuln['vulnerability']
            except Exception:
                Name = "Not Found"

            try:
                NamespaceName = vuln['namespace']
            except Exception:
                NamespaceName = "Not Found"

            try:
                Description = vuln['description']
            except Exception:
                Description = "Not Found"

            try:
                Link = vuln['link']
            except Exception:
                Link = "Not Found"

            try:
                Severity = vuln['severity']
            except Exception:
                Severity = "Not Found"
            try:
                Metadata = vuln['Metadata']
            except Exception:
                Metadata = "Not Found"

            try:
                FeatureName = vuln['featurename']
            except Exception:
                FeatureName = "Not Found"

            try:
                FeatureVersion = vuln['featureversion']
            except Exception:
                FeatureName = "Not Found"

            if Severity == "Low":
                vul_col = "info"

            if Severity == "Critical":
                Severity = "High"
                vul_col = "danger"

            if Severity == "High":
                vul_col = "danger"

            if Severity == "Medium":
                vul_col = "warning"

            dup_data = Name + Severity + NamespaceName

            duplicate_hash = hashlib.sha256(dup_data.encode('utf-8')).hexdigest()

            match_dup = clair_scan_results_db.objects.filter(username=username,
                dup_hash=duplicate_hash).values('dup_hash')
            lenth_match = len(match_dup)

            if lenth_match == 0:
                duplicate_vuln = 'No'

                false_p = clair_scan_results_db.objects.filter(username=username,
                                                               false_positive_hash=duplicate_hash)
                fp_lenth_match = len(false_p)

                if fp_lenth_match == 1:
                    false_positive = 'Yes'
                else:
                    false_positive = 'No'

                save_all = clair_scan_results_db(
                    vuln_id=vul_id,
                    scan_id=scan_id,
                    project_id=project_id,
                    Name=Name,
                    NamespaceName=NamespaceName,
                    Description=Description,
                    Link=Link,
                    Severity=Severity,
                    Metadata=Metadata,
                    FeatureName=FeatureName,
                    FeatureVersion=FeatureVersion,
                    vuln_status='Open',
                    dup_hash=duplicate_hash,
                    vuln_duplicate=duplicate_vuln,
                    false_positive=false_positive,
                    vul_col=vul_col,
                    username=username,
                )
                save_all.save()

            else:
                duplicate_vuln = 'Yes'

                save_all = clair_scan_results_db(
                    vuln_id=vul_id,
                    scan_id=scan_id,
                    project_id=project_id,
                    Name=Name,
                    NamespaceName=NamespaceName,
                    Description=Description,
                    Link=Link,
                    Severity=Severity,
                    Metadata=Metadata,
                    FeatureName=FeatureName,
                    FeatureVersion=FeatureVersion,
                    vuln_status='Duplicate',
                    dup_hash=duplicate_hash,
                    vuln_duplicate=duplicate_vuln,
                    false_positive='Duplicate',
                    vul_col=vul_col,
                    username=username,
                )
                save_all.save()
        # pass

    all_clair_data = clair_scan_results_db.objects.filter(username=username, scan_id=scan_id, false_positive='No')

    duplicate_count = clair_scan_results_db.objects.filter(username=username, scan_id=scan_id,
                                                                     vuln_duplicate='Yes')

    total_vul = len(all_clair_data)
    total_high = len(all_clair_data.filter(Severity='High'))
    total_medium = len(all_clair_data.filter(Severity='Medium'))
    total_low = len(all_clair_data.filter(Severity='Low'))
    total_duplicate = len(duplicate_count.filter(vuln_duplicate='Yes'))

    clair_scan_db.objects.filter(username=username, scan_id=scan_id).update(
        total_vuln=total_vul,
        SEVERITY_HIGH=total_high,
        SEVERITY_MEDIUM=total_medium,
        SEVERITY_LOW=total_low,
        total_dup=total_duplicate
    )

    subject = 'Archery Tool Scan Status - Clair Report Uploaded'
    message = 'Clair Scanner has completed the scan ' \
              '  %s <br> Total: %s <br>High: %s <br>' \
              'Medium: %s <br>Low %s' % (Name, total_vul, total_high, total_medium, total_low)

    email_sch_notify(subject=subject, message=message)
