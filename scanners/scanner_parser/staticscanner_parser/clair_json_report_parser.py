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

import hashlib
import uuid
from datetime import datetime

from dashboard.views import trend_update
from staticscanners.models import StaticScanResultsDb, StaticScansDb
from utility.email_notify import email_sch_notify

vul_col = ""
Name = ""


def clair_report_json(data, project_id, scan_id):
    """

    :param data:
    :param project_id:
    :param scan_id:
    :return:
    """
    date_time = datetime.now()
    global vul_col, Name
    try:
        high = data["Vulnerabilities"]["High"]
        for vuln in high:
            vul_id = uuid.uuid4()
            try:
                Name = vuln["Name"]

            except Exception:
                Name = "Not Found"

            try:
                NamespaceName = vuln["NamespaceName"]
            except Exception:
                NamespaceName = "Not Found"

            try:
                Description = vuln["Description"]
            except Exception:
                Description = "Not Found"

            try:
                Link = vuln["Link"]
            except Exception:
                Link = "Not Found"

            try:
                Severity = vuln["Severity"]
            except Exception:
                Severity = "Not Found"
            try:
                Metadata = vuln["Metadata"]
            except Exception:
                Metadata = "Not Found"

            try:
                FeatureName = vuln["FeatureName"]
            except Exception:
                FeatureName = "Not Found"

            try:
                FeatureVersion = vuln["FeatureVersion"]
            except Exception:
                FeatureName = "Not Found"

            if Severity == "High":
                vul_col = "danger"

            dup_data = Name + Severity + NamespaceName

            duplicate_hash = hashlib.sha256(dup_data.encode("utf-8")).hexdigest()

            match_dup = StaticScanResultsDb.objects.filter(
                dup_hash=duplicate_hash
            ).values("dup_hash")
            lenth_match = len(match_dup)

            if lenth_match == 0:
                duplicate_vuln = "No"

                false_p = StaticScanResultsDb.objects.filter(
                    false_positive_hash=duplicate_hash
                )
                fp_lenth_match = len(false_p)

                if fp_lenth_match == 1:
                    false_positive = "Yes"
                else:
                    false_positive = "No"

                save_all = StaticScanResultsDb(
                    vuln_id=vul_id,
                    scan_id=scan_id,
                    date_time=date_time,
                    project_id=project_id,
                    title=Name,
                    description=str(Description)
                    + "\n\n"
                    + str(NamespaceName)
                    + "\n\n"
                    + str(Metadata)
                    + "\n\n"
                    + str(FeatureName),
                    references=Link,
                    severity=Severity,
                    vuln_status="Open",
                    dup_hash=duplicate_hash,
                    vuln_duplicate=duplicate_vuln,
                    false_positive=false_positive,
                    severity_color=vul_col,
                    scanner="Clair",
                )
                save_all.save()

            else:
                duplicate_vuln = "Yes"

                save_all = StaticScanResultsDb(
                    vuln_id=vul_id,
                    scan_id=scan_id,
                    date_time=date_time,
                    project_id=project_id,
                    title=Name,
                    description=str(Description)
                    + "\n\n"
                    + str(NamespaceName)
                    + "\n\n"
                    + str(Metadata)
                    + "\n\n"
                    + str(FeatureName),
                    references=Link,
                    severity=Severity,
                    vuln_status="Duplicate",
                    dup_hash=duplicate_hash,
                    vuln_duplicate=duplicate_vuln,
                    false_positive="Duplicate",
                    severity_color=vul_col,
                    scanner="Clair",
                )
                save_all.save()

    except Exception:
        print("High Vulnerability Not Found")
        # pass

    try:

        medium = data["Vulnerabilities"]["Medium"]
        for vuln in medium:
            vul_id = uuid.uuid4()
            try:
                Name = vuln["Name"]
            except Exception:
                Name = "Not Found"

            try:
                NamespaceName = vuln["NamespaceName"]
            except Exception:
                NamespaceName = "Not Found"

            try:
                Description = vuln["Description"]
            except Exception:
                Description = "Not Found"

            try:
                Link = vuln["Link"]
            except Exception:
                Link = "Not Found"

            try:
                Severity = vuln["Severity"]
            except Exception:
                Severity = "Not Found"
            try:
                Metadata = vuln["Metadata"]
            except Exception:
                Metadata = "Not Found"

            try:
                FeatureName = vuln["FeatureName"]
            except Exception:
                FeatureName = "Not Found"

            try:
                FeatureVersion = vuln["FeatureVersion"]
            except Exception:
                FeatureName = "Not Found"

            if Severity == "Medium":
                vul_col = "warning"

            dup_data = Name + Severity + NamespaceName

            duplicate_hash = hashlib.sha256(dup_data.encode("utf-8")).hexdigest()

            match_dup = StaticScanResultsDb.objects.filter(
                dup_hash=duplicate_hash
            ).values("dup_hash")
            lenth_match = len(match_dup)

            if lenth_match == 0:

                duplicate_vuln = "No"

                false_p = StaticScanResultsDb.objects.filter(
                    false_positive_hash=duplicate_hash
                )
                fp_lenth_match = len(false_p)

                if fp_lenth_match == 1:
                    false_positive = "Yes"
                else:
                    false_positive = "No"

                save_all = StaticScanResultsDb(
                    vuln_id=vul_id,
                    scan_id=scan_id,
                    date_time=date_time,
                    project_id=project_id,
                    title=Name,
                    description=str(Description)
                    + "\n\n"
                    + str(NamespaceName)
                    + "\n\n"
                    + str(Metadata)
                    + "\n\n"
                    + str(FeatureName),
                    references=Link,
                    severity=Severity,
                    vuln_status="Open",
                    dup_hash=duplicate_hash,
                    vuln_duplicate=duplicate_vuln,
                    false_positive=false_positive,
                    severity_color=vul_col,
                    scanner="Clair",
                )
                save_all.save()

            else:
                duplicate_vuln = "Yes"

                save_all = StaticScanResultsDb(
                    vuln_id=vul_id,
                    scan_id=scan_id,
                    date_time=date_time,
                    project_id=project_id,
                    title=Name,
                    description=str(Description)
                    + "\n\n"
                    + str(NamespaceName)
                    + "\n\n"
                    + str(Metadata)
                    + "\n\n"
                    + str(FeatureName),
                    references=Link,
                    severity=Severity,
                    vuln_status="Duplicate",
                    dup_hash=duplicate_hash,
                    vuln_duplicate=duplicate_vuln,
                    false_positive="Duplicate",
                    severity_color=vul_col,
                    scanner="Clair",
                )
                save_all.save()

    except Exception:
        print("Medium Vulnerability not found.")
        # pass

    try:
        low = data["Vulnerabilities"]["Low"]

        for vuln in low:
            vul_id = uuid.uuid4()
            try:
                Name = vuln["Name"]
            except Exception:
                Name = "Not Found"

            try:
                NamespaceName = vuln["NamespaceName"]
            except Exception:
                NamespaceName = "Not Found"

            try:
                Description = vuln["Description"]
            except Exception:
                Description = "Not Found"

            try:
                Link = vuln["Link"]
            except Exception:
                Link = "Not Found"

            try:
                Severity = vuln["Severity"]
            except Exception:
                Severity = "Not Found"
            try:
                Metadata = vuln["Metadata"]
            except Exception:
                Metadata = "Not Found"

            try:
                FeatureName = vuln["FeatureName"]
            except Exception:
                FeatureName = "Not Found"

            try:
                FeatureVersion = vuln["FeatureVersion"]
            except Exception:
                FeatureName = "Not Found"

            if Severity == "Low":
                vul_col = "info"

            dup_data = Name + Severity + NamespaceName

            duplicate_hash = hashlib.sha256(dup_data.encode("utf-8")).hexdigest()

            match_dup = StaticScanResultsDb.objects.filter(
                dup_hash=duplicate_hash
            ).values("dup_hash")
            lenth_match = len(match_dup)

            if lenth_match == 0:
                duplicate_vuln = "No"

                false_p = StaticScanResultsDb.objects.filter(
                    false_positive_hash=duplicate_hash
                )
                fp_lenth_match = len(false_p)

                if fp_lenth_match == 1:
                    false_positive = "Yes"
                else:
                    false_positive = "No"

                save_all = StaticScanResultsDb(
                    vuln_id=vul_id,
                    scan_id=scan_id,
                    date_time=date_time,
                    project_id=project_id,
                    title=Name,
                    description=str(Description)
                    + "\n\n"
                    + str(NamespaceName)
                    + "\n\n"
                    + str(Metadata)
                    + "\n\n"
                    + str(FeatureName),
                    references=Link,
                    severity=Severity,
                    vuln_status="Open",
                    dup_hash=duplicate_hash,
                    vuln_duplicate=duplicate_vuln,
                    false_positive=false_positive,
                    severity_color=vul_col,
                    scanner="Clair",
                )
                save_all.save()

            else:
                duplicate_vuln = "Yes"

                save_all = StaticScanResultsDb(
                    vuln_id=vul_id,
                    scan_id=scan_id,
                    date_time=date_time,
                    project_id=project_id,
                    title=Name,
                    description=str(Description)
                    + "\n\n"
                    + str(NamespaceName)
                    + "\n\n"
                    + str(Metadata)
                    + "\n\n"
                    + str(FeatureName),
                    references=Link,
                    severity=Severity,
                    vuln_status="Duplicate",
                    dup_hash=duplicate_hash,
                    vuln_duplicate=duplicate_vuln,
                    false_positive="Duplicate",
                    severity_color=vul_col,
                    scanner="Clair",
                )
                save_all.save()

    except Exception:
        print("Low Vulnerability Not found")
        low = data["Vulnerabilities"]["Low"]

        for vuln in low:
            vul_id = uuid.uuid4()
            try:
                Name = vuln["vulnerability"]
            except Exception:
                Name = "Not Found"

            try:
                NamespaceName = vuln["namespace"]
            except Exception:
                NamespaceName = "Not Found"

            try:
                Description = vuln["description"]
            except Exception:
                Description = "Not Found"

            try:
                Link = vuln["link"]
            except Exception:
                Link = "Not Found"

            try:
                Severity = vuln["severity"]
            except Exception:
                Severity = "Not Found"
            try:
                Metadata = vuln["Metadata"]
            except Exception:
                Metadata = "Not Found"

            try:
                FeatureName = vuln["featurename"]
            except Exception:
                FeatureName = "Not Found"

            try:
                FeatureVersion = vuln["featureversion"]
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

            duplicate_hash = hashlib.sha256(dup_data.encode("utf-8")).hexdigest()

            match_dup = StaticScanResultsDb.objects.filter(
                dup_hash=duplicate_hash
            ).values("dup_hash")
            lenth_match = len(match_dup)

            if lenth_match == 0:
                duplicate_vuln = "No"

                false_p = StaticScanResultsDb.objects.filter(
                    false_positive_hash=duplicate_hash
                )
                fp_lenth_match = len(false_p)

                if fp_lenth_match == 1:
                    false_positive = "Yes"
                else:
                    false_positive = "No"

                save_all = StaticScanResultsDb(
                    vuln_id=vul_id,
                    scan_id=scan_id,
                    date_time=date_time,
                    project_id=project_id,
                    title=Name,
                    description=str(Description)
                    + "\n\n"
                    + str(NamespaceName)
                    + "\n\n"
                    + str(Metadata)
                    + "\n\n"
                    + str(FeatureName),
                    references=Link,
                    severity=Severity,
                    vuln_status="Open",
                    dup_hash=duplicate_hash,
                    vuln_duplicate=duplicate_vuln,
                    false_positive=false_positive,
                    severity_color=vul_col,
                    scanner="Clair",
                )
                save_all.save()

            else:
                duplicate_vuln = "Yes"

                save_all = StaticScanResultsDb(
                    vuln_id=vul_id,
                    scan_id=scan_id,
                    date_time=date_time,
                    project_id=project_id,
                    title=Name,
                    description=str(Description)
                    + "\n\n"
                    + str(NamespaceName)
                    + "\n\n"
                    + str(Metadata)
                    + "\n\n"
                    + str(FeatureName),
                    references=Link,
                    severity=Severity,
                    vuln_status="Duplicate",
                    dup_hash=duplicate_hash,
                    vuln_duplicate=duplicate_vuln,
                    false_positive="Duplicate",
                    severity_color=vul_col,
                    scanner="Clair",
                )
                save_all.save()
        # pass

    all_clair_data = StaticScanResultsDb.objects.filter(
        scan_id=scan_id, false_positive="No"
    )

    duplicate_count = StaticScanResultsDb.objects.filter(
        scan_id=scan_id, vuln_duplicate="Yes"
    )

    total_vul = len(all_clair_data)
    total_high = len(all_clair_data.filter(severity="High"))
    total_medium = len(all_clair_data.filter(severity="Medium"))
    total_low = len(all_clair_data.filter(severity="Low"))
    total_duplicate = len(duplicate_count.filter(vuln_duplicate="Yes"))

    StaticScansDb.objects.filter(scan_id=scan_id).update(
        total_vul=total_vul,
        high_vul=total_high,
        date_time=date_time,
        medium_vul=total_medium,
        low_vul=total_low,
        total_dup=total_duplicate,
        scanner="Clair",
    )
    trend_update()
    subject = "Archery Tool Scan Status - Clair Report Uploaded"
    message = (
        "Clair Scanner has completed the scan "
        "  %s <br> Total: %s <br>High: %s <br>"
        "Medium: %s <br>Low %s" % (Name, total_vul, total_high, total_medium, total_low)
    )

    email_sch_notify(subject=subject, message=message)
