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
import json
from datetime import datetime

from dashboard.views import trend_update
from staticscanners.models import StaticScanResultsDb, StaticScansDb
from utility.email_notify import email_sch_notify

vul_col = ""
Target = ""
VulnerabilityID = ""
PkgName = ""
InstalledVersion = ""
FixedVersion = ""
Title = ""
Description = ""
Severity = ""
References = ""
total_vul = ""
total_high = ""
total_medium = ""
total_low = ""


def trivy_report_json(data, project_id, scan_id):
    """

    :param data:
    :param project_id:
    :param scan_id:
    :return:
    """
    global total_vul, total_high, total_medium, total_low
    date_time = datetime.now()
    vul_col = ""
    t_target = ''
    t_type = ''
    t_class = ''
    vuln = ''
    if data['ArtifactType'] == "container_image":
        for vuln_data in data['Results']:
            try:
                vuln = vuln_data["Vulnerabilities"]
                t_target = vuln_data["Target"]
                t_class = vuln_data["Class"]
                t_type = vuln_data["Type"]
            except Exception:
                pass
            for issue in vuln:
                try:
                    VulnerabilityID = issue["VulnerabilityID"]
                except Exception as e:
                    VulnerabilityID = "Not Found"
                    print(e)
                try:
                    PkgName = issue["PkgName"]
                except Exception as e:
                    PkgName = "Not Found"
                    print(e)
                try:
                    InstalledVersion = issue["InstalledVersion"]
                except Exception as e:
                    InstalledVersion = "Not Found"
                    print(e)
                try:
                    FixedVersion = issue["FixedVersion"]
                except Exception as e:
                    FixedVersion = "Not Found"
                    print(e)
                try:
                    Title = issue["Title"]
                except Exception as e:
                    Title = "Not Found"
                    print(e)
                try:
                    Description = issue["Description"]
                except Exception as e:
                    Description = "Not Found"
                    print(e)
                try:
                    Severity = issue["Severity"]
                except Exception as e:
                    Severity = "Not Found"
                    print(e)
                try:
                    References = issue["References"]
                except Exception as e:
                    References = "Not Found"
                    print(e)

                if Severity == "CRITICAL":
                    Severity = "Critical"
                    vul_col = "critical"

                if Severity == "HIGH":
                    Severity = "High"
                    vul_col = "danger"

                if Severity == "MEDIUM":
                    Severity = "Medium"
                    vul_col = "warning"

                if Severity == "LOW":
                    Severity = "Low"
                    vul_col = "info"

                if Severity == "UNKNOWN":
                    Severity = "Low"
                    vul_col = "info"

                vul_id = uuid.uuid4()

                dup_data = str(VulnerabilityID) + \
                    str(Severity) + \
                    str(PkgName) + \
                    str(t_target) + \
                    str(t_type) + \
                    str(t_class)

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
                        fileName=PkgName,
                        title=VulnerabilityID,
                        description=str(Description)
                        + str(Title)
                        + "\n\n"
                        + str(t_target)
                        + str(t_type)
                        + str(t_class)
                        + "\n\n"
                        + str(VulnerabilityID)
                        + "\n\n"
                        + str(PkgName)
                        + "\n\n"
                        + str(InstalledVersion)
                        + "\n\n"
                        + str(FixedVersion),
                        severity=Severity,
                        solution=PkgName + ' can be fixed by upgrading version :' + FixedVersion,
                        references=References,
                        severity_color=vul_col,
                        vuln_status="Open",
                        dup_hash=duplicate_hash,
                        vuln_duplicate=duplicate_vuln,
                        false_positive=false_positive,
                        scanner="Trivy",
                    )
                    save_all.save()

                else:
                    duplicate_vuln = "Yes"

                    save_all = StaticScanResultsDb(
                        vuln_id=vul_id,
                        scan_id=scan_id,
                        date_time=date_time,
                        project_id=project_id,
                        fileName=PkgName,
                        title=VulnerabilityID,
                        description=str(Description)
                        + str(Title)
                        + "\n\n"
                        + str(t_target)
                        + str(t_type)
                        + str(t_class)
                        + "\n\n"
                        + str(VulnerabilityID)
                        + "\n\n"
                        + str(PkgName)
                        + "\n\n"
                        + str(InstalledVersion)
                        + "\n\n"
                        + str(FixedVersion),
                        severity=Severity,
                        references=References,
                        severity_color=vul_col,
                        vuln_status="Duplicate",
                        dup_hash=duplicate_hash,
                        vuln_duplicate=duplicate_vuln,
                        false_positive="Duplicate",
                        scanner="Trivy",
                    )
                    save_all.save()

            all_findbugs_data = StaticScanResultsDb.objects.filter(
                scan_id=scan_id, false_positive="No"
            )

            duplicate_count = StaticScanResultsDb.objects.filter(
                scan_id=scan_id, vuln_duplicate="Yes"
            )

            total_vul = len(all_findbugs_data)
            total_high = len(all_findbugs_data.filter(severity="High"))
            total_medium = len(all_findbugs_data.filter(severity="Medium"))
            total_low = len(all_findbugs_data.filter(severity="Low"))
            total_duplicate = len(duplicate_count.filter(vuln_duplicate="Yes"))

            StaticScansDb.objects.filter(scan_id=scan_id).update(
                total_vul=total_vul,
                date_time=date_time,
                high_vul=total_high,
                medium_vul=total_medium,
                low_vul=total_low,
                total_dup=total_duplicate,
                scanner="Trivy",
            )
    elif data['ArtifactType'] == "filesystem":
        description = 'na'
        message = 'na'
        startline = 'na'
        endline = 'na'
        resource = 'na'
        provider = 'na'
        resolution = 'na'
        references = 'na'
        Severity = 'na'
        code = 'na'
        title = 'na'
        mis_data = ''
        for mis in data['Results']:
            target = mis['Target']
            try:
                mis_data = mis['Misconfigurations']
            except Exception:
                pass
            if mis['Class'] == 'secret':
                title = mis['Secrets'][0]['Title']
                Severity = mis['Secrets'][0]['Severity']
                category = mis['Secrets'][0]['Category']
                startline = mis['Secrets'][0]['StartLine']
                endline = mis['Secrets'][0]['EndLine']
                match = mis['Secrets'][0]['Match']

                if Severity == "CRITICAL":
                    Severity = "Critical"
                    vul_col = "critical"

                if Severity == "HIGH":
                    Severity = "High"
                    vul_col = "danger"

                if Severity == "MEDIUM":
                    Severity = "Medium"
                    vul_col = "warning"

                if Severity == "LOW":
                    Severity = "Low"
                    vul_col = "info"

                if Severity == "UNKNOWN":
                    Severity = "Low"
                    vul_col = "info"

                vul_id = uuid.uuid4()

                dup_data = str(title) + \
                    str(Severity) + \
                    str(match) + \
                    str(target)

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
                        fileName=target,
                        title=title,
                        description=str(description)
                        + str(title)
                        + "\n\n"
                        + str(match)
                        + "\n\n"
                        + 'Start Line: ' + str(startline)
                        + "\n\n"
                        + 'End Line: ' + str(endline)
                        + "\n\n"
                        + str(category),
                        severity=Severity,
                        solution='Remove secret ' + match + ' form the code',
                        references=references,
                        severity_color=vul_col,
                        vuln_status="Open",
                        dup_hash=duplicate_hash,
                        vuln_duplicate=duplicate_vuln,
                        false_positive=false_positive,
                        scanner="Trivy",
                    )
                    save_all.save()

                else:
                    duplicate_vuln = "Yes"

                    save_all = StaticScanResultsDb(
                        vuln_id=vul_id,
                        scan_id=scan_id,
                        date_time=date_time,
                        project_id=project_id,
                        fileName=target,
                        title=title,
                        description=str(description)
                        + str(title)
                        + "\n\n"
                        + str(match)
                        + "\n\n"
                        + 'Start Line: ' + str(startline)
                        + "\n\n"
                        + 'End Line: ' + str(endline)
                        + "\n\n"
                        + str(category),
                        severity=Severity,
                        references=references,
                        severity_color=vul_col,
                        vuln_status="Duplicate",
                        dup_hash=duplicate_hash,
                        vuln_duplicate=duplicate_vuln,
                        false_positive="Duplicate",
                        scanner="Trivy",
                    )
                    save_all.save()

            if mis['Class'] == 'config':
                for miscon in mis_data:
                    try:
                        title = miscon['Title']
                        description = miscon['Description']
                        message = miscon['Message']
                        resolution = miscon['Resolution']
                        Severity = miscon['Severity']
                        references = miscon['References']
                        code = miscon['CauseMetadata']['Code']
                        startline = miscon['CauseMetadata']['StartLine']
                        endline = miscon['CauseMetadata']['EndLine']
                        resource = miscon['CauseMetadata']['Resource']
                        provider = miscon['CauseMetadata']['Provider']

                    except Exception as e:
                        print(e)

                    if Severity == "CRITICAL":
                        Severity = "Critical"
                        vul_col = "critical"

                    if Severity == "HIGH":
                        Severity = "High"
                        vul_col = "danger"

                    if Severity == "MEDIUM":
                        Severity = "Medium"
                        vul_col = "warning"

                    if Severity == "LOW":
                        Severity = "Low"
                        vul_col = "info"

                    if Severity == "UNKNOWN":
                        Severity = "Low"
                        vul_col = "info"

                    vul_id = uuid.uuid4()

                    dup_data = str(title) + \
                        str(Severity) + \
                        str(code) + \
                        str(target)

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
                            fileName=target,
                            title=title,
                            description=str(description)
                            + str(title)
                            + "\n\n"
                            + str(message)
                            + "\n\n"
                            + 'Start Line: ' + str(startline)
                            + "\n\n"
                            + 'End Line: ' + str(endline)
                            + "\n\n"
                            + str(resource)
                            + "\n\n"
                            + str(provider)
                            + str(code),
                            severity=Severity,
                            solution=resolution,
                            references=references,
                            severity_color=vul_col,
                            vuln_status="Open",
                            dup_hash=duplicate_hash,
                            vuln_duplicate=duplicate_vuln,
                            false_positive=false_positive,
                            scanner="Trivy",
                        )
                        save_all.save()

                    else:
                        duplicate_vuln = "Yes"

                        save_all = StaticScanResultsDb(
                            vuln_id=vul_id,
                            scan_id=scan_id,
                            date_time=date_time,
                            project_id=project_id,
                            fileName=target,
                            title=title,
                            description=str(description)
                            + str(title)
                            + "\n\n"
                            + str(message)
                            + "\n\n"
                            + 'Start Line: ' + str(startline)
                            + "\n\n"
                            + 'End Line: ' + str(endline)
                            + "\n\n"
                            + str(resource),
                            severity=Severity,
                            references=references,
                            severity_color=vul_col,
                            vuln_status="Duplicate",
                            dup_hash=duplicate_hash,
                            vuln_duplicate=duplicate_vuln,
                            false_positive="Duplicate",
                            scanner="Trivy",
                        )
                        save_all.save()

    all_findbugs_data = StaticScanResultsDb.objects.filter(
        scan_id=scan_id, false_positive="No"
    )

    duplicate_count = StaticScanResultsDb.objects.filter(
        scan_id=scan_id, vuln_duplicate="Yes"
    )

    total_vul = len(all_findbugs_data)
    total_critical = len(all_findbugs_data.filter(severity="Critical"))
    total_high = len(all_findbugs_data.filter(severity="High"))
    total_medium = len(all_findbugs_data.filter(severity="Medium"))
    total_low = len(all_findbugs_data.filter(severity="Low"))
    total_duplicate = len(duplicate_count.filter(vuln_duplicate="Yes"))

    StaticScansDb.objects.filter(scan_id=scan_id).update(
        total_vul=total_vul,
        date_time=date_time,
        critical_vul=total_critical,
        high_vul=total_high,
        medium_vul=total_medium,
        low_vul=total_low,
        total_dup=total_duplicate,
        scanner="Trivy",
    )

    trend_update()
    subject = "Archery Tool Scan Status - Trivy Report Uploaded"
    message = (
        "Trivy Scanner has completed the scan "
        "  %s <br> Total: %s <br>High: %s <br>"
        "Medium: %s <br>Low %s"
        % (Target, total_vul, total_high, total_medium, total_low)
    )

    email_sch_notify(subject=subject, message=message)


parser_header_dict = {
    "trivy_scan": {
        "displayName": "Trivy Scanner",
        "dbtype": "StaticScans",
        "dbname": "Trivy",
        "type": "JSON",
        "parserFunction": trivy_report_json,
        "icon": "/static/tools/trivy.png"
    }
}
