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
Target = ""
VulnerabilityID = ""
PkgName = ""
InstalledVersion = ""
FixedVersion = ""
Title = ""
Description = ""
Severity = ""
References = ""


def vuls_report_json(data, project_id, scan_id, request):
    """

    :param data:
    :param project_id:
    :param scan_id:
    :return:
    """
    date_time = datetime.now()
    vul_col = ""

    scanner = "Vuls"
    vulns = data["scannedCves"]
    targetHost = data["config"]["scan"]["servers"]["target"]["host"]

    for _, vuln_scanned in vulns.items():  # For each scanned item...
        for _, cveContentType in vuln_scanned["cveContents"].items():  # For each content type...
            for vuln_data in cveContentType:  # For all elements...

                # First get all the fields common to all affected packages
                try:
                    description = vuln_data["summary"]
                except Exception:
                    description = "Not Found"

                try:
                    cve = vuln_data["cveID"]
                except Exception:
                    cve = "Not Found"

                try:
                    title = vuln_data["title"]
                except Exception:
                    title = "Not Found"

                try:
                    severity = vuln_data["cvss3Severity"]
                except Exception:
                    severity = "Not found"
                # Backup with CVSS2
                if severity == "Not found":
                    try:
                        severity = vuln_data["cvss2Severity"]
                    except Exception:
                        severity = "Not found"

                if severity == "Critical":
                    severity = "High"
                    vul_col = "danger"

                if severity == "High":
                    vul_col = "danger"

                elif severity == "Medium":
                    vul_col = "warning"

                elif severity == "Low":
                    vul_col = "info"

                elif severity == "Unknown" or severity == "Everything else" or severity == "None":
                    severity = "Low"
                    vul_col = "info"

                refList = []
                try:
                    sourceRef = vuln_data["sourceLink"]
                except Exception:
                    sourceRef = "Not found"
                refList.append(sourceRef)

                for refs in vuln_data["references"]:
                    try:
                        link = refs["link"]
                        refList.append(link)
                    except Exception:
                        # Do nothing
                        link = "Not found"

                # Create an entry for each affected package
                # These entries will all share the same CVE ID

                for pack in vuln_scanned["affectedPackages"]:
                    try:
                        packname = pack["name"]
                    except Exception:
                        packname = "Not found"

                    displayName = packname + " | " + title
                    # Only one reflink supported at the moment
                    # displayRefs = "\n\n".join(refList)

                    vul_id = uuid.uuid4()

                    dup_data = str(cve) + str(severity) + str(packname)

                    duplicate_hash = hashlib.sha256(dup_data.encode("utf-8")).hexdigest()

                    match_dup = StaticScanResultsDb.objects.filter(dup_hash=duplicate_hash, organization=request.user.organization).values(
                        "dup_hash"
                    )
                    lenth_match = len(match_dup)

                    if lenth_match == 0:
                        duplicate_vuln = "No"

                        false_p = StaticScanResultsDb.objects.filter(
                            false_positive_hash=duplicate_hash, organization=request.user.organization
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
                            title=displayName,
                            description=str(description) + " Scanner: " + str(scanner),
                            filePath=packname,
                            fileName=targetHost,
                            severity=severity,
                            severity_color=vul_col,
                            vuln_status="Open",
                            dup_hash=duplicate_hash,
                            vuln_duplicate=duplicate_vuln,
                            false_positive=false_positive,
                            scanner="Vuls",
                            references=sourceRef,
                            organization=request.user.organization
                        )
                        save_all.save()
                    else:
                        duplicate_vuln = "Yes"

                        save_all = StaticScanResultsDb(
                            vuln_id=vul_id,
                            scan_id=scan_id,
                            date_time=date_time,
                            project_id=project_id,
                            title=displayName,
                            description=description,
                            filePath=packname,
                            fileName=targetHost,
                            severity=severity,
                            severity_color=vul_col,
                            vuln_status="Duplicate",
                            dup_hash=duplicate_hash,
                            vuln_duplicate=duplicate_vuln,
                            false_positive="Duplicate",
                            scanner="Vuls",
                            references=sourceRef,
                            organization=request.user.organization
                        )
                        save_all.save()

    all_findbugs_data = StaticScanResultsDb.objects.filter(
        scan_id=scan_id, false_positive="No", vuln_duplicate="No", organization=request.user.organization
    )

    duplicate_count = StaticScanResultsDb.objects.filter(
        scan_id=scan_id, vuln_duplicate="Yes", organization=request.user.organization
    )

    total_vul = len(all_findbugs_data)
    total_high = len(all_findbugs_data.filter(severity="High"))
    total_medium = len(all_findbugs_data.filter(severity="Medium"))
    total_low = len(all_findbugs_data.filter(severity="Low"))
    total_duplicate = len(duplicate_count.filter(vuln_duplicate="Yes"))

    StaticScansDb.objects.filter(scan_id=scan_id, organization=request.user.organization).update(
        date_time=date_time,
        total_vul=total_vul,
        high_vul=total_high,
        medium_vul=total_medium,
        low_vul=total_low,
        total_dup=total_duplicate,
        scanner="Vuls",
        organization=request.user.organization
    )
    trend_update()
    subject = "Archery Tool Scan Status - Vuls Report Uploaded"
    message = (
        "Vuls Scanner has completed the scan "
        "  %s <br> Total: %s <br>High: %s <br>"
        "Medium: %s <br>Low %s"
        % (Target, total_vul, total_high, total_medium, total_low)
    )

    email_sch_notify(subject=subject, message=message)


parser_header_dict = {
    "vuls": {
        "displayName": "Vuls Scanner",
        "dbtype": "StaticScans",
        "dbname": "Vuls",
        "type": "JSON",
        "parserFunction": vuls_report_json,
        "icon": "/static/tools/vuls.png"
    }
}
