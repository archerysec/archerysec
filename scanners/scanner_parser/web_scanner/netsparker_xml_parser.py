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
from utility.email_notify import email_sch_notify
from webscanners.models import WebScanResultsDb, WebScansDb

vuln_url = ""
vuln_type = ""
vuln_severity = ""
vuln_certainty = ""
vuln_rawrequest = ""
vuln_rawresponse = ""
vuln_extrainformation = ""
vuln_classification = ""
vuln_id = ""
vul_col = ""
description = ""
impact = ""
actionsToTake = ""
remedy = ""
requiredSkillsForExploitation = ""
externalReferences = ""
remedyReferences = ""
proofOfConcept = ""
proofs = ""
false_positive = ""
target = ""


def xml_parser(root, project_id, scan_id):
    global vuln_url, vuln_type, vuln_severity, vuln_certainty, vuln_rawrequest, vuln_rawresponse, vuln_extrainformation, vuln_classification, vuln_id, vul_col, description, impact, actionsToTake, remedy, requiredSkillsForExploitation, externalReferences, remedyReferences, proofOfConcept, proofs, target
    date_time = datetime.now()
    for data in root:
        if data.tag == "target":
            for url in data:
                if url.tag == "url":
                    target = url.text
        for vuln in data:

            if vuln.tag == "url":
                vuln_url = vuln.text

            if vuln.tag == "type":
                vuln_type = vuln.text

            if vuln.tag == "severity":
                if vuln.text == "Important":
                    vuln_severity = "High"
                else:
                    vuln_severity = vuln.text

            if vuln.tag == "certainty":
                vuln_certainty = vuln.text

            if vuln.tag == "rawrequest":
                vuln_rawrequest = vuln.text

            if vuln.tag == "rawresponse":
                vuln_rawresponse = vuln.text

            if vuln.tag == "extrainformation":
                vuln_extrainformation = vuln.text

            if vuln.tag == "classification":
                vuln_classification = vuln.text

            if vuln.tag == "description":
                description = vuln.text

            if vuln.tag == "impact":
                impact = vuln.text

            if vuln.tag == "actionsToTake":
                actionsToTake = vuln.text

            if vuln.tag == "remedy":
                remedy = vuln.text

            if vuln.tag == "requiredSkillsForExploitation":
                requiredSkillsForExploitation = vuln.text

            if vuln.tag == "externalReferences":
                externalReferences = vuln.text

            if vuln.tag == "remedyReferences":
                remedyReferences = vuln.text

            if vuln.tag == "proofOfConcept":
                proofOfConcept = vuln.text

            if vuln.tag == "proofs":
                proofs = vuln.text

        vuln_id = uuid.uuid4()

        if vuln_severity == "Critical":
            vul_col = "critical"

        elif vuln_severity == "High":
            vul_col = "danger"

        elif vuln_severity == "Medium":
            vul_col = "warning"

        elif vuln_severity == "Low":
            vul_col = "info"

        else:
            vuln_severity = "Low"
            vul_col = "info"

        dup_data = str(vuln_type) + str(vuln_url) + str(vuln_severity)
        duplicate_hash = hashlib.sha256(dup_data.encode("utf-8")).hexdigest()
        match_dup = (
            WebScanResultsDb.objects.filter(dup_hash=duplicate_hash)
            .values("dup_hash")
            .distinct()
        )
        lenth_match = len(match_dup)

        if lenth_match == 0:
            duplicate_vuln = "No"

            false_p = WebScanResultsDb.objects.filter(
                false_positive_hash=duplicate_hash
            )
            fp_lenth_match = len(false_p)

            global false_positive
            if fp_lenth_match == 1:
                false_positive = "Yes"
            elif lenth_match == 0:
                false_positive = "No"
            else:
                false_positive = "No"

            dump_data = WebScanResultsDb(
                scan_id=scan_id,
                project_id=project_id,
                date_time=date_time,
                vuln_id=vuln_id,
                title=vuln_type,
                url=vuln_url,
                severity=vuln_severity,
                false_positive=false_positive,
                severity_color=vul_col,
                description=description,
                solution=str(remedy) + "\n\n" + str(actionsToTake),
                reference=str(externalReferences) + "\n\n" + str(remedyReferences),
                vuln_status="Open",
                dup_hash=duplicate_hash,
                vuln_duplicate=duplicate_vuln,
                scanner="Netsparker",
            )
            dump_data.save()
        else:
            duplicate_vuln = "Yes"

            dump_data = WebScanResultsDb(
                scan_id=scan_id,
                project_id=project_id,
                date_time=date_time,
                vuln_id=vuln_id,
                url=vuln_url,
                title=vuln_type,
                severity=vuln_severity,
                false_positive="Duplicate",
                vuln_status="Duplicate",
                severity_color=vul_col,
                description=description,
                solution=remedy + "\n\n" + str(actionsToTake),
                reference=externalReferences + "\n\n" + str(remedyReferences),
                dup_hash=duplicate_hash,
                vuln_duplicate=duplicate_vuln,
                scanner="Netsparker",
            )
            dump_data.save()

    netsparker_all_vul = WebScanResultsDb.objects.filter(
        scan_id=scan_id, false_positive="No", scanner="Netsparker"
    )
    duplicate_count = WebScanResultsDb.objects.filter(
        scan_id=scan_id, vuln_duplicate="Yes", scanner="Netsparker"
    )

    total_critical = len(netsparker_all_vul.filter(severity="Critical"))
    total_high = len(netsparker_all_vul.filter(severity="High"))
    total_medium = len(netsparker_all_vul.filter(severity="Medium"))
    total_low = len(netsparker_all_vul.filter(severity="Low"))
    total_info = len(netsparker_all_vul.filter(severity="Information"))
    total_duplicate = len(duplicate_count.filter(vuln_duplicate="Yes"))
    total_vul = total_high + total_medium + total_low + total_info

    WebScansDb.objects.filter(scan_id=scan_id).update(
        total_vul=total_vul,
        date_time=date_time,
        critical_vul=total_critical,
        high_vul=total_high,
        medium_vul=total_medium,
        low_vul=total_low,
        info_vul=total_info,
        total_dup=total_duplicate,
        scan_url=target,
        scanner="Netsparker",
    )
    trend_update()
    subject = "Archery Tool Scan Status - Netsparker Report Uploaded"
    message = (
        "Netsparker Scanner has completed the scan "
        "  %s <br> Total: %s <br>High: %s <br>"
        "Medium: %s <br>Low %s"
        % (target, total_vul, total_high, total_medium, total_low)
    )

    email_sch_notify(subject=subject, message=message)


ParserHeaderDict = {
    "netsparker": {
        "displayName": "Netsparker Scanner",
        "dbtype": "WebScans",
        "dbname": "Netsparker",
        "type": "XML",
        "parserFunction": xml_parser
    }
}
