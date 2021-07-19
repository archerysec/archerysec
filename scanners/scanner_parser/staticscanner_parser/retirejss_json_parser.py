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
from staticscanners.models import StaticScansDb, StaticScanResultsDb

scan_id = None
rescan_id = None
scan_date = None
project_id = None
vuln_id = None
severity = None
files = None
cve = None
issue = None
bug = None
summary = None
info = None
version = None


def retirejs_report_json(data, project_id, scan_id):
    """

    :param data:
    :param project_id:
    :param scan_id:
    :return:
    """
    date_time = datetime.now()
    global component, files, severity
    for f in data:
        files = f["file"]

        for components in data:

            component = components["results"][0]["component"]

        for versions in data:
            global version
            version = versions["results"][0]["version"]

        for vuln in data:
            global identifires
            identifires = vuln["results"][0]["vulnerabilities"][0]["identifiers"]
            for key, value in identifires.items():
                if key == "CVE":
                    for cve_v in value:
                        global cve
                        cve = cve_v
                if key == "issue":
                    global issue
                    issue = value
                if key == "bug":
                    global bug
                    bug = value
                if key == "summary":
                    global summary
                    summary = value
        for infos in data:
            global info
            info = infos["results"][0]["vulnerabilities"][0]["info"]

        for severities in data:
            global severity
            severity = severities["results"][0]["vulnerabilities"][0]["severity"]

        date_time = datetime.now()
        vul_id = uuid.uuid4()

        global vul_col
        if severity == "HIGH":
            vul_col = "danger"

        elif severity == "MEDIUM":
            vul_col = "warning"

        elif severity == "LOW":
            vul_col = "info"

        dup_data = files + component + severity
        duplicate_hash = hashlib.sha256(dup_data.encode("utf-8")).hexdigest()

        match_dup = (
            StaticScanResultsDb.objects.filter(dup_hash=duplicate_hash
            )
            .values("dup_hash")
            .distinct()
        )
        lenth_match = len(match_dup)

        if lenth_match == 1:
            duplicate_vuln = "Yes"
        elif lenth_match == 0:
            duplicate_vuln = "No"
        else:
            duplicate_vuln = "None"

        false_p = StaticScanResultsDb.objects.filter(false_positive_hash=duplicate_hash
        )
        fp_lenth_match = len(false_p)

        if fp_lenth_match == 1:
            false_positive = "Yes"
        else:
            false_positive = "No"
        save_all = StaticScanResultsDb(
            scan_id=scan_id,
            date_time=date_time,
            scan_date=date_time,
            project_id=project_id,
            vuln_id=vul_id,
            fileName=files,
            #component=component,
            #CVE=cve,
            title=issue,
            #bug=bug,
            description=summary,
            #info=info,
            severity=severity,
            # false_positive=false_positive,
            vuln_status="Open",
            # dup_hash=duplicate_hash,
            # vuln_duplicate=duplicate_vuln,
            # version=version,
            scanner='Retirejs'
        )
        save_all.save()
        trend_update()
