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

import datetime
import hashlib
import uuid

from dashboard.views import trend_update
from networkscanners.models import NetworkScanDb, NetworkScanResultsDb
from utility.email_notify import email_sch_notify

agent = "NA"
description = "NA"
fname = "NA"
plugin_modification_date = "NA"
plugin_name = "NA"
plugin_publication_date = "NA"
plugin_type = "NA"
risk_factor = "NA"
script_version = "NA"
see_also = "NA"
solution = "NA"
synopsis = "NA"
plugin_output = "NA"
scan_ip = "NA"
pluginName = "NA"
pluginID = "NA"
protocol = "NA"
severity = "NA"
svc_name = "NA"
pluginFamily = "NA"
port = "NA"
ip = ""
false_positive = None
vuln_color = None
total_vul = "na"
total_high = "na"
total_medium = "na"
total_low = "na"
target = ""
report_name = ""


def updated_nessus_parser(root, project_id, scan_id):
    global agent, description, fname, plugin_modification_date, plugin_name, plugin_publication_date, plugin_type, risk_factor, script_version, solution, synopsis, plugin_output, see_also, scan_ip, pluginName, pluginID, protocol, severity, svc_name, pluginFamily, port, vuln_color, total_vul, total_high, total_medium, total_low, target, report_name

    date_time = datetime.datetime.now()

    for data in root:
        if data.tag == "Report":
            report_name = data.attrib["name"]

        for reportHost in data.iter("ReportHost"):
            try:
                for key, value in reportHost.items():
                    target = value
                    scan_id = uuid.uuid4()
                    scan_status = "100"
                    scan_dump = NetworkScanDb(
                        ip=target,
                        scan_id=scan_id,
                        date_time=date_time,
                        project_id=project_id,
                        scan_status=scan_status,
                        scanner="Nessus",
                    )
                    scan_dump.save()
                    for ReportItem in reportHost.iter("ReportItem"):
                        for key, value in ReportItem.attrib.items():
                            if key == "pluginName":
                                pluginName = value

                            if key == "pluginID":
                                pluginID = value

                            if key == "protocol":
                                protocol = value

                            if key == "severity":
                                severity = value

                            if key == "svc_name":
                                svc_name = value

                            if key == "pluginFamily":
                                pluginFamily = value

                            if key == "port":
                                port = value
                        try:
                            agent = ReportItem.find("agent").text
                        except:
                            agent = "NA"
                        try:
                            description = ReportItem.find("description").text
                        except:
                            description = "NA"
                        try:
                            fname = ReportItem.find("fname").text
                        except:
                            fname = "NA"
                        try:
                            plugin_modification_date = ReportItem.find(
                                "plugin_modification_date"
                            ).text
                        except:
                            plugin_modification_date = "NA"
                        try:
                            plugin_name = ReportItem.find("plugin_name").text
                        except:
                            plugin_name = "NA"
                        try:
                            plugin_publication_date = ReportItem.find(
                                "plugin_publication_date"
                            ).text
                        except:
                            plugin_publication_date = "NA"
                        try:
                            plugin_type = ReportItem.find("plugin_type").text
                        except:
                            plugin_type = "NA"
                        try:
                            risk_factor = ReportItem.find("risk_factor").text
                        except:
                            risk_factor = "NA"
                        try:
                            script_version = ReportItem.find("script_version").text
                        except:
                            script_version = "NA"
                        try:
                            see_also = ReportItem.find("see_also").text
                        except:
                            see_also = "NA"
                        try:
                            solution = ReportItem.find("solution").text
                        except:
                            solution = "NA"
                        try:
                            synopsis = ReportItem.find("synopsis").text
                        except:
                            synopsis = "NA"
                        try:
                            plugin_output = ReportItem.find("plugin_output").text
                        except:
                            plugin_output = "NA"
                        vuln_id = uuid.uuid4()

                        if risk_factor == "Critical":
                            vuln_color = "critical"
                            risk_factor = "Critical"
                        elif risk_factor == "High":
                            vuln_color = "danger"
                            risk_factor = "High"
                        elif risk_factor == "Medium":
                            vuln_color = "warning"
                            risk_factor = "Medium"
                        elif risk_factor == "Low":
                            vuln_color = "info"
                            risk_factor = "Low"
                        else:
                            risk_factor = "Low"
                            vuln_color = "info"

                        dup_data = target + plugin_name + severity + port
                        duplicate_hash = hashlib.sha256(
                            dup_data.encode("utf-8")
                        ).hexdigest()
                        match_dup = (
                            NetworkScanResultsDb.objects.filter(dup_hash=duplicate_hash)
                            .values("dup_hash")
                            .distinct()
                        )
                        lenth_match = len(match_dup)

                        if lenth_match == 0:
                            duplicate_vuln = "No"

                            global false_positive
                            false_p = NetworkScanResultsDb.objects.filter(
                                false_positive_hash=duplicate_hash
                            )
                            fp_lenth_match = len(false_p)
                            if fp_lenth_match == 1:
                                false_positive = "Yes"
                            else:
                                false_positive = "No"
                            if risk_factor == "None":
                                risk_factor = "Low"

                            all_data_save = NetworkScanResultsDb(
                                project_id=project_id,
                                scan_id=scan_id,
                                date_time=date_time,
                                title=pluginName,
                                ip=target,
                                vuln_id=vuln_id,
                                description=description,
                                solution=solution,
                                severity=risk_factor,
                                port=port,
                                false_positive=false_positive,
                                vuln_status="Open",
                                dup_hash=duplicate_hash,
                                vuln_duplicate=duplicate_vuln,
                                severity_color=vuln_color,
                                scanner="Nessus",
                            )
                            all_data_save.save()

                        else:
                            duplicate_vuln = "Yes"

                            all_data_save = NetworkScanResultsDb(
                                project_id=project_id,
                                scan_id=scan_id,
                                date_time=date_time,
                                title=pluginName,
                                ip=target,
                                vuln_id=vuln_id,
                                description=description,
                                solution=solution,
                                severity=risk_factor,
                                port=port,
                                false_positive="Duplicate",
                                vuln_status="Duplicate",
                                dup_hash=duplicate_hash,
                                vuln_duplicate=duplicate_vuln,
                                severity_color=vuln_color,
                                scanner="Nessus",
                            )
                            all_data_save.save()
            except:
                continue
        for reportHost in data.iter("ReportHost"):
            try:
                for key, value in reportHost.items():
                    target = value
                    target_filter = NetworkScanResultsDb.objects.filter(
                        ip=target,
                        vuln_status="Open",
                        vuln_duplicate="No",
                    )

                    duplicate_count = NetworkScanResultsDb.objects.filter(
                        ip=target, vuln_duplicate="Yes"
                    )

                    target_total_vuln = len(target_filter)
                    target_total_critical = len(target_filter.filter(severity="Critical"))
                    target_total_high = len(target_filter.filter(severity="High"))
                    target_total_medium = len(target_filter.filter(severity="Medium"))
                    target_total_low = len(target_filter.filter(severity="Low"))
                    target_total_duplicate = len(
                        duplicate_count.filter(vuln_duplicate="Yes")
                    )
                    NetworkScanDb.objects.filter(ip=target).update(
                        date_time=date_time,
                        total_vul=target_total_vuln,
                        critical_vul=target_total_critical,
                        high_vul=target_total_high,
                        medium_vul=target_total_medium,
                        low_vul=target_total_low,
                        total_dup=target_total_duplicate,
                    )
            except:
                continue
    trend_update()
    subject = "Archery Tool Scan Status - Nessus Report Uploaded"
    message = (
        "Nessus Scanner has completed the scan "
        "  %s <br> Total: %s <br>High: %s <br>"
        "Medium: %s <br>Low %s"
        % (scan_id, total_vul, total_high, total_medium, total_low)
    )

    email_sch_notify(subject=subject, message=message)
