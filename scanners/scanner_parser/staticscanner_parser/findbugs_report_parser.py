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

Details = "NA"
classname = "NA"
ShortMessage = "NA"
sourcepath = "NA"
sourcefile = "NA"
LongMessage = "NA"
name = ""
vul_col = ""
lenth_match = ""
duplicate_hash = ""
vul_id = ""
total_vul = ""
total_high = ""
total_medium = ""
total_low = ""
details = "na"
message = "na"


def findsecbug_report_xml(root, project_id, scan_id, request):
    findbugs_report_parser = FindsecbugsParser(
        project_id=project_id, scan_id=scan_id, root=root, request=request
    )
    findbugs_report_parser.xml_parser()


class FindsecbugsParser(object):
    def __init__(self, root, project_id, scan_id, request):
        self.root = root
        self.project_id = project_id
        self.scan_id = scan_id
        self.request = request

    def find_bug_pattern(self, type):
        Details = "NA"
        for bug in self.root:
            if bug.tag == "BugPattern":
                if bug.attrib["type"] is not None:
                    if bug.attrib["type"] == type:
                        for BugPattern in bug:
                            if BugPattern.tag == "Details":
                                Details = BugPattern.text
        return Details

    def xml_parser(self):
        """

        :param root:
        :param project_id:
        :param scan_id:
        :return:
        """
        date_time = datetime.now()
        global name, classname, risk, ShortMessage, LongMessage, sourcepath, vul_col, ShortDescription, Details, lenth_match, duplicate_hash, vul_id, total_vul, total_high, total_medium, total_low, details, message
        for bug in self.root:
            if bug.tag == "BugInstance":
                name = bug.attrib["type"]
                priority = bug.attrib["priority"]
                for BugInstance in bug:
                    if BugInstance.tag == "ShortMessage":
                        global ShortMessage
                        ShortMessage = BugInstance.text
                    if BugInstance.tag == "LongMessage":
                        global LongMessage
                        LongMessage = BugInstance.text
                    if BugInstance.tag == "Class":
                        global classname
                        try:
                            classname = BugInstance.attrib["classname"]
                        except Exception:
                            classname = "na"
                    if BugInstance.tag == "SourceLine":
                        global sourcepath, sourcefile
                        try:
                            sourcepath = BugInstance.attrib["sourcepath"]
                        except Exception:
                            sourcepath = "NA"
                        try:
                            sourcefile = BugInstance.attrib["sourcefile"]
                        except Exception:
                            sourcefile = "NA"

                        for data in bug:
                            for message_data in data:
                                if message_data.tag == "Message":
                                    message = message_data.text

                    if priority == "1":
                        risk = "High"
                        vul_col = "danger"

                    elif priority == "2":
                        risk = "Medium"
                        vul_col = "warning"

                    elif priority == "3":
                        risk = "Low"
                        vul_col = "info"

                    vul_id = uuid.uuid4()

                    dup_data = (
                        str(ShortMessage) + str(message) + str(sourcepath) + str(risk)
                    )

                    duplicate_hash = hashlib.sha256(
                        dup_data.encode("utf-8")
                    ).hexdigest()

                    match_dup = StaticScanResultsDb.objects.filter(
                        dup_hash=duplicate_hash,
                        organization=self.request.user.organization,
                    ).values("dup_hash")
                    lenth_match = len(match_dup)

                    details = self.find_bug_pattern(name)
                if lenth_match == 0:
                    duplicate_vuln = "No"

                    false_p = StaticScanResultsDb.objects.filter(
                        false_positive_hash=duplicate_hash,
                        organization=self.request.user.organization,
                    )
                    fp_lenth_match = len(false_p)

                    if fp_lenth_match == 1:
                        false_positive = "Yes"
                    else:
                        false_positive = "No"

                    save_all = StaticScanResultsDb(
                        vuln_id=vul_id,
                        date_time=date_time,
                        scan_id=self.scan_id,
                        project_id=self.project_id,
                        title=str(ShortMessage),
                        severity=risk,
                        description="<b>Finding Path & Line:</b> %s" % str(message)
                        + "<br><br>"
                        "<b>Finding Classes:</b> %s" % str(classname) + "<br><br>"
                        "<b>Finding Source Path</b>: %s" % str(sourcepath)
                        + "<br><br>"
                        + str(ShortMessage)
                        + "<br><br>"
                        + str(LongMessage)
                        + "<br><br>"
                        + str(details),
                        # + "\n\n"
                        # + str(classname),
                        fileName=str(message),
                        severity_color=vul_col,
                        vuln_status="Open",
                        dup_hash=duplicate_hash,
                        vuln_duplicate=duplicate_vuln,
                        false_positive=false_positive,
                        scanner="Findbugs",
                        organization=self.request.user.organization,
                    )
                    save_all.save()

                else:
                    duplicate_vuln = "Yes"
                    save_all = StaticScanResultsDb(
                        vuln_id=vul_id,
                        date_time=date_time,
                        scan_id=self.scan_id,
                        project_id=self.project_id,
                        title=str(ShortMessage),
                        severity=risk,
                        description="<b>Finding Path & Line:</b> %s" % str(message)
                        + "<br><br>"
                        "<b>Finding Classes:</b> %s" % str(classname) + "<br><br>"
                        "<b>Finding Source Path</b>: %s" % str(sourcepath)
                        + "<br><br>"
                        + str(ShortMessage)
                        + "<br><br>"
                        + str(LongMessage)
                        + "<br><br>"
                        + str(details),
                        # + "\n\n"
                        # + str(classname),
                        fileName=str(message),
                        severity_color=vul_col,
                        vuln_status="Duplicate",
                        dup_hash=duplicate_hash,
                        vuln_duplicate=duplicate_vuln,
                        false_positive="Duplicate",
                        scanner="Findbugs",
                        organization=self.request.user.organization,
                    )
                    save_all.save()

            # if bug.tag == "BugPattern":
            #     for BugPattern in bug:
            #         name = bug.attrib["type"]
            #         if BugPattern.tag == "ShortDescription":
            #             ShortDescription = BugPattern.text
            #         if BugPattern.tag == "Details":
            #             global Details
            #             Details = BugPattern.text
            #         print(Details)
            #         StaticScanResultsDb.objects.filter(vuln_id=vul_id, title=name).update(
            #             description=str(Details)
            #                         + "\n\n"
            #                         + str(ShortMessage)
            #                         + "\n\n"
            #                         + str(LongMessage)
            #                         + "\n\n"
            #                         + str(classname),
            #         )

            all_findbugs_data = StaticScanResultsDb.objects.filter(
                scan_id=self.scan_id,
                false_positive="No",
                organization=self.request.user.organization,
            )

            duplicate_count = StaticScanResultsDb.objects.filter(
                scan_id=self.scan_id,
                vuln_duplicate="Yes",
                organization=self.request.user.organization,
            )

            total_vul = len(all_findbugs_data)
            total_critical = len(all_findbugs_data.filter(severity="Critical"))
            total_high = len(all_findbugs_data.filter(severity="High"))
            total_medium = len(all_findbugs_data.filter(severity="Medium"))
            total_low = len(all_findbugs_data.filter(severity="Low"))
            total_duplicate = len(duplicate_count.filter(vuln_duplicate="Yes"))

            StaticScansDb.objects.filter(
                scan_id=self.scan_id, organization=self.request.user.organization
            ).update(
                total_vul=total_vul,
                date_time=date_time,
                critical_vul=total_critical,
                high_vul=total_high,
                medium_vul=total_medium,
                low_vul=total_low,
                total_dup=total_duplicate,
                scanner="Findbugs",
                organization=self.request.user.organization,
            )
        trend_update()
        subject = "Archery Tool Scan Status - Findbugs Report Uploaded"
        message = (
            "Findbugs Scanner has completed the scan "
            "  %s <br> Total: %s <br>High: %s <br>"
            "Medium: %s <br>Low %s"
            % (self.scan_id, total_vul, total_high, total_medium, total_low)
        )

        email_sch_notify(subject=subject, message=message)


parser_header_dict = {
    "findbugs": {
        "displayName": "FindBug",
        "dbtype": "StaticScans",
        "dbname": "Findbugs",
        "type": "XML",
        "parserFunction": findsecbug_report_xml,
        "icon": "/static/tools/findbugs.png",
    }
}
