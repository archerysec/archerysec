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
import json
import uuid
from datetime import datetime

from dashboard.views import trend_update
from staticscanners.models import StaticScansDb, StaticScanResultsDb
from utility.email_notify import email_sch_notify

vul_col = ""
Target = ""
VulnerabilityID = ""
PkgName = ""
InstalledVersion = ""
FixedVersion = ""
Title = ""
Description = ""
severity = ""
References = ""
false_positive = ""


def brakeman_report_json(data, project_id, scan_id, username):
    """

    :param data:
    :param project_id:
    :param scan_id:
    :return:
    """

    """
    {
    "scan_info": {
        "app_path": "/test_app",
        "rails_version": "4.2.7.1",
        "security_warnings": 5,
        "start_time": "2018-10-23 19:32:28 +0300",
        "end_time": "2018-10-23 19:32:42 +0300",
        "duration": 3.723474664,
        "checks_performed": [
        "BasicAuth",
        "BasicAuthTimingAttack",
        "ContentTag",
        "CreateWith",
        "CrossSiteScripting",
        "DefaultRoutes",
        "Deserialize",
        "DetailedExceptions",
        "DigestDoS",
        "DynamicFinders",
        "EscapeFunction",
        "Evaluation",
        "Execute",
        "FileAccess",
        "FileDisclosure",
        "FilterSkipping",
        "ForgerySetting",
        "HeaderDoS",
        "I18nXSS",
        "JRubyXML",
        "JSONEncoding",
        "JSONParsing",
        "LinkTo",
        "LinkToHref",
        "MailTo",
        "MassAssignment",
        "MimeTypeDoS",
        "ModelAttrAccessible",
        "ModelAttributes",
        "ModelSerialize",
        "NestedAttributes",
        "NestedAttributesBypass",
        "NumberToCurrency",
        "PermitAttributes",
        "QuoteTableName",
        "Redirect",
        "RegexDoS",
        "Render",
        "RenderDoS",
        "RenderInline",
        "ResponseSplitting",
        "RouteDoS",
        "SQL",
        "SQLCVEs",
        "SSLVerify",
        "SafeBufferManipulation",
        "SanitizeMethods",
        "SelectTag",
        "SelectVulnerability",
        "Send",
        "SendFile",
        "SessionManipulation",
        "SessionSettings",
        "SimpleFormat",
        "SingleQuotes",
        "SkipBeforeFilter",
        "StripTags",
        "SymbolDoSCVE",
        "TranslateBug",
        "UnsafeReflection",
        "ValidationRegex",
        "WithoutProtection",
        "XMLDoS",
        "YAMLParsing"
        ],
        "number_of_controllers": 5,
        "number_of_models": 12,
        "number_of_templates": 25,
        "ruby_version": "2.5.1",
        "brakeman_version": "4.3.1"
    },
    "warnings": [
        {
        "warning_type": "Mass Assignment",
        "warning_code": 60,
        "fingerprint": "00a38ca07fd6d6058d0b8664aae5b0ec1e2fd89c59d8d74ee95babab02f6fbdf",
        "check_name": "ModelAttrAccessible",
        "message": "Potentially dangerous attribute available for mass assignment",
        "file": "app/models/test1.rb",
        "line": null,
        "link": "https://brakemanscanner.org/docs/warning_types/mass_assignment/",
        "code": ":test_id",
        "render_path": null,
        "location": {
            "type": "model",
            "model": "Test1"
        },
        "user_input": null,
        "confidence": "Weak"
        },
        {
        "warning_type": "Cross-Site Scripting",
        "warning_code": 2,
        "fingerprint": "00ac2b92111049e24c28fa4f315d962c4e81c21a7bb28d7b205c8a32e99f643d",
        "check_name": "CrossSiteScripting",
        "message": "Unescaped model attribute",
        "file": "app/views/test1.html.erb",
        "line": 88,
        "link": "https://brakemanscanner.org/docs/warning_types/cross_site_scripting",
        "code": "Test::Test.find(params[:id]).name(:test)",
        "render_path": [{"type":"controller","class":"TestController","method":"test_access","line":6,"file":"app/controllers/test1.rb"}],
        "location": {
            "type": "template",
            "template": "test1"
        },
        "user_input": null,
        "confidence": "High"
        },
        {
        "warning_type": "SQL Injection",
        "warning_code": 0,
        "fingerprint": "0c8be6f7618c44181ab46aa9108a3e3624df7f89146349e4de884f5ae2d35a77",
        "check_name": "SQL",
        "message": "Possible SQL injection",
        "file": "app/models/test2.rb",
        "line": 260,
        "link": "https://brakemanscanner.org/docs/warning_types/sql_injection/",
        "code": "where(\"#{column_name} IS NOT NULL\")",
        "render_path": null,
        "location": {
            "type": "method",
            "class": "Test",
            "method": "Test.test_retrieve"
        },
        "user_input": "column_name",
        "confidence": "Medium"
        },
        {
        "warning_type": "Dynamic Render Path",
        "warning_code": 15,
        "fingerprint": "1c1e1a42a8b8bb0ad2b74bd3b91db2dd48f21062b3fe7e96e45be3ea1faa7c43",
        "check_name": "Render",
        "message": "Render path contains parameter value",
        "file": "app/controllers/test_controller.rb",
        "line": 5,
        "link": "https://brakemanscanner.org/docs/warning_types/dynamic_render_path/",
        "code": "render(action => { :json => (...)})",
        "render_path": null,
        "location": {
            "type": "method",
            "class": "TestController",
            "method": "index"
        },
        "user_input": "params[:fields].split(\",\")",
        "confidence": "Weak"
        },
        {
        "warning_type": "Attribute Restriction",
        "warning_code": 19,
        "fingerprint": "29e2c701f167599ce572ead7c3ff377aac1bc0e71834fe5867f10660e9a42de7",
        "check_name": "ModelAttributes",
        "message": "Mass assignment is not restricted using attr_accessible",
        "file": "app/models/test2.rb",
        "line": 2,
        "link": "https://brakemanscanner.org/docs/warning_types/attribute_restriction/",
        "code": null,
        "render_path": null,
        "location": {
            "type": "method",
            "model": "Test2::TestParameter"
        },
        "user_input": null,
        "confidence": "High"
        }
    ],
    "ignored_warnings": [

    ],
    "errors": [

    ],
    "obsolete": [

    ]
    }

    """
    global false_positive
    date_time = datetime.now()
    vul_col = ""

    # Parser for above json data
    # print(data['warnings'])

    vuln = data["warnings"]

    for vuln_data in vuln:
        try:
            name = vuln_data["warning_type"]
        except Exception as e:
            name = "Not Found"

        try:
            warning_code = vuln_data["warning_code"]
        except Exception as e:
            warning_code = "Not Found"

        try:
            fingerprint = vuln_data["fingerprint"]
        except Exception as e:
            fingerprint = "Not Found"

        try:
            description = vuln_data["message"]
        except Exception as e:
            description = "Not Found"

        try:
            check_name = vuln_data["check_name"]
        except Exception as e:
            check_name = "Not Found"

        try:
            severity = vuln_data["confidence"]
            if severity == "Weak":
                severity = "Low"
        except Exception as e:
            severity = "Not Found"

        try:
            file = vuln_data["file"]
        except Exception as e:
            file = "Not Found"

        try:
            line = vuln_data["line"]
        except Exception as e:
            line = "Not Found"

        try:
            link = vuln_data["link"]
        except Exception as e:
            link = "Not Found"

        try:
            code = vuln_data["code"]
        except Exception as e:
            code = "Not Found"

        try:
            render_path = vuln_data["render_path"]
        except Exception as e:
            render_path = "Not Found"

        if severity == "Critical":
            severity = "High"
            vul_col = "danger"

        if severity == "High":
            vul_col = "danger"

        elif severity == "Medium":
            vul_col = "warning"

        elif severity == "Low":
            vul_col = "info"

        elif severity == "Unknown":
            severity = "Low"
            vul_col = "info"

        elif severity == "Everything else":
            severity = "Low"
            vul_col = "info"

        vul_id = uuid.uuid4()

        dup_data = str(name) + str(severity) + str(file)

        duplicate_hash = hashlib.sha256(dup_data.encode("utf-8")).hexdigest()

        match_dup = StaticScanResultsDb.objects.filter(
            username=username, dup_hash=duplicate_hash
        ).values("dup_hash")
        lenth_match = len(match_dup)

        if lenth_match == 0:
            duplicate_vuln = "No"

            false_p = StaticScanResultsDb.objects.filter(
                username=username, false_positive_hash=duplicate_hash
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
                vul_col=vul_col,
                vuln_status="Open",
                dup_hash=duplicate_hash,
                vuln_duplicate=duplicate_vuln,
                false_positive=false_positive,
                username=username,
                name=name,
                warning_code=warning_code,
                description=description,
                severity=severity,
                file=file,
                check_name=check_name,
                fingerprint=fingerprint,
                line=line,
                code=code,
                render_path=render_path,
                link=link,
            )
            save_all.save()
        else:
            duplicate_vuln = "Yes"

            save_all = StaticScanResultsDb(
                vuln_id=vul_id,
                scan_id=scan_id,
                date_time=date_time,
                project_id=project_id,
                vul_col=vul_col,
                vuln_status="Duplicate",
                dup_hash=duplicate_hash,
                vuln_duplicate=duplicate_vuln,
                false_positive="Duplicate",
                username=username,
                name=name,
                warning_code=warning_code,
                description=description,
                severity=severity,
                file=file,
                check_name=check_name,
                fingerprint=fingerprint,
                line=line,
                code=code,
                render_path=render_path,
                link=link,
            )
            save_all.save()

    all_findbugs_data = StaticScanResultsDb.objects.filter(
        username=username, scan_id=scan_id, false_positive="No", vuln_duplicate="No"
    )

    duplicate_count = StaticScanResultsDb.objects.filter(
        username=username, scan_id=scan_id, vuln_duplicate="Yes"
    )

    total_vul = len(all_findbugs_data)
    total_high = len(all_findbugs_data.filter(severity="High"))
    total_medium = len(all_findbugs_data.filter(severity="Medium"))
    total_low = len(all_findbugs_data.filter(severity="Low"))
    total_duplicate = len(duplicate_count.filter(vuln_duplicate="Yes"))

    StaticScansDb.objects.filter(scan_id=scan_id).update(
        username=username,
        date_time=date_time,
        total_vul=total_vul,
        high_vul=total_high,
        medium_vul=total_medium,
        low_vul=total_low,
        total_dup=total_duplicate,
    )
    trend_update(username=username)
    subject = "Archery Tool Scan Status - brakeman Report Uploaded"
    message = (
        "brakeman Scanner has completed the scan "
        "  %s <br> Total: %s <br>High: %s <br>"
        "Medium: %s <br>Low %s"
        % (Target, total_vul, total_high, total_medium, total_low)
    )

    email_sch_notify(subject=subject, message=message)
