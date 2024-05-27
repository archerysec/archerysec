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

from archeryapi.models import OrgAPIKey
from dashboard.views import trend_update
from staticscanners.models import StaticScanResultsDb, StaticScansDb
from utility.email_notify import email_sch_notify
from bs4 import BeautifulSoup


def html_parser(data, project_id, scan_id, request):
    """

    :param data:
    :param project_id:
    :param scan_id:
    :return:
    """
    date_time = datetime.now()

    api_key = request.META.get("HTTP_X_API_KEY")
    key_object = OrgAPIKey.objects.filter(api_key=api_key).first()
    if str(request.user) == 'AnonymousUser':
        organization = key_object.organization
    else:
        organization = request.user.organization
    soup = BeautifulSoup(data, 'html.parser')

    # Extracting summary, class, h3, span with badge critical-bg, span class, Rule ID, CWE, filename, class="term-container", class="description", <h4>Remediations</h2>, <pre> code, <h4>References</h2>
    findings = soup.find_all('details', class_='finding')

    for finding in findings:
        # Extract the required details safely
        summary = finding.find('span').text.strip() if finding.find('summary') else ''
        # heading = finding.find('h3').text.strip() if finding.find('h3') else ''
        badge = finding.find('span', class_='badge').text.strip() if finding.find('span', class_='badge') else ''
        rule_id_cwe = finding.find('span', class_='cwe').text.strip() if finding.find('span', class_='cwe') else ''
        file_name = finding.find('p', class_='filename').text.strip() if finding.find('p', class_='filename') else ''
        # term_container = finding.find('div', class_='term-container').text.strip() if finding.find('div', class_='term-container') else ''
        description = finding.find('div', class_='description').find('p').text.strip() if finding.find('div', class_='description').find('p') else ''

        # Extract Remediations section
        # remediations_header = finding.find('div', class_='description').find('h4', string='Remediations').text.strip() if finding.find('div', class_='description').find('h4', string='Remediations') else ''
        remediations = finding.find('div', class_='description').find('ul').text.strip() if finding.find('div', class_='description').find('ul') else ''

        # Extract code block
        code_block = finding.find('div', class_='description').find('pre').text.strip() if finding.find('div', class_='description').find('pre') else ''

        name = summary
        severity = badge

        if severity == "critical":
            vul_col = "critical"
            severity = "Critical"
        elif severity == "high":
            vul_col = "danger"
            severity = "High"
        elif severity == "medium":
            vul_col = "warning"
            severity = "Medium"
        elif severity == "low":
            vul_col = "info"
            severity = "Low"
        else:
            severity = "Low"
            vul_col = "info"
        vul_id = uuid.uuid4()

        dup_data = str(name) + str(severity) + str(file_name)
        duplicate_hash = hashlib.sha256(dup_data.encode("utf-8")).hexdigest()
        match_dup = StaticScanResultsDb.objects.filter(
            dup_hash=duplicate_hash, organization=organization
        ).values("dup_hash")
        lenth_match = len(match_dup)
        if lenth_match == 0:
            duplicate_vuln = "No"

            false_p = StaticScanResultsDb.objects.filter(
                false_positive_hash=duplicate_hash,
                organization=organization,
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
                severity_color=vul_col,
                vuln_status="Open",
                dup_hash=duplicate_hash,
                vuln_duplicate=duplicate_vuln,
                false_positive=false_positive,
                title=name,
                severity=severity,
                solution=remediations,
                description=str(description + '<br><br>' + file_name + '<br><br>' + rule_id_cwe + '<br><br>' + 'Code Block: \n' + code_block),
                fileName=file_name,
                scanner="Bearer",
                organization=organization,
            )
            save_all.save()

        else:
            duplicate_vuln = "Yes"

            save_all = StaticScanResultsDb(
                vuln_id=vul_id,
                scan_id=scan_id,
                date_time=date_time,
                project_id=project_id,
                severity_color=vul_col,
                vuln_status="Duplicate",
                dup_hash=duplicate_hash,
                vuln_duplicate=duplicate_vuln,
                false_positive="Duplicate",
                title=name,
                severity=severity,
                solution=remediations,
                description=str(description + '<br><br>' + file_name + '<br><br>' + 'Code Block: \n' + code_block + '<br><br>' + 'Remediations: \n' + remediations),
                fileName=file_name,
                scanner="Bearer",
                organization=organization,
            )
            save_all.save()

    all_bearer_data = StaticScanResultsDb.objects.filter(
        scan_id=scan_id, false_positive="No", organization=organization
    )

    duplicate_count = StaticScanResultsDb.objects.filter(
        scan_id=scan_id, vuln_duplicate="Yes", organization=organization
    )

    total_critical = len(all_bearer_data.filter(severity="Critical"))
    total_high = len(all_bearer_data.filter(severity="High"))
    total_medium = len(all_bearer_data.filter(severity="Medium"))
    total_low = len(all_bearer_data.filter(severity="Low"))
    total_vul = len(all_bearer_data)
    total_duplicate = len(duplicate_count.filter(vuln_duplicate="Yes"))

    StaticScansDb.objects.filter(scan_id=scan_id).update(
        date_time=date_time,
        total_vul=total_vul,
        critical_vul=total_critical,
        high_vul=total_high,
        medium_vul=total_medium,
        low_vul=total_low,
        total_dup=total_duplicate,
        scanner="Bearer",
        organization=organization,
    )
    trend_update()
    subject = "Archery Tool Scan Status - Bearer Report Uploaded"
    message = (
            "Bearer Scanner has completed the scan "
            "  %s <br> Total: %s <br>High: %s <br>"
            "Medium: %s <br>Low %s"
            % ("Bearer", total_vul, total_high, total_medium, total_low)
    )

    email_sch_notify(subject=subject, message=message)


parser_header_dict = {
    "Bearer": {
        "displayName": "Bearer Scanner",
        "dbtype": "StaticScans",
        "dbname": "Bearer",
        "type": "HTML",
        "parserFunction": html_parser,
        "icon": "/static/tools/bearer.png",
    }
}
