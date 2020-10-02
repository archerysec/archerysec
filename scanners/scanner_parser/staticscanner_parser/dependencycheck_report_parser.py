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
from builtins import len

from staticscanners.models import dependencycheck_scan_db, dependencycheck_scan_results_db
import uuid
import hashlib
from datetime import datetime
from django.shortcuts import HttpResponse

from webscanners.zapscanner.views import email_sch_notify


def xml_parser(data, project_id, scan_id, username):
    """

    :param data:
    :param project_id:
    :param scan_id:
    :return:
    """
    fileName = 'Na'
    filePath = 'Na'
    evidenceCollected = 'Na'
    name = 'Na'
    cvssScore = 'Na'
    cvssAccessVector = 'Na'
    cvssAccessComplexity = 'Na'
    cvssAuthenticationr = 'Na'
    cvssConfidentialImpact = 'Na'
    cvssIntegrityImpact = 'Na'
    cvssAvailabilityImpact = 'Na'
    severity = 'Na'
    cwe = 'Na'
    description = 'Na'
    references = 'Na'
    vulnerableSoftware = 'Na'
    vul_col = 'Na'

    pt = data.xpath('namespace-uri(.)')
    # root = data.getroot()
    inst = []
    for scan in data:
        for dependencies in scan:
            for dependency in dependencies:
                if dependency.tag == '{%s}fileName' % pt:
                    fileName = dependency.text
                if dependency.tag == '{%s}filePath' % pt:
                    filePath = dependency.text
                if dependency.tag == '{%s}evidenceCollected' % pt:
                    evidenceCollected = dependency.text
                for vuln in dependency:
                    if vuln.tag == '{%s}vulnerability' % pt:
                        if pt == 'https://jeremylong.github.io/DependencyCheck/dependency-check.2.0.xsd':
                            for vulner in vuln:
                                if vulner.tag == '{%s}name' % pt:
                                    name = vulner.text
                                if vulner.tag == '{%s}description' % pt:
                                    description = vulner.text
                                if vulner.tag == '{%s}references' % pt:
                                    references = vulner.text
                                if vulner.tag == '{%s}vulnerableSoftware' % pt:
                                    vulnerableSoftware = vulner.text
                                for vuln_dat in vulner:
                                    if vuln_dat.tag == '{%s}cwe' % pt:
                                        cwe = vuln_dat.text
                                    if vuln_dat.tag == '{%s}severity' % pt:
                                        severity_dat = vuln_dat.text
                                        if severity_dat == 'HIGH':
                                            severity = 'High'
                                        elif severity_dat == 'MEDIUM':
                                            severity = 'Medium'
                                        elif severity_dat == 'LOW':
                                            severity = 'Low'

                        elif pt == 'https://jeremylong.github.io/DependencyCheck/dependency-check.2.2.xsd':
                            for dc22 in vuln:

                                if dc22.tag == '{%s}name' % pt:
                                    name = dc22.text

                                if dc22.tag == '{%s}description' % pt:
                                    description = dc22.text

                                if dc22.tag == '{%s}vulnerableSoftware' % pt:
                                    vulnerableSoftware = dc22.text

                                for vuln_dat in dc22:
                                    for d in vuln_dat:
                                        if d.tag == '{%s}url' % pt:
                                            references = d.text

                                    if vuln_dat.tag == '{%s}cwe' % pt:
                                        cwe = vuln_dat.text
                                    if vuln_dat.tag == '{%s}severity' % pt:
                                        severity_dat = vuln_dat.text
                                        if severity_dat == 'HIGH':
                                            severity = 'High'
                                        elif severity_dat == 'MEDIUM':
                                            severity = 'Medium'
                                        elif severity_dat == 'LOW':
                                            severity = 'Low'
                        elif pt == 'https://jeremylong.github.io/DependencyCheck/dependency-check.2.3.xsd':
                            for dc22 in vuln:

                                if dc22.tag == '{%s}name' % pt:
                                    name = dc22.text

                                if dc22.tag == '{%s}description' % pt:
                                    description = dc22.text

                                if dc22.tag == '{%s}vulnerableSoftware' % pt:
                                    vulnerableSoftware = dc22.text

                                for vuln_dat in dc22:
                                    for d in vuln_dat:
                                        if d.tag == '{%s}url' % pt:
                                            references = d.text

                                    if vuln_dat.tag == '{%s}cwe' % pt:
                                        cwe = vuln_dat.text
                                    if vuln_dat.tag == '{%s}severity' % pt:
                                        severity_dat = vuln_dat.text
                                        if severity_dat == 'HIGH':
                                            severity = 'High'
                                        elif severity_dat == 'MEDIUM':
                                            severity = 'Medium'
                                        elif severity_dat == 'LOW':
                                            severity = 'Low'
                        elif pt == 'https://jeremylong.github.io/DependencyCheck/dependency-check.2.4.xsd':
                            for dc22 in vuln:

                                if dc22.tag == '{%s}name' % pt:
                                    name = dc22.text

                                if dc22.tag == '{%s}description' % pt:
                                    description = dc22.text

                                if dc22.tag == '{%s}vulnerableSoftware' % pt:
                                    vulnerableSoftware = dc22.text

                                for vuln_dat in dc22:
                                    for d in vuln_dat:
                                        if d.tag == '{%s}url' % pt:
                                            references = d.text

                                    if vuln_dat.tag == '{%s}cwe' % pt:
                                        cwe = vuln_dat.text
                                    if vuln_dat.tag == '{%s}severity' % pt:
                                        severity_dat = vuln_dat.text
                                        if severity_dat == 'HIGH':
                                            severity = 'High'
                                        elif severity_dat == 'MEDIUM':
                                            severity = 'Medium'
                                        elif severity_dat == 'LOW':
                                            severity = 'Low'
                        elif pt == 'https://jeremylong.github.io/DependencyCheck/dependency-check.2.5.xsd':
                            for dc22 in vuln:

                                if dc22.tag == '{%s}name' % pt:
                                    name = dc22.text

                                if dc22.tag == '{%s}description' % pt:
                                    description = dc22.text

                                if dc22.tag == '{%s}vulnerableSoftware' % pt:
                                    vulnerableSoftware = dc22.text

                                for vuln_dat in dc22:
                                    for d in vuln_dat:
                                        if d.tag == '{%s}url' % pt:
                                            references = d.text

                                    if vuln_dat.tag == '{%s}cwe' % pt:
                                        cwe = vuln_dat.text
                                    if vuln_dat.tag == '{%s}severity' % pt:
                                        severity_dat = vuln_dat.text
                                        if severity_dat == 'HIGH':
                                            severity = 'High'
                                        elif severity_dat == 'MEDIUM':
                                            severity = 'Medium'
                                        elif severity_dat == 'LOW':
                                            severity = 'Low'

                        else:
                            for vulner in vuln:
                                if vulner.tag == '{%s}name' % pt:
                                    name = vulner.text
                                if vulner.tag == '{%s}cvssScore' % pt:
                                    cvssScore = vulner.text
                                if vulner.tag == '{%s}cvssAccessVector' % pt:
                                    cvssAccessVector = vulner.text
                                if vulner.tag == '{%s}cvssAccessComplexity' % pt:
                                    cvssAccessComplexity = vulner.text
                                if vulner.tag == '{%s}cvssAuthenticationr' % pt:
                                    cvssAuthenticationr = vulner.text
                                if vulner.tag == '{%s}cvssConfidentialImpact' % pt:
                                    cvssConfidentialImpact = vulner.text
                                if vulner.tag == '{%s}cvssIntegrityImpact' % pt:
                                    cvssIntegrityImpact = vulner.text
                                if vulner.tag == '{%s}cvssAvailabilityImpact' % pt:
                                    cvssAvailabilityImpact = vulner.text
                                if vulner.tag == '{%s}severity' % pt:
                                    severity = vulner.text
                                if vulner.tag == '{%s}cwe' % pt:
                                    cwe = vulner.text
                                if vulner.tag == '{%s}description' % pt:
                                    description = vulner.text
                                if vulner.tag == '{%s}references' % pt:
                                    references = vulner.text
                                if vulner.tag == '{%s}vulnerableSoftware' % pt:
                                    vulnerableSoftware = vulner.text

                        date_time = datetime.now()
                        vul_id = uuid.uuid4()

                        if severity == "High":
                            vul_col = "danger"

                        elif severity == 'Medium':
                            vul_col = "warning"

                        elif severity == 'Low':
                            vul_col = "info"

                        dup_data = name + fileName + severity
                        duplicate_hash = hashlib.sha256(dup_data.encode('utf-8')).hexdigest()

                        match_dup = dependencycheck_scan_results_db.objects.filter(username=username,
                            dup_hash=duplicate_hash).values('dup_hash')
                        lenth_match = len(match_dup)

                        if lenth_match == 0:
                            duplicate_vuln = 'No'

                            false_p = dependencycheck_scan_results_db.objects.filter(username=username,
                                                                                     false_positive_hash=duplicate_hash)
                            fp_lenth_match = len(false_p)

                            if fp_lenth_match == 1:
                                false_positive = 'Yes'
                            else:
                                false_positive = 'No'

                            if cwe == 'Na':
                                cwe = name

                            save_all = dependencycheck_scan_results_db(
                                # date_time=date_time,
                                vuln_id=vul_id,
                                scan_id=scan_id,
                                project_id=project_id,
                                fileName=fileName,
                                filePath=filePath,
                                evidenceCollected=evidenceCollected,
                                name=name,
                                cvssScore=cvssScore,
                                cvssAccessVector=cvssAccessVector,
                                cvssAccessComplexity=cvssAccessComplexity,
                                cvssAuthenticationr=cvssAuthenticationr,
                                cvssConfidentialImpact=cvssConfidentialImpact,
                                cvssIntegrityImpact=cvssIntegrityImpact,
                                cvssAvailabilityImpact=cvssAvailabilityImpact,
                                severity=severity,
                                cwe=cwe,
                                description=description,
                                references=references,
                                vulnerableSoftware=vulnerableSoftware,
                                vul_col=vul_col,
                                vuln_status='Open',
                                dup_hash=duplicate_hash,
                                vuln_duplicate=duplicate_vuln,
                                false_positive=false_positive,
                                username=username,
                            )
                            save_all.save()

                        else:
                            duplicate_vuln = 'Yes'

                            false_p = dependencycheck_scan_results_db.objects.filter(username=username,
                                                                                     false_positive_hash=duplicate_hash)
                            fp_lenth_match = len(false_p)

                            if fp_lenth_match == 1:
                                false_positive = 'Yes'
                            else:
                                false_positive = 'No'

                            if cwe == 'Na':
                                cwe = name

                            save_all = dependencycheck_scan_results_db(
                                # date_time=date_time,
                                vuln_id=vul_id,
                                scan_id=scan_id,
                                project_id=project_id,
                                fileName=fileName,
                                filePath=filePath,
                                evidenceCollected=evidenceCollected,
                                name=name,
                                cvssScore=cvssScore,
                                cvssAccessVector=cvssAccessVector,
                                cvssAccessComplexity=cvssAccessComplexity,
                                cvssAuthenticationr=cvssAuthenticationr,
                                cvssConfidentialImpact=cvssConfidentialImpact,
                                cvssIntegrityImpact=cvssIntegrityImpact,
                                cvssAvailabilityImpact=cvssAvailabilityImpact,
                                severity=severity,
                                cwe=cwe,
                                description=description,
                                references=references,
                                vulnerableSoftware=vulnerableSoftware,
                                vul_col=vul_col,
                                vuln_status='Duplicate',
                                dup_hash=duplicate_hash,
                                vuln_duplicate=duplicate_vuln,
                                false_positive="Duplicate",
                                username=username,
                            )
                            save_all.save()


        all_dependency_data = dependencycheck_scan_results_db.objects.filter(username=username, scan_id=scan_id, false_positive='No')

        duplicate_count = dependencycheck_scan_results_db.objects.filter(username=username, scan_id=scan_id,
                                                                             vuln_duplicate='Yes')

        total_vul = len(all_dependency_data)
        total_high = len(all_dependency_data.filter(severity="High"))
        total_medium = len(all_dependency_data.filter(severity="Medium"))
        total_low = len(all_dependency_data.filter(severity="Low"))
        total_duplicate = len(duplicate_count.filter(vuln_duplicate='Yes'))

        dependencycheck_scan_db.objects.filter(username=username, scan_id=scan_id).update(
            total_vuln=total_vul,
            SEVERITY_HIGH=total_high,
            SEVERITY_MEDIUM=total_medium,
            SEVERITY_LOW=total_low,
            total_dup=total_duplicate
        )

    subject = 'Archery Tool Scan Status - DependencyCheck Report Uploaded'
    message = 'DependencyCheck Scanner has completed the scan ' \
              '  %s <br> Total: %s <br>High: %s <br>' \
              'Medium: %s <br>Low %s' % (name, total_vul, total_high, total_medium, total_low)

    email_sch_notify(subject=subject, message=message)

    return HttpResponse(status=201)
