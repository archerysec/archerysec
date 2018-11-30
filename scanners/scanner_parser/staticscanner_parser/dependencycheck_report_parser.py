#                   _
#    /\            | |
#   /  \   _ __ ___| |__   ___ _ __ _   _
#  / /\ \ | '__/ __| '_ \ / _ \ '__| | | |
# / ____ \| | | (__| | | |  __/ |  | |_| |
# /_/    \_\_|  \___|_| |_|\___|_|   \__, |
#                                    __/ |
#                                   |___/
# Copyright (C) 2017-2018 ArcherySec
# This file is part of ArcherySec Project.

from staticscanners.models import dependencycheck_scan_db, dependencycheck_scan_results_db
import uuid
import hashlib
from datetime import datetime


def xml_parser(data, project_id, scan_id):
    """

    :param data:
    :param project_id:
    :param scan_id:
    :return:
    """
    fileName = None,
    filePath = None
    evidenceCollected = None
    name = None
    cvssScore = None
    cvssAccessVector = None
    cvssAccessComplexity = None
    cvssAuthenticationr = None
    cvssConfidentialImpact = None
    cvssIntegrityImpact = None
    cvssAvailabilityImpact = None
    severity = None
    cwe = None
    description = None
    references = None
    vulnerableSoftware = None
    vul_col = None

    pt = data.xpath('namespace-uri(.)')
    root = data.getroot()
    for scan in root:
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
                            vul_col = "important"

                        elif severity == 'Medium':
                            vul_col = "warning"

                        elif severity == 'Low':
                            vul_col = "info"

                        dup_data = name + fileName + severity
                        duplicate_hash = hashlib.sha256(dup_data).hexdigest()

                        match_dup = dependencycheck_scan_results_db.objects.filter(
                            dup_hash=duplicate_hash).values('dup_hash')
                        lenth_match = len(match_dup)

                        if lenth_match == 1:
                            duplicate_vuln = 'Yes'
                        elif lenth_match == 0:
                            duplicate_vuln = 'No'
                        else:
                            duplicate_vuln = 'None'

                        false_p = dependencycheck_scan_results_db.objects.filter(
                            false_positive_hash=duplicate_hash)
                        fp_lenth_match = len(false_p)

                        if fp_lenth_match == 1:
                            false_positive = 'Yes'
                        else:
                            false_positive = 'No'

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
                            false_positive=false_positive
                        )
                        save_all.save()
        all_dependency_data = dependencycheck_scan_results_db.objects.filter(scan_id=scan_id)

        total_vul = len(all_dependency_data)
        total_high = len(all_dependency_data.filter(severity="High"))
        total_medium = len(all_dependency_data.filter(severity="Medium"))
        total_low = len(all_dependency_data.filter(severity="Low"))
        total_duplicate = len(all_dependency_data.filter(vuln_duplicate='Yes'))
        print "total duplicats", total_duplicate

        dependencycheck_scan_db.objects.filter(scan_id=scan_id).update(
            total_vuln=total_vul,
            SEVERITY_HIGH=total_high,
            SEVERITY_MEDIUM=total_medium,
            SEVERITY_LOW=total_low,
            total_dup=total_duplicate
        )