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
                            vul_col=vul_col
                        )
                        save_all.save()
