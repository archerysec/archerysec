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

from webscanners.models import netsparker_scan_result_db, netsparker_scan_db
import uuid
import hashlib

from webscanners.zapscanner.views import email_sch_notify

vuln_url = None
vuln_type = None
vuln_severity = None
vuln_certainty = None
vuln_rawrequest = None
vuln_rawresponse = None
vuln_extrainformation = None
vuln_classification = None
vuln_id = None
vul_col = None
description = None
impact = None
actionsToTake = None
remedy = None
requiredSkillsForExploitation = None
externalReferences = None
remedyReferences = None
proofOfConcept = None
proofs = None
false_positive = None


def xml_parser(root,
               project_id,
               scan_id, username):
    global vuln_url, vuln_type, vuln_severity, vuln_certainty, vuln_rawrequest, \
        vuln_rawresponse, vuln_extrainformation, vuln_classification, vuln_id, \
        vul_col, description, impact, actionsToTake, remedy, requiredSkillsForExploitation, \
        externalReferences, remedyReferences, proofOfConcept, proofs

    for data in root:
        if data.tag == "target":
            for url in data:
                if url.tag == 'url':
                    target = url.text
        for vuln in data:

            if vuln.tag == 'url':
                vuln_url = vuln.text

            if vuln.tag == 'type':
                vuln_type = vuln.text

            if vuln.tag == 'severity':
                if vuln.text == 'Important':
                    vuln_severity = 'High'
                else:
                    vuln_severity = vuln.text

            if vuln.tag == 'certainty':
                vuln_certainty = vuln.text

            if vuln.tag == 'rawrequest':
                vuln_rawrequest = vuln.text

            if vuln.tag == 'rawresponse':
                vuln_rawresponse = vuln.text

            if vuln.tag == 'extrainformation':
                vuln_extrainformation = vuln.text

            if vuln.tag == 'classification':
                vuln_classification = vuln.text

            if vuln.tag == 'description':
                description = vuln.text

            if vuln.tag == 'impact':
                impact = vuln.text

            if vuln.tag == 'actionsToTake':
                actionsToTake = vuln.text

            if vuln.tag == 'remedy':
                remedy = vuln.text

            if vuln.tag == 'requiredSkillsForExploitation':
                requiredSkillsForExploitation = vuln.text

            if vuln.tag == 'externalReferences':
                externalReferences = vuln.text

            if vuln.tag == 'remedyReferences':
                remedyReferences = vuln.text

            if vuln.tag == 'proofOfConcept':
                proofOfConcept = vuln.text

            if vuln.tag == 'proofs':
                proofs = vuln.text

            vuln_id = uuid.uuid4()

        if vuln_severity == "Critical":
            vuln_severity = "High"
            vul_col = "danger"

        elif vuln_severity == "High":
            vul_col = 'danger'

        elif vuln_severity == 'Medium':
            vul_col = "warning"

        elif vuln_severity == 'Low':
            vul_col = "info"

        else:
            vuln_severity = "Low"
            vul_col = "info"

        dup_data = str(vuln_type) + str(vuln_url) + str(vuln_severity)
        duplicate_hash = hashlib.sha256(dup_data.encode('utf-8')).hexdigest()
        match_dup = netsparker_scan_result_db.objects.filter(username=username,
                                                             dup_hash=duplicate_hash).values('dup_hash').distinct()
        lenth_match = len(match_dup)

        if lenth_match == 0:
            duplicate_vuln = 'No'

            false_p = netsparker_scan_result_db.objects.filter(username=username,
                                                               false_positive_hash=duplicate_hash)
            fp_lenth_match = len(false_p)

            global false_positive
            if fp_lenth_match == 1:
                false_positive = 'Yes'
            elif lenth_match == 0:
                false_positive = 'No'
            else:
                false_positive = 'No'

            dump_data = netsparker_scan_result_db(scan_id=scan_id,
                                                  project_id=project_id,
                                                  vuln_id=vuln_id,
                                                  vuln_url=vuln_url,
                                                  type=vuln_type,
                                                  severity=vuln_severity,
                                                  certainty=vuln_certainty,
                                                  rawrequest=vuln_rawrequest,
                                                  rawresponse=vuln_rawresponse,
                                                  extrainformation=vuln_extrainformation,
                                                  classification=vuln_classification,
                                                  false_positive=false_positive,
                                                  vuln_color=vul_col,
                                                  description=description,
                                                  impact=impact,
                                                  actionsToTake=actionsToTake,
                                                  remedy=remedy,
                                                  requiredSkillsForExploitation=requiredSkillsForExploitation,
                                                  externalReferences=externalReferences,
                                                  remedyReferences=remedyReferences,
                                                  proofOfConcept=proofOfConcept,
                                                  proofs=proofs,
                                                  vuln_status='Open',
                                                  dup_hash=duplicate_hash,
                                                  vuln_duplicate=duplicate_vuln,
                                                  username=username
                                                  )
            dump_data.save()

        else:
            duplicate_vuln = 'Yes'

            dump_data = netsparker_scan_result_db(scan_id=scan_id,
                                                  project_id=project_id,
                                                  vuln_id=vuln_id,
                                                  vuln_url=vuln_url,
                                                  type=vuln_type,
                                                  severity=vuln_severity,
                                                  certainty=vuln_certainty,
                                                  rawrequest=vuln_rawrequest,
                                                  rawresponse=vuln_rawresponse,
                                                  extrainformation=vuln_extrainformation,
                                                  classification=vuln_classification,
                                                  false_positive='Duplicate',
                                                  vuln_color=vul_col,
                                                  description=description,
                                                  impact=impact,
                                                  actionsToTake=actionsToTake,
                                                  remedy=remedy,
                                                  requiredSkillsForExploitation=requiredSkillsForExploitation,
                                                  externalReferences=externalReferences,
                                                  remedyReferences=remedyReferences,
                                                  proofOfConcept=proofOfConcept,
                                                  proofs=proofs,
                                                  vuln_status='Duplicate',
                                                  dup_hash=duplicate_hash,
                                                  vuln_duplicate=duplicate_vuln,
                                                  username=username
                                                  )
            dump_data.save()

    netsparker_all_vul = netsparker_scan_result_db.objects.filter(username=username, scan_id=scan_id,
                                                                  false_positive='No')
    duplicate_count = netsparker_scan_result_db.objects.filter(username=username, scan_id=scan_id, vuln_duplicate='Yes')

    total_critical = len(netsparker_all_vul.filter(severity='Critical'))
    total_high = len(netsparker_all_vul.filter(severity="High"))
    total_medium = len(netsparker_all_vul.filter(severity="Medium"))
    total_low = len(netsparker_all_vul.filter(severity="Low"))
    total_info = len(netsparker_all_vul.filter(severity="Information"))
    total_duplicate = len(duplicate_count.filter(vuln_duplicate='Yes'))
    total_vul = total_critical + total_high + total_medium + total_low + total_info

    netsparker_scan_db.objects.filter(username=username, scan_id=scan_id).update(total_vul=total_vul,
                                                                                 high_vul=total_high,
                                                                                 medium_vul=total_medium,
                                                                                 low_vul=total_low,
                                                                                 critical_vul=total_critical,
                                                                                 info_vul=total_info,
                                                                                 total_dup=total_duplicate,
                                                                                 url=target
                                                                                 )

    if total_vul == total_duplicate:
        netsparker_scan_db.objects.filter(username=username, scan_id=scan_id).update(total_vul=total_vul,
                                                                                     high_vul=total_high,
                                                                                     medium_vul=total_medium,
                                                                                     low_vul=total_low,
                                                                                     critical_vul=total_critical,
                                                                                     info_vul=total_info,
                                                                                     total_dup=total_duplicate,
                                                                                     url=target
                                                                                     )
    subject = 'Archery Tool Scan Status - Netsparker Report Uploaded'
    message = 'Netsparker Scanner has completed the scan ' \
              '  %s <br> Total: %s <br>High: %s <br>' \
              'Medium: %s <br>Low %s' % (target, total_vul, total_high, total_medium, total_low)

    email_sch_notify(subject=subject, message=message)
