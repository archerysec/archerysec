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


from compliance.models import inspec_scan_db, inspec_scan_results_db
import uuid

from webscanners.zapscanner.views import email_sch_notify

status = None
controls_results_message = None


def inspec_report_json(data, project_id, scan_id, username):
    """

    :param data:
    :param project_id:
    :param scan_id:
    :return:
    """
    global controls_results_message, status
    vul_col = 'info'

    for key, value in data.items():
        if key == 'profiles':
            for profile in value:
                controls = profile['controls']
                for con in controls:
                    controls_id = con['id']
                    controls_title = con['title']
                    controls_desc = con['desc']
                    controls_descriptions = ""
                    try:
                        controls_descriptions = con['descriptions'][0]['data'] 
                    except:
                        ontrols_descriptions = controls_desc

                    controls_impact = con['impact']
                    controls_refs = con['refs']

                    try:
                        controls_tags_severity = con['tags']['severity']
                    except:
                        controls_tags_severity= "INFO"

                    try:
                        controls_tags_cis_id = con['tags']['severity']
                    except:
                        controls_tags_cis_id= "None"
                    try:
                        controls_tags_cis_control = con['tags']['cis_control']
                    except:
                        controls_tags_cis_control= "None"
                    try:
                        controls_tags_cis_level = con['tags']['cis_level']
                    except:
                        controls_tags_cis_level= "None"
                    try:
                        controls_tags_audit = con['tags']['audit text']
                    except:
                        controls_tags_audit= "None"
                    try:
                        controls_tags_fix = con['tags']['fix']
                    except:
                        controls_tags_fix= "None"
                                                                                                                        
                   # controls_tags_cis_id = con['tags']['cis_id'] ? con['tags']['cis_id'] : "None"
                   # controls_tags_cis_control = con['tags']['cis_control'] ? con['tags']['cis_control'] : "None"
                   # controls_tags_cis_level = con['tags']['cis_level'] ? con['tags']['cis_level'] : "None"
                   # controls_tags_audit = con['tags']['audit text'] ? con['tags']['audit text'] : "None"
                   # controls_tags_fix = con['tags']['fix'] ? con['tags']['fix'] : "None"
                    # controls_tags_severity = "INFO"
                    # controls_tags_cis_id = "None"
                    # controls_tags_cis_control = "None"
                    # controls_tags_cis_level = "None"
                    # controls_tags_audit = "None"
                    # controls_tags_fix = "None"

                    controls_code = con['code']
                    controls_source_location = con['source_location']['line']
                    for res in con['results']:
                        controls_results_status = res['status']
                        controls_results_code_desc = res['code_desc']
                        controls_results_run_time = res['run_time']
                        controls_results_start_time = res['start_time']
                        for key, value in res.items():
                            if key == 'message':
                                controls_results_message = value

                        if controls_results_status == "failed":
                            vul_col = "danger"
                            status = "Failed"

                        elif controls_results_status == 'passed':
                            vul_col = "warning"
                            status = "Passed"

                        elif controls_results_status == 'skipped':
                            vul_col = "info"
                            status = "Skipped"

                        vul_id = uuid.uuid4()

                        save_all = inspec_scan_results_db(
                            scan_id=scan_id,
                            project_id=project_id,
                            vul_col=vul_col,
                            vuln_id=vul_id,
                            controls_id=controls_id,
                            controls_title=controls_title,
                            controls_desc=controls_desc,
                            controls_descriptions=controls_descriptions,
                            controls_impact=controls_impact,
                            controls_refs=controls_refs,
                            controls_tags_severity=controls_tags_severity,
                            controls_tags_cis_id=controls_tags_cis_id,
                            controls_tags_cis_control=controls_tags_cis_control,
                            controls_tags_cis_level=controls_tags_cis_level,
                            controls_tags_audit=controls_tags_audit,
                            controls_tags_fix=controls_tags_fix,

                            controls_code=controls_code,
                            controls_source_location=controls_source_location,
                            controls_results_status=status,
                            controls_results_code_desc=controls_results_code_desc,
                            controls_results_run_time=controls_results_run_time,
                            controls_results_start_time=controls_results_start_time,
                            controls_results_message=controls_results_message,
                            username=username,

                        )
                        save_all.save()

            all_inspec_data = inspec_scan_results_db.objects.filter(username=username, scan_id=scan_id)

            total_vul = len(all_inspec_data)
            inspec_failed = len(all_inspec_data.filter(controls_results_status="Failed"))
            inspec_passed = len(all_inspec_data.filter(controls_results_status="Passed"))
            inspec_skipped = len(all_inspec_data.filter(controls_results_status="Skipped"))
            total_duplicate = len(all_inspec_data.filter(vuln_duplicate='Yes'))

            inspec_scan_db.objects.filter(username=username, scan_id=scan_id).update(
                total_vuln=total_vul,
                inspec_failed=inspec_failed,
                inspec_passed=inspec_passed,
                inspec_skipped=inspec_skipped,
                total_dup=total_duplicate
            )
            subject = 'Archery Tool Scan Status - Inspec Report Uploaded'
            message = 'Inspec Scanner has completed the scan ' \
                      '  %s <br> Total: %s <br>Failed: %s <br>' \
                      'failed: %s <br>Skipped %s' % (scan_id, total_vul, inspec_failed, inspec_failed, inspec_skipped)

            email_sch_notify(subject=subject, message=message)
