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

# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.shortcuts import render, render_to_response, HttpResponseRedirect
from jiraticketing.models import jirasetting
from django.core import signing
from jira import JIRA
from webscanners.models import zap_scan_results_db, burp_scan_result_db, arachni_scan_result_db
from networkscanners.models import ov_scan_result_db, nessus_report_db

jira_url = ''
username = ''

password = ''

def jira_setting(request):
    """

    :param request:
    :return:
    """

    all_jira_settings = jirasetting.objects.all()
    for jira in all_jira_settings:
        global jira_url, username, password
        jira_url = jira.jira_server
        username = signing.loads(jira.jira_username)
        password = signing.loads(jira.jira_password)
    jira_server = jira_url
    jira_username = username
    jira_password = password

    if request.method == 'POST':
        jira_url = request.POST.get('jira_url')
        jira_username = request.POST.get('jira_username')
        jira_password = request.POST.get('jira_password')

        username = signing.dumps(jira_username)
        password = signing.dumps(jira_password)
        save_data = jirasetting(jira_server=jira_url,
                                jira_username=username,
                                jira_password=password)
        save_data.save()

        return HttpResponseRedirect('/webscanners/setting/')

    return render(request, 'jira_setting_form.html', {'jira_server': jira_server,
                                                      'jira_username': jira_username,
                                                      'jira_password': jira_password,
                                                      })


def submit_jira_ticket(request):
    jira_setting = jirasetting.objects.all()

    for jira in jira_setting:
        jira_url = jira.jira_server
        username = jira.jira_username
        password = jira.jira_password
    jira_server = jira_url
    jira_username = signing.loads(username)
    jira_password = signing.loads(password)

    options = {'server': jira_server}
    jira_ser = JIRA(options, basic_auth=(jira_username, jira_password))
    jira_projects = jira_ser.projects()

    if request.method == 'GET':
        summary = request.GET['summary']
        description = request.GET['description']
        scanner = request.GET['scanner']
        vuln_id = request.GET['vuln_id']
        scan_id = request.GET['scan_id']

        return render(request, 'submit_jira_ticket.html', {'jira_projects': jira_projects,
                                                           'summary': summary,
                                                           'description': description,
                                                           'scanner': scanner,
                                                           'vuln_id': vuln_id,
                                                           'scan_id': scan_id
                                                           })

    if request.method == 'POST':
        summary = request.POST.get('summary')
        description = request.POST.get('description')
        project_id = request.POST.get('project_id')
        issue_type = request.POST.get('issue_type')
        vuln_id = request.POST.get('vuln_id')
        scanner = request.POST.get('scanner')
        scan_id = request.POST.get('scan_id')

        issue_dict = {
            'project': {'id': project_id},
            'summary': summary,
            'description': description,
            'issuetype': {'name': issue_type},
        }
        new_issue = jira_ser.create_issue(fields=issue_dict)
        # print new_issue

        if scanner == 'zap':
            zap_scan_results_db.objects.filter(vuln_id=vuln_id).update(jira_ticket=new_issue)
            return HttpResponseRedirect('/webscanners/zap_vul_details/?scan_id=%s&scan_name=%s' % (
                scan_id,
                summary
            )
        )
        elif scanner == 'burp':
            burp_scan_result_db.objects.filter(vuln_id=vuln_id).update(jira_ticket=new_issue)
            return HttpResponseRedirect('/webscanners/burp_vuln_out/?scan_id=%s&scan_name=%s' % (
                scan_id,
                summary
            )
        )
        elif scanner == 'arachni':
            arachni_scan_result_db.objects.filter(vuln_id=vuln_id).update(jira_ticket=new_issue)
            return HttpResponseRedirect('/webscanners/arachni_vuln_out/?scan_id=%s&scan_name=%s' % (scan_id, summary))
        elif scanner == 'open_vas':
            ov_scan_result_db.objects.filter(vul_id=vuln_id).update(jira_ticket=new_issue)
            return HttpResponseRedirect('/networkscanners/vul_details/?scan_id=%s' % scan_id)
        elif scanner == 'nessus':
            nessus_report_db.objects.filter(vul_id=vuln_id).update(jira_ticket=new_issue)
            return HttpResponseRedirect('/networkscanners/nessus_vuln_details/?scan_id=%s' % scan_id)

            # return render(request, 'submit_jira_ticket.html')
