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

from django.shortcuts import render,  HttpResponseRedirect
from jiraticketing.models import jirasetting
from django.core import signing
from jira import JIRA
from webscanners.models import zap_scan_results_db,\
    burp_scan_result_db, arachni_scan_result_db, netsparker_scan_result_db,\
    acunetix_scan_result_db, \
    webinspect_scan_result_db
from staticscanners.models import bandit_scan_results_db,\
    findbugs_scan_results_db,\
    retirejs_scan_results_db, clair_scan_results_db, dependencycheck_scan_results_db,\
    trivy_scan_results_db, npmaudit_scan_results_db, nodejsscan_scan_results_db, tfsec_scan_results_db
from networkscanners.models import ov_scan_result_db, nessus_report_db
from django.urls import reverse
from notifications.signals import notify

jira_url = ''
j_username = ''

password = ''
jira_projects = ''



def jira_setting(request):
    """

    :param request:
    :return:
    """
    username = request.user.username
    all_jira_settings = jirasetting.objects.filter(username=username)
    for jira in all_jira_settings:
        global jira_url, j_username, password
        jira_url = jira.jira_server
        j_username = signing.loads(jira.jira_username)
        password = signing.loads(jira.jira_password)
    jira_server = jira_url
    jira_username = j_username
    jira_password = password

    if request.method == 'POST':
        jira_url = request.POST.get('jira_url')
        jira_username = request.POST.get('jira_username')
        jira_password = request.POST.get('jira_password')

        j_username = signing.dumps(jira_username)
        password = signing.dumps(jira_password)
        save_data = jirasetting(username=username,
                                jira_server=jira_url,
                                jira_username=j_username,
                                jira_password=password)
        save_data.save()

        return HttpResponseRedirect(reverse('webscanners:setting'))

    return render(request, 'jira_setting_form.html', {'jira_server': jira_server,
                                                      'jira_username': jira_username,
                                                      'jira_password': jira_password,
                                                      })


def submit_jira_ticket(request):
    global jira_projects, jira_ser
    r_username = request.user.username
    jira_setting = jirasetting.objects.filter(username=r_username)
    user = request.user

    for jira in jira_setting:
        jira_url = jira.jira_server
        username = jira.jira_username
        password = jira.jira_password
    jira_server = jira_url
    jira_username = signing.loads(username)
    jira_password = signing.loads(password)

    options = {'server': jira_server}
    try:
        jira_ser = JIRA(options, basic_auth=(jira_username, jira_password))
        jira_projects = jira_ser.projects()
    except Exception as e:
        print(e)
        notify.send(user, recipient=user, verb='Jira settings not found')

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
        print(new_issue)

        if scanner == 'zap':
            zap_scan_results_db.objects.filter(username=r_username, vuln_id=vuln_id).update(jira_ticket=new_issue)
            return HttpResponseRedirect(reverse('zapscanner:zap_vuln_details') + '?scan_id=%s&scan_name=%s' % (
                scan_id,
                summary
            )
                                        )
        elif scanner == 'burp':
            burp_scan_result_db.objects.filter(username=r_username, vuln_id=vuln_id).update(jira_ticket=new_issue)
            return HttpResponseRedirect(reverse('burpscanner:burp_vuln_out') + '?scan_id=%s&scan_name=%s' % (
                scan_id,
                summary
            )
                                        )
        elif scanner == 'arachni':
            arachni_scan_result_db.objects.filter(username=r_username, vuln_id=vuln_id).update(jira_ticket=new_issue)
            return HttpResponseRedirect(
                reverse('arachniscanner:arachni_vuln_out') + '?scan_id=%s&scan_name=%s' % (scan_id, summary))

        elif scanner == 'netsparker':
            netsparker_scan_result_db.objects.filter(username=r_username, vuln_id=vuln_id).update(jira_ticket=new_issue)
            return HttpResponseRedirect(
                reverse('netsparkerscanner:netsparker_vuln_out') + '?scan_id=%s&scan_name=%s' % (scan_id, summary))

        elif scanner == 'webinspect':
            webinspect_scan_result_db.objects.filter(username=r_username, vuln_id=vuln_id).update(jira_ticket=new_issue)
            return HttpResponseRedirect(
                reverse('webinspectscanner:webinspect_vuln_out') + '?scan_id=%s&scan_name=%s' % (scan_id, summary))

        elif scanner == 'acunetix':
            acunetix_scan_result_db.objects.filter(username=r_username, vuln_id=vuln_id).update(jira_ticket=new_issue)
            return HttpResponseRedirect(
                reverse('acunetixscanner:acunetix_vuln_out') + '?scan_id=%s&scan_name=%s' % (scan_id, summary))

        elif scanner == 'bandit':
            bandit_scan_results_db.objects.filter(username=r_username, vuln_id=vuln_id).update(jira_ticket=new_issue)
            return HttpResponseRedirect(
                reverse('banditscanner:banditscan_vuln_data') + '?scan_id=%s&test_name=%s' % (scan_id, summary))

        elif scanner == 'dependencycheck':
            dependencycheck_scan_results_db.objects.filter(username=r_username, vuln_id=vuln_id).update(jira_ticket=new_issue)
            return HttpResponseRedirect(
                reverse('dependencycheck:dependencycheck_vuln_data') + '?scan_id=%s&test_name=%s' % (scan_id, summary))

        elif scanner == 'findbugs':
            findbugs_scan_results_db.objects.filter(username=r_username, vuln_id=vuln_id).update(jira_ticket=new_issue)
            return HttpResponseRedirect(
                reverse('findbugs:findbugs_vuln_data') + '?scan_id=%s&test_name=%s' % (scan_id, summary))

        elif scanner == 'clair':
            clair_scan_results_db.objects.filter(username=r_username, vuln_id=vuln_id).update(jira_ticket=new_issue)
            return HttpResponseRedirect(
                reverse('clair:clair_vuln_data') + '?scan_id=%s&test_name=%s' % (scan_id, summary))

        elif scanner == 'trivy':
            trivy_scan_results_db.objects.filter(username=r_username, vuln_id=vuln_id).update(jira_ticket=new_issue)
            return HttpResponseRedirect(
                reverse('trivy:trivy_vuln_data') + '?scan_id=%s&test_name=%s' % (scan_id, summary))

        elif scanner == 'npmaudit':
            npmaudit_scan_results_db.objects.filter(username=r_username, vuln_id=vuln_id).update(jira_ticket=new_issue)
            return HttpResponseRedirect(
                reverse('npmaudit:npmaudit_vuln_data') + '?scan_id=%s&test_name=%s' % (scan_id, summary))

        elif scanner == 'nodejsscan':
            nodejsscan_scan_results_db.objects.filter(username=r_username, vuln_id=vuln_id).update(jira_ticket=new_issue)
            return HttpResponseRedirect(
                reverse('nodejsscan:nodejsscan_vuln_data') + '?scan_id=%s&test_name=%s' % (scan_id, summary))

        elif scanner == 'tfsec':
            tfsec_scan_results_db.objects.filter(username=r_username, vuln_id=vuln_id).update(jira_ticket=new_issue)
            return HttpResponseRedirect(
                reverse('tfsec:tfsec_vuln_data') + '?scan_id=%s&test_name=%s' % (scan_id, summary))

        elif scanner == 'open_vas':
            ov_scan_result_db.objects.filter(username=r_username, vul_id=vuln_id).update(jira_ticket=new_issue)
            return HttpResponseRedirect(reverse('networkscanners:vul_details') + '?scan_id=%s' % scan_id)
        elif scanner == 'nessus':
            nessus_report_db.objects.filter(username=r_username, vul_id=vuln_id).update(jira_ticket=new_issue)
            return HttpResponseRedirect(reverse('networkscanners:nessus_vuln_details') + '?scan_id=%s' % scan_id)
