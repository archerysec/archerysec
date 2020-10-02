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

from __future__ import unicode_literals
from django.shortcuts import render, HttpResponseRedirect
from django.contrib import messages
import uuid
from projects.models import project_db, project_scan_db
from webscanners.models import zap_scans_db, zap_scan_results_db, \
    burp_scan_db, burp_scan_result_db, \
    arachni_scan_db, arachni_scan_result_db, \
    netsparker_scan_db, netsparker_scan_result_db, \
    webinspect_scan_db, webinspect_scan_result_db, \
    acunetix_scan_db, acunetix_scan_result_db
from staticscanners.models import dependencycheck_scan_db, dependencycheck_scan_results_db, \
    findbugs_scan_db, findbugs_scan_results_db, \
    bandit_scan_db, bandit_scan_results_db, clair_scan_db, clair_scan_results_db, \
    trivy_scan_db, trivy_scan_results_db, npmaudit_scan_db, npmaudit_scan_results_db, nodejsscan_scan_results_db, \
    nodejsscan_scan_db, tfsec_scan_results_db, tfsec_scan_db, checkmarx_scan_results_db, checkmarx_scan_db, whitesource_scan_db, whitesource_scan_results_db, gitlabsca_scan_results_db, gitlabsast_scan_results_db, gitlabsca_scan_db, gitlabsast_scan_db, semgrepscan_scan_results_db, semgrepscan_scan_db, gitlabcontainerscan_scan_results_db, gitlabcontainerscan_scan_db
from compliance.models import inspec_scan_results_db, inspec_scan_db, dockle_scan_db, dockle_scan_results_db
from networkscanners.models import scan_save_db, ov_scan_result_db, nessus_scan_db, nessus_report_db
import datetime
from manual_scan.models import manual_scan_results_db, manual_scans_db
from itertools import chain
from django.urls import reverse

project_dat = None


def create_form(request):
    return render(request, 'project_create.html')


def create(request):
    if request.method == 'POST':
        username = request.user.username
        print(username)
        project_id = uuid.uuid4()
        project_name = request.POST.get("projectname", )
        project_date = request.POST.get("projectstart", )
        project_end = request.POST.get("projectend", )
        project_owner = request.POST.get("projectowner", )
        project_disc = request.POST.get("project_disc", )
        date_time = datetime.datetime.now()

        save_project = project_db(username=username, project_name=project_name, project_id=project_id,
                                  project_start=project_date, project_end=project_end,
                                  project_owner=project_owner, project_disc=project_disc, date_time=date_time)
        save_project.save()

        # messages.success(request, "Project Created")

        return HttpResponseRedirect(reverse('dashboard:dashboard'))

    return render(request, 'dashboard/project.html')


def projects(request):
    username = request.user.username
    all_projects = project_db.objects.filter(username=username)

    if request.method == 'POST':
        project_id = request.POST.get("proj_id", )

        del_proj = project_db.objects.filter(project_id=project_id)
        del_proj.delete()

        burp = burp_scan_db.objects.filter(project_id=project_id)
        burp.delete()
        burp_result_data = burp_scan_result_db.objects.filter(project_id=project_id)
        burp_result_data.delete()

        zap = zap_scans_db.objects.filter(project_id=project_id)
        zap.delete()
        zap_result = zap_scan_results_db.objects.filter(project_id=project_id)
        zap_result.delete()

        arachni = arachni_scan_db.objects.filter(project_id=project_id)
        arachni.delete()
        arachni_result = arachni_scan_result_db.objects.filter(project_id=project_id)
        arachni_result.delete()

        webinspect = webinspect_scan_db.objects.filter(project_id=project_id)
        webinspect.delete()
        webinspect_result = webinspect_scan_result_db.objects.filter(project_id=project_id)
        webinspect_result.delete()

        netsparker = netsparker_scan_db.objects.filter(project_id=project_id)
        netsparker.delete()
        netsparker_result = netsparker_scan_result_db.objects.filter(project_id=project_id)
        netsparker_result.delete()

        acunetix = acunetix_scan_db.objects.filter(project_id=project_id)
        acunetix.delete()
        acunetix_result = acunetix_scan_result_db.objects.filter(project_id=project_id)
        acunetix_result.delete()

        dependency_check = dependencycheck_scan_db.objects.filter(project_id=project_id)
        dependency_check.delete()
        dependency_check_result = dependencycheck_scan_results_db.objects.filter(project_id=project_id)
        dependency_check_result.delete()

        findbugs = findbugs_scan_db.objects.filter(project_id=project_id)
        findbugs.delete()
        findbugs_result = findbugs_scan_results_db.objects.filter(project_id=project_id)
        findbugs_result.delete()

        bandit = bandit_scan_db.objects.filter(project_id=project_id)
        bandit.delete()
        bandit_result = bandit_scan_results_db.objects.filter(project_id=project_id)
        bandit_result.delete()

        clair = clair_scan_db.objects.filter(project_id=project_id)
        clair.delete()
        clair_result = clair_scan_results_db.objects.filter(project_id=project_id)
        clair_result.delete()

        trivy = trivy_scan_db.objects.filter(project_id=project_id)
        trivy.delete()
        trivy_result = trivy_scan_results_db.objects.filter(project_id=project_id)
        trivy_result.delete()

        npmaudit = npmaudit_scan_db.objects.filter(project_id=project_id)
        npmaudit.delete()
        npmaudit_result = npmaudit_scan_results_db.objects.filter(project_id=project_id)
        npmaudit_result.delete()

        nodejsscan = nodejsscan_scan_db.objects.filter(project_id=project_id)
        nodejsscan.delete()
        nodejsscan_result = nodejsscan_scan_results_db.objects.filter(project_id=project_id)
        nodejsscan_result.delete()

        tfsec = tfsec_scan_db.objects.filter(project_id=project_id)
        tfsec.delete()
        tfsec_result = tfsec_scan_results_db.objects.filter(project_id=project_id)
        tfsec_result.delete()

        whitesource = whitesource_scan_db.objects.filter(project_id=project_id)
        whitesource.delete()
        whitesource_result = whitesource_scan_results_db.objects.filter(project_id=project_id)
        whitesource_result.delete()

        gitlabsca = gitlabsca_scan_db.objects.filter(project_id=project_id)
        gitlabsca.delete()
        gitlabsca_result = gitlabsca_scan_results_db.objects.filter(project_id=project_id)
        gitlabsca_result.delete()

        gitlabsast = gitlabsast_scan_db.objects.filter(project_id=project_id)
        gitlabsast.delete()
        gitlabsast_result = gitlabsast_scan_results_db.objects.filter(project_id=project_id)
        gitlabsast_result.delete()

        gitlabcontainerscan = gitlabcontainerscan_scan_db.objects.filter(project_id=project_id)
        gitlabcontainerscan.delete()
        gitlabcontainerscan_result = gitlabcontainerscan_scan_results_db.objects.filter(project_id=project_id)
        gitlabcontainerscan_result.delete()

        checkmarx = checkmarx_scan_db.objects.filter(project_id=project_id)
        checkmarx.delete()
        checkmarx_result = checkmarx_scan_results_db.objects.filter(project_id=project_id)
        checkmarx_result.delete()

        semgrepscan = semgrepscan_scan_db.objects.filter(project_id=project_id)
        semgrepscan.delete()
        semgrepscan_result = semgrepscan_scan_results_db.objects.filter(project_id=project_id)
        semgrepscan_result.delete()

        inspec = inspec_scan_db.objects.filter(project_id=project_id)
        inspec.delete()
        inspec_result = inspec_scan_results_db.objects.filter(project_id=project_id)
        inspec_result.delete()

        dockle = dockle_scan_db.objects.filter(project_id=project_id)
        dockle.delete()
        dockle_result = dockle_scan_results_db.objects.filter(project_id=project_id)
        dockle_result.delete()

        openvas = scan_save_db.objects.filter(project_id=project_id)
        openvas.delete()
        openvas_result = ov_scan_result_db.objects.filter(project_id=project_id)
        openvas_result.delete()

        nessus = nessus_scan_db.objects.filter(project_id=project_id)
        nessus.delete()

        nessus_result = nessus_report_db.objects.filter(project_id=project_id)
        nessus_result.delete()

        pentest = manual_scan_results_db.objects.filter(project_id=project_id)
        pentest.delete()

        pentest_dat = manual_scans_db.objects.filter(project_id=project_id)
        pentest_dat.delete()

        # messages.success(request, "Deleted Project")

        return HttpResponseRedirect(reverse('dashboard:dashboard'))

    return render(request, 'dashboard/project.html', {'all_projects': all_projects})


def project_edit(request):
    """

    :param request:
    :return:
    """
    global project_dat
    if request.method == 'GET':
        project_id = request.GET['project_id']
        username = request.user.username
        project_dat = project_db.objects.filter(project_id=project_id, username=username)

    if request.method == 'POST':
        project_id = request.POST.get('project_id')
        project_name = request.POST.get("projectname")
        project_date = request.POST.get("projectstart")
        project_end = request.POST.get("projectend")
        project_owner = request.POST.get("projectowner")
        project_disc = request.POST.get("project_disc")

        project_db.objects.filter(
            project_id=project_id
        ).update(
            project_name=project_name,
            project_start=project_date,
            project_end=project_end,
            project_owner=project_owner,
            project_disc=project_disc
        )
        return HttpResponseRedirect(reverse('projects:projects') + '?proj_id=%s' % project_id)
    return render(request,
                  'project_edit.html',
                  {'project_dat': project_dat}
                  )
