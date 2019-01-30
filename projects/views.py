# -*- coding: utf-8 -*-
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

from __future__ import unicode_literals
from django.shortcuts import render, render_to_response, HttpResponse, HttpResponseRedirect
from projects.models import project_db
from django.contrib import messages
import uuid
from projects.models import project_db, project_scan_db
from webscanners import web_views
from webscanners.models import zap_scans_db, zap_scan_results_db, \
    burp_scan_db, burp_scan_result_db, \
    arachni_scan_db, arachni_scan_result_db, \
    netsparker_scan_db, netsparker_scan_result_db, \
    webinspect_scan_db, webinspect_scan_result_db, \
    acunetix_scan_db, acunetix_scan_result_db
from staticscanners.models import dependencycheck_scan_db, dependencycheck_scan_results_db, \
    findbugs_scan_db, findbugs_scan_results_db, \
    bandit_scan_db, bandit_scan_results_db
from networkscanners.models import scan_save_db, ov_scan_result_db
import datetime
# from webscanners.models import burp_scan_db
from itertools import chain

project_dat = None


def create_form(request):
    return render(request, 'project_create.html')


def create(request):
    if request.method == 'POST':
        project_id = uuid.uuid4()
        project_name = request.POST.get("projectname", )
        project_date = request.POST.get("projectstart", )
        project_end = request.POST.get("projectend", )
        project_owner = request.POST.get("projectowner", )
        project_disc = request.POST.get("project_disc", )
        date_time = datetime.datetime.now()

        save_project = project_db(project_name=project_name, project_id=project_id,
                                  project_start=project_date, project_end=project_end,
                                  project_owner=project_owner, project_disc=project_disc, date_time=date_time)
        save_project.save()

        messages.success(request, "Project Created")

        return HttpResponseRedirect("/projects/")

    return render(request, 'project_create.html')


def projects(request):
    all_projects = project_db.objects.all()

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

        openvas = scan_save_db.objects.filter(project_id=project_id)
        openvas.delete()
        openvas_result = ov_scan_result_db.objects.filter(project_id=project_id)
        openvas_result.delete()

        messages.success(request, "Deleted Project")
        return HttpResponseRedirect("/projects/")

    return render(request, 'projects.html', {'all_projects': all_projects})


def projects_view(request):
    if request.method == 'GET':
        project_id = request.GET['proj_id']

    else:
        project_id = ''

    print "pROJECT ID ", project_id

    if request.POST.get("scan_id", ):
        project_id = request.GET['proj_id']
        scan_ids = request.POST.get("scan_id", )

        del_scans = project_scan_db.objects.filter(id=scan_ids)
        del_scans.delete()

        messages.success(request, "Deleted scan")
        return HttpResponseRedirect("/projects/projects_view/?proj_id=%s" % project_id)

    if request.POST.get("project_status", ):
        project_status = request.POST.get("project_status", )
        project_id = request.POST.get("project_id", )

        project_db.objects.filter(project_id=project_id).update(project_status=project_status)

    project_dat = project_db.objects.filter(project_id=project_id)
    burp = burp_scan_db.objects.filter(project_id=project_id)
    zap = zap_scans_db.objects.filter(project_id=project_id)
    arachni = arachni_scan_db.objects.filter(project_id=project_id)
    webinspect = webinspect_scan_db.objects.filter(project_id=project_id)
    netsparker = netsparker_scan_db.objects.filter(project_id=project_id)
    acunetix = acunetix_scan_db.objects.filter(project_id=project_id)

    dependency_check = dependencycheck_scan_db.objects.filter(project_id=project_id)
    findbugs = findbugs_scan_db.objects.filter(project_id=project_id)

    scan_dat = chain(burp, zap, arachni, webinspect, netsparker, acunetix)
    static_scan = chain(dependency_check, findbugs)
    network_dat = scan_save_db.objects.filter(project_id=project_id)

    return render(request, 'project_view.html',
                  {'project_dat': project_dat,
                   'scan_dat': scan_dat,
                   'project_id': project_id,
                   'network_dat': network_dat,
                   'static_scan': static_scan
                   })


def project_edit(request):
    """

    :param request:
    :return:
    """
    global project_dat
    if request.method == 'GET':
        project_id = request.GET['project_id']
        project_dat = project_db.objects.filter(project_id=project_id)

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
        return HttpResponseRedirect('/projects/projects_view/?proj_id=%s' % project_id)
    return render(request,
                  'project_edit.html',
                  {'project_dat': project_dat}
                  )


def add_scan_v(request):
    if request.method == 'GET':
        project_id = request.GET['proj_id']

    else:
        project_id = ''

    return render(request, 'add_scan.html', {'project_id': project_id})


def add_scan(request):
    if request.method == 'POST':
        scan_type = request.POST.get("scan_type", )
        project_id = request.POST.get("project_id", )
        scan_target = request.POST.get("scan_target", )
        save_scan = project_scan_db(scan_type=scan_type, project_url=scan_target, project_id=project_id)
        save_scan.save()
        messages.success(request, "Scan Added")
        return HttpResponseRedirect("/projects/projects_view/?proj_id=%s" % project_id)

    return render(request, 'project_view.html')
