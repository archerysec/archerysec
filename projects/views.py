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

import datetime
import uuid

from django.contrib import messages
from django.shortcuts import HttpResponseRedirect, render
from django.urls import reverse

from compliance.models import (DockleScanDb, DockleScanResultsDb,
                               InspecScanDb, InspecScanResultsDb)
from dashboard.scans_data import scans_query
from manual_scan.models import ManualScanResultsDb, ManualScansDb
from projects.models import MonthDb, ProjectDb, ProjectScanDb
from staticscanners.models import (StaticScansDb, StaticScanResultsDb)
from webscanners.models import (WebScanResultsDb, WebScansDb)
from networkscanners.models import (NetworkScanDb, NetworkScanResultsDb)

from django.contrib.auth.hashers import make_password
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from django.http import HttpResponseRedirect
from rest_framework.views import APIView
from rest_framework.renderers import TemplateHTMLRenderer
from django.shortcuts import get_object_or_404
from projects.serializers import ProjectDataSerializers, ProjectCreateSerializers
from user_management.models import Organization

from user_management import permissions

project_dat = None

def project_edit(request):
    """

    :param request:
    :return:
    """
    global project_dat
    if request.method == "GET":
        project_id = request.GET["project_id"]

        project_dat = ProjectDb.objects.filter(
            project_id=project_id,
        )

    if request.method == "POST":
        project_id = request.POST.get("project_id")
        project_name = request.POST.get("projectname")
        project_date = request.POST.get("projectstart")
        project_end = request.POST.get("projectend")
        project_owner = request.POST.get("projectowner")
        project_disc = request.POST.get("project_disc")

        ProjectDb.objects.filter(project_id=project_id).update(
            project_name=project_name,
            project_start=project_date,
            project_end=project_end,
            project_owner=project_owner,
            project_disc=project_disc,
        )
        return HttpResponseRedirect(
            reverse("projects:projects") + "?proj_id=%s" % project_id
        )
    return render(request, "projects/project_edit.html", {"project_dat": project_dat})


class ProjectList(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = 'dashboard/project.html'

    permission_classes = (
        IsAuthenticated,
    )

    def get(self, request, uu_id=None):
        if uu_id == None:
            projects = ProjectDb.objects.all()
            serialized_data = ProjectDataSerializers(projects, many=True)
        else:
            try:
                projects = ProjectDb.objects.get(uu_id=uu_id)
                serialized_data = ProjectDataSerializers(projects, many=False)
            except ProjectDb.DoesNotExist:
                return Response(
                    {"message": "User Doesn't Exist"}, status=status.HTTP_404_NOT_FOUND
                )
        return Response({'serializer': serialized_data, 'projects': projects})


class ProjectDelete(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = 'dashboard/project.html'

    permission_classes = (
        IsAuthenticated,
        permissions.IsAdmin
    )

    def post(self, request):
        try:
            project_id = request.data.get("project_id")
            projects = ProjectDb.objects.get(uu_id=project_id)
            projects.delete()
            return HttpResponseRedirect('/dashboard/')
        except ProjectDb.DoesNotExist:
            return Response(
                {"message": "User Doesn't Exist"}, status=status.HTTP_404_NOT_FOUND
            )


class ProjectCreate(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = 'projects/project_create.html'

    permission_classes = (
        IsAuthenticated,
        permissions.IsAdmin
    )

    def get(self, request):
        org = Organization.objects.all()
        projects = ProjectDb.objects.all()
        serialized_data = ProjectDataSerializers(projects, many=True)

        return Response({'serializer': serialized_data, 'projects': projects, 'org': org})

    def post(self, request):
        serializer = ProjectCreateSerializers(data=request.data)
        serializer.is_valid(raise_exception=True)

        name = request.data.get("project_name")
        description = request.data.get("project_disc")

        project = ProjectDb(
            project_name=name,
            project_disc=description,
            created_by=request.user,
            total_vuln=0,
            total_high=0,
            total_medium=0,
            total_low=0,
            total_open=0,
            total_false=0,
            total_close=0,
            total_net=0,
            total_web=0,
            total_static=0,
            high_net=0,
            high_web=0,
            high_static=0,
            medium_net=0,
            medium_web=0,
            medium_static=0,
            low_net=0,
            low_web=0,
            low_static=0,
        )
        project.save()
        all_month_data_display = MonthDb.objects.filter()

        if len(all_month_data_display) == 0:
            save_months_data = MonthDb(
                project_id=project.id,
                month=datetime.datetime.now().month,
                high=0,
                medium=0,
                low=0,
            )
            save_months_data.save()
        messages.success(request, "Project Created")
        return HttpResponseRedirect('/dashboard/')
