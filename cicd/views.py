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

from django.shortcuts import HttpResponse, render
from notifications.models import Notification
from rest_framework.permissions import IsAuthenticated
from rest_framework.renderers import TemplateHTMLRenderer
from rest_framework.response import Response
from rest_framework.views import APIView
from user_management import permissions
from projects.models import ProjectDb
import json as simplejson
from archeryapi.models import OrgAPIKey
from rest_framework import status
from jiraticketing.models import jirasetting
from cicd.models import CicdDb
from archeryapi.views import APIKey
from django.shortcuts import HttpResponseRedirect, render, reverse


class CicdScanList(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = "cicd/cicd_list.html"

    permission_classes = (IsAuthenticated,)

    def get(self, request):
        all_scans = CicdDb.objects.all()
        all_notify = Notification.objects.unread()

        all_projects = ProjectDb.objects.all()
        return Response({"all_scans": all_scans, "all_projects": all_projects})


class ScannerCommand(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = "cicd/cicd_list.html"

    permission_classes = (IsAuthenticated, permissions.IsAnalyst)

    def get(self, request):
        result_set = ''
        api_key = ''
        scanner = request.GET.get('scanner', None)
        host = request.GET.get('host', None)
        protocol = request.GET.get('protocol', None)
        code_path = request.GET.get('code_path', None)
        target_name = request.GET.get('target_name', None)
        project = request.GET.get('project', None)

        cicd_id = request.GET.get('cicd_id', None)

        access_key = OrgAPIKey.objects.all().count()

        if access_key == 0:
            user = request.user
            api_key = APIKey().generate_api_key(user)
            OrgAPIKey.objects.create(
                api_key=api_key, created_by=user, name='cicd'
            )
        else:
            access_key = OrgAPIKey.objects.all()
            for data in access_key:
                api_key = data.api_key

        if scanner == 'Bandit':
            result_set = 'archerysec-cli ' + \
                         '-h ' + protocol + \
                         '//' + host + ' ' + \
                         '-t' + ' ' + api_key + ' ' + '--cicd_id=' + str(cicd_id) + \
                         ' ' + '--project=' + \
                         project + ' ' + '--bandit' + ' ' + '--report_path=$(pwd)'

        if scanner == 'DependencyCheck':
            result_set = 'archerysec-cli ' + \
                         '-h ' + protocol + \
                         '//' + host + ' ' + \
                         '-t' + ' ' + api_key + ' ' + '--cicd_id=' + str(cicd_id) + \
                         ' ' + '--project=' + \
                         project + ' ' + '--dependency-check' + ' ' + '--report_path=$(pwd)'

        if scanner == 'owasp-base-line':
            result_set = 'archerysec-cli ' + \
                         '-h ' + protocol + \
                         '//' + host + ' ' + \
                         '-t' + ' ' + api_key + ' ' + '--cicd_id=' + str(cicd_id) + \
                         ' ' + '--project=' + \
                         project + ' ' + '--zap-base-line-scan' + ' ' + '--report_path=$(pwd)'

        if scanner == 'owasp-zap-full':
            result_set = 'archerysec-cli ' + \
                         '-h ' + protocol + \
                         '//' + host + ' ' + \
                         '-t' + ' ' + api_key + ' ' + '--cicd_id=' + str(cicd_id) + \
                         ' ' + '--project=' + \
                         project + ' ' + '--zap-full-scan' + ' ' + '--report_path=$(pwd)'

        if scanner == 'findsecbugs':
            result_set = 'archerysec-cli ' + \
                         '-h ' + protocol + \
                         '//' + host + ' ' + \
                         '-t' + ' ' + api_key + ' ' + '--cicd_id=' + str(cicd_id) + \
                         ' ' + '--project=' + \
                         project + ' ' + '--findsecbugs-scan' + ' ' + '--report_path=$(pwd)'

        return HttpResponse(simplejson.dumps(result_set), content_type='application/json')


class CreatePolicies(APIView):
    enderer_classes = [TemplateHTMLRenderer]
    template_name = "cicd/cicd_list.html"

    permission_classes = (IsAuthenticated, permissions.IsAnalyst)

    def post(self, request):
        name = request.POST.get("name")
        uu_id = request.POST.get("project_id")
        threshold = request.POST.get("threshold")
        threshold_count = request.POST.get("threshold_count")
        scm_server = request.POST.get("scm_server")
        build_server = request.POST.get("build_server")
        target_name = request.POST.get("target_name")
        scanner = request.POST.get("scanner")
        command = request.POST.get("command")
        cicd_id = request.POST.get("cicd_id")
        code_path = request.POST.get("code_path")

        project_id = (
            ProjectDb.objects.filter(uu_id=uu_id).values("id").get()["id"]
        )

        if code_path == '':
            code_path = '$(pwd)'

        if target_name == '':
            target_name = 'TARGET_NAME'

        CicdDb.objects.create(
            cicd_id=cicd_id,
            name=name,
            project_id=project_id,
            threshold=threshold,
            threshold_count=threshold_count,
            scm_server=scm_server,
            build_server=build_server,
            target_name=target_name,
            scanner=scanner,
            command=command,
            target=code_path
        )
        return HttpResponseRedirect("/cicd/")


class PoliciesEdit(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = "cicd/cicd_edit.html"

    permission_classes = (
        IsAuthenticated,
        permissions.IsAnalyst,
    )

    def get(self, request, uu_id=None):
        if uu_id == None:
            cicd_details = CicdDb.objects.all()
        else:
            try:
                cicd_details = CicdDb.objects.get(cicd_id=uu_id)
            except CicdDb.DoesNotExist:
                return Response(
                    {"message": "CICD Policies Doesn't Exist"}, status=status.HTTP_404_NOT_FOUND
                )
        return Response(
            {"cicd_details": cicd_details}
        )

    def post(self, request, uu_id):
        name = request.data.get("name")
        threshold = request.data.get("threshold")
        threshold_count = request.data.get("threshold_count")
        build_server = request.data.get("build_server")
        target_name = request.data.get("target_name")

        CicdDb.objects.filter(cicd_id=uu_id).update(
            name=name,
            threshold=threshold,
            threshold_count=threshold_count,
            build_server=build_server,
            target_name=target_name,
        )
        return HttpResponseRedirect("/cicd/")


class PoliciesDelete(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = "cicd/cicd_list.html"

    permission_classes = (IsAuthenticated, permissions.IsAnalyst)

    def post(self, request):
        cicd_id = request.POST.get("scan_id")

        scan_item = str(cicd_id)
        value = scan_item.replace(" ", "")
        value_split = value.split(",")
        split_length = value_split.__len__()
        # print "split_length", split_length
        for i in range(0, split_length):
            scan_id = value_split.__getitem__(i)

            item = CicdDb.objects.filter(cicd_id=scan_id)
            item.delete()
            item_results = CicdDb.objects.filter(cicd_id=scan_id)
            item_results.delete()
        return HttpResponseRedirect(reverse("cicd:cicd_list"))
