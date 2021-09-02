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

import hashlib

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

from jiraticketing.models import jirasetting
from cicd.models import CicdDb
from archeryapi.views import APIKey


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

        if code_path == '':
            code_path = '$(pwd)'

        if target_name == '':
            target_name = 'TARGET_NAME'

        if scanner == 'Bandit':
            result_set = 'archerysec-cli' + \
                         '-h ' + protocol + \
                         '//' + host + ' ' + \
                         '-t' + ' ' + api_key + \
                         ' ' + '--bandit --project=' + \
                         project + ' ' + '--project-name=' + \
                         target_name + ' ' + \
                         '--report_path=$(pwd) --code_path=' + code_path

        return HttpResponse(simplejson.dumps(result_set), content_type='application/json')


class CreatePolicies(APIView):
    enderer_classes = [TemplateHTMLRenderer]
    template_name = "cicd/cicd_list.html"

    permission_classes = (IsAuthenticated, permissions.IsAnalyst)
