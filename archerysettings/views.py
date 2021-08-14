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

import uuid

from archerysettings.models import (
    EmailDb,
    SettingsDb,
)

from django.http import HttpResponseRedirect
from django.shortcuts import HttpResponse, render
from django.urls import reverse
from notifications.models import Notification
from rest_framework.permissions import IsAuthenticated
from rest_framework.renderers import TemplateHTMLRenderer
from rest_framework.views import APIView

from user_management import permissions


class EmailSetting(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = "setting/email_setting_form.html"

    permission_classes = (IsAuthenticated, permissions.IsAdmin)

    def get(self, request):
        all_email = EmailDb.objects.filter()
        return render(request, "setting/email_setting_form.html", {"all_email": all_email})

    def post(self, request):
        all_email = EmailDb.objects.filter()

        email_setting_data = SettingsDb.objects.filter(setting_scanner="Email")

        subject = request.POST.get("email_subject")
        from_message = request.POST.get("email_message")
        email_to = request.POST.get("to_email")

        all_email.delete()
        email_setting_data.delete()

        setting_id = uuid.uuid4()

        save_setting_info = SettingsDb(
            setting_id=setting_id,
            setting_scanner="Email",
            setting_status=True,
        )
        save_setting_info.save()

        save_email = EmailDb(
            subject=subject,
            message=from_message,
            recipient_list=email_to,
            setting_id=setting_id,
        )
        save_email.save()
        return HttpResponseRedirect(reverse("archerysettings:settings"))


class DeleteSettings(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = "webscanners/scans/list_scans.html"

    permission_classes = (IsAuthenticated, permissions.IsAdmin)

    def post(self, request):
        setting_id = request.POST.get("setting_id")

        delete_dat = SettingsDb.objects.filter(setting_id=setting_id)
        delete_dat.delete()
        return HttpResponseRedirect(reverse("archerysettings:settings"))


class Settings(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = "setting/settings_page.html"

    permission_classes = (IsAuthenticated, permissions.IsAdmin)

    def get(self, request):
        all_notify = Notification.objects.unread()

        all_settings_data = SettingsDb.objects.filter()

        return render(
            request,
            "setting/settings_page.html",
            {
                "all_settings_data": all_settings_data,
                "all_notify": all_notify
            },
        )