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

import json
import os
import threading
import time
import uuid
from datetime import datetime

import defusedxml.ElementTree as ET
from background_task import background
from background_task.models import Task
from django.contrib import messages
from django.db.models import Q
from django.http import HttpResponseRedirect
from django.shortcuts import HttpResponse, render
from django.urls import reverse
from lxml import etree
from notifications.models import Notification
from rest_framework.permissions import IsAuthenticated
from rest_framework.renderers import TemplateHTMLRenderer
from rest_framework.views import APIView

from projects.models import ProjectDb
from scanners.scanner_plugin.web_scanner import burp_plugin, zap_plugin
from user_management import permissions
from webscanners.models import (WebScansDb, cookie_db, excluded_db,
                                task_schedule_db)
from webscanners.zapscanner.views import launch_schudle_zap_scan

setting_file = os.getcwd() + "/" + "apidata.json"


def error_404_view(request):
    return render(request, "error/404.html")


class DeleteNotify(APIView):
    renderer_classes = [TemplateHTMLRenderer]

    permission_classes = (IsAuthenticated,)

    def get(self, request):
        notify_id = request.GET["notify_id"]

        notify_del = Notification.objects.filter(id=notify_id)
        notify_del.delete()

        return HttpResponseRedirect(reverse("dashboard:dashboard"))


class DeleteAllNotify(APIView):
    renderer_classes = [TemplateHTMLRenderer]

    permission_classes = (IsAuthenticated,)

    def get(self, request):
        notify_del = Notification.objects.all()
        notify_del.delete()

        return HttpResponseRedirect(reverse("dashboard:dashboard"))


class Index(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = "webscanners/webscanner.html"

    permission_classes = (IsAuthenticated, permissions.IsAnalyst)

    def get(self, request):
        all_scans = WebScansDb.objects.filter()
        all_excluded_url = excluded_db.objects.filter()
        all_cookies = cookie_db.objects.filter()

        all_scans_db = ProjectDb.objects.filter()

        all_notify = Notification.objects.unread()

        return render(
            request,
            "webscanners/webscanner.html",
            {
                "all_scans": all_scans,
                "all_excluded_url": all_excluded_url,
                "all_cookies": all_cookies,
                "all_scans_db": all_scans_db,
                "message": all_notify,
            },
        )


@background(schedule=60)
def task(target_url, project_id, scanner, **kwargs):
    rescan_id = ""
    rescan = "No"
    target__split = target_url.split(",")
    split_length = target__split.__len__()
    for i in range(0, split_length):
        target = target__split.__getitem__(i)
        # noinspection PyInterpreter
        if scanner == "zap_scan":
            scan_id = uuid.uuid4()
            thread = threading.Thread(
                target=launch_schudle_zap_scan,
                args=(
                    target,
                    project_id,
                    rescan_id,
                    rescan,
                    scan_id,
                    kwargs["username"],
                ),
            )
            thread.daemon = True
            thread.start()
        elif scanner == "burp_scan":
            scan_id = uuid.uuid4()
            do_scan = burp_plugin.burp_scans(
                project_id, target, scan_id, user=kwargs["username"]
            )
            thread = threading.Thread(
                target=do_scan.scan_launch,
            )
            thread.daemon = True
            thread.start()

        return HttpResponse(status=200)


class WebTaskLaunch(APIView):
    permission_classes = (IsAuthenticated, permissions.IsAnalyst)

    def get(self, request):
        task_time = request.GET["time"]

        t = Task.objects.all()
        # t.delete()
        print(task_time)

        for ta in t:
            print(ta.run_at)
            print(ta.id)


class WebScanSchedule(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = "webscanners/web_scan_schedule.html"

    permission_classes = (IsAuthenticated, permissions.IsAnalyst)

    def get(self, request):
        all_scans_db = ProjectDb.objects.filter()
        all_scheduled_scans = task_schedule_db.objects.filter()

        return render(
            request,
            "webscanners/web_scan_schedule.html",
            {"all_scans_db": all_scans_db, "all_scheduled_scans": all_scheduled_scans},
        )

    def post(self, request):
        all_scans_db = ProjectDb.objects.filter()
        all_scheduled_scans = task_schedule_db.objects.filter()
        scan_url = request.POST.get("url")
        scan_schedule_time = request.POST.get("datetime")
        project_id = request.POST.get("project_id")
        scanner = request.POST.get("scanner")
        # periodic_task = request.POST.get('periodic_task')
        periodic_task_value = request.POST.get("periodic_task_value")
        # periodic_task = 'Yes'
        if periodic_task_value == "HOURLY":
            periodic_time = Task.HOURLY
        elif periodic_task_value == "DAILY":
            periodic_time = Task.DAILY
        elif periodic_task_value == "WEEKLY":
            periodic_time = Task.WEEKLY
        elif periodic_task_value == "EVERY_2_WEEKS":
            periodic_time = Task.EVERY_2_WEEKS
        elif periodic_task_value == "EVERY_4_WEEKS":
            periodic_time = Task.EVERY_4_WEEKS
        else:
            periodic_time = None
        dt_str = scan_schedule_time
        dt_obj = datetime.strptime(dt_str, "%d/%m/%Y %H:%M:%S %p")
        target__split = scan_url.split(",")
        split_length = target__split.__len__()
        for i in range(0, split_length):
            target = target__split.__getitem__(i)

            if scanner == "zap_scan":
                if periodic_task_value == "None":
                    my_task = task(target, project_id, scanner, schedule=dt_obj)
                    task_id = my_task.id
                    print("Savedddddd taskid", task_id)
                else:

                    my_task = task(
                        target,
                        project_id,
                        scanner,
                        repeat=periodic_time,
                        repeat_until=None,
                    )
                    task_id = my_task.id
                    print("Savedddddd taskid", task_id)
            elif scanner == "burp_scan":
                if periodic_task_value == "None":
                    my_task = task(target, project_id, scanner, schedule=dt_obj)
                    task_id = my_task.id
                else:
                    my_task = task(
                        target,
                        project_id,
                        scanner,
                        repeat=periodic_time,
                        repeat_until=None,
                    )
                    task_id = my_task.id
                    print("Savedddddd taskid", task_id)
            save_scheadule = task_schedule_db(
                task_id=task_id,
                target=target,
                schedule_time=scan_schedule_time,
                project_id=project_id,
                scanner=scanner,
                periodic_task=periodic_task_value,
            )
            save_scheadule.save()

        return render(
            request,
            "webscanners/web_scan_schedule.html",
            {"all_scans_db": all_scans_db, "all_scheduled_scans": all_scheduled_scans},
        )


class WebScanScheduleDelete(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = "webscanners/web_scan_schedule.html"

    permission_classes = (IsAuthenticated, permissions.IsAnalyst)

    def post(self, request):
        task_id = request.POST.get("task_id")

        scan_item = str(task_id)
        taskid = scan_item.replace(" ", "")
        target_split = taskid.split(",")
        split_length = target_split.__len__()
        print("split_length", split_length)
        for i in range(0, split_length):
            task_id = target_split.__getitem__(i)
            del_task = task_schedule_db.objects.filter(task_id=task_id)
            del_task.delete()
            del_task_schedule = Task.objects.filter(id=task_id)
            del_task_schedule.delete()

        return HttpResponseRedirect(reverse("webscanners:web_scan_schedule"))


class AddCookies(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = "webscanners/web_scan_schedule.html"

    permission_classes = (IsAuthenticated, permissions.IsAnalyst)

    def get(self, request):
        return render(request, "webscanners/cookie_add.html")

    def post(self, request):
        target_url = request.POST.get("url")
        target_cookies = request.POST.get("cookies")
        all_cookie_url = cookie_db.objects.filter(Q(url__icontains=target_url))
        for da in all_cookie_url:
            global cookies
            cookies = da.url

        if cookies == target_url:
            cookie_db.objects.filter(Q(url__icontains=target_url)).update(
                cookie=target_cookies
            )
            return HttpResponseRedirect(reverse("webscanners:index"))
        else:
            data_dump = cookie_db(url=target_url, cookie=target_cookies)
            data_dump.save()
            return HttpResponseRedirect(reverse("webscanners:index"))
