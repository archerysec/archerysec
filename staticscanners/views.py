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
# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.shortcuts import render, HttpResponseRedirect
from projects.models import project_db
from staticscanners.models import retirejs_scan_results_db, retirejs_scan_db, bandit_scan_results_db, bandit_scan_db
import uuid
from datetime import datetime
import json
from scanners.scanner_parser.staticscanner_parser.retirejss_json_parser import retirejs_report_json
from scanners.scanner_parser.staticscanner_parser.bandit_report_parser import bandit_report_json


# Create your views here.


def report_import(request):
    """

    :param request:
    :return:
    """
    all_project = project_db.objects.all()

    if request.method == "POST":
        project_id = request.POST.get("project_id")
        scanner = request.POST.get("scanner")
        json_file = request.FILES['jsonfile']
        project_name = request.POST.get("project_name")
        scan_id = uuid.uuid4()
        scan_status = '100'
        if scanner == "bandit_scan":
            date_time = datetime.now()
            scan_dump = bandit_scan_db(project_name=project_name,
                                         scan_id=scan_id,
                                         date_time=date_time,
                                         project_id=project_id,
                                         scan_status=scan_status,
                                         )
            scan_dump.save()
            j = json_file.read()
            data = json.loads(j)
            print data
            bandit_report_json(data=data,
                               project_id=project_id,
                               scan_id=scan_id)

            return HttpResponseRedirect("/banditscanner/banditscans_list")

        if scanner == "retirejs_scan":
            date_time = datetime.now()
            scan_dump = retirejs_scan_db(project_name=project_name,
                                         scan_id=scan_id,
                                         date_time=date_time,
                                         project_id=project_id,
                                         scan_status=scan_status,
                                         )
            scan_dump.save()
            j = json_file.read()
            data = json.loads(j)
            retirejs_report_json(data=data,
                                 project_id=project_id,
                                 scan_id=scan_id)

            return HttpResponseRedirect("/retirejsscanner/retirejsscans_list")

    return render(request, 'report_import.html', {'all_project': all_project})
