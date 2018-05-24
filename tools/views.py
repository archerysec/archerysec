# -*- coding: utf-8 -*-
from __future__ import unicode_literals
from tools.models import sslscan_result_db
from django.shortcuts import render
import uuid
import subprocess

# Create your views here.
sslscan_output = None


def sslscan(request):
    """

    :return:
    """
    global sslscan_output
    all_sslscan = sslscan_result_db.objects.all()

    if request.method == 'POST':
        scan_url = request.POST.get('scan_url')
        project_id = request.POST.get('project_id')
        scan_id = uuid.uuid4()

        try:
            sslscan_output = subprocess.check_output(['sslscan', '--no-colour', scan_url])
            print(sslscan_output)

        except Exception as e:
            print (e)

        dump_scans = sslscan_result_db(scan_url=scan_url,
                                       scan_id=scan_id,
                                       project_id=project_id,
                                       sslscan_output=sslscan_output)

        dump_scans.save()

    return render(request,
                  'sslscan_list.html',
                  {'all_sslscan': all_sslscan}

                  )


def sslscan_result(request):
    """

    :param request:
    :return:
    """

    if request.method == 'GET':
        scan_id = request.GET['scan_id']
        scan_result = sslscan_result_db.objects.filter(scan_id=scan_id)

    return render(request,
                  'sslscan_result.html',
                  {'scan_result': scan_result}
                  )
