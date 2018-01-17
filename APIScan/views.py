# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.shortcuts import render, HttpResponseRedirect
import uuid
from projects.models import project_db
from APIScan.models import APIScan_db, api_token_db
import json
import requests
import urllib2
import httplib
import urllib

scan_url = "aa"
req_header = "aa"
req_body = "aa"


def add_api_scan(request):
    all_scans_db = project_db.objects.all()

    if request.POST.get("scan_target", ):
        project_id = request.POST.get("project_id")
        scan_target = request.POST.get("scan_target")
        req_header = request.POST.get("req_header")
        req_body = request.POST.get("req_body")
        method = request.POST.get("method")
        auth_url = request.POST.get("auth_url")
        auth_header = request.POST.get("auth_header")
        scan_id = uuid.uuid4()
        dump_data = APIScan_db(project_id=project_id, scan_url=scan_target, scan_id=scan_id, req_header=req_header,
                               req_body=req_body, method=method, auth_url=auth_url, auth_token_key=auth_header)
        dump_data.save()
        # api_key_dump = api_token_db(scan_id=scan_id, scan_url=scan_target)
        # api_key_dump.save()

        return HttpResponseRedirect('/scanapi/')

    return render(request, 'addapiscan.html', {'all_scans_db': all_scans_db})


def list_api_scan(request):
    all_api_scan = APIScan_db.objects.all()
    all_api_key = api_token_db.objects.all()

    return render(request, 'api_scan_list.html', {'all_api_scan': all_api_scan, 'all_api_key': all_api_key})


def del_api_scan(request):
    if request.POST.get("scan_id"):
        del_scan = request.POST.get("del_scan")
        if del_scan == 'Yes':
            scan_ids = request.POST.get("scan_id")
            item = APIScan_db.objects.filter(scan_id=scan_ids)
            item.delete()
    return HttpResponseRedirect('/scanapi/')


def edit_scan(request):
    if request.method == 'GET':
        api_scan_id = request.GET['scan_id']
    else:
        api_scan_id = ''

    all_scan = APIScan_db.objects.filter(scan_id=api_scan_id)

    if request.POST.get("scan_url"):
        scan_id = request.POST.get("scan_id")
        scan_url = request.POST.get("scan_url")
        req_header = request.POST.get("req_header")
        req_body = request.POST.get("req_body")
        method = request.POST.get("method")
        auth_header = request.POST.get("auth_header")
        APIScan_db.objects.filter(scan_id=scan_id).update(scan_url=scan_url, req_header=req_header,
                                                          req_body=req_body, method=method, auth_token_key=auth_header)

        return HttpResponseRedirect('/scanapi/')
    return render(request, 'edit_scan.html', {'all_scan': all_scan})


def authenticate(request):
    if request.POST.get("scan_url"):
        auth_val = request.POST.get("auth_val")
        if auth_val == 'Yes':
            scan_url = request.POST.get("scan_url")
            req_header = json.dumps(request.POST.get("req_header"))
            req_body = request.POST.get("req_body")
            method = request.POST.get("method")
            project_id = request.POST.get("project_id")
            scan_id = request.POST.get("scan_id")
            if method == "POST":
                print scan_url
                print json.dumps(req_header)
                # rq = ""
                r = requests.post(scan_url, headers={'Content-Type': 'application/json'}, data=req_body)

                data = json.loads(r.text)
                for key, value in data.viewitems():
                    print key, ':', value
                    items = api_token_db(scan_url=scan_url, api_token=value, project_id=project_id, scan_id=scan_id)
                    items.save()

    return HttpResponseRedirect('/scanapi/')


def auth_token_list(request):

    return render(request, 'api_scan_list.html')
