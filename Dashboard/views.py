# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from webscanners.models import zap_scans_db, burp_scan_db
from networkscanners.models import scan_save_db
from projects.models import project_db
from django.shortcuts import render, render_to_response, HttpResponse
from itertools import chain
from django.db.models import Sum

# Create your views here.
chart = []


def dash_call(request):
    all_project = project_db.objects.all()

    all_zap_scan = zap_scans_db.objects.aggregate(Sum('total_vul'))
    all_burp_scan = burp_scan_db.objects.aggregate(Sum('total_vul'))
    all_openvas_scan = scan_save_db.objects.aggregate(Sum('total_vul'))

    for key, value in all_zap_scan.iteritems():
        all_zap = value
    for key, value in all_burp_scan.iteritems():
        all_burp = value
    for key, value in all_openvas_scan.iteritems():
        all_openvas = value

    all_vuln = all_zap + all_burp + all_openvas

    total_network = all_openvas
    total_web = all_zap + all_burp

    all_zap_high = zap_scans_db.objects.aggregate(Sum('high_vul'))
    all_burp_high = burp_scan_db.objects.aggregate(Sum('high_vul'))
    all_openvas_high = scan_save_db.objects.aggregate(Sum('high_total'))

    for key, value in all_zap_high.iteritems():
        zap_high = value
    for key, value in all_burp_high.iteritems():
        burp_high = value
    for key, value in all_openvas_high.iteritems():
        openvas_high = value

    all_high = zap_high + burp_high + openvas_high
    all_web_high = zap_high + burp_high
    all_network_high = openvas_high

    all_zap_medium = zap_scans_db.objects.aggregate(Sum('medium_vul'))
    all_burp_medium = burp_scan_db.objects.aggregate(Sum('medium_vul'))
    all_openvas_medium = scan_save_db.objects.aggregate(Sum('medium_total'))

    for key, value in all_zap_medium.iteritems():
        zap_medium = value
    for key, value in all_burp_medium.iteritems():
        burp_medium = value
    for key, value in all_openvas_medium.iteritems():
        openvas_medium = value

    all_medium = zap_medium + burp_medium + openvas_medium
    all_web_medium = zap_medium + burp_medium
    all_network_medium = openvas_medium

    all_zap_low = zap_scans_db.objects.aggregate(Sum('low_vul'))
    all_burp_low = burp_scan_db.objects.aggregate(Sum('low_vul'))
    all_openvas_low = scan_save_db.objects.aggregate(Sum('low_total'))

    for key, value in all_zap_low.iteritems():
        zap_low = value
    for key, value in all_burp_low.iteritems():
        burp_low = value
    for key, value in all_openvas_low.iteritems():
        openvas_low = value

    all_low = zap_low + burp_low + openvas_low
    all_web_low = zap_low + burp_low
    all_network_low = openvas_low

    return render(request, 'dashboard.html',
                  {'all_project': all_project, 'all_vuln': all_vuln, 'total_web': total_web,
                   'total_network': total_network, 'all_high': all_high, 'all_medium': all_medium, 'all_low': all_low,
                   'all_web_high': all_web_high, 'all_web_medium': all_web_medium,
                   'all_network_medium': all_network_medium, 'all_network_high': all_network_high,
                   'all_web_low': all_web_low, 'all_network_low': all_network_low
                   })


def project_dashboard(request):
    global all_vuln, total_web, all_high, total_network, all_medium, all_low, all_web_high, all_web_medium, all_network_medium, all_web_low, all_network_low, all_network_high
    all_project = project_db.objects.all()

    return render(request, 'project_dashboard.html', {'all_project': all_project, })


def proj_data(request):
    all_project = project_db.objects.all()
    if request.GET['project_id']:
        project_id = request.GET['project_id']

    else:
        project_id = ''

    all_zap_scan = zap_scans_db.objects.filter(project_id=project_id).aggregate(Sum('total_vul'))
    all_burp_scan = burp_scan_db.objects.filter(project_id=project_id).aggregate(Sum('total_vul'))
    all_openvas_scan = scan_save_db.objects.filter(project_id=project_id).aggregate(Sum('total_vul'))

    for key, value in all_zap_scan.iteritems():
        if value is None:
            all_zap = '0'
        else:
            all_zap = value
    for key, value in all_burp_scan.iteritems():
        if value is None:
            all_burp = '0'
        else:
            all_burp = value
    for key, value in all_openvas_scan.iteritems():
        if value is None:
            all_openvas = '0'
        else:
            all_openvas = value

    all_vuln = all_zap + all_burp + all_openvas

    total_network = all_openvas

    total_web = all_zap + all_burp

    all_zap_high = zap_scans_db.objects.filter(project_id=project_id).aggregate(Sum('high_vul'))
    all_burp_high = burp_scan_db.objects.filter(project_id=project_id).aggregate(Sum('high_vul'))
    all_openvas_high = scan_save_db.objects.filter(project_id=project_id).aggregate(Sum('high_total'))

    for key, value in all_zap_high.iteritems():
        if value is None:
            zap_high = '0'
        else:
            zap_high = value
    for key, value in all_burp_high.iteritems():
        if value is None:
            burp_high = '0'
        else:
            burp_high = value
    for key, value in all_openvas_high.iteritems():
        if value is None:
            openvas_high = '0'
        else:
            openvas_high = value

    all_high = zap_high + burp_high + openvas_high
    all_web_high = zap_high + burp_high
    all_network_high = openvas_high

    all_zap_medium = zap_scans_db.objects.filter(project_id=project_id).aggregate(Sum('medium_vul'))
    all_burp_medium = burp_scan_db.objects.filter(project_id=project_id).aggregate(Sum('medium_vul'))
    all_openvas_medium = scan_save_db.objects.filter(project_id=project_id).aggregate(Sum('medium_total'))

    for key, value in all_zap_medium.iteritems():
        if value is None:
            zap_medium = '0'
        else:
            zap_medium = value
    for key, value in all_burp_medium.iteritems():
        if value is None:
            burp_medium = '0'
        else:
            burp_medium = value
    for key, value in all_openvas_medium.iteritems():
        if value is None:
            openvas_medium = '0'
        else:
            openvas_medium = value

    all_medium = zap_medium + burp_medium + openvas_medium
    all_web_medium = zap_medium + burp_medium
    all_network_medium = openvas_medium

    all_zap_low = zap_scans_db.objects.filter(project_id=project_id).aggregate(Sum('low_vul'))
    all_burp_low = burp_scan_db.objects.filter(project_id=project_id).aggregate(Sum('low_vul'))
    all_openvas_low = scan_save_db.objects.filter(project_id=project_id).aggregate(Sum('low_total'))

    for key, value in all_zap_low.iteritems():
        if value is None:
            zap_low = '0'
        else:
            zap_low = value
    for key, value in all_burp_low.iteritems():
        if value is None:
            burp_low = '0'
        else:
            burp_low = value
    for key, value in all_openvas_low.iteritems():
        if value is None:
            openvas_low = '0'
        else:
            openvas_low = value

    all_low = zap_low + burp_low + openvas_low
    all_web_low = zap_low + burp_low
    all_network_low = openvas_low

    return render(request, 'project_dashboard.html', {'all_vuln': all_vuln, 'total_web': total_web,
                                                      'total_network': total_network, 'all_high': all_high,
                                                      'all_medium': all_medium, 'all_low': all_low,
                                                      'all_web_high': all_web_high,
                                                      'all_web_medium': all_web_medium,
                                                      'all_network_medium': all_network_medium,
                                                      'all_network_high': all_network_high,
                                                      'all_web_low': all_web_low,
                                                      'all_network_low': all_network_low,
                                                      'all_project': all_project})


def web_dashboard(request):
    all_burp_data = burp_scan_db.objects.all()
    all_zap_data = zap_scans_db.objects.all()
    all_web_data = chain(all_burp_data, all_zap_data)

    return render(request, 'web_scan_dashboard.html', {'all_web_data': all_web_data})


def web_dash_data(request):
    all_burp_data = burp_scan_db.objects.all()
    all_zap_data = zap_scans_db.objects.all()
    all_web_data = chain(all_burp_data, all_zap_data)

    if request.GET['scan_id']:
        scan_id = request.GET['scan_id']

    else:
        scan_id = ''

    all_zap_scan = zap_scans_db.objects.filter(scan_scanid=scan_id).aggregate(Sum('total_vul'))
    all_burp_scan = burp_scan_db.objects.filter(scan_id=scan_id).aggregate(Sum('total_vul'))

    for key, value in all_zap_scan.iteritems():
        if value is None:
            all_zap = '0'
        else:
            all_zap = value

    for key, value in all_burp_scan.iteritems():
        if value is None:
            all_burp = '0'
        else:
            all_burp = value

    print "burp", all_zap
    print "burp", all_burp

    all_vuln = int(all_zap) + int(all_burp)

    total_web = all_vuln
    print total_web

    all_zap_high = zap_scans_db.objects.filter(scan_scanid=scan_id).aggregate(Sum('high_vul'))
    all_burp_high = burp_scan_db.objects.filter(scan_id=scan_id).aggregate(Sum('high_vul'))

    for key, value in all_zap_high.iteritems():
        if value is None:
            all_high_zap = '0'
        else:
            all_high_zap = value
    for key, value in all_burp_high.iteritems():
        if value is None:
            all_high_burp = '0'
        else:
            all_high_burp = value

    all_high = int(all_high_zap) + int(all_high_burp)

    all_zap_medium = zap_scans_db.objects.filter(scan_scanid=scan_id).aggregate(Sum('medium_vul'))
    all_burp_medium = burp_scan_db.objects.filter(scan_id=scan_id).aggregate(Sum('medium_vul'))

    for key, value in all_zap_medium.iteritems():
        if value is None:
            all_medium_zap = '0'
        else:
            all_medium_zap = value
    for key, value in all_burp_medium.iteritems():
        if value is None:
            all_medium_burp = '0'
        else:
            all_medium_burp = value

    all_medium = int(all_medium_zap) + int(all_medium_burp)

    all_zap_low = zap_scans_db.objects.filter(scan_scanid=scan_id).aggregate(Sum('low_vul'))
    all_burp_low = burp_scan_db.objects.filter(scan_id=scan_id).aggregate(Sum('low_vul'))

    for key, value in all_zap_low.iteritems():
        if value is None:
            all_low_zap = '0'
        else:
            all_low_zap = value
    for key, value in all_burp_low.iteritems():
        if value is None:
            all_low_burp = '0'
        else:
            all_low_burp = value

    all_low = int(all_low_zap) + int(all_low_burp)

    return render(request, 'web_scan_dashboard.html', {'all_web_data': all_web_data, 'total_web': total_web,
                                                       'all_high': all_high, 'all_medium': all_medium,
                                                       'all_low': all_low})


def net_dashboard(request):
    all_openvas_data = scan_save_db.objects.all()
    all_network_data = all_openvas_data
    return render(request, 'network_scan_dashboard.html', {'all_network_data': all_network_data})


def net_dash_data(request):
    all_openvas_data = scan_save_db.objects.all()
    all_network_data = all_openvas_data

    if request.GET['scan_id']:
        scan_id = request.GET['scan_id']

    else:
        scan_id = ''

    all_openvas_scan = scan_save_db.objects.filter(scan_id=scan_id).aggregate(Sum('total_vul'))

    for key, value in all_openvas_scan.iteritems():
        if value is None:
            all_openvas = '0'
        else:
            all_openvas = value

    total_network = all_openvas

    all_openvas_high = scan_save_db.objects.filter(scan_id=scan_id).aggregate(Sum('high_total'))

    for key, value in all_openvas_high.iteritems():
        if value is None:
            openvas_high = '0'
        else:
            openvas_high = value

    all_network_high = openvas_high

    all_openvas_medium = scan_save_db.objects.filter(scan_id=scan_id).aggregate(Sum('medium_total'))

    for key, value in all_openvas_medium.iteritems():
        if value is None:
            openvas_medium = '0'
        else:
            openvas_medium = value

    all_network_medium = openvas_medium

    all_openvas_low = scan_save_db.objects.filter(scan_id=scan_id).aggregate(Sum('low_total'))

    for key, value in all_openvas_low.iteritems():
        if value is None:
            openvas_low = '0'
        else:
            openvas_low = value

    all_network_low = openvas_low

    return render(request, 'network_scan_dashboard.html',
                  {'all_network_data': all_network_data, 'total_network': total_network,
                   'all_network_high': all_network_high, 'all_network_medium': all_network_medium,
                   'all_network_low': all_network_low})
