# -*- coding: utf-8 -*-
from __future__ import unicode_literals
from tools.models import sslscan_result_db, nikto_result_db, nmap_result_db, nmap_scan_db
from django.shortcuts import render, HttpResponseRedirect
import uuid
import subprocess

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


def sslcan_del(request):
    """

    :param request:
    :return:
    """

    if request.method == 'POST':
        scan_id = request.POST.get('scan_id')
        del_scan = sslscan_result_db.objects.filter(scan_id=scan_id)
        del_scan.delete()

    return HttpResponseRedirect('/tools/sslscan/')


def nikto(request):
    """

    :return:
    """
    global nikto_output
    all_nikto = nikto_result_db.objects.all()

    if request.method == 'POST':
        scan_url = request.POST.get('scan_url')
        project_id = request.POST.get('project_id')
        scan_id = uuid.uuid4()

        try:
            print(scan_url)
            nikto_output = subprocess.check_output(['nikto.pl', '-host', scan_url])
            print(nikto_output)

        except Exception as e:
            print (e)

            try:
                nikto_output = subprocess.check_output(['nikto', '-host', scan_url])
                print(nikto_output)
            except Exception as e:
                print(e)

        dump_scans = nikto_result_db(scan_url=scan_url,
                                     scan_id=scan_id,
                                     project_id=project_id,
                                     nikto_scan_output=nikto_output)

        dump_scans.save()

    return render(request,
                  'nikto_scan_list.html',
                  {'all_nikto': all_nikto}

                  )


def nikto_result(request):
    """

    :param request:
    :return:
    """

    if request.method == 'GET':
        scan_id = request.GET['scan_id']
        scan_result = nikto_result_db.objects.filter(scan_id=scan_id)

    return render(request,
                  'nikto_scan_result.html',
                  {'scan_result': scan_result}
                  )


def nikto_scan_del(request):
    """

    :param request:
    :return:
    """

    if request.method == 'POST':
        scan_id = request.POST.get('scan_id')
        del_scan = nikto_result_db.objects.filter(scan_id=scan_id)
        del_scan.delete()

    return HttpResponseRedirect('/tools/nikto/')


def nmap_scan(request):
    """

    :return:
    """
    all_nmap = nmap_scan_db.objects.all()

    return render(request,
                  'nmap_scan.html',
                  {'all_nmap': all_nmap}

                  )


def nmap(request):
    """

    :return:
    """

    if request.method == 'GET':

        ip_address = request.GET['ip']

        all_nmap = nmap_result_db.objects.filter(ip_address=ip_address)

    return render(request,
                  'nmap_list.html',
                  {'all_nmap': all_nmap}

                  )


def nmap_result(request):
    """

    :param request:
    :return:
    """

    if request.method == 'GET':
        scan_id = request.GET['scan_id']
        scan_result = nmap_result_db.objects.filter(scan_id=scan_id)

    return render(request,
                  'nmap_scan_result.html',
                  {'scan_result': scan_result}
                  )


def nmap_scan_del(request):
    """

    :param request:
    :return:
    """

    if request.method == 'POST':
        scan_id = request.POST.get('scan_id')
        del_scan = nmap_result_db.objects.filter(scan_id=scan_id)
        del_scan.delete()
        del_scan = nmap_scan_db.objects.filter(scan_id=scan_id)
        del_scan.delete()

    return HttpResponseRedirect('/tools/nmap_scan/')

