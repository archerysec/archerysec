# -*- coding: utf-8 -*-
from __future__ import unicode_literals
from tools.models import sslscan_result_db, nikto_result_db, nmap_result_db, nmap_scan_db, nikto_vuln_db
from django.shortcuts import render, HttpResponseRedirect
import subprocess
import defusedxml.ElementTree as ET
from scanners.scanner_parser.network_scanner import nmap_parser
import uuid
import codecs
from scanners.scanner_parser.tools.nikto_htm_parser import nikto_html_parser
import hashlib
import os

# NOTE[gmedian]: in order to be more portable we just import everything rather than add anything in this very script
from tools.nmap_vulners.nmap_vulners_view import nmap_vulners, nmap_vulners_port, nmap_vulners_scan

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

        scan_item = str(scan_url)
        value = scan_item.replace(" ", "")
        value_split = value.split(',')
        split_length = value_split.__len__()
        for i in range(0, split_length):
            scan_id = uuid.uuid4()
            scans_url = value_split.__getitem__(i)

            try:
                sslscan_output = subprocess.check_output(['sslscan', '--no-colour', scans_url])
                print(sslscan_output)


            except Exception as e:
                print (e)

            dump_scans = sslscan_result_db(scan_url=scans_url,
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

        scan_item = str(scan_id)
        value = scan_item.replace(" ", "")
        value_split = value.split(',')
        split_length = value_split.__len__()
        print "split_length", split_length
        for i in range(0, split_length):
            vuln_id = value_split.__getitem__(i)

            del_scan = sslscan_result_db.objects.filter(scan_id=vuln_id)
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

        scan_item = str(scan_url)
        value = scan_item.replace(" ", "")
        value_split = value.split(',')
        split_length = value_split.__len__()
        for i in range(0, split_length):
            scan_id = uuid.uuid4()
            scans_url = value_split.__getitem__(i)

            nikto_res_path = os.getcwd() + '/nikto_result/' + str(scan_id) + '.html'
            print nikto_res_path

            try:

                nikto_output = subprocess.check_output(['nikto', '-o', nikto_res_path,
                                                        '-Format', 'htm', '-Tuning', '123bde',
                                                        '-host', scans_url])
                print(nikto_output)
                f = codecs.open(nikto_res_path, 'r')
                data = f.read()
                try:
                    nikto_html_parser(data, project_id, scan_id)
                except Exception as e:
                    print e

            except Exception as e:
                print (e)

                try:
                    print("New command running......")
                    print(scans_url)
                    nikto_output = subprocess.check_output(['nikto.pl', '-o', nikto_res_path,
                                                            '-Format', 'htm', '-Tuning', '123bde',
                                                            '-host', scans_url])
                    print(nikto_output)
                    f = codecs.open(nikto_res_path, 'r')
                    data = f.read()
                    try:
                        nikto_html_parser(data, project_id, scan_id)
                    except Exception as e:
                        print e


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


def nikto_result_vul(request):
    """

    :param request:
    :return:
    """
    if request.method == 'GET':
        scan_id = request.GET['scan_id']

    if request.method == "POST":
        false_positive = request.POST.get('false')
        status = request.POST.get('status')
        vuln_id = request.POST.get('vuln_id')
        scan_id = request.POST.get('scan_id')
        nikto_vuln_db.objects.filter(vuln_id=vuln_id,
                                     scan_id=scan_id).update(false_positive=false_positive, vuln_status=status)

        if false_positive == 'Yes':
            vuln_info = nikto_vuln_db.objects.filter(scan_id=scan_id, vuln_id=vuln_id)
            for vi in vuln_info:
                discription = vi.discription
                hostname = vi.hostname
                dup_data = discription + hostname
                false_positive_hash = hashlib.sha256(dup_data).hexdigest()
                nikto_vuln_db.objects.filter(vuln_id=vuln_id,
                                             scan_id=scan_id).update(false_positive=false_positive,
                                                                     vuln_status=status,
                                                                     false_positive_hash=false_positive_hash
                                                                     )
    scan_result = nikto_vuln_db.objects.filter(scan_id=scan_id)

    vuln_data = nikto_vuln_db.objects.filter(scan_id=scan_id,
                                             false_positive='No',
                                             )

    vuln_data_close = nikto_vuln_db.objects.filter(scan_id=scan_id,
                                                   false_positive='No',
                                                   vuln_status='Closed'
                                                   )

    false_data = nikto_vuln_db.objects.filter(scan_id=scan_id,
                                              false_positive='Yes')

    return render(request,
                  'nikto_vuln_list.html',
                  {'scan_result': scan_result,
                   'vuln_data': vuln_data,
                   'vuln_data_close': vuln_data_close,
                   'false_data': false_data
                   }
                  )


def nikto_vuln_del(request):
    """

    :param request:
    :return:
    """
    if request.method == 'POST':
        vuln_id = request.POST.get("del_vuln")
        scan_id = request.POST.get("scan_id")

        scan_item = str(vuln_id)
        value = scan_item.replace(" ", "")
        value_split = value.split(',')
        split_length = value_split.__len__()
        print "split_length", split_length
        for i in range(0, split_length):
            _vuln_id = value_split.__getitem__(i)
            delete_vuln = nikto_vuln_db.objects.filter(vuln_id=_vuln_id)
            delete_vuln.delete()

        return HttpResponseRedirect("/tools/nikto_result_vul/?scan_id=%s" % scan_id)


def nikto_scan_del(request):
    """

    :param request:
    :return:
    """

    if request.method == 'POST':
        scan_id = request.POST.get('scan_id')

        scan_item = str(scan_id)
        value = scan_item.replace(" ", "")
        value_split = value.split(',')
        split_length = value_split.__len__()
        print "split_length", split_length
        for i in range(0, split_length):
            _scan_id = value_split.__getitem__(i)

            del_scan = nikto_result_db.objects.filter(scan_id=_scan_id)
            del_scan.delete()
            del_scan = nikto_vuln_db.objects.filter(scan_id=_scan_id)
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

    if request.method == 'POST':
        ip_address = request.POST.get('ip')
        project_id = request.POST.get('project_id')
        scan_id = uuid.uuid4()

        try:
            print('Start Nmap scan')
            subprocess.check_output(
                ['nmap', '-v', '-sV', '-Pn', '-p', '1-65535', ip_address, '-oX', 'output.xml']
            )

            print('Completed nmap scan')

        except Exception as e:
            print('Eerror in nmap scan:', e)

        try:
            tree = ET.parse('output.xml')
            root_xml = tree.getroot()

            nmap_parser.xml_parser(root=root_xml,
                                   scan_id=scan_id,
                                   project_id=project_id,
                                   )

        except Exception as e:
            print('Error in xml parser:', e)

        return HttpResponseRedirect('/tools/nmap_scan/')

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
        ip_address = request.POST.get('ip_address')

        scan_item = str(ip_address)
        value = scan_item.replace(" ", "")
        value_split = value.split(',')
        split_length = value_split.__len__()
        print "split_length", split_length
        for i in range(0, split_length):
            vuln_id = value_split.__getitem__(i)

            del_scan = nmap_result_db.objects.filter(ip_address=vuln_id)
            del_scan.delete()
            del_scan = nmap_scan_db.objects.filter(scan_ip=vuln_id)
            del_scan.delete()

    return HttpResponseRedirect('/tools/nmap_scan/')
