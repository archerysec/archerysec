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

from rest_framework.response import Response
from webscanners.models import zap_scans_db, zap_scan_results_db, burp_scan_db, burp_scan_result_db, arachni_scan_db, \
    netsparker_scan_db, webinspect_scan_db
from networkscanners.models import scan_save_db, ov_scan_result_db
from projects.models import project_db
from webscanners.serializers import WebScanSerializer, WebScanResultSerializer, UploadScanSerializer, \
    WebScanStatusSerializer
from rest_framework import status
from webscanners import web_views
from webscanners.zapscanner.views import launch_zap_scan
from networkscanners import views
from networkscanners.serializers import NetworkScanSerializer, NetworkScanResultSerializer
from serializers import CreateUser
from rest_framework import generics
import uuid
from projects.serializers import ProjectDataSerializers
from scanners.scanner_plugin.web_scanner import burp_plugin
from itertools import chain
import threading
from django.utils import timezone
import datetime
import defusedxml.ElementTree as ET
from scanners.scanner_parser.web_scanner import zap_xml_parser, \
    arachni_xml_parser, netsparker_xml_parser, webinspect_xml_parser
from rest_framework.response import Response
from rest_framework.views import APIView
import json
from rest_framework.parsers import MultiPartParser, FormParser
from staticscanners.models import bandit_scan_db, bandit_scan_results_db
from scanners.scanner_parser.staticscanner_parser.bandit_report_parser import bandit_report_json
from django.contrib.auth.models import User
from stronghold.decorators import public
from rest_framework import authentication, permissions
from webscanners.arachniscanner.views import launch_arachni_scan
from scanners.scanner_parser.staticscanner_parser import dependencycheck_report_parser
from lxml import etree
from staticscanners.models import dependencycheck_scan_db


class WebScan(generics.ListCreateAPIView):
    queryset = zap_scans_db.objects.all()
    serializer_class = WebScanSerializer

    def get(self, request, format=None, **kwargs):
        """
            GET List all scans and check status.
        """
        all_scans = zap_scans_db.objects.all()
        serialized_scans = WebScanSerializer(all_scans, many=True)
        return Response(serialized_scans.data)

    def post(self, request, format=None, **kwargs):
        """
        Launch scans using this api
        """
        serializer = WebScanSerializer(data=request.data)
        if serializer.is_valid():
            scan_id = uuid.uuid4()
            scanner = request.data.get('scanner')
            target_url = request.data.get('scan_url', )
            project_id = request.data.get('project_id', )
            rescanid = None
            rescan = 'No'
            if scanner == 'zap_scan':
                # run_s = launch_zap_scan
                thread = threading.Thread(target=launch_zap_scan, args=(target_url,
                                                                        project_id,
                                                                        rescanid,
                                                                        rescan,
                                                                        scan_id))
                thread.daemon = True
                thread.start()

            elif scanner == 'burp_scan':
                date_time = datetime.datetime.now()
                scan_dump = burp_scan_db(scan_id=scan_id,
                                         project_id=project_id,
                                         url=target_url,
                                         date_time=date_time)
                scan_dump.save()
                # do_scan = burp_plugin.burp_scans(project_id, target_url, scan_id)
                # # o = ()
                # thread = threading.Thread(target=do_scan.scan_launch(), args=(project_id, target_url, scan_id))
                # thread.daemon = True
                # thread.start()
                try:
                    do_scan = burp_plugin.burp_scans(
                        project_id,
                        target_url,
                        scan_id)
                    # do_scan.scan_lauch(project_id,
                    #                    target,
                    #                    scan_id)

                    thread = threading.Thread(
                        target=do_scan.scan_launch,
                    )
                    thread.daemon = True
                    thread.start()
                    # time.sleep(5)
                except Exception as e:
                    print e
            elif scanner == 'arachni':
                thread = threading.Thread(target=launch_arachni_scan, args=(target_url,
                                                                            project_id,
                                                                            rescanid,
                                                                            rescan,
                                                                            scan_id))
                thread.daemon = True
                thread.start()

            if not target_url:
                return Response({"error": "No name passed"})
            return Response({"message": "Scan Launched", "scanid": scan_id})
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class NetworkScan(generics.ListCreateAPIView):
    """
    Network Scan API call to perform scan.
    """
    queryset = scan_save_db.objects.all()
    serializer_class = NetworkScanSerializer

    def get(self, request, format=None, **kwargs):

        """
        Returns a list of all **Network Scans** in the system.

        """
        all_scans = scan_save_db.objects.all()
        serialized_scans = NetworkScanSerializer(all_scans, many=True)
        return Response(serialized_scans.data)

    def post(self, request, format=None, **kwargs):
        """
           Current user's identity endpoint.

        """
        serializer = NetworkScanSerializer(data=request.data)
        if serializer.is_valid():
            target_ip = request.data.get('scan_ip', )
            project_id = request.data.get('project_id', )
            profile = None
            # views.openvas_scanner(target_ip, project_id, profile)
            thread = threading.Thread(
                target=views.openvas_scanner,
                args=(target_ip, project_id, profile)
            )
            thread.daemon = True
            thread.start()
            # time.sleep(5)
            if not target_ip:
                return Response({"error": "No name passed"})
            return Response({"message": "Scan Started"})
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class Project(generics.CreateAPIView):
    queryset = project_db.objects.all()
    serializer_class = ProjectDataSerializers

    def get(self, request, format=None, **kwargs):

        """
        Returns a list of all **Network Scans** in the system.

        """
        all_scans = project_db.objects.all()
        serialized_scans = ProjectDataSerializers(all_scans, many=True)
        return Response(serialized_scans.data)

    def post(self, request, format=None, **kwargs):
        """
           Current user's identity endpoint.

        """
        serializer = ProjectDataSerializers(data=request.data)
        if serializer.is_valid():
            project_id = uuid.uuid4()
            project_name = request.data.get("project_name", )
            project_start = request.data.get("project_start", )
            project_end = request.data.get("project_end", )
            project_owner = request.data.get("project_owner", )
            project_disc = request.data.get("project_disc", )
            save_project = project_db(project_name=project_name, project_id=project_id,
                                      project_start=project_start, project_end=project_end,
                                      project_owner=project_owner, project_disc=project_disc, )
            save_project.save()

            if not project_name:
                return Response({"error": "No name passed"})
            return Response({"message": "Project Created", "Project ID": project_id})
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class WebScanResult(generics.ListCreateAPIView):
    queryset = zap_scan_results_db.objects.all()
    serializer_class = WebScanResultSerializer

    def post(self, request, format=None, **kwargs):
        """
            Post request to get all vulnerability Data.
        """
        serializer = WebScanResultSerializer(data=request.data)
        if serializer.is_valid():
            scan_id = request.data.get('scan_id', )
            # project_id = request.data.get('project_id',)
            zap_scan = zap_scan_results_db.objects.filter(scan_id=scan_id)
            burp_scan = burp_scan_result_db.objects.filter(scan_id=scan_id)
            all_scans = chain(zap_scan, burp_scan)
            serialized_scans = WebScanResultSerializer(all_scans, many=True)
            return Response(serialized_scans.data)


class ZapScanStatus(generics.ListCreateAPIView):
    queryset = zap_scans_db.objects.all()
    serializer_class = WebScanStatusSerializer

    def post(self, request, format=None, **kwargs):
        """
            Post request to get all vulnerability Data.
        """
        serializer = WebScanStatusSerializer(data=request.data)
        if serializer.is_valid():
            scan_id = request.data.get('scan_scanid', )
            zap_scan = zap_scans_db.objects.filter(scan_scanid=scan_id)
            all_scans = chain(zap_scan)
            serialized_scans = WebScanStatusSerializer(all_scans, many=True)
            return Response(serialized_scans.data)


class NetworkScanResult(generics.ListCreateAPIView):
    queryset = ov_scan_result_db.objects.all()
    serializer_class = NetworkScanResultSerializer

    def post(self, request, format=None, **kwargs):
        """
            Post request to get all vulnerability Data.
        """
        serializer = NetworkScanResultSerializer(data=request.data)
        if serializer.is_valid():
            scan_id = request.data.get('scan_id', )
            all_scans = ov_scan_result_db.objects.filter(scan_id=scan_id)
            serialized_scans = NetworkScanResultSerializer(all_scans, many=True)
            return Response(serialized_scans.data)


@public
class CreateUsers(generics.CreateAPIView):
    authentication_classes = ()
    permission_classes = ()
    serializer_class = CreateUser

    def post(self, request, format=None, **kwargs):
        """
            Post request to get all vulnerability Data.
        """
        serializer = CreateUser(data=request.data)
        if serializer.is_valid():
            username = request.data.get('username')
            password = request.data.get('password')
            email = request.data.get('email')
            user = User.objects.create_user(username, email, password)
            user.save()

            return Response({"message": "User Created !!!"})
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UpladScanResult(APIView):
    parser_classes = (MultiPartParser,)

    def post(self, request, format=None):

        project_id = request.data.get("project_id")
        scanner = request.data.get("scanner")
        xml_file = request.data.get("filename")
        scan_url = request.data.get("scan_url")
        scan_id = uuid.uuid4()
        scan_status = "100"
        print xml_file
        print scanner
        if scanner == "zap_scan":
            date_time = datetime.datetime.now()
            scan_dump = zap_scans_db(scan_url=scan_url,
                                     scan_scanid=scan_id,
                                     date_time=date_time,
                                     project_id=project_id,
                                     vul_status=scan_status,
                                     rescan='No')
            scan_dump.save()
            tree = ET.parse(xml_file)
            root_xml = tree.getroot()
            zap_xml_parser.xml_parser(project_id=project_id,
                                      scan_id=scan_id,
                                      root=root_xml)
            return Response({"message": "ZAP Scan Data Uploaded",
                             "scanner": scanner,
                             "project_id": project_id,
                             "scan_id": scan_id
                             })
        elif scanner == "burp_scan":
            date_time = datetime.datetime.now()
            scan_dump = burp_scan_db(url=scan_url,
                                     scan_id=scan_id,
                                     date_time=date_time,
                                     project_id=project_id,
                                     scan_status=scan_status)
            scan_dump.save()
            # Burp scan XML parser
            tree = ET.parse(xml_file)
            root_xml = tree.getroot()
            do_xml_data = burp_plugin.burp_scans(project_id,
                                                 scan_url,
                                                 scan_id)
            do_xml_data.burp_scan_data(root_xml)
            return Response({"message": "Burp Scan Data Uploaded",
                             "project_id": project_id,
                             "scan_id": scan_id,
                             "scanner": scanner
                             })

        elif scanner == "arachni":
            date_time = datetime.datetime.now()
            scan_dump = arachni_scan_db(url=scan_url,
                                        scan_id=scan_id,
                                        date_time=date_time,
                                        project_id=project_id,
                                        scan_status=scan_status)
            scan_dump.save()
            tree = ET.parse(xml_file)
            root_xml = tree.getroot()
            arachni_xml_parser.xml_parser(project_id=project_id,
                                          scan_id=scan_id,
                                          root=root_xml)
            return Response({"message": "Scan Data Uploaded",
                             "project_id": project_id,
                             "scan_id": scan_id,
                             "scanner": scanner
                             })

        elif scanner == 'netsparker':
            date_time = datetime.datetime.now()
            scan_dump = netsparker_scan_db(
                url=scan_url,
                scan_id=scan_id,
                date_time=date_time,
                project_id=project_id,
                scan_status=scan_status
            )
            scan_dump.save()
            tree = ET.parse(xml_file)
            root_xml = tree.getroot()
            netsparker_xml_parser.xml_parser(project_id=project_id,
                                             scan_id=scan_id,
                                             root=root_xml)
            return Response({"message": "Scan Data Uploaded",
                             "project_id": project_id,
                             "scan_id": scan_id,
                             "scanner": scanner
                             })
        elif scanner == 'webinspect':
            date_time = datetime.datetime.now()
            scan_dump = webinspect_scan_db(
                url=scan_url,
                scan_id=scan_id,
                date_time=date_time,
                project_id=project_id,
                scan_status=scan_status
            )
            scan_dump.save()
            tree = ET.parse(xml_file)
            root_xml = tree.getroot()
            webinspect_xml_parser.xml_parser(project_id=project_id,
                                             scan_id=scan_id,
                                             root=root_xml)
            return Response({"message": "Scan Data Uploaded",
                             "project_id": project_id,
                             "scan_id": scan_id,
                             "scanner": scanner
                             })

        elif scanner == 'banditscan':
            date_time = datetime.datetime.now()
            scan_dump = bandit_scan_db(
                project_name=scan_url,
                scan_id=scan_id,
                date_time=date_time,
                project_id=project_id,
                scan_status=scan_status
            )
            scan_dump.save()
            data = json.loads(xml_file)
            bandit_report_json(data=data,
                               project_id=project_id,
                               scan_id=scan_id)
            return Response({"message": "Scan Data Uploaded",
                             "project_id": project_id,
                             "scan_id": scan_id,
                             "scanner": scanner
                             })

        elif scanner == 'dependencycheck':
            date_time = datetime.datetime.now()
            scan_dump = dependencycheck_scan_db(
                project_name=scan_url,
                scan_id=scan_id,
                date_time=date_time,
                project_id=project_id,
                scan_status=scan_status
            )
            scan_dump.save()
            data = etree.parse(xml_file)
            dependencycheck_report_parser.xml_parser(project_id=project_id,
                                                     scan_id=scan_id,
                                                     data=data)
            return Response({"message": "Scan Data Uploaded",
                             "project_id": project_id,
                             "scan_id": scan_id,
                             "scanner": scanner
                             })

        return Response({"message": "Scan Data Uploaded"})
