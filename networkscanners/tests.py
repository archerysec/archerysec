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

import logging

import requests
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import Client, TestCase

from authentication.tests import UserCreationTest
from projects.models import *
from networkscanners.models import *

logging.disable(logging.CRITICAL)


class NetworkScanTest(TestCase):
    fixtures = [
        "fixtures/default_user_roles.json",
        "fixtures/default_organization.json",
    ]

    auth_test = UserCreationTest()

    def setUp(self):
        """
        This is the class which runs at the start before running test case.
        This method updates password of admin user
        """
        # Creating Admin user
        UserProfile.objects.create_user(
            name=self.auth_test.admin.get("name"),
            email=self.auth_test.admin.get("email"),
            password=self.auth_test.admin.get("password"),
            role=1,
            organization=1,
        )

        # Creating analyst User
        UserProfile.objects.create_user(
            name=self.auth_test.analyst.get("name"),
            email=self.auth_test.analyst.get("email"),
            password=self.auth_test.analyst.get("password"),
            role=2,
            organization=1,
        )

        # Create viewer user
        UserProfile.objects.create_user(
            name=self.auth_test.viewer.get("name"),
            email=self.auth_test.viewer.get("email"),
            password=self.auth_test.viewer.get("password"),
            role=3,
            organization=1,
        )

    # Test user profile page
    def test_network_scan_list(self):
        client = Client()

        # from admin users
        client.login(
            username=self.auth_test.admin.get("email"),
            password=self.auth_test.admin.get("password"),
        )

        response = client.get("/networkscanners/list_scans/")
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "networkscanners/scans/list_scans.html")

        # from analyst users
        client.login(
            username=self.auth_test.analyst.get("email"),
            password=self.auth_test.analyst.get("password"),
        )

        response = client.get("/networkscanners/list_scans/")
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "networkscanners/scans/list_scans.html")

        # from viewers users
        client.login(
            username=self.auth_test.viewer.get("email"),
            password=self.auth_test.viewer.get("password"),
        )

        response = client.get("/networkscanners/list_scans/")
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "networkscanners/scans/list_scans.html")

    def test_network_scan_vuln_info(self):
        client = Client()

        # from admin users
        client.login(
            username=self.auth_test.admin.get("email"),
            password=self.auth_test.admin.get("password"),
        )

        client.post(
            "/projects/project_create/",
            data={"project_name": "name", "project_disc": "disc"},
        )
        project_id = (
            ProjectDb.objects.filter(project_name="name").values("uu_id").get()["uu_id"]
        )

        file_path = "https://raw.githubusercontent.com/archerysec/report-sample/main/Openvas/openvas.xml"

        response = requests.get(file_path)

        file_n = SimpleUploadedFile(
            name="test.xml",
            content=response.text.encode(),
            content_type="multipart/form-data",
        )

        data = {
            "scanner": "openvas",
            "file": file_n,
            "target": "http://test.com",
            "project_id": str(project_id),
        }
        # upload one sample report
        client.post("/report-upload/upload/", data=data)

        scan_id = (
            NetworkScanDb.objects.filter().values("scan_id").get()["scan_id"]
        )

        ip = NetworkScanDb.objects.filter().values("ip").get()["ip"]

        response = client.get("/networkscanners/list_vuln_info/?scan_id=%s&ip=%s&scanner=Openvas" % (scan_id, ip))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "networkscanners/scans/list_vuln_info.html")

        # from analyst users
        client.login(
            username=self.auth_test.analyst.get("email"),
            password=self.auth_test.analyst.get("password"),
        )

        response = client.get("/networkscanners/list_vuln_info/?scan_id=%s&ip=%s&scanner=Openvas" % (scan_id, ip))
        self.assertEqual(response.status_code, 200)

        # from viewers users
        client.login(
            username=self.auth_test.viewer.get("email"),
            password=self.auth_test.viewer.get("password"),
        )

        response = client.get("/networkscanners/list_vuln_info/?scan_id=%s&ip=%s&scanner=Openvas" % (scan_id, ip))
        self.assertEqual(response.status_code, 200)

    def test_network_scan_vuln_mark(self):
        client = Client()

        # from admin users
        client.login(
            username=self.auth_test.admin.get("email"),
            password=self.auth_test.admin.get("password"),
        )

        client.post(
            "/projects/project_create/",
            data={"project_name": "name", "project_disc": "disc"},
        )
        project_id = (
            ProjectDb.objects.filter(project_name="name").values("uu_id").get()["uu_id"]
        )

        file_path = "https://raw.githubusercontent.com/archerysec/report-sample/main/Openvas/openvas.xml"

        response = requests.get(file_path)

        file_n = SimpleUploadedFile(
            name="test.xml",
            content=response.text.encode(),
            content_type="multipart/form-data",
        )

        data = {
            "scanner": "openvas",
            "file": file_n,
            "target": "http://test.com",
            "project_id": str(project_id),
        }
        # upload one sample report
        client.post("/report-upload/upload/", data=data)

        # get scan_id form network scans db
        scan_id = (
            NetworkScanDb.objects.filter().values("scan_id").get()["scan_id"]
        )

        vuln_info = NetworkScanResultsDb.objects.filter(scan_id=scan_id)
        vuln_id = ""
        vuln_name = ""
        ip = ""
        for vuln in vuln_info:
            vuln_id = vuln.vuln_id
            vuln_name = vuln.title
            ip = vuln.ip

        # post data
        data = {
            "false": "Yes",
            "status": "Close",
            "vuln_id": vuln_id,
            "scan_id": scan_id,
            "vuln_name": vuln_name,
            "scanner": "Openvas",
            "ip": ip
        }

        # mark vulnerability as closed and false positive
        response = client.post("/networkscanners/vuln_mark/", data=data)
        self.assertEqual(response.status_code, 302)

        vuln_info = NetworkScanResultsDb.objects.filter(vuln_id=vuln_id)
        for vuln in vuln_info:
            vuln_false = vuln.false_positive
            vuln_status = vuln.vuln_status

            self.assertEqual(vuln_false, "Yes")
            self.assertEqual(vuln_status, "Closed")

        # post data
        data = {
            "false": "Yes",
            "status": "Close",
            "vuln_id": vuln_id,
            "scan_id": scan_id,
            "vuln_name": vuln_name,
            "scanner": "Openvas",
            "ip": ip
        }

        # mark vulnerability as closed and false positive
        response = client.post("/networkscanners/vuln_mark/", data=data)
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(
            response,
            "/networkscanners/list_vuln_info/"
            + "?scan_id=%s&ip=%s&scanner=%s" % (scan_id, ip, "Openvas"),
        )

        vuln_info = NetworkScanResultsDb.objects.filter(vuln_id=vuln_id)
        for vuln in vuln_info:
            vuln_false = vuln.false_positive
            vuln_status = vuln.vuln_status

            self.assertEqual(vuln_false, "Yes")
            self.assertEqual(vuln_status, "Closed")

            # from analyst users
            client.login(
                username=self.auth_test.analyst.get("email"),
                password=self.auth_test.analyst.get("password"),
            )

            response = client.get("/networkscanners/list_scans/")
            self.assertEqual(response.status_code, 200)
            self.assertTemplateUsed(response, "networkscanners/scans/list_scans.html")

            # from viewers users
            client.login(
                username=self.auth_test.viewer.get("email"),
                password=self.auth_test.viewer.get("password"),
            )

            response = client.get("/networkscanners/list_scans/")
            self.assertEqual(response.status_code, 200)
            self.assertTemplateUsed(response, "networkscanners/scans/list_scans.html")

        # mark false positive and close using analyst account
        client.login(
            username=self.auth_test.analyst.get("email"),
            password=self.auth_test.analyst.get("password"),
        )

        # mark vulnerability as closed and false positive using analyst account
        response = client.post("/networkscanners/vuln_mark/", data=data)
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(
            response,
            "/networkscanners/list_vuln_info/"
            + "?scan_id=%s&ip=%s&scanner=%s" % (scan_id, ip, "Openvas")
        )

        # mark false positive and close using viewer account
        client.login(
            username=self.auth_test.viewer.get("email"),
            password=self.auth_test.viewer.get("password"),
        )

        # mark vulnerability as closed and false positive using viewer account
        response = client.post("/networkscanners/vuln_mark/", data=data)
        self.assertEqual(response.status_code, 403)

    def test_network_scan_details(self):
        client = Client()

        # from admin users
        client.login(
            username=self.auth_test.admin.get("email"),
            password=self.auth_test.admin.get("password"),
        )

        client.post(
            "/projects/project_create/",
            data={"project_name": "name", "project_disc": "disc"},
        )
        project_id = (
            ProjectDb.objects.filter(project_name="name").values("uu_id").get()["uu_id"]
        )

        file_path = "https://raw.githubusercontent.com/archerysec/report-sample/main/Openvas/openvas.xml"

        response = requests.get(file_path)

        file_n = SimpleUploadedFile(
            name="test.xml",
            content=response.text.encode(),
            content_type="multipart/form-data",
        )

        data = {
            "scanner": "openvas",
            "file": file_n,
            "target": "http://test.com",
            "project_id": str(project_id),
        }
        # upload one sample report
        client.post("/report-upload/upload/", data=data)

        # get scan_id form network scans db
        scan_id = (
            NetworkScanDb.objects.filter().values("scan_id").get()["scan_id"]
        )

        vuln_info = NetworkScanResultsDb.objects.filter(scan_id=scan_id)
        vuln_id = ""
        for vuln in vuln_info:
            vuln_id = vuln.vuln_id

        response = client.get("/networkscanners/scan_details/?vuln_id=%s&scanner=%s" % (vuln_id, "Openvas"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "networkscanners/scans/vuln_details.html")

        # from analyst users
        client.login(
            username=self.auth_test.analyst.get("email"),
            password=self.auth_test.analyst.get("password"),
        )

        response = client.get("/networkscanners/scan_details/?vuln_id=%s&scanner=%s" % (vuln_id, "Openvas"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "networkscanners/scans/vuln_details.html")

        # from viewer users
        client.login(
            username=self.auth_test.analyst.get("email"),
            password=self.auth_test.analyst.get("password"),
        )

        response = client.get("/networkscanners/scan_details/?vuln_id=%s&scanner=%s" % (vuln_id, "Openvas"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "networkscanners/scans/vuln_details.html")

    def test_network_scan_delete(self):
        client = Client()

        # from admin users
        client.login(
            username=self.auth_test.admin.get("email"),
            password=self.auth_test.admin.get("password"),
        )

        client.post(
            "/projects/project_create/",
            data={"project_name": "name", "project_disc": "disc"},
        )
        project_id = (
            ProjectDb.objects.filter(project_name="name").values("uu_id").get()["uu_id"]
        )

        file_path = "https://raw.githubusercontent.com/archerysec/report-sample/main/Openvas/openvas.xml"

        response = requests.get(file_path)

        file_n = SimpleUploadedFile(
            name="test.xml",
            content=response.text.encode(),
            content_type="multipart/form-data",
        )

        data = {
            "scanner": "openvas",
            "file": file_n,
            "target": "http://test.com",
            "project_id": str(project_id),
        }
        # upload one sample report
        client.post("/report-upload/upload/", data=data)

        # get scan_id form network scans db
        scan_id = (
            NetworkScanDb.objects.filter().values("scan_id").get()["scan_id"]
        )

        response = client.post("/networkscanners/scan_delete/", data={"scan_id": scan_id})
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, "/networkscanners/list_scans/")
        scan_id = NetworkScanDb.objects.filter(scan_id=scan_id).values()
        self.assertEqual(str(scan_id), "<QuerySet []>")

        # from analyst users
        client.login(
            username=self.auth_test.analyst.get("email"),
            password=self.auth_test.analyst.get("password"),
        )

        client.post(
            "/projects/project_create/",
            data={"project_name": "name", "project_disc": "disc"},
        )
        project_id = (
            ProjectDb.objects.filter(project_name="name").values("uu_id").get()["uu_id"]
        )

        file_path = "https://raw.githubusercontent.com/archerysec/report-sample/main/Openvas/openvas.xml"

        response = requests.get(file_path)

        file_n = SimpleUploadedFile(
            name="test.xml",
            content=response.text.encode(),
            content_type="multipart/form-data",
        )

        data = {
            "scanner": "openvas",
            "file": file_n,
            "target": "http://test.com",
            "project_id": str(project_id),
        }
        # upload one sample report
        client.post("/report-upload/upload/", data=data)

        scan_id = (
            NetworkScanDb.objects.filter().values("scan_id").get()["scan_id"]
        )

        response = client.post("/networkscanners/scan_delete/", data={"scan_id": scan_id})
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, "/networkscanners/list_scans/")
        scan_id = NetworkScanDb.objects.filter(scan_id=scan_id).values()
        self.assertEqual(str(scan_id), "<QuerySet []>")

        # from analyst users
        client.login(
            username=self.auth_test.viewer.get("email"),
            password=self.auth_test.viewer.get("password"),
        )

        response = client.post("/networkscanners/scan_delete/", data={"scan_id": scan_id})
        self.assertEqual(response.status_code, 403)

    def test_network_scan_vuln_delete(self):
        client = Client()

        # from admin users
        client.login(
            username=self.auth_test.admin.get("email"),
            password=self.auth_test.admin.get("password"),
        )

        client.post(
            "/projects/project_create/",
            data={"project_name": "name", "project_disc": "disc"},
        )
        project_id = (
            ProjectDb.objects.filter(project_name="name").values("uu_id").get()["uu_id"]
        )

        file_path = "https://raw.githubusercontent.com/archerysec/report-sample/main/Openvas/openvas.xml"

        response = requests.get(file_path)

        file_n = SimpleUploadedFile(
            name="test.xml",
            content=response.text.encode(),
            content_type="multipart/form-data",
        )

        data = {
            "scanner": "openvas",
            "file": file_n,
            "target": "http://test.com",
            "project_id": str(project_id),
        }
        # upload one sample report
        client.post("/report-upload/upload/", data=data)

        # get scan_id form network scans db
        scan_id = (
            NetworkScanDb.objects.filter().values("scan_id").get()["scan_id"]
        )

        vuln_info = NetworkScanResultsDb.objects.filter(scan_id=scan_id)
        vuln_id = ""
        for vuln in vuln_info:
            vuln_id = vuln.vuln_id

        response = client.post(
            "/networkscanners/vuln_delete/", data={"scan_id": scan_id, "vuln_id": vuln_id}
        )
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(
            response, "/networkscanners/list_scans/"
        )
        vuln_id = NetworkScanResultsDb.objects.filter(vuln_id=vuln_id).values()
        self.assertEqual(str(vuln_id), "<QuerySet []>")

        # from analyst users
        client.login(
            username=self.auth_test.analyst.get("email"),
            password=self.auth_test.analyst.get("password"),
        )

        # get scan_id form network scans db
        scan_id = (
            NetworkScanDb.objects.filter().values("scan_id").get()["scan_id"]
        )

        vuln_info = NetworkScanResultsDb.objects.filter(scan_id=scan_id)
        vuln_id = ""
        for vuln in vuln_info:
            vuln_id = vuln.vuln_id

        response = client.post(
            "/networkscanners/vuln_delete/", data={"scan_id": scan_id, "vuln_id": vuln_id}
        )
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(
            response, "/networkscanners/list_scans/"
        )
        vuln_id = NetworkScanResultsDb.objects.filter(vuln_id=vuln_id).values()
        self.assertEqual(str(vuln_id), "<QuerySet []>")

        # from analyst users
        client.login(
            username=self.auth_test.viewer.get("email"),
            password=self.auth_test.viewer.get("password"),
        )

        # get scan_id form network scans db
        scan_id = (
            NetworkScanDb.objects.filter().values("scan_id").get()["scan_id"]
        )

        vuln_info = NetworkScanResultsDb.objects.filter(scan_id=scan_id)
        vuln_id = ""
        for vuln in vuln_info:
            vuln_id = vuln.vuln_id

        response = client.post(
            "/networkscanners/vuln_delete/", data={"scan_id": scan_id, "vuln_id": vuln_id}
        )
        self.assertEqual(response.status_code, 403)