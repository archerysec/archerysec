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
from webscanners.models import *

logging.disable(logging.CRITICAL)


class UploadTest(TestCase):
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
    def test_file_upload_page(self):
        client = Client()

        # from admin users
        client.login(
            username=self.auth_test.admin.get("email"),
            password=self.auth_test.admin.get("password"),
        )

        response = client.get("/report-upload/upload/")
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "report_upload/upload.html")

        # from analyst users
        client.login(
            username=self.auth_test.analyst.get("email"),
            password=self.auth_test.analyst.get("password"),
        )

        response = client.get("/report-upload/upload/")
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "report_upload/upload.html")

        # from viewers users
        client.login(
            username=self.auth_test.viewer.get("email"),
            password=self.auth_test.viewer.get("password"),
        )

        response = client.get("/report-upload/upload/")
        self.assertEqual(response.status_code, 403)

    def test_upload_zap_report_files(self):
        client = Client()

        # from admin users
        client.login(
            username=self.auth_test.admin.get("email"),
            password=self.auth_test.admin.get("password"),
        )

        # Create project

        client.post(
            "/projects/project_create/",
            data={"project_name": "name", "project_disc": "disc"},
        )
        project_id = (
            ProjectDb.objects.filter(project_name="name").values("uu_id").get()["uu_id"]
        )

        file_path = "https://raw.githubusercontent.com/archerysec/report-sample/main/OWASP-ZAP/OWASP-ZAP-v2.7.0.xml"

        response = requests.get(file_path)

        file_n = SimpleUploadedFile(
            name="zap.xml",
            content=response.text.encode(),
            content_type="multipart/form-data",
        )

        data = {
            "scanner": "zap_scan",
            "file": file_n,
            "target": "http://test.com",
            "project_id": str(project_id),
        }
        # upload one sample report
        response = client.post("/report-upload/upload/", data=data)
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, "/webscanners/list_scans/")

        scan_id = (
            WebScansDb.objects.filter(scanner="Zap").values("scan_id").get()["scan_id"]
        )

        response = client.get("/webscanners/list_vuln/?scan_id=%s" % scan_id)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "webscanners/scans/list_vuln.html")
