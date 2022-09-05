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
from django.contrib import messages
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import Client, TestCase

from authentication.tests import UserCreationTest
from compliance.models import *
from networkscanners.models import *
from projects.models import *
from staticscanners.models import *
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

    def upload_report_file(
        self, scanner, file_path, error_message, test_file_path, redirect_to, file_type
    ):
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

        response = requests.get(file_path)

        file_name = ""

        if file_type == "xml":
            file_name = "test.xml"
        if file_type == "json":
            file_name = "test.json"

        file_n = SimpleUploadedFile(
            name=file_name,
            content=response.text.encode(),
            content_type="multipart/form-data",
        )

        data = {
            "scanner": scanner,
            "file": file_n,
            "target": "http://test.com",
            "project_id": str(project_id),
        }
        # upload one sample report
        response = client.post("/report-upload/upload/", data=data)
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, redirect_to)

        # test from analyst users

        response = requests.get(file_path)

        file_name = ""

        if file_type == "xml":
            file_name = "test.xml"
        if file_type == "json":
            file_name = "test.json"

        file_n = SimpleUploadedFile(
            name=file_name,
            content=response.text.encode(),
            content_type="multipart/form-data",
        )

        data = {
            "scanner": scanner,
            "file": file_n,
            "target": "http://test.com",
            "project_id": str(project_id),
        }

        client.login(
            username=self.auth_test.analyst.get("email"),
            password=self.auth_test.analyst.get("password"),
        )
        response = client.post("/report-upload/upload/", data=data)
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, redirect_to)

        # test from viewers users

        response = requests.get(file_path)

        file_n = SimpleUploadedFile(
            name=file_name,
            content=response.text.encode(),
            content_type="multipart/form-data",
        )

        data = {
            "scanner": scanner,
            "file": file_n,
            "target": "http://test.com",
            "project_id": str(project_id),
        }

        client.login(
            username=self.auth_test.viewer.get("email"),
            password=self.auth_test.viewer.get("password"),
        )
        response = client.post("/report-upload/upload/", data=data)
        self.assertEqual(response.status_code, 403)

        # test for json file

        client.login(
            username=self.auth_test.analyst.get("email"),
            password=self.auth_test.analyst.get("password"),
        )

        response = requests.get(test_file_path)

        if file_type == "xml":
            file_name = "test.json"
        if file_type == "json":
            file_name = "test.xml"

        file_n = SimpleUploadedFile(
            name=file_name,
            content=response.text.encode(),
            content_type="multipart/form-data",
        )

        data = {
            "scanner": scanner,
            "file": file_n,
            "target": "http://test.com",
            "project_id": str(project_id),
        }
        # upload one sample report
        response = client.post("/report-upload/upload/", data=data, follow=True)
        # get message from context and check that expected text is there
        message = list(response.context.get("messages"))[0]
        self.assertEqual(message.tags, "alert-danger")
        self.assertTrue(error_message in message.message)

    def test_upload_zap_report_files(self):
        file_path = "https://raw.githubusercontent.com/archerysec/report-sample/main/OWASP-ZAP/OWASP-ZAP-v2.11.1.xml"
        test_file_path = "https://raw.githubusercontent.com/archerysec/report-sample/main/Bandit/bandit_report.json"
        scanner = "zap_scan"
        error_message = "ZAP Scanner Only XML file Support"
        redirect_to = "/webscanners/list_scans/"
        file_type = "xml"
        self.upload_report_file(
            scanner, file_path, error_message, test_file_path, redirect_to, file_type
        )

    def test_upload_burp_report_files(self):
        file_path = "https://raw.githubusercontent.com/archerysec/report-sample/main/Burp/Burp_Report.xml"
        test_file_path = "https://raw.githubusercontent.com/archerysec/report-sample/main/Bandit/bandit_report.json"
        scanner = "burp_scan"
        error_message = "Burp Scan Only XML file Support"
        redirect_to = "/webscanners/list_scans/"
        file_type = "xml"
        self.upload_report_file(
            scanner, file_path, error_message, test_file_path, redirect_to, file_type
        )

    def test_upload_arachni_report_files(self):
        file_path = "https://raw.githubusercontent.com/archerysec/report-sample/main/Arachni/Arachni_v1.3.xml"
        test_file_path = "https://raw.githubusercontent.com/archerysec/report-sample/main/Bandit/bandit_report.json"
        scanner = "arachni"
        error_message = "Arachni Only XML file Support"
        redirect_to = "/webscanners/list_scans/"
        file_type = "xml"
        self.upload_report_file(
            scanner, file_path, error_message, test_file_path, redirect_to, file_type
        )

    def test_upload_netsparker_report_files(self):
        file_path = "https://raw.githubusercontent.com/archerysec/report-sample/main/Netsparker/Netsparker_report.xml"
        test_file_path = "https://raw.githubusercontent.com/archerysec/report-sample/main/Bandit/bandit_report.json"
        scanner = "netsparker"
        error_message = "Netsparker Only XML file Support"
        redirect_to = "/webscanners/list_scans/"
        file_type = "xml"
        self.upload_report_file(
            scanner, file_path, error_message, test_file_path, redirect_to, file_type
        )

    def test_upload_webinspect_report_files(self):
        file_path = "https://raw.githubusercontent.com/archerysec/report-sample/main/Webinspect/Webinspect_v18.20.xml"
        test_file_path = "https://raw.githubusercontent.com/archerysec/report-sample/main/Bandit/bandit_report.json"
        scanner = "webinspect"
        error_message = "Webinspect Only XML file Support"
        redirect_to = "/webscanners/list_scans/"
        file_type = "xml"
        self.upload_report_file(
            scanner, file_path, error_message, test_file_path, redirect_to, file_type
        )

    def test_upload_acunetix_report_files(self):
        file_path = "https://raw.githubusercontent.com/archerysec/report-sample/main/Acunetix/Acunetix_report_sample.xml"
        test_file_path = "https://raw.githubusercontent.com/archerysec/report-sample/main/Bandit/bandit_report.json"
        scanner = "acunetix"
        error_message = "Acunetix Only XML file Support"
        redirect_to = "/webscanners/list_scans/"
        file_type = "xml"
        self.upload_report_file(
            scanner, file_path, error_message, test_file_path, redirect_to, file_type
        )

    def test_upload_dependencycheck_report_files(self):
        file_path = "https://raw.githubusercontent.com/archerysec/report-sample/main/Dependency-check/dependency-check-report_v5.2.1.xml"
        test_file_path = "https://raw.githubusercontent.com/archerysec/report-sample/main/Bandit/bandit_report.json"
        scanner = "dependencycheck"
        error_message = "Dependencycheck Only XML file Support"
        redirect_to = "/staticscanners/list_scans/"
        file_type = "xml"
        self.upload_report_file(
            scanner, file_path, error_message, test_file_path, redirect_to, file_type
        )

    def test_upload_checkmarx_report_files(self):
        file_path = "https://raw.githubusercontent.com/archerysec/report-sample/main/Checkmarx/Checkmarx_v8.9.0.210.xml"
        test_file_path = "https://raw.githubusercontent.com/archerysec/report-sample/main/Bandit/bandit_report.json"
        scanner = "checkmarx"
        error_message = "Checkmarx Only XML file Support"
        redirect_to = "/staticscanners/list_scans/"
        file_type = "xml"
        self.upload_report_file(
            scanner, file_path, error_message, test_file_path, redirect_to, file_type
        )

    def test_upload_findbugs_report_files(self):
        file_path = "https://raw.githubusercontent.com/archerysec/report-sample/main/Findbugs/findbugs_report_v3.1.5.xml"
        test_file_path = "https://raw.githubusercontent.com/archerysec/report-sample/main/Bandit/bandit_report.json"
        scanner = "findbugs"
        error_message = "Findbugs Only XML file Support"
        redirect_to = "/staticscanners/list_scans/"
        file_type = "xml"
        self.upload_report_file(
            scanner, file_path, error_message, test_file_path, redirect_to, file_type
        )

    def test_upload_bandit_scan_report_files(self):
        file_path = "https://raw.githubusercontent.com/archerysec/report-sample/main/Bandit/bandit_report.json"
        test_file_path = "https://raw.githubusercontent.com/archerysec/report-sample/main/Findbugs/findbugs_report_v3.1.5.xml"
        scanner = "bandit_scan"
        error_message = "Bandit Only JSON file Supported"
        redirect_to = "/staticscanners/list_scans/"
        file_type = "json"
        self.upload_report_file(
            scanner, file_path, error_message, test_file_path, redirect_to, file_type
        )

    def test_upload_clair_scan_report_files(self):
        file_path = "https://raw.githubusercontent.com/archerysec/report-sample/main/Clair/clair_output.json"
        test_file_path = "https://raw.githubusercontent.com/archerysec/report-sample/main/Findbugs/findbugs_report_v3.1.5.xml"
        scanner = "clair_scan"
        error_message = "Clair Only JSON file Supported"
        redirect_to = "/staticscanners/list_scans/"
        file_type = "json"
        self.upload_report_file(
            scanner, file_path, error_message, test_file_path, redirect_to, file_type
        )

    def test_upload_trivy_scan_report_files(self):
        file_path = "https://raw.githubusercontent.com/archerysec/report-sample/main/Trivy/trivy-all.json"
        test_file_path = "https://raw.githubusercontent.com/archerysec/report-sample/main/Findbugs/findbugs_report_v3.1.5.xml"
        scanner = "trivy_scan"
        error_message = "Trivy Only JSON file Supported"
        redirect_to = "/staticscanners/list_scans/"
        file_type = "json"
        self.upload_report_file(
            scanner, file_path, error_message, test_file_path, redirect_to, file_type
        )

    def test_upload_npmaudit_scan_report_files(self):
        file_path = "https://raw.githubusercontent.com/archerysec/report-sample/main/Npmaudit/npm_audit_report.json"
        test_file_path = "https://raw.githubusercontent.com/archerysec/report-sample/main/Findbugs/findbugs_report_v3.1.5.xml"
        scanner = "npmaudit_scan"
        error_message = "NPM Audit Only JSON file Supported"
        redirect_to = "/staticscanners/list_scans/"
        file_type = "json"
        self.upload_report_file(
            scanner, file_path, error_message, test_file_path, redirect_to, file_type
        )

    def test_upload_nodejsscan_scan_report_files(self):
        file_path = "https://raw.githubusercontent.com/archerysec/report-sample/main/Nodejsscan/nodejsscan_report.json"
        test_file_path = "https://raw.githubusercontent.com/archerysec/report-sample/main/Findbugs/findbugs_report_v3.1.5.xml"
        scanner = "nodejsscan_scan"
        error_message = "Nodejs scan Only JSON file Supported"
        redirect_to = "/staticscanners/list_scans/"
        file_type = "json"
        self.upload_report_file(
            scanner, file_path, error_message, test_file_path, redirect_to, file_type
        )

    def test_upload_semgrepscan_scan_report_files(self):
        file_path = "https://raw.githubusercontent.com/archerysec/report-sample/main/Semgrep/semgrep-WebGoat.json"
        test_file_path = "https://raw.githubusercontent.com/archerysec/report-sample/main/Findbugs/findbugs_report_v3.1.5.xml"
        scanner = "semgrepscan_scan"
        error_message = "Semgrep scan Only JSON file Supported"
        redirect_to = "/staticscanners/list_scans/"
        file_type = "json"
        self.upload_report_file(
            scanner, file_path, error_message, test_file_path, redirect_to, file_type
        )

    def test_upload_tfsec_scan_report_files(self):
        file_path = "https://raw.githubusercontent.com/archerysec/report-sample/main/tfsec/tfsec_report.json"
        test_file_path = "https://raw.githubusercontent.com/archerysec/report-sample/main/Findbugs/findbugs_report_v3.1.5.xml"
        scanner = "tfsec_scan"
        error_message = "Tfsec Only JSON file Supported"
        redirect_to = "/staticscanners/list_scans/"
        file_type = "json"
        self.upload_report_file(
            scanner, file_path, error_message, test_file_path, redirect_to, file_type
        )

    def test_upload_whitesource_scan_report_files(self):
        file_path = "https://raw.githubusercontent.com/archerysec/report-sample/main/Whitesource/whitesource-report.json"
        test_file_path = "https://raw.githubusercontent.com/archerysec/report-sample/main/Findbugs/findbugs_report_v3.1.5.xml"
        scanner = "whitesource_scan"
        error_message = "Whitesource Only JSON file Supported"
        redirect_to = "/staticscanners/list_scans/"
        file_type = "json"
        self.upload_report_file(
            scanner, file_path, error_message, test_file_path, redirect_to, file_type
        )

    def test_upload_inspec_scan_report_files(self):
        file_path = "https://raw.githubusercontent.com/archerysec/report-sample/main/Inspec/inspec_report.json"
        test_file_path = "https://raw.githubusercontent.com/archerysec/report-sample/main/Findbugs/findbugs_report_v3.1.5.xml"
        scanner = "inspec_scan"
        error_message = "Inspec Only JSON file Supported"
        redirect_to = "/inspec/inspec_list/"
        file_type = "json"
        self.upload_report_file(
            scanner, file_path, error_message, test_file_path, redirect_to, file_type
        )

    def test_upload_dockle_scan_report_files(self):
        file_path = "https://raw.githubusercontent.com/archerysec/report-sample/main/Dockle/dockle_report.json"
        test_file_path = "https://raw.githubusercontent.com/archerysec/report-sample/main/Findbugs/findbugs_report_v3.1.5.xml"
        scanner = "dockle_scan"
        error_message = "Dockle Only JSON file Supported"
        redirect_to = "/dockle/dockle_list/"
        file_type = "json"
        self.upload_report_file(
            scanner, file_path, error_message, test_file_path, redirect_to, file_type
        )

    def test_upload_gitlabsast_scan_report_files(self):
        file_path = "https://raw.githubusercontent.com/archerysec/report-sample/main/Gitlab/gl-sast-report.json"
        test_file_path = "https://raw.githubusercontent.com/archerysec/report-sample/main/Findbugs/findbugs_report_v3.1.5.xml"
        scanner = "gitlabsast_scan"
        error_message = "Gitlabsast Only JSON file Supported"
        redirect_to = "/staticscanners/list_scans/"
        file_type = "json"
        self.upload_report_file(
            scanner, file_path, error_message, test_file_path, redirect_to, file_type
        )

    def test_upload_gitlabcontainerscan_scan_report_files(self):
        file_path = "https://raw.githubusercontent.com/archerysec/report-sample/main/Gitlab/gl-container-scanning-report.json"
        test_file_path = "https://raw.githubusercontent.com/archerysec/report-sample/main/Findbugs/findbugs_report_v3.1.5.xml"
        scanner = "gitlabcontainerscan_scan"
        error_message = "Gitlabcontainerscan Only JSON file Supported"
        redirect_to = "/staticscanners/list_scans/"
        file_type = "json"
        self.upload_report_file(
            scanner, file_path, error_message, test_file_path, redirect_to, file_type
        )

    def test_upload_gitlabsca_scan_report_files(self):
        file_path = "https://raw.githubusercontent.com/archerysec/report-sample/main/Gitlab/gl-dependency-scanning-report.json"
        test_file_path = "https://raw.githubusercontent.com/archerysec/report-sample/main/Findbugs/findbugs_report_v3.1.5.xml"
        scanner = "gitlabsca_scan"
        error_message = "Gitlabsca Only JSON file Supported"
        redirect_to = "/staticscanners/list_scans/"
        file_type = "json"
        self.upload_report_file(
            scanner, file_path, error_message, test_file_path, redirect_to, file_type
        )

    def test_upload_twistlock_scan_report_files(self):
        file_path = "https://raw.githubusercontent.com/archerysec/report-sample/main/Twistlock/twistlock.json"
        test_file_path = "https://raw.githubusercontent.com/archerysec/report-sample/main/Findbugs/findbugs_report_v3.1.5.xml"
        scanner = "twistlock_scan"
        error_message = "Twistlock Only JSON file Supported"
        redirect_to = "/staticscanners/list_scans/"
        file_type = "json"
        self.upload_report_file(
            scanner, file_path, error_message, test_file_path, redirect_to, file_type
        )

    def test_upload_brakeman_scan_report_files(self):
        file_path = "https://raw.githubusercontent.com/archerysec/report-sample/main/Brakeman/brakeman_output.json"
        test_file_path = "https://raw.githubusercontent.com/archerysec/report-sample/main/Findbugs/findbugs_report_v3.1.5.xml"
        scanner = "brakeman_scan"
        error_message = "Brakeman Only JSON file Supported"
        redirect_to = "/staticscanners/list_scans/"
        file_type = "json"
        self.upload_report_file(
            scanner, file_path, error_message, test_file_path, redirect_to, file_type
        )

    def test_upload_openvas_report_files(self):
        file_path = "https://raw.githubusercontent.com/archerysec/report-sample/main/Openvas/openvas.xml"
        test_file_path = "https://raw.githubusercontent.com/archerysec/report-sample/main/Brakeman/brakeman_output.json"
        scanner = "openvas"
        error_message = "Openvas Only XML file Supported"
        redirect_to = "/networkscanners/list_scans/"
        file_type = "xml"
        self.upload_report_file(
            scanner, file_path, error_message, test_file_path, redirect_to, file_type
        )
