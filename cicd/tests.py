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
from cicd.models import *
from webscanners.models import *
from projects.models import *
import uuid

logging.disable(logging.CRITICAL)


class WebScanTest(TestCase):
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
    def test_cicd_scan_list(self):
        client = Client()

        # from admin users
        client.login(
            username=self.auth_test.admin.get("email"),
            password=self.auth_test.admin.get("password"),
        )

        response = client.get("/cicd/")
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "cicd/cicd_list.html")

        # from analyst users
        client.login(
            username=self.auth_test.analyst.get("email"),
            password=self.auth_test.analyst.get("password"),
        )

        response = client.get("/cicd/")
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "cicd/cicd_list.html")

        # from viewers users
        client.login(
            username=self.auth_test.viewer.get("email"),
            password=self.auth_test.viewer.get("password"),
        )

        response = client.get("/cicd/")
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "cicd/cicd_list.html")

    def test_create_policies(self):
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

        data = {
            "name": "name",
            "threshold": 'high',
            "threshold_count": "10",
            "scm_server": "github",
            "build_server": "jenkins",
            "target_name": "target_name",
            "scanner": "scanner",
            "command": "command",
            "cicd_id": uuid.uuid4(),
            "code_path": "code/path",
            "project_id": str(project_id),
        }

        response = client.post("/cicd/createpolicies/", data=data)
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, "/cicd/")

        # from analyst users
        client.login(
            username=self.auth_test.analyst.get("email"),
            password=self.auth_test.analyst.get("password"),
        )

        response = client.post("/cicd/createpolicies/", data=data)
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, "/cicd/")

        # from viewer users
        client.login(
            username=self.auth_test.viewer.get("email"),
            password=self.auth_test.viewer.get("password"),
        )

        response = client.post("/cicd/createpolicies/", data=data)
        self.assertEqual(response.status_code, 403)
