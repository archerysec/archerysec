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

from django.test import Client, TestCase

from archerysettings.models import *
from authentication.tests import UserCreationTest
from projects.models import *

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
    def test_settings_page(self):
        client = Client()

        # from admin users
        client.login(
            username=self.auth_test.admin.get("email"),
            password=self.auth_test.admin.get("password"),
        )

        response = client.get("/settings/settings/")
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "setting/settings_page.html")

        # from analyst users
        client.login(
            username=self.auth_test.analyst.get("email"),
            password=self.auth_test.analyst.get("password"),
        )

        response = client.get("/settings/settings/")
        self.assertEqual(response.status_code, 403)

        # from viewer users
        client.login(
            username=self.auth_test.viewer.get("email"),
            password=self.auth_test.viewer.get("password"),
        )

        response = client.get("/settings/settings/")
        self.assertEqual(response.status_code, 403)

    def test_email_page(self):
        client = Client()

        # from admin users
        client.login(
            username=self.auth_test.admin.get("email"),
            password=self.auth_test.admin.get("password"),
        )

        response = client.get("/settings/email_setting/")
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "setting/email_setting_form.html")

        # from analyst users
        client.login(
            username=self.auth_test.analyst.get("email"),
            password=self.auth_test.analyst.get("password"),
        )

        response = client.get("/settings/email_setting/")
        self.assertEqual(response.status_code, 403)

        # from viwers users
        client.login(
            username=self.auth_test.viewer.get("email"),
            password=self.auth_test.viewer.get("password"),
        )

        response = client.get("/settings/email_setting/")
        self.assertEqual(response.status_code, 403)

    def test_add_email_setting(self):
        client = Client()

        # from admin users
        client.login(
            username=self.auth_test.admin.get("email"),
            password=self.auth_test.admin.get("password"),
        )

        data = {
            "email_message": "test",
            "email_subject": "test",
            "to_email": "to_email",
        }

        response = client.post("/settings/email_setting/", data=data)
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, "/settings/settings/")

        # from analyst users
        client.login(
            username=self.auth_test.analyst.get("email"),
            password=self.auth_test.analyst.get("password"),
        )

        data = {
            "email_subject": "email_subject",
            "email_message": "email_message",
            "to_email": "to_email",
        }
        response = client.post("/settings/email_setting/", data=data)
        self.assertEqual(response.status_code, 403)

        # from viewer users
        client.login(
            username=self.auth_test.viewer.get("email"),
            password=self.auth_test.viewer.get("password"),
        )

        data = {
            "email_subject": "email_subject",
            "email_message": "email_message",
            "to_email": "to_email",
        }
        response = client.post("/settings/email_setting/", data=data)
        self.assertEqual(response.status_code, 403)

        # delete analyst setting from analyst user
        client.login(
            username=self.auth_test.analyst.get("email"),
            password=self.auth_test.analyst.get("password"),
        )

        setting_id = (
            SettingsDb.objects.filter().values("setting_id").get()["setting_id"]
        )
        response = client.post(
            "/settings/del_setting/", data={"setting_id": setting_id}
        )
        self.assertEqual(response.status_code, 403)

        # delete analyst setting from viewer user
        client.login(
            username=self.auth_test.viewer.get("email"),
            password=self.auth_test.viewer.get("password"),
        )

        setting_id = (
            SettingsDb.objects.filter().values("setting_id").get()["setting_id"]
        )
        response = client.post(
            "/settings/del_setting/", data={"setting_id": setting_id}
        )
        self.assertEqual(response.status_code, 403)

        # delete email setting from admin user
        client.login(
            username=self.auth_test.admin.get("email"),
            password=self.auth_test.admin.get("password"),
        )

        setting_id = (
            SettingsDb.objects.filter().values("setting_id").get()["setting_id"]
        )
        response = client.post(
            "/settings/del_setting/", data={"setting_id": setting_id}
        )
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, "/settings/settings/")
