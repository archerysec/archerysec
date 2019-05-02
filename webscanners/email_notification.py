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

from django.core.mail import send_mail
import json
import os

api_key_path = os.getcwd() + '/' + 'apidata.json'

email_subject = []
email_from = []
to_email = []


def email_notify():
    global email_subject, email_from, to_email
    try:
        with open(api_key_path, 'r+') as f:
            data = json.load(f)
            email_subject = data['email_subject']
            email_from = data['from_email']
            to_email = data['to_email']
    except Exception as e:
        print(e)

    send_mail(
        email_subject,
        'Your burp scan has been completed !!! Vulnerability found: Total: ',
        email_from,
        [to_email],
        fail_silently=False,
    )
