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

import os
from .base import *

INTERNAL_IPS = [
    '172.18.0.1',
    '127.0.0.1'
]

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': os.getenv("DB_NAME"),
        'USER': os.getenv("DB_USER"),
        'PASSWORD': os.getenv("DB_PASSWORD"),
        'HOST': os.getenv("DB_HOST"),
        'PORT': 5432,
    }
}

ADMINS = [
    ('admin', os.getenv('DJANGO_ADMIN_EMAIL', 'admin@example.com'))
]

EMAIL_HOST = os.getenv("EMAIL_HOST", "localhost")
EMAIL_PORT = os.getenv("EMAIL_PORT", 25)
EMAIL_SUBJECT_PREFIX = "[ArcherySec] "
