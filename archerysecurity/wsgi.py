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

"""
WSGI config for archerysecurity project.

It exposes the WSGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/1.11/howto/deployment/wsgi/
"""

import os
import warnings

from django.core.wsgi import get_wsgi_application
from whitenoise import WhiteNoise

from archerysecurity.settings import base

warnings.filterwarnings("ignore", category=UserWarning, module="cffi")
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "archerysecurity.settings.base")

static = os.path.join(base.BASE_DIR, "static")
application = WhiteNoise(
    get_wsgi_application(), root="templates/static", prefix="static/"
)
