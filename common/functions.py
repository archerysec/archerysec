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

import time


def epoch_to_date(epoch):
    """
    INPUT: Integer epoch
    OUTPUT: Date in %Y-%m-%d %H:%M:%S format
    """

    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(epoch))


def current_epoch():
    """
    INPUT: None
    OUTPUT: Current epoch time
    """

    return int(time.time())
