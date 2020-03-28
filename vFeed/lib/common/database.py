#!/usr/bin/env python
# Copyright (C) 2017 vFeed IO
# This file is part of vFeed Correlated Vulnerability & Threat Database Python Wrapper  - https://vfeed.io
# See the file 'LICENSE' for copying permission.

import sqlite3

from vFeed.config.constants import db
from vFeed.lib.common.utils import check_env


class Database(object):
    def __init__(self, identifier, cursor="", query=""):
        self.identifier = identifier
        self.cur = cursor
        self.query = query
        self.db = db
        self.db_exist = check_env(self.db)

    def db_stats(self):
        try:
            self.conn = sqlite3.connect(self.db)
            self.cur = self.conn.cursor()
            return self.cur, self.conn
        except Exception as e:
            return"[error] something occurred while opening the database", e

    def db_init(self):
        try:
            self.conn = sqlite3.connect(self.db)
            self.cur = self.conn.cursor()
            self.query = (self.identifier,)
            return self.cur, self.query
        except Exception as e:
            return "[error] something occurred while opening the database", e

    def check_cve(self):
        try:
            self.cur.execute('SELECT * FROM nvd_db WHERE cveid=?', self.query)
            self.data = self.cur.fetchone()
            if self.data is None:
                return False
        except Exception as e:
            return "[error]:", e

        return self.data

