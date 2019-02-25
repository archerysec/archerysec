#!/usr/bin/env python
# Copyright (C) 2017 vFeed IO
# This file is part of vFeed Correlated Vulnerability & Threat Database Python Wrapper  - https://vfeed.io
# See the file 'LICENSE' for copying permission.

import json

from vFeed.lib.common.database import Database


class CveRules(object):
    def __init__(self, cve):
        self.cve = cve.upper()
        (self.cur, self.query) = Database(self.cve).db_init()
        self.data = Database(self.cve, self.cur, self.query).check_cve()

    def get_snort(self):
        """ Snort method
        :return: JSON response with Snort ID, signature and category
        """
        self.snort = []
        self.cur.execute('SELECT * FROM map_cve_snort WHERE cveid=?', self.query)

        for self.data in self.cur.fetchall():
            item = {"id": str(self.data[0]), 'signature': str(self.data[1]), 'category': str(self.data[2])}
            self.snort.append(item)

        if len(self.snort) != 0:
            return json.dumps(self.snort, indent=2, sort_keys=True)
        else:
            return json.dumps(None)

    def get_suricata(self):
        """ Suricata method
        :return: JSON response with Suricata ID, signature and category
        """
        self.suricata = []
        self.cur.execute('SELECT * FROM map_cve_suricata WHERE cveid=?', self.query)

        for self.data in self.cur.fetchall():
            item = {"id": str(self.data[0]), 'signature': str(self.data[1]), 'classtype': str(self.data[2])}
            self.suricata.append(item)

        if len(self.suricata) != 0:
            return json.dumps(self.suricata, indent=2, sort_keys=True)
        else:
            return json.dumps(None)
