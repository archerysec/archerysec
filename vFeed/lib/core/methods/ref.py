#!/usr/bin/env python
# Copyright (C) 2017 vFeed IO
# This file is part of vFeed Correlated Vulnerability & Threat Database Python Wrapper  - https://vfeed.io
# See the file 'LICENSE' for copying permission.


import json

from vFeed.config.constants import osvdb_url, bid_url
from vFeed.lib.common.database import Database


class CveRef(object):
    def __init__(self, cve):
        self.cve = cve.upper()
        (self.cur, self.query) = Database(self.cve).db_init()
        self.data = Database(self.cve, self.cur, self.query).check_cve()

    def get_refs(self):
        """ CVE references method
        :return: JSON response with CVE References link and vendor
        """
        self.references = []

        self.cur.execute(
            'SELECT * FROM cve_reference WHERE cveid=?', self.query)

        for self.data in self.cur.fetchall():
            item = {"vendor": self.data[0], "url": self.data[1]}
            self.references.append(item)

        if len(self.references) != 0:
            return json.dumps(self.references, indent=2, sort_keys=True)
        else:
            return json.dumps(None)

    def get_scip(self):
        """ SCIP Method
        :return: JSON response with SCIP ID and link
        """
        self.scip = []
        self.cur.execute(
            'SELECT * FROM map_cve_scip WHERE cveid=?', self.query)

        for self.data in self.cur.fetchall():
            item = {"id": self.data[0], "url": self.data[1]}
            self.scip.append(item)

        if len(self.scip) != 0:
            return json.dumps(self.scip, indent=2, sort_keys=True)
        else:
            return json.dumps(None)

    def get_osvdb(self):
        """ OSVDB Open Sourced Vulnerability Database Method
        :return: JSON response with OSVDB ID and link
        """
        self.osvdb = []
        self.cur.execute(
            'SELECT * FROM map_cve_osvdb WHERE cveid=?', self.query)

        for self.data in self.cur.fetchall():
            item = {"id": self.data[0], "url": osvdb_url + str(self.data[0])}
            self.osvdb.append(item)

        if len(self.osvdb) != 0:
            return json.dumps(self.osvdb, indent=2, sort_keys=True)
        else:
            return json.dumps(None)

    def get_certvn(self):
        """ CERTVN Method
        :return: JSON response with CERTVN ID and link
        """
        self.certvn = []
        self.cur.execute(
            'SELECT * FROM map_cve_certvn WHERE cveid=?', self.query)

        for self.data in self.cur.fetchall():
            item = {"id": self.data[0], "url": self.data[1]}
            self.certvn.append(item)

        if len(self.certvn) != 0:
            return json.dumps(self.certvn, indent=2, sort_keys=True)
        else:
            return json.dumps(None)

    def get_iavm(self):
        """ IAVM Information Assurance Vulnerability Management Method
        :return: JSON response with IAVM ID, DISA key and title
        """
        self.iavm = []
        self.cur.execute(
            'SELECT * FROM map_cve_iavm WHERE cveid=?', self.query)

        for self.data in self.cur.fetchall():
            item = {"id": self.data[0], "key": self.data[1], "title": self.data[2]}
            self.iavm.append(item)

        if len(self.iavm) != 0:
            return json.dumps(self.iavm, indent=2, sort_keys=True)
        else:
            return json.dumps(None)

    def get_bid(self):
        """ BID SecurityFocus Method
        :return: JSON response with BID ID and link
        """
        self.bid = []
        self.cur.execute(
            'SELECT * FROM map_cve_bid WHERE cveid=?', self.query)

        for self.data in self.cur.fetchall():
            item = {"id": self.data[0], "url": bid_url + str(self.data[0])}
            self.bid.append(item)

        if len(self.bid) != 0:
            return json.dumps(self.bid, indent=2, sort_keys=True)
        else:
            return json.dumps(None)
