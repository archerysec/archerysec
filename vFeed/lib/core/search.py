#!/usr/bin/env python
# Copyright (C) 2017 vFeed IO
# This file is part of vFeed Correlated Vulnerability & Threat Database Python Wrapper  - https://vfeed.io
# See the file 'LICENSE' for copying permission.

import json

from vFeed.config.constants import db
from vFeed.lib.core.methods import CveExploit
from vFeed.lib.common.database import Database


class Search(object):
    def __init__(self, query):
        self.query = query
        self.db = db
        self.res = []

    def cve(self):
        """ Simple method to search for CVE occurrences
        :return: CVE summary and msf, edb when available
        """
        self.cve_id = self.query.upper()
        (self.cur, self.query) = Database(self.cve_id).db_init()
        self.data = Database(self.cve, self.cur, self.query).check_cve()
        self.cur.execute("SELECT * from nvd_db where cveid=?", (self.cve_id,))
        self.cve_data = self.cur.fetchall()

        if self.cve_data:
            item = {"id": self.cve_id, "published": self.data[1], "modified": self.data[2],
                    "summary": self.data[3],
                    "exploits": {"metasploit": self.check_msf(self.cve_id), "exploitdb": self.check_edb(self.cve_id)}}
            self.res.append(item)
        else:
            self.res = None

        return json.dumps(self.res, indent=2)

    def cpe(self):
        """
        Simple method to search for CPEs
        :return: CVEs and msf exploits when available
        """
        self.cpe = self.query.lower()
        (self.cur, self.query) = Database(self.cpe).db_init()

        self.cur.execute("SELECT count(distinct cpeid) from cve_cpe where cpeid like ?", ('%' + self.cpe + '%',))
        self.count_cpe = self.cur.fetchone()

        self.cur.execute("SELECT distinct cpeid from cve_cpe where cpeid like ? ORDER BY cpeid DESC",
                         ('%' + self.cpe + '%',))
        self.cpe_data = self.cur.fetchall()

        if self.cpe_data:
            for i in range(0, self.count_cpe[0]):
                self.cve_id = []
                self.exploit_msf = []
                self.cpe_id = self.cpe_data[i][0]
                self.cur.execute("SELECT cveid from cve_cpe where cpeid=?", (self.cpe_id,))
                self.cve_datas = self.cur.fetchall()

                for self.cve_data in self.cve_datas:
                    self.cve_id.append(self.cve_data[0])
                    self.exploit = self.check_msf(self.cve_data[0])
                    if self.exploit is not None:
                        self.exploit_msf.append(self.exploit)

                item = {self.cpe_id: {"exploits": {"metasploit": self.exploit_msf}, "vulnerability": self.cve_id}}
                self.res.append(item)

        else:
            self.res = None

        return json.dumps(self.res, indent=2)

    def cwe(self):
        """
        Simple method to search CWEs
        :return: CVEs related to CWE
        """
        self.cve_id = []
        self.cwe = self.query.upper()
        (self.cur, self.query) = Database(self.cwe).db_init()

        self.cur.execute("SELECT cveid from cve_cwe where cweid=? ORDER BY cveid DESC", (self.cwe,))
        self.cve_datas = self.cur.fetchall()

        if self.cve_datas:
            for self.cve_data in self.cve_datas:
                self.cve_id.append(self.cve_data[0])
            item = {self.cwe: {"vulnerability": self.cve_id}}
            self.res.append(item)
        else:
            self.res = None

        return json.dumps(self.res, indent=2)

    def oval(self):
        """
        Simple method to search OVAL
        :return: CVEs related to OVAL
        """
        self.cve_id = []
        self.oval = self.query.lower()
        (self.cur, self.query) = Database(self.oval).db_init()

        self.cur.execute("SELECT distinct ovalid from map_cve_oval where ovalid=? ", (self.oval,))
        self.oval_data = self.cur.fetchall()

        if self.oval_data:
            self.oval_id = self.oval_data[0][0]
            self.cur.execute("SELECT cveid from map_cve_oval where ovalid=?", (self.oval_id,))
            self.cve_datas = self.cur.fetchall()

            for self.cve_data in self.cve_datas:
                self.cve_id.append(self.cve_data[0])

            item = {self.oval_id: {"vulnerability": self.cve_id}}
            self.res.append(item)
        else:
            self.res = None

        return json.dumps(self.res, indent=2)

    def text(self):
        self.cve_id = []
        self.entry = self.query
        (self.cur, self.conn) = Database(None).db_init()

        self.cur.execute("SELECT * from nvd_db where summary like ? ORDER BY cveid DESC",
                         ('%' + self.entry + '%',))
        self.entry_data = self.cur.fetchall()

        if self.entry_data:
            for self.data in self.entry_data:
                self.cve_id.append(self.data[0] + " : " + self.data[3])

            item = {self.entry: {"vulnerability": self.cve_id}}
            self.res.append(item)
        else:
            self.res = None

        return json.dumps(self.res, indent=2)

    @staticmethod
    def check_msf(cve):
        msf = CveExploit(cve).get_msf()
        if msf is not "null":
            msf = json.loads(msf)
            return msf
        else:
            return None

    @staticmethod
    def check_edb(cve):
        edb = CveExploit(cve).get_edb()
        if edb is not "null":
            edb = json.loads(edb)
            return edb
        else:
            return None
