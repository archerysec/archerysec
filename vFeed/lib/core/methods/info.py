#!/usr/bin/env python
# Copyright (C) 2017 vFeed IO
# This file is part of vFeed Correlated Vulnerability & Threat Database Python Wrapper  - https://vfeed.io
# See the file 'LICENSE' for copying permission.

import json

from vFeed.lib.common.database import Database
from vFeed.config.constants import cve_url, cwe_url, capec_url, wasc_url


class CveInfo(object):
    def __init__(self, cve):
        self.cve = cve.upper()
        (self.cur, self.query) = Database(self.cve).db_init()
        self.data = Database(self.cve, self.cur, self.query).check_cve()

    def get_cve(self):
        """ CVE Basic Information method
             :return: JSON response with CVE published, modified, summary
            """
        self.info = []

        if self.data:
            item = {"id": self.cve, "published": self.data[1], "modified": self.data[2],
                    "summary": self.data[3], "url": cve_url + self.cve}
            self.info.append(item)
        else:
            self.info = None

        return json.dumps(self.info, indent=2)

    def get_cwe(self):
        """ CWE method
        Returning:  JSON response with CWE id and title
        """
        self.cwe = []
        self.cur.execute('SELECT * FROM cve_cwe WHERE cveid=?', self.query)

        for self.data in self.cur.fetchall():
            self.cwe_id = self.data[0]
            query2 = (self.cwe_id,)
            self.cur.execute('SELECT * FROM cwe_db WHERE cweid=?', query2)

            for self.data2 in self.cur.fetchall():
                item = {"id": self.data2[0], "title": self.data2[1],
                        "url": cwe_url + str(self.data2[0]).replace("CWE-", "") + ".html"}
                self.cwe.append(item)

        if len(self.cwe) != 0:
            return json.dumps(self.cwe, indent=2, sort_keys=True)
        else:
            return json.dumps(None)

    def get_capec(self):
        """ Capec method
        Returning:  JSON response with CAPEC id, title, URL and Methods of Attack
        """
        self.cwe = self.get_cwe()
        self.capec = []
        cwe_json = json.loads(self.cwe)

        if cwe_json is None:
            return json.dumps(None)

        for cwe in cwe_json:
            query2 = (cwe.get("id"),)
            self.cur.execute('SELECT * FROM cwe_capec WHERE cweid=?', query2)
            for self.data2 in self.cur.fetchall():
                self.capec_id = self.data2[0].strip()
                self.cur.execute("select capectitle from capec_db where capecid='%s' " % self.capec_id)
                self.capec_title = self.cur.fetchone()
                self.cur.execute("select attack from capec_db where capecid='%s' " % self.capec_id)
                self.capec_attack = self.cur.fetchall()
                self.cur.execute("select mitigation from capec_mit where capecid='%s' " % self.capec_id)
                self.capec_mitigation = self.cur.fetchall()

                item = {"id": self.capec_id, "attack_method": self.capec_attack, "title": str(self.capec_title[0]),
                        "url": capec_url + self.capec_id + ".html", "mitigations": self.capec_mitigation}
                self.capec.append(item)

        if len(self.capec) != 0:
            return json.dumps(self.capec, indent=2, sort_keys=True)
        else:
            return json.dumps(None)

    def get_category(self):
        """ CWE Weaknesses Categories method (as Top 2011, CERT C++, Top 25, OWASP ....)
        Returning:  JSON response with Category id and title
        """
        self.category = []
        self.cwe = self.get_cwe()
        cwe_json = json.loads(self.cwe)

        if cwe_json is None:
            return json.dumps(None)

        if self.cwe:
            for cwe in cwe_json:
                query2 = (cwe.get("id"),)
                self.cur.execute('SELECT * FROM cwe_category WHERE cweid=?', query2)

                for self.data2 in self.cur.fetchall():
                    item = {"id": self.data2[0],
                            "title": self.data2[1], "url": cwe_url + str(self.data2[0]).replace("CWE-", "") + ".html"}
                    self.category.append(item)

        if len(self.category) != 0:
            return json.dumps(self.category, indent=2, sort_keys=True)
        else:
            return json.dumps(None)

    def get_cpe(self):
        """ CPE method
        Returning:  JSON response with CPE id
        """
        self.cpe = []
        self.cur.execute('SELECT * FROM cve_cpe WHERE cveid=?', self.query)

        for self.data in self.cur.fetchall():
            item = {"id": self.data[0]}
            self.cpe.append(item)

        if len(self.cpe) != 0:
            return json.dumps(self.cpe, indent=2, sort_keys=True)
        else:
            return json.dumps(None)

    def get_wasc(self):
        """ WASC Web Application Security Consortium Method
        :return: JSON response with WASC ID and title.
        """
        self.cwe = self.get_cwe()
        self.wasc = []
        cwe_json = json.loads(self.cwe)

        if cwe_json is None:
            return json.dumps(None)

        if self.cwe:
            for cwe in cwe_json:
                query2 = (cwe.get("id"),)
                self.cur.execute('SELECT * FROM cwe_wasc WHERE cweid=?', query2)

                for self.data2 in self.cur.fetchall():
                    self.wasc_id = self.data2[1].strip()
                    self.wasc_title = self.data2[0].rstrip().title()

                    item = {"id": self.wasc_id,
                            "title": self.wasc_title, "url": wasc_url + self.wasc_title.replace(" ", "-")}
                    self.wasc.append(item)

        if len(self.wasc) != 0:
            return json.dumps(self.wasc, indent=2, sort_keys=True)
        else:
            return json.dumps(None)
