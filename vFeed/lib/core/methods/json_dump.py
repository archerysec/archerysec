#!/usr/bin/env python
# Copyright (C) 2017 vFeed IO
# This file is part of vFeed Correlated Vulnerability & Threat Database Python Wrapper  - https://vfeed.io
# See the file 'LICENSE' for copying permission.

import json

from vFeed.config.constants import title, author, build, repository, twitter, db
from vFeed.lib.common.database import Database
from vFeed.lib.common.utils import check_env, move_export
from vFeed.lib.core.methods import *


class ExportJson(object):
    def __init__(self, cve):
        self.cve = cve.upper()
        self.db = db
        check_env(self.db)
        (self.cur, self.query) = Database(self.cve).db_init()
        self.data = Database(self.cve, self.cur, self.query).check_cve()
        self.vfeed_id = self.cve.replace('CVE', 'VFD')
        self.json_file = self.cve.replace('-', '_') + '.json'

    def json_dump(self):
        """ Snort method
        :return: JSON response with Snort ID, signature and category
        """
        # CVE basic information
        self.data = CveInfo(self.cve)
        cve_info = json.loads(self.data.get_cve())

        if cve_info is None:
            return False

        cpe = json.loads(self.data.get_cpe())
        cwe = json.loads(self.data.get_cwe())
        capec = json.loads(self.data.get_capec())
        category = json.loads(self.data.get_category())
        wasc = json.loads(self.data.get_wasc())

        # Reference information
        self.data = CveRef(self.cve)
        scip = json.loads(self.data.get_scip())
        osvdb = json.loads(self.data.get_osvdb())
        certvn = json.loads(self.data.get_certvn())
        bid = json.loads(self.data.get_bid())
        iavm = json.loads(self.data.get_iavm())
        refs = json.loads(self.data.get_refs())

        # Risk calculation
        self.data = CveRisk(self.cve)
        severity = json.loads(self.data.get_severity())

        # Patch Information
        self.data = CvePatches(self.cve)
        ms = json.loads(self.data.get_ms())
        aixapar = json.loads(self.data.get_aixapar())
        redhat = json.loads(self.data.get_redhat())
        debian = json.loads(self.data.get_debian())
        ubuntu = json.loads(self.data.get_ubuntu())
        suse = json.loads(self.data.get_suse())
        gentoo = json.loads(self.data.get_gentoo())
        fedora = json.loads(self.data.get_fedora())
        mandriva = json.loads(self.data.get_mandriva())
        vmware = json.loads(self.data.get_vmware())
        cisco = json.loads(self.data.get_cisco())
        hp = json.loads(self.data.get_hp())

        # Scanners Information
        self.data = CveScanners(self.cve)
        nessus = json.loads(self.data.get_nessus())
        openvas = json.loads(self.data.get_openvas())
        oval = json.loads(self.data.get_oval())
        nmap = json.loads(self.data.get_nmap())

        # Exploitation Information
        self.data = CveExploit(self.cve)
        msf = json.loads(self.data.get_msf())
        saint = json.loads(self.data.get_saint())
        edb = json.loads(self.data.get_edb())
        elliot = json.loads(self.data.get_d2())

        # Rules Information
        self.data = CveRules(self.cve)
        snort = json.loads(self.data.get_snort())
        suricata = json.loads(self.data.get_suricata())

        json_export = {
            "vFeed": {"id": self.vfeed_id, "author": author, "product": title, "wrapper": build, "url": repository,
                      'Contact': twitter},
            "information": {"cve": cve_info, "cpe": cpe, "cwe": cwe, "capec": capec, "category": category, "wasc": wasc},
            "references": {"scip": scip, "osvdb": osvdb, "certvn": certvn, "bid": bid, "iavm": iavm,
                           'other': {"links": refs}}, "risk": severity,
            "patches": {"microsoft": ms, "ibm": aixapar, "redhat": redhat, "debian": debian,
                        "ubuntu": ubuntu, "gentoo": gentoo, "suse": suse, "fedora": fedora,
                        "mandriva": mandriva, "vmware": vmware, "cisco": cisco, "hp": hp},
            "scanners": {"nessus": nessus, "openvas": openvas, "oval": oval, "nmap": nmap},
            "exploits": {"metasploit": msf, "saint": saint, "edb": edb, "elliot D2": elliot},
            "rules": {"snort": snort, "suricata": suricata}}

        move_export(json_export, self.json_file)
        return json.dumps(json_export, indent=2, sort_keys=True)
