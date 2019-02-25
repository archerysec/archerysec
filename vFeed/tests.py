#!/usr/bin/env python
# Copyright (C) 2017 vFeed IO
# This file is part of vFeed Correlated Vulnerability & Threat Database Python Wrapper  - https://vfeed.io
# See the file 'LICENSE' for copying permission.

from __future__ import print_function

import json
import sys
import os.path

from lib.core.methods import *
from lib.core.search import Search

cve = "CVE-2014-01333360"
print("Basic information of", cve)
info = CveInfo(cve).get_cve()
print(info)

cve = "CVE-2014-0160"
print("Basic information of", cve)
info = CveInfo(cve).get_cve()
print(info)

print("CWE information related to", cve)
cwe = CveInfo(cve).get_cwe()
print(cwe)

print("CPE information related to", cve)
cpe = CveInfo(cve).get_cpe()
print(cpe)
print("Total of CPEs found is:", len(json.loads(cpe)))

print("CVSS information related to", cve)
cvss = CveRisk(cve).get_cvss()
print(cvss)

cve = "CVE-2008-4250"
print("Risk information related to", cve)
print("Note that severity includes the CVSS v2 as well")
severity = CveRisk(cve).get_severity()
print(severity)

cve = "CVE-2015-0222"
print("Ubuntu patches related to", cve)
ubuntu = CvePatches(cve).get_ubuntu()
print(ubuntu)

cve = "CVE-2008-4250"
print("Nessus information related to", cve)
nessus = CveScanners(cve).get_nessus()
print(nessus)
print("Total of Nessus scripts found is:", len(json.loads(nessus)))

cve = "CVE-2006-6077"
print("OVAL information related to", cve)
oval = CveScanners(cve).get_oval()
print(oval)

cve = "CVE-2011-3402"
print("Metasploit information related to", cve)
metasploit = CveExploit(cve).get_msf()
print(metasploit)

cve = "CVE-2004-0990"
print("Snort information related to", cve)
snort = CveRules(cve).get_snort()
print(snort)

cve = "CVE-2004-0990"
print(ExportJson(cve).json_dump())

cve = "CVE-2004-0990"
print("Search for", cve)
print(Search(cve).cve())

cve = "CVE-2004-1231213233123312313"
print("Search for", cve)
print(Search(cve).cve())

cve = "CVE-AAAA-1_D233123312313"
print("Search for", cve)
print(Search(cve).cve())

cpe = "cpe:/a:invensys:foxboro"
print("Search for", cpe)
print(Search(cpe).cpe())

cpe = "cpe:/a:invensys:AZEAZZEAZEAZEEEAZZA"
print("Search for", cpe)
print(Search(cpe).cpe())

oval = "oval:org.mitre.oval:def:17538"
print("Search for", oval)
print(Search(oval).oval())

oval = "oval:org.mitre.oval:def:AAAAAAAAAA"
print("Search for", oval)
print(Search(oval).oval())

txt = "default cred"
print("Search for", txt)
print(Search(txt).text())

txt = "what are you talking about willis ?"
print("Search for", txt)
print(Search(txt).text())

from config.stats import Stats

Stats().get_stats()

from lib.core.update import Update

Update().update()

