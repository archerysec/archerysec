#!/usr/bin/env python
# Copyright (C) 2017 vFeed IO
# This file is part of vFeed Correlated Vulnerability & Threat Database Python Wrapper  - https://vfeed.io
# See the file 'LICENSE' for copying permission
# DO NOT DELETE OR MODIFY.

import os

current_dir = os.path.abspath(os.path.dirname(__file__))
root_dir = os.path.normpath(os.path.join(current_dir, ".."))
export_dir = os.path.normpath(os.path.join(root_dir, "export"))
db = "vfeed.db"
db_location = os.path.join(root_dir, db)

# vFeed database information
title = "vFeed - The Correlated Vulnerability and Threat Intelligence Database API"
author = "vFeed IO"
twitter = "@vfeed_io"
repository = "https://vfeed.io"
build = "0.7.2.1"

# Automated update Information
dropbox_dl  = " INSERT YOUR DB LINK HERE"
dropbox_cksum = " INSERT YOUR UPDATE FILE LINK HERE"

# Third party URLs
cve_url = "http://cve.mitre.org/cgi-bin/cvename.cgi?name="
cwe_url = "https://cwe.mitre.org/data/definitions/"
capec_url = "https://capec.mitre.org/data/definitions/"
osvdb_url = "http://www.osvdb.org/"
bid_url = "http://www.securityfocus.com/bid/"
ibm_url = "http://www-01.ibm.com/support/docview.wss?uid=swg1"
redhat_url = "https://rhn.redhat.com/errata/"
redhat_oval_url = "https://www.redhat.com/security/data/oval/com.redhat.rhsa-"
bugzilla_url = "https://bugzilla.redhat.com/show_bug.cgi?id="
debian_url = "https://security-tracker.debian.org/tracker/"
suse_url = "https://www.suse.com/security/cve/"
ubuntu_url = "http://www.ubuntu.com/usn/"
gentoo_url = "https://security.gentoo.org/glsa/"
fedora_url = "https://admin.fedoraproject.org/updates/"
mandriva_url = "http://www.mandriva.com/security/advisories?name="
vmware_url = "https://www.vmware.com/security/advisories/"
edb_url = "http://www.exploit-db.com/exploits/"
oval_url = "https://oval.cisecurity.org/repository/search/definition/"
nmap_url = "https://nmap.org/nsedoc/scripts/"
wasc_url = "http://projects.webappsec.org/"

# Migration to MongoDB
migration_dir = os.path.normpath(os.path.join(root_dir, "lib/migration"))
mongo_conf = os.path.join(migration_dir, "mongo.conf")
migration_script = os.path.join(migration_dir, "csvexports.sql")
csv_dir = os.path.join(root_dir, "csv_exports/")
