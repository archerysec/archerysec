vFeed The Correlated Vulnerability and Threat Intelligence Database Wrapper
=======================================================================
![vFeed](https://vfeed.io/wp-content/uploads/2016/08/logo_new-e1472658851686.png)

[![Build Status](https://travis-ci.org/toolswatch/vFeed.svg?branch=master)](https://travis-ci.org/toolswatch/vFeed)
[![Code Health](https://landscape.io/github/toolswatch/vFeed/master/landscape.svg?style=flat)](https://landscape.io/github/toolswatch/vFeed/master)
[![Compatibility](https://img.shields.io/badge/CWE-Compatible-yellow.svg)](http://cwe.mitre.org/compatible/organizations.html#ToolsWatch)
[![Compatibility](https://img.shields.io/badge/CVE-Compatible-yellow.svg)](https://cve.mitre.org/compatible/compatible.html#ToolsWatch)
[![Compatibility](https://img.shields.io/badge/OVAL-Compatible-yellow.svg)](http://oval.mitre.org/adoption/participants.html#ToolsWatch)

**vFeed Python Wrapper / Database** is a CVE, CWE, and OVAL Compatible naming scheme concept that provides extra structured detailed third-party references and technical characteristics for a CVE entry through an extensible XML/JSON schema.
It also improves the reliability of CVEs by providing a flexible and comprehensive vocabulary for describing the relationship with other standards and security references.

vFeed API generates a JSON-based format outputs to describe in detail vulnerabilities. 
It can be leveraged as input by security researchers, practitioners, and tools as part of their vulnerability description. The standard syntax is easy to interpret by humans and systems.

The mandatory associated **vFeed DB (The Correlated Vulnerability and Threat Intelligence Database)** is a detective and preventive security information repository used for gathering vulnerability and mitigation data from scattered internet sources into an unified database. The vFeed DB must be obtained directly from [vFeed IO](https://vfeed.io).

* Open security standards:
    * [CVE](http://cve.mitre.org)
    * [CWE](http://cwe.mitre.org)
    * [CPE](http://cpe.mitre.org) 
    * [OVAL](http://oval.mitre.org) 
    * [CAPEC](http://capec.mitre.org) 
    * [CVSS](http://www.first.org/cvss)
    * [WASC](http://projects.webappsec.org/w/page/13246978/Threat%20Classification)

* Vulnerability Assessment & Exploitation IDs (Metasploit, SAINT Corporation, Tenable's Nessus Plugin IDs, Nmap, Exploit-DB)
* Vendors Security Alerts:
    * Microsoft MS
    * Mandriva
    * Redhat
    * Cisco
    * Sun
    * Gentoo
    * Ubuntu
    * And more ...


Key features
=================

* Registered as CVE, CWE, and OVAL Compatible by the Mitre Corporation
* Support Open Standards such as CVE, CPE, CWE, CAPEC, WASC, CVSS and more
* Downloadable as SQLite database
* Support correlation with 3rd-party security references IAVA, OVAL and more
* Support correlation with security assessment and patch vendors (Nessus, Exploit-DB, Redhat, Microsoft..)
* Easy and ready-to-use python Wrapper

More features at [vFeed IO](https://vfeed.io/features/).

Target Audience
=================

* Penetration testers who want to analyze CVEs and gather extra information to help shape avenues to exploit vulnerabilities.
* Security auditors who want to report accurate information about findings. vFeed could be the best way to describe a CVE with attributes based on standards and 3rd party references as vendors or companies involved into standarization efforts.
* Security tools vendors / security open source developers who need to implement libraries to enumerate useful information about CVEs without wasting time to correlate and to create a proprietary database. vFeed is by far the best solution. Methods can be invoked from programs or scripts with a simple call.
* Any security hacker who is conducting research and needs a very fast and accurate way to enumerate available exploits or techniques to check a vulnerability.


How to ?
==============

Run `vfeedcli.py -h` for help.
Refer to the [Documentation](https://vfeed.io/docs) official documentation page.
 

Latest release
==============

0.7.2.1
-----
* [Fix] Fixed Migrate() module (SQLite to MongoDB). Thanks to Thiago Palmeira from Infolink for reporting the bug.

0.7.2
-----
* Added support to CAPEC v2.10. Check [the full changelog](http://capec.mitre.org/data/reports/diff_reports/v2.9_v2.10.html).
* Added support to CWE v2.11. Check [the full changelog](http://cwe.mitre.org/data/reports/diff_reports/v2.10_v2.11.html).
* Added support to the new [Microsoft security update](https://portal.msrc.microsoft.com/en-us/security-guidance)
* [Improve] Improved the `get_ms` method to returns both all and new Microsoft bulletins and KBs.
* [Improve] Fixed issue #65. Cleaned the database from **Reject** entries.
* [Doc] [Documentation](https://vfeed.io/docs) updated to reflect the new changes.
_All changes are immediate for consultancy / integrator license customers. The CE database will be available by the end of the month_

0.7.1
-----
* [New] Reactivated the ability to automate the download process for Consultancy / Integrator plans using private Dropbox repository.
* [Improve] Improved the `mongo.py` to check whether SQLite exists. Thanks to Alex Faraino (https://github.com/AlexFaraino/vFeed)
* [Fix] Modified vfeedcli from API to wrapper.
* [Doc] [Documentation](https://vfeed.io/docs) updated to reflect the new changes.
