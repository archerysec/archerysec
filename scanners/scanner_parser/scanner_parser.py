# -*- coding: utf-8 -*-
#                    _
#     /\            | |
#    /  \   _ __ ___| |__   ___ _ __ _   _
#   / /\ \ | '__/ __| '_ \ / _ \ '__| | | |
#  / ____ \| | | (__| | | |  __/ |  | |_| |
# /_/    \_\_|  \___|_| |_|\___|_|   \__, |
#                                     __/ |
#                                    |___/
# Copyright (C) 2022 Anand Tiwari
#
# Email:   anandtiwarics@gmail.com
# Twitter: @anandtiwarics
#
# This file is part of ArcherySec Project.

from scanners.scanner_parser.cloud_scanner import (prisma_cloud_csv,
                                                   scoutsuite_js,
                                                   wiz_security_csv)
from scanners.scanner_parser.compliance_parser import (dockle_json_parser,
                                                       inspec_json_parser)
from scanners.scanner_parser.network_scanner import (Nessus_Parser,
                                                     OpenVas_Parser,
                                                     nmap_parser)
from scanners.scanner_parser.tools import nikto_htm_parser
from scanners.scanner_parser.web_scanner import (acunetix_xml_parser,
                                                 arachni_xml_parser,
                                                 burp_xml_parser,
                                                 netsparker_xml_parser,
                                                 webinspect_xml_parser,
                                                 zap_xml_parser)
from scanners.scanner_parser.staticscanner_parser import (bandit_report_parser,
                                                          brakeman_json_report_parser,
                                                          clair_json_report_parser,
                                                          checkmarx_xml_report_parser, dependencycheck_report_parser,
                                                          gitlab_container_json_report_parser,
                                                          gitlab_sast_json_report_parser,
                                                          gitlab_sca_json_report_parser,
                                                          findbugs_report_parser,
                                                          nodejsscan_report_json,
                                                          npm_audit_report_json,
                                                          retirejss_json_parser,
                                                          semgrep_json_report_parser,
                                                          tfsec_report_parser,
                                                          trivy_json_report_parser,
                                                          twistlock_json_report_parser,
                                                          whitesource_json_report_parser,
                                                          grype_report_json_parser)

ParserFunctionDict = {
    #
    # Use this format to add a new parser
    #
    # "parser_internal_code": {
    #     "displayName": "New Scanner",
    #     "dbtype": "TypeScans",
    #     "dbname": "New",  ---Do not define if not using a generic DB model---
    #     "type": "File Format",
    #     "parserFunction": new_parser.new_parser
    # }
    #
    "zap_scan": {
        "displayName": "ZAP Scanner",
        "dbtype": "WebScans",
        "dbname": "Zap",
        "type": "XML",
        "parserFunction": zap_xml_parser.xml_parser
    },
    "burp_scan": {
        "displayName": "Burp Scanner",
        "dbtype": "WebScans",
        "dbname": "Burp",
        "type": "XML",
        "parserFunction": burp_xml_parser.burp_scan_data
    },
    "arachni": {
        "displayName": "Arachni Scanner",
        "dbtype": "WebScans",
        "dbname": "Arachni",
        "type": "XML",
        "parserFunction": arachni_xml_parser.xml_parser
    },
    "netsparker": {
        "displayName": "Netsparker Scanner",
        "dbtype": "WebScans",
        "dbname": "Netsparker",
        "type": "XML",
        "parserFunction": netsparker_xml_parser.xml_parser
    },
    "webinspect": {
        "displayName": "Webinspect Scanner",
        "dbtype": "WebScans",
        "dbname": "Webinspect",
        "type": "XML",
        "parserFunction": webinspect_xml_parser.xml_parser
    },
    "acunetix": {
        "displayName": "Acutenix Scanner",
        "dbtype": "WebScans",
        "dbname": "Acutenix",
        "type": "XML",
        "parserFunction": acunetix_xml_parser.xml_parser
    },
    "dependencycheck": {
        "displayName": "Dependency Check",
        "dbtype": "StaticScans",
        "dbname": "Dependencycheck",
        "type": "LXML",
        "parserFunction": dependencycheck_report_parser.xml_parser
    },
    "checkmarx": {
        "displayName": "Checkmarx",
        "dbtype": "StaticScans",
        "dbname": "Checkmarx",
        "type": "XML",
        "parserFunction": checkmarx_xml_report_parser.checkmarx_report_xml
    },
    "findbugs": {
        "displayName": "FindBug",
        "dbtype": "StaticScans",
        "dbname": "Findbugs",
        "type": "XML",
        "parserFunction": findbugs_report_parser.findsecbug_report_xml
    },
    "nikto": {
        "displayName": "Nikto",
        "dbtype": "NiktoResult",
        "type": "XML",
        "parserFunction": nikto_htm_parser.nikto_html_parser
    },
    "bandit_scan": {
        "displayName": "Bandit Scanner",
        "dbtype": "StaticScans",
        "dbname": "Bandit",
        "type": "JSON",
        "parserFunction": bandit_report_parser.bandit_report_json
    },
    "retirejs_scan": {
        "displayName": "RetireJS Scanner",
        "dbtype": "StaticScans",
        "dbname": "Retirejs",
        "type": "JSON",
        "parserFunction": retirejss_json_parser.retirejs_report_json
    },
    "clair_scan": {
        "displayName": "Clair Scanner",
        "dbtype": "StaticScans",
        "dbname": "Clair",
        "type": "JSON",
        "parserFunction": clair_json_report_parser.clair_report_json
    },
    "trivy_scan": {
        "displayName": "Trivy Scanner",
        "dbtype": "StaticScans",
        "dbname": "Trivy",
        "type": "JSON",
        "parserFunction": trivy_json_report_parser.trivy_report_json
    },
    "npmaudit_scan": {
        "displayName": "npm-audit Scanner",
        "dbtype": "StaticScans",
        "dbname": "Npmaudit",
        "type": "JSON",
        "parserFunction": npm_audit_report_json.npmaudit_report_json
    },
    "nodejsscan_scan": {
        "displayName": "Nodejs Scanner",
        "dbtype": "StaticScans",
        "dbname": "Nodejsscan",
        "type": "JSON",
        "parserFunction": nodejsscan_report_json.nodejsscan_report_json
    },
    "semgrepscan_scan": {
        "displayName": "Semgrep Scanner",
        "dbtype": "StaticScans",
        "dbname": "Semgrep",
        "type": "JSON",
        "parserFunction": semgrep_json_report_parser.semgrep_report_json
    },
    "tfsec_scan": {
        "displayName": "tfsec Scanner",
        "dbtype": "StaticScans",
        "dbname": "Tfsec",
        "type": "JSON",
        "parserFunction": tfsec_report_parser.tfsec_report_json
    },
    "whitesource_scan": {
        "displayName": "Whitesource Scanner",
        "dbtype": "StaticScans",
        "dbname": "Whitesource",
        "type": "JSON",
        "parserFunction": whitesource_json_report_parser.whitesource_report_json
    },
    "inspec_scan": {
        "displayName": "Inspec Scanner",
        "dbtype": "InspecScan",
        "type": "JSON",
        "parserFunction": inspec_json_parser.inspec_report_json
    },

    "dockle_scan": {
        "displayName": "Dockle Scanner",
        "dbtype": "DockleScan",
        "type": "JSON",
        "parserFunction": dockle_json_parser.dockle_report_json
    },
    "gitlabsast_scan": {
        "displayName": "Gitlab SAST Scanner",
        "dbtype": "StaticScans",
        "dbname": "Gitlabsast",
        "type": "JSON",
        "parserFunction": gitlab_sast_json_report_parser.gitlabsast_report_json
    },
    "gitlabcontainerscan_scan": {
        "displayName": "Gitlab Container Scanner",
        "dbtype": "StaticScans",
        "dbname": "Gitlabcontainerscan",
        "type": "JSON",
        "parserFunction": gitlab_container_json_report_parser.gitlabcontainerscan_report_json
    },
    "gitlabsca_scan": {
        "displayName": "Gitlab Dependancy Scanner",
        "dbtype": "StaticScans",
        "dbname": "Gitlabsca",
        "type": "JSON",
        "parserFunction": gitlab_sca_json_report_parser.gitlabsca_report_json
    },
    "twistlock_scan": {
        "displayName": "twistlock Scanner",
        "dbtype": "StaticScans",
        "dbname": "Twistlock",
        "type": "JSON",
        "parserFunction": twistlock_json_report_parser.twistlock_report_json
    },
    "grype_scan": {
        "displayName": "grype Scanner",
        "dbtype": "StaticScans",
        "dbname": "grype_scan",
        "type": "JSON",
        "parserFunction": grype_report_json_parser.grype_report_json
    },
    "brakeman_scan": {
        "displayName": "brakeman Scanner",
        "dbtype": "StaticScans",
        "dbname": "Brakeman_scan",
        "type": "JSON",
        "parserFunction": brakeman_json_report_parser.brakeman_report_json
    },
    "openvas": {
        "displayName": "OpenVAS",
        "dbtype": "NetworkScan",
        "dbname": "Openvas",
        "type": "XML",
        "parserFunction": OpenVas_Parser.updated_xml_parser
    },
    "nessus": {
        "displayName": "Nessus",
        "dbtype": "Nessus",
        "type": "Nessus",
        "parserFunction": Nessus_Parser.updated_nessus_parser
    },
    "prisma_cspm": {
        "displayName": "prisma_cspm",
        "dbtype": "CloudScans",
        "dbname": "Prismacloud",
        "type": "CSV",
        "parserFunction": prisma_cloud_csv.prisma_cloud_report_csv
    },
    "wiz": {
        "displayName": "wiz",
        "dbtype": "CloudScans",
        "dbname": "wiz",
        "type": "CSV",
        "parserFunction": wiz_security_csv.wiz_cloud_report_csv
    },
    "scoutsuite": {
        "displayName": "scoutsuite",
        "dbtype": "CloudScans",
        "dbname": "scoutsuite",
        "type": "JS",
        "parserFunction": scoutsuite_js.scoutsuite_cloud_report_js
    }
}
