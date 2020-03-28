#!/usr/bin/env python
# Copyright (C) 2017 vFeed IO
# This file is part of vFeed Correlated Vulnerability & Threat Database Python Wrapper  - https://vfeed.io
# See the file 'LICENSE' for copying permission.
# Original code by Ushan89 https://github.com/ushan89/vFeed
# Modified to Class by NJ Ouchn

from __future__ import print_function

import os
import glob
import subprocess

from config.constants import csv_dir
from config.constants import mongo_conf
from config.constants import db_location
from config.constants import migration_dir
from config.constants import migration_script

class Migrate(object):
    def __init__(self):
        self.migration_dir = migration_dir
        self.mongo_conf = mongo_conf
        self.migration_script = migration_script
        self.db = db_location
        self.mongo_url = self.mongo_conf_read()
        self.csv_dir = csv_dir
        self.do_sqlite_to_csv()
        self.do_csv_to_mongo()

    def mongo_conf_read(self, ):
        """ read the mongo configuration file
        :return: the configuration server and port
        """
        with open(self.mongo_conf) as self.conf_reader:
            for line in self.conf_reader:
                if 'Mongo_Server' in line:
                    self.conf_line = str(line.split(' ')[1]).strip()
        return self.conf_line

    def do_sqlite_to_csv(self, ):
        """ read the vFeed.db and export entries to CSV
        :return: CSV files into csv_exports directory
        """
        print("[+] Starting Migration Process ....")
        self.migration_read = '.read ' + self.migration_script

        try:
            subprocess.check_call([
                'sqlite3',
                self.db,
                self.migration_read
            ])
        except OSError as e:
            if e.errno == os.errno.ENOENT:
                print("[Error] SQlite binary not found: install SQLite", e)
                raise
            else:
                raise

    def do_csv_to_mongo(self, ):
        """ read the csv files and populate the vFeed MongoDB
        :return: CSV files into csv_exports directory
        """
        self.mongo_host = self.mongo_url
        for csv_file in glob.glob(self.csv_dir + '*.csv'):
            self.table_name = csv_file.split('\\') if '\\' in csv_file else csv_file.split('/')
            self.table_name = self.table_name[len(self.table_name) - 1].replace('.csv', '')
            try:
                subprocess.check_call([
                    'mongoimport',
                    '--host',
                    self.mongo_host,
                    '-d',
                    'vFeed',
                    '-c',
                    self.table_name,
                    '--type',
                    'csv',
                    '--file',
                    csv_file,
                    '--headerline'
                ])
            except Exception as e:
                print("[Warning] Caught an exception", e)

            print (("[+] Imported collection: {} --> vFeed MongoDB".format(self.table_name)))
