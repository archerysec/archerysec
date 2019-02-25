#!/usr/bin/env python
# Copyright (C) 2017 ToolsWatch.org
# This file is part of vFeed Correlated Vulnerability & Threat Database Python Wrapper  - https://vfeed.io
# See the file 'LICENSE' for copying permission.

from __future__ import print_function

import os
import sys
import urllib2
import tarfile

from vFeed.lib.common.utils import checksum
from vFeed.config.constants import db, dropbox_cksum, dropbox_dl


class Update(object):
    def __init__(self):
        self.db = db
        # It is important to add ?dl=1 to dropbox link as described https://www.dropbox.com/en/help/201
        self.db_status = dropbox_cksum + "?dl=1"
        self.remote_db = dropbox_dl + "?dl=1"
        self.check_drobpox_lnk()
        self.db_compressed = dropbox_dl.split('/')[-1].split("?dl=1")[0]
        self.db_update = dropbox_cksum.split('/')[-1].split("?dl=1")[0]

    def update(self):
        """
        Initiate the update process.
        :return:
        """

        try:
            if urllib2.urlopen(self.remote_db):
                if not os.path.isfile(self.db):
                    print("[+] New install. Download in progress ...")
                    self.download(self.remote_db, self.db_compressed)
                    print("\n[+] Installing %s " % self.db_compressed)
                    self.uncompress()
                    self.clean()
                    sys.exit(1)
                if os.path.isfile(self.db):
                    print("[+] Checking for the latest database build")
                    self.check_status()
        except urllib2.URLError as e:
            print("[!] Connection issue detected: ", e.reason)
            sys.exit()

    def download(self, url, filename):
        """
        This function was found in internet. So thanks to its author wherever he is.
        Just improve it a little by adding the percentage display
        :param filename:
        :param url:
        :return:
        """

        self.filename = filename
        self.u = urllib2.urlopen(url)
        self.f = open(self.filename, 'wb')
        self.meta = self.u.info()
        self.filesize = int(self.meta.getheaders("Content-Length")[0])
        self.filesize_dl = 0
        self.block_sz = 8192
        while True:
            sys.stdout.flush()
            self.buffer = self.u.read(self.block_sz)
            if not self.buffer:
                break

            self.filesize_dl += len(self.buffer)
            self.f.write(self.buffer)
            self.status = r"%10d [%3.0f %%]" % (self.filesize_dl, self.filesize_dl * 100. / self.filesize)
            self.status += chr(8) * (len(self.status) + 1)
            sys.stdout.write("\r[+] Receiving %d out of %s Bytes of %s (%3.0f %%)" % (
                self.filesize_dl, self.filesize, self.filename, self.filesize_dl * 100. / self.filesize))
            sys.stdout.flush()
        self.f.close()

    def uncompress(self):
        """

        :return:
        """

        if not os.path.isfile(self.db_compressed):
            print("[!] " + self.db_compressed + " not found")
            sys.exit()
        try:
            self.tar = tarfile.open(self.db_compressed, 'r:gz')
            self.tar.extractall('.')
        except Exception, e:
            print("[!] Database not extracted ", e)

    def check_status(self):
        """ Check the remote update status and
        update the existing vfeed database if needed
        """
        self.download(self.db_status, self.db_update)
        self.hashLocal = checksum(self.db)
        with open(self.db_update, 'r') as f:
            self.output = f.read()
            self.hashRemote = self.output.split(',')[1]

        if self.hashRemote != self.hashLocal:
            print("\n[+] New database build found. Download in progress ... ")
            self.download(self.remote_db, self.db_compressed)
            print("\n[+] Decompressing %s " % self.db_compressed)
            self.uncompress()

        if self.hashRemote == self.hashLocal:
            print("\n[+] You have the latest %s database" % self.db)

        self.clean()

    def clean(self):
        """ Clean the tgz, update.dat temporary file and move database to repository
        """
        print("[+] Cleaning the compressed database and update file")
        try:
            if os.path.isfile(self.db_compressed):
                os.remove(self.db_compressed)
            if os.path.isfile(self.db_update):
                os.remove(self.db_update)
        except Exception, e:
            print("[+] Already cleaned", e)

    def check_drobpox_lnk(self):
        """ Check whether the automated download is activated or not
        """
        if "dropbox" not in self.remote_db:
            print(" +++ Consultancy / Integrator Plans +++)")
            print("Please insert your private links as described in the documentation.\n")
            print(" +++ Community Edition Users +++")
            print("The vFeed CE must be downloaded from the official repository at https://vfeed.io")
            print("Once retrieved, it must be decompressed into the python wrapper repository.")
            sys.exit()
        return
