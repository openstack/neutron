# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2012 Isaku Yamahata <yamahata at private email ne jp>
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import mox
import stubout
import unittest

import quantum.db.api as db
import quantum.plugins.ryu.db.models    # for ryu specific tables
from quantum.plugins.ryu.tests.unit import utils


class BaseRyuTest(unittest.TestCase):
    """base test class for Ryu unit tests"""
    def setUp(self):
        config = utils.get_config()
        options = {"sql_connection": config.get("DATABASE", "sql_connection")}
        db.configure_db(options)

        self.config = config
        self.mox = mox.Mox()
        self.stubs = stubout.StubOutForTesting()

    def tearDown(self):
        self.mox.UnsetStubs()
        self.stubs.UnsetAll()
        self.stubs.SmartUnsetAll()
        self.mox.VerifyAll()
        db.clear_db()
