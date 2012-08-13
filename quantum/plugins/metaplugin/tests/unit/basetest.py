# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2012, Nachi Ueno, NTT MCL, Inc.
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import mox
import stubout
import unittest

import quantum.db.api as db
from quantum.db import models_v2
from quantum.plugins.metaplugin.tests.unit import utils


class BaseMetaTest(unittest.TestCase):
    """base test class for MetaPlugin unit tests"""
    def setUp(self):
        config = utils.get_config()
        options = {"sql_connection": config.get("DATABASE", "sql_connection")}
        options.update({'base': models_v2.model_base.BASEV2})
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
