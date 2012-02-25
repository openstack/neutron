# Copyright 2012 Nicira Networks, Inc.
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
#
# @author: Brad Hall, Nicira Networks, Inc.

import logging
import unittest

from nicira_nvp_plugin.QuantumPlugin import NvpPlugin
from nicira_nvp_plugin import nvplib

logging.basicConfig(level=logging.DEBUG)
LOG = logging.getLogger("test_check")


class NvpTests(unittest.TestCase):
    def setUp(self):
        self.quantum = NvpPlugin()

    def tearDown(self):
        pass

    # These nvplib functions will throw an exception if the check fails
    def test_check_default_transport_zone(self):
        nvplib.check_default_transport_zone(self.quantum.controller)
