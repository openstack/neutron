# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2010-2011 ????
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
#    @author: Salvatore Orlando, Citrix Systems

""" Module containing unit tests for Quantum 
    command line interface
    
"""


import logging
import stubout
import sys
import unittest

from quantum import api as server
from quantum import cli
from quantum.client import Client
from quantum.db import api as db
from tests.unit.client_tools import stubs as client_stubs

LOG = logging.getLogger('quantum.tests.test_cli')

class CLITest(unittest.TestCase):

    def setUp(self):
        """Prepare the test environment"""
        options = {}
        options['plugin_provider'] = 'quantum.plugins.SamplePlugin.FakePlugin'
        self.api = server.APIRouterV01(options)
        #self.client = Client("host", "port", False,
        #                args[0], FORMAT)

        self.tenant_id = "test_tenant"
        self.network_name_1 = "test_network_1"
        self.network_name_2 = "test_network_2"
        # Stubout do_request
        self.stubs = stubout.StubOutForTesting()
        client_stubs.stubout_send_request(self.stubs, self.api)
        # Redirect stdout
        # Pre-populate data
        pass
    
    def tearDown(self):
        """Clear the test environment"""
        db.clear_db()
        
    def test_list_networks_api(self):
        cli.api_list_nets(client)
        pass
