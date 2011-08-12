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
import sys
import unittest

from quantum import api as server
from quantum import cli
from quantum.client import Client
from quantum.db import api as db
from quantum.manager import QuantumManager
from tests.unit.client_tools import stubs as client_stubs

LOG = logging.getLogger('quantum.tests.test_cli')
FORMAT = 'json'

class CLITest(unittest.TestCase):

    def setUp(self):
        """Prepare the test environment"""
        options = {}
        options['plugin_provider'] = 'quantum.plugins.SamplePlugin.FakePlugin'
        self.api = server.APIRouterV01(options)

        self.tenant_id = "test_tenant"
        self.network_name_1 = "test_network_1"
        self.network_name_2 = "test_network_2"
        # Prepare client and plugin manager
        self.client = Client(tenant = self.tenant_id, format = FORMAT,
                             testingStub = client_stubs.FakeHTTPConnection)
        self.manager = QuantumManager(options).get_plugin()
        # Redirect stdout
        self.fake_stdout = client_stubs.FakeStdout()
        sys.stdout = self.fake_stdout
    
    def tearDown(self):
        """Clear the test environment"""
        db.clear_db()
        sys.stdout = sys.__stdout__
        
    
    def _verify_list_networks(self):
            # Verification - get raw result from db
            nw_list = db.network_list(self.tenant_id)
            networks=[dict(id=nw.uuid, name=nw.name) for nw in nw_list]
            # Fill CLI template
            output = cli.prepare_output('list_nets', self.tenant_id,
                                        dict(networks=networks))
            # Verify!
            # Must add newline at the end to match effect of print call
            self.assertEquals(self.fake_stdout.make_string(), output + '\n')

    def _verify_create_network(self):
            # Verification - get raw result from db
            nw_list = db.network_list(self.tenant_id)
            if len(nw_list) != 1:
                self.fail("No network created")
            network_id = nw_list[0].uuid
            # Fill CLI template
            output = cli.prepare_output('create_net', self.tenant_id,
                                        dict(network_id=network_id))
            # Verify!
            # Must add newline at the end to match effect of print call
            self.assertEquals(self.fake_stdout.make_string(), output + '\n')
        
    def test_list_networks(self):
        try: 
            # Pre-populate data for testing using db api
            db.network_create(self.tenant_id, self.network_name_1)
            db.network_create(self.tenant_id, self.network_name_2)
            
            cli.list_nets(self.manager, self.tenant_id)
            LOG.debug("Operation completed. Verifying result")
            LOG.debug(self.fake_stdout.content)
            self._verify_list_networks()
        except: 
            LOG.exception("Exception caught: %s", sys.exc_info())
            self.fail("test_list_network failed due to an exception")

    
    def test_list_networks_api(self):
        try: 
            # Pre-populate data for testing using db api
            db.network_create(self.tenant_id, self.network_name_1)
            db.network_create(self.tenant_id, self.network_name_2)
            
            cli.api_list_nets(self.client, self.tenant_id)
            LOG.debug("Operation completed. Verifying result")
            LOG.debug(self.fake_stdout.content)
            self._verify_list_networks()  
        except: 
            LOG.exception("Exception caught: %s", sys.exc_info())
            self.fail("test_list_network_api failed due to an exception")

    def test_create_network(self):
        try: 
            cli.create_net(self.manager, self.tenant_id, "test")
            LOG.debug("Operation completed. Verifying result")
            LOG.debug(self.fake_stdout.content)
            self._verify_create_network()
        except: 
            LOG.exception("Exception caught: %s", sys.exc_info())
            self.fail("test_create_network failed due to an exception")

    
    def test_create_network_api(self):
        try: 
            cli.api_create_net(self.client, self.tenant_id, "test")
            LOG.debug("Operation completed. Verifying result")
            LOG.debug(self.fake_stdout.content)
            self._verify_create_network()  
        except: 
            LOG.exception("Exception caught: %s", sys.exc_info())
            self.fail("test_create_network_api failed due to an exception")
