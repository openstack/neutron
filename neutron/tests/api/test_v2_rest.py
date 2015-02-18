# Copyright 2014, Red Hat Inc.
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

"""
This module implements BaseNeutronClient for the Tempest rest client
and configures the api tests with scenarios targeting the Neutron API.
"""

from tempest import test as t_test
from tempest_lib import exceptions
import testscenarios

from neutron.tests.api import base_v2


# Required to generate tests from scenarios.  Not compatible with nose.
load_tests = testscenarios.load_tests_apply_scenarios


class TempestRestClient(base_v2.BaseNeutronClient):

    @property
    def client(self):
        if not hasattr(self, '_client'):
            manager = t_test.BaseTestCase.get_client_manager()
            self._client = manager.network_client
        return self._client

    @property
    def NotFound(self):
        return exceptions.NotFound

    def _cleanup_network(self, id_):
        try:
            self.delete_network(id_)
        except self.NotFound:
            pass

    def create_network(self, **kwargs):
        network = self._create_network(**kwargs)
        self.test_case.addCleanup(self._cleanup_network, network.id)
        return network

    def _create_network(self, **kwargs):
        # Internal method - use create_network() instead
        body = self.client.create_network(**kwargs)
        return base_v2.AttributeDict(body['network'])

    def update_network(self, id_, **kwargs):
        body = self.client.update_network(id_, **kwargs)
        return base_v2.AttributeDict(body['network'])

    def get_network(self, id_, **kwargs):
        body = self.client.show_network(id_, **kwargs)
        return base_v2.AttributeDict(body['network'])

    def get_networks(self, **kwargs):
        body = self.client.list_networks(**kwargs)
        return [base_v2.AttributeDict(x) for x in body['networks']]

    def delete_network(self, id_):
        self.client.delete_network(id_)


class TestApiWithRestClient(base_v2.BaseTestApi):
    scenarios = [('tempest', {'client': TempestRestClient()})]
