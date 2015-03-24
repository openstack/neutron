# Licensed under the Apache License, Version 2.0 (the "License"); you
# may not use this file except in compliance with the License. You may
# obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied. See the License for the specific language governing
# permissions and limitations under the License.

"""
This module defines a client fixture that can be used to target a
deployed neutron daemon.  The potential for conflict between Tempest
configuration and Neutron configuration requires that
neutron.tests.tempest imports be isolated in this module for now.
"""

from tempest_lib import exceptions as tlib_exceptions

from neutron.tests import base
from neutron.tests.retargetable import client_fixtures
from neutron.tests.tempest import test as t_test


class RestClientFixture(client_fixtures.AbstractClientFixture):
    """Targets the Neutron API via REST."""

    @property
    def client(self):
        if not hasattr(self, '_client'):
            manager = t_test.BaseTestCase.get_client_manager()
            self._client = manager.network_client
        return self._client

    @property
    def NotFound(self):
        return tlib_exceptions.NotFound

    def _cleanup_network(self, id_):
        try:
            self.delete_network(id_)
        except self.NotFound:
            pass

    def create_network(self, **kwargs):
        network = self._create_network(**kwargs)
        self.addCleanup(self._cleanup_network, network.id)
        return network

    def _create_network(self, **kwargs):
        # Internal method - use create_network() instead
        body = self.client.create_network(**kwargs)
        return base.AttributeDict(body['network'])

    def update_network(self, id_, **kwargs):
        body = self.client.update_network(id_, **kwargs)
        return base.AttributeDict(body['network'])

    def get_network(self, id_, **kwargs):
        body = self.client.show_network(id_, **kwargs)
        return base.AttributeDict(body['network'])

    def get_networks(self, **kwargs):
        body = self.client.list_networks(**kwargs)
        return [base.AttributeDict(x) for x in body['networks']]

    def delete_network(self, id_):
        self.client.delete_network(id_)
