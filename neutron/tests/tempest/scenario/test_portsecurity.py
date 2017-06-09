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

from tempest.lib import decorators

from neutron.tests.tempest import config
from neutron.tests.tempest.scenario import base

CONF = config.CONF


class PortSecurityTest(base.BaseTempestTestCase):
    credentials = ['primary']
    required_extensions = ['port-security']

    @decorators.idempotent_id('61ab176e-d48b-42b7-b38a-1ba571ecc033')
    def test_port_security_removed_added(self):
        """Test connection works after port security has been removed

        Initial test that vm is accessible. Then port security is removed,
        checked connectivity. Port security is added back and checked
        connectivity again.
        """
        self.setup_network_and_server()
        self.check_connectivity(self.fip['floating_ip_address'],
                                CONF.validation.image_ssh_user,
                                self.keypair['private_key'])
        sec_group_id = self.security_groups[0]['id']

        self.port = self.update_port(port=self.port,
                                     port_security_enabled=False,
                                     security_groups=[])
        self.check_connectivity(self.fip['floating_ip_address'],
                                CONF.validation.image_ssh_user,
                                self.keypair['private_key'])

        self.port = self.update_port(port=self.port,
                                     port_security_enabled=True,
                                     security_groups=[sec_group_id])
        self.check_connectivity(self.fip['floating_ip_address'],
                                CONF.validation.image_ssh_user,
                                self.keypair['private_key'])
