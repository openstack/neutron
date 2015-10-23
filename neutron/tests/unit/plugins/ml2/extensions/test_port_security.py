# Copyright (c) 2015 OpenStack Foundation.
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

from neutron.extensions import portsecurity as psec
from neutron.plugins.ml2.extensions import port_security
from neutron.tests.unit.plugins.ml2 import test_plugin


class TestML2ExtensionPortSecurity(test_plugin.Ml2PluginV2TestCase):
    def test_extend_port_dict_no_port_security(self):
        """Test _extend_port_security_dict won't crash
        if port_security item is None
        """
        for db_data in ({'port_security': None, 'name': 'net1'}, {}):
            response_data = {}

            driver = port_security.PortSecurityExtensionDriver()
            driver._extend_port_security_dict(response_data, db_data)

            self.assertTrue(response_data[psec.PORTSECURITY])
