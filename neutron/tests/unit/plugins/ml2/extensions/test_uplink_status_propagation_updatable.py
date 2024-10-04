# Copyright (c) 2024 Red Hat Inc.
# All rights reserved.
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

import ddt
from neutron_lib.api.definitions import uplink_status_propagation as usp_def
from neutron_lib.api.definitions import uplink_status_propagation_updatable \
    as uspu_def
from neutron_lib.plugins import directory
from oslo_config import cfg

from neutron.tests.unit.plugins.ml2 import test_plugin


@ddt.ddt
class UplinkStatusPropagationUpdatableML2ExtDriverTestCase(
        test_plugin.Ml2PluginV2TestCase):

    _extension_drivers = [usp_def.ALIAS.replace('-', '_'),
                          uspu_def.ALIAS.replace('-', '_')]

    def setUp(self):
        cfg.CONF.set_override('extension_drivers',
                              self._extension_drivers,
                              group='ml2')
        super().setUp()
        self.plugin = directory.get_plugin()

    @ddt.data(True, False)
    def test_port_update_propagate_uplink_status(self, _status):
        with self.network() as n:
            args = {'port': {'name': 'test',
                             'network_id': n['network']['id'],
                             'tenant_id': n['network']['id'],
                             'device_id': '',
                             'device_owner': '',
                             'fixed_ips': '',
                             'propagate_uplink_status': _status,
                             'admin_state_up': True,
                             'status': 'ACTIVE'}}
            try:
                port = self.plugin.create_port(self.context, args)
                args = {'port': {'propagate_uplink_status': not _status}}
                self.plugin.update_port(self.context, port['id'], args)
                port = self.plugin.get_port(self.context, port['id'])
                self.assertEqual(not _status, port['propagate_uplink_status'])
            finally:
                if port:
                    self.plugin.delete_port(self.context, port['id'])
