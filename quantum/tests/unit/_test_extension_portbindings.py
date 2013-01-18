# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 NEC Corporation
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
#
# @author: Akihiro Motoki, NEC Corporation
#

import contextlib

from quantum import context
from quantum.extensions import portbindings
from quantum.manager import QuantumManager
from quantum.openstack.common import cfg
from quantum.tests.unit import test_db_plugin


class PortBindingsTestCase(test_db_plugin.QuantumDbPluginV2TestCase):

    # VIF_TYPE must be overridden according to plugin vif_type
    VIF_TYPE = portbindings.VIF_TYPE_OTHER
    # The plugin supports the port security feature such as
    # security groups and anti spoofing.
    HAS_PORT_FILTER = False

    def _check_response_portbindings(self, port):
        self.assertEqual(port['binding:vif_type'], self.VIF_TYPE)
        port_cap = port[portbindings.CAPABILITIES]
        self.assertEqual(port_cap[portbindings.CAP_PORT_FILTER],
                         self.HAS_PORT_FILTER)

    def _check_response_no_portbindings(self, port):
        self.assertTrue('status' in port)
        self.assertFalse(portbindings.VIF_TYPE in port)
        self.assertFalse(portbindings.CAPABILITIES in port)

    def test_port_vif_details(self):
        plugin = QuantumManager.get_plugin()
        with self.port(name='name') as port:
            port_id = port['port']['id']
            # Check a response of create_port
            self._check_response_portbindings(port['port'])
            # Check a response of get_port
            ctx = context.get_admin_context()
            port = plugin.get_port(ctx, port_id)
            self._check_response_portbindings(port)
            # By default user is admin - now test non admin user
            ctx = context.Context(user_id=None,
                                  tenant_id=self._tenant_id,
                                  is_admin=False,
                                  read_deleted="no")
            non_admin_port = plugin.get_port(ctx, port_id)
            self._check_response_no_portbindings(non_admin_port)

    def test_ports_vif_details(self):
        plugin = QuantumManager.get_plugin()
        cfg.CONF.set_default('allow_overlapping_ips', True)
        with contextlib.nested(self.port(), self.port()):
            ctx = context.get_admin_context()
            ports = plugin.get_ports(ctx)
            self.assertEqual(len(ports), 2)
            for port in ports:
                self._check_response_portbindings(port)
            # By default user is admin - now test non admin user
            ctx = context.Context(user_id=None,
                                  tenant_id=self._tenant_id,
                                  is_admin=False,
                                  read_deleted="no")
            ports = plugin.get_ports(ctx)
            self.assertEqual(len(ports), 2)
            for non_admin_port in ports:
                self._check_response_no_portbindings(non_admin_port)
