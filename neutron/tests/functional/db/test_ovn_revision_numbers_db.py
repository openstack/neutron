# Copyright 2020 Red Hat, Inc.
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

from neutron.common.ovn import constants as ovn_const
from neutron.tests.functional import base


class TestRevisionNumbers(base.TestOVNFunctionalBase):

    def _create_network(self, name):
        data = {'network': {'name': name, 'tenant_id': self._tenant_id}}
        req = self.new_create_request('networks', data, self.fmt)
        res = req.get_response(self.api)
        return self.deserialize(self.fmt, res)['network']

    def _update_network_name(self, net_id, new_name):
        data = {'network': {'name': new_name}}
        req = self.new_update_request('networks', data, net_id, self.fmt)
        res = req.get_response(self.api)
        return self.deserialize(self.fmt, res)['network']

    def _find_network_row_by_name(self, name):
        for row in self.nb_api._tables['Logical_Switch'].rows.values():
            if (row.external_ids.get(
                    ovn_const.OVN_NETWORK_NAME_EXT_ID_KEY) == name):
                return row

    def _create_port(self, name, net_id):
        data = {'port': {'name': name,
                         'tenant_id': self._tenant_id,
                         'network_id': net_id}}
        req = self.new_create_request('ports', data, self.fmt)
        res = req.get_response(self.api)
        return self.deserialize(self.fmt, res)['port']

    def _update_port_name(self, port_id, new_name):
        data = {'port': {'name': new_name}}
        req = self.new_update_request('ports', data, port_id, self.fmt)
        res = req.get_response(self.api)
        return self.deserialize(self.fmt, res)['port']

    def _find_port_row_by_name(self, name):
        for row in self.nb_api._tables['Logical_Switch_Port'].rows.values():
            if (row.external_ids.get(
                    ovn_const.OVN_PORT_NAME_EXT_ID_KEY) == name):
                return row

    def _create_router(self, name):
        data = {'router': {'name': name, 'tenant_id': self._tenant_id}}
        req = self.new_create_request('routers', data, self.fmt)
        res = req.get_response(self.api)
        return self.deserialize(self.fmt, res)['router']

    def _update_router_name(self, net_id, new_name):
        data = {'router': {'name': new_name}}
        req = self.new_update_request('routers', data, net_id, self.fmt)
        res = req.get_response(self.api)
        return self.deserialize(self.fmt, res)['router']

    def _find_router_row_by_name(self, name):
        for row in self.nb_api._tables['Logical_Router'].rows.values():
            if (row.external_ids.get(
                    ovn_const.OVN_ROUTER_NAME_EXT_ID_KEY) == name):
                return row

    def _create_subnet(self, net_id, cidr, name='subnet1'):
        data = {'subnet': {'name': name,
                           'tenant_id': self._tenant_id,
                           'network_id': net_id,
                           'cidr': cidr,
                           'ip_version': 4,
                           'enable_dhcp': True}}
        req = self.new_create_request('subnets', data, self.fmt)
        res = req.get_response(self.api)
        return self.deserialize(self.fmt, res)['subnet']

    def _update_subnet_name(self, subnet_id, new_name):
        data = {'subnet': {'name': new_name}}
        req = self.new_update_request('subnets', data, subnet_id, self.fmt)
        res = req.get_response(self.api)
        return self.deserialize(self.fmt, res)['subnet']

    def _find_subnet_row_by_id(self, subnet_id):
        for row in self.nb_api._tables['DHCP_Options'].rows.values():
            if (row.external_ids.get('subnet_id') == subnet_id and
               not row.external_ids.get('port_id')):
                return row

    def test_create_network(self):
        name = 'net1'
        neutron_net = self._create_network(name)
        ovn_net = self._find_network_row_by_name(name)

        ovn_revision = ovn_net.external_ids[ovn_const.OVN_REV_NUM_EXT_ID_KEY]
        # Assert it matches with the newest returned by neutron API
        self.assertEqual(str(neutron_net['revision_number']), ovn_revision)

    def test_update_network(self):
        new_name = 'netnew1'
        neutron_net = self._create_network('net1')
        updated_net = self._update_network_name(neutron_net['id'], new_name)
        ovn_net = self._find_network_row_by_name(new_name)

        ovn_revision = ovn_net.external_ids[ovn_const.OVN_REV_NUM_EXT_ID_KEY]
        # Assert it matches with the newest returned by neutron API
        self.assertEqual(str(updated_net['revision_number']), ovn_revision)

    def test_create_port(self):
        name = 'port1'
        neutron_net = self._create_network('net1')
        neutron_port = self._create_port(name, neutron_net['id'])
        ovn_port = self._find_port_row_by_name(name)

        ovn_revision = ovn_port.external_ids[ovn_const.OVN_REV_NUM_EXT_ID_KEY]
        # Assert it matches with the newest returned by neutron API
        self.assertEqual(str(neutron_port['revision_number']), ovn_revision)

    def test_update_port(self):
        new_name = 'portnew1'
        neutron_net = self._create_network('net1')
        neutron_port = self._create_port('port1', neutron_net['id'])
        updated_port = self._update_port_name(neutron_port['id'], new_name)
        ovn_port = self._find_port_row_by_name(new_name)

        ovn_revision = ovn_port.external_ids[ovn_const.OVN_REV_NUM_EXT_ID_KEY]
        # Assert it matches with the newest returned by neutron API
        self.assertEqual(str(updated_port['revision_number']), ovn_revision)

    def test_create_router(self):
        name = 'router1'
        neutron_router = self._create_router(name)
        ovn_router = self._find_router_row_by_name(name)

        ovn_revision = ovn_router.external_ids[
            ovn_const.OVN_REV_NUM_EXT_ID_KEY]
        # Assert it matches with the newest returned by neutron API
        self.assertEqual(str(neutron_router['revision_number']), ovn_revision)

    def test_update_router(self):
        new_name = 'newrouter'
        neutron_router = self._create_router('router1')
        updated_router = self._update_router_name(neutron_router['id'],
                                                  new_name)
        ovn_router = self._find_router_row_by_name(new_name)

        ovn_revision = ovn_router.external_ids[
            ovn_const.OVN_REV_NUM_EXT_ID_KEY]
        # Assert it matches with the newest returned by neutron API
        self.assertEqual(str(updated_router['revision_number']), ovn_revision)

    def test_create_subnet(self):
        neutron_net = self._create_network('net1')
        neutron_subnet = self._create_subnet(neutron_net['id'], '10.0.0.0/24')
        ovn_subnet = self._find_subnet_row_by_id(neutron_subnet['id'])

        ovn_revision = ovn_subnet.external_ids[
            ovn_const.OVN_REV_NUM_EXT_ID_KEY]
        # Assert it matches with the newest returned by neutron API
        self.assertEqual(str(neutron_subnet['revision_number']), ovn_revision)

    def test_update_subnet(self):
        neutron_net = self._create_network('net1')
        neutron_subnet = self._create_subnet(neutron_net['id'], '10.0.0.0/24')
        updated_subnet = self._update_subnet_name(
            neutron_subnet['id'], 'newsubnet')
        ovn_subnet = self._find_subnet_row_by_id(neutron_subnet['id'])

        ovn_revision = ovn_subnet.external_ids[
            ovn_const.OVN_REV_NUM_EXT_ID_KEY]
        # Assert it matches with the newest returned by neutron API
        self.assertEqual(str(updated_subnet['revision_number']), ovn_revision)

    # TODO(lucasagomes): Add a test for floating IPs here when we get
    # the router stuff done.
