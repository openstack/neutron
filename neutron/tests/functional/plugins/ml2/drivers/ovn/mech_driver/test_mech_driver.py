# Copyright 2016 Red Hat, Inc.
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

import functools
from unittest import mock

from neutron_lib.api.definitions import portbindings
from neutron_lib import constants
from neutron_lib.exceptions import agent as agent_exc
from oslo_config import cfg
from oslo_utils import uuidutils
from ovsdbapp.backend.ovs_idl import event
from ovsdbapp.tests.functional import base as ovs_base

from neutron.common.ovn import constants as ovn_const
from neutron.common.ovn import utils
from neutron.common import utils as n_utils
from neutron.db import ovn_revision_numbers_db as db_rev
from neutron.plugins.ml2.drivers.ovn.mech_driver import mech_driver
from neutron.plugins.ml2.drivers.ovn.mech_driver.ovsdb import impl_idl_ovn
from neutron.tests import base as tests_base
from neutron.tests.functional import base


class TestPortBinding(base.TestOVNFunctionalBase):

    def setUp(self):
        super(TestPortBinding, self).setUp()
        self.ovs_host = 'ovs-host'
        self.dpdk_host = 'dpdk-host'
        self.invalid_dpdk_host = 'invalid-host'
        self.vhu_mode = 'server'
        self.add_fake_chassis(self.ovs_host)
        self.add_fake_chassis(
            self.dpdk_host,
            external_ids={'datapath-type': 'netdev',
                          'iface-types': 'dummy,dummy-internal,dpdkvhostuser'})

        self.add_fake_chassis(
            self.invalid_dpdk_host,
            external_ids={'datapath-type': 'netdev',
                          'iface-types': 'dummy,dummy-internal,geneve,vxlan'})
        self.n1 = self._make_network(self.fmt, 'n1', True)
        res = self._create_subnet(self.fmt, self.n1['network']['id'],
                                  '10.0.0.0/24')
        self.deserialize(self.fmt, res)

    def _create_or_update_port(self, port_id=None, hostname=None):

        if port_id is None:
            port_data = {
                'port': {'network_id': self.n1['network']['id'],
                         'tenant_id': self._tenant_id}}

            if hostname:
                port_data['port']['device_id'] = uuidutils.generate_uuid()
                port_data['port']['device_owner'] = 'compute:None'
                port_data['port']['binding:host_id'] = hostname

            port_req = self.new_create_request('ports', port_data, self.fmt)
            port_res = port_req.get_response(self.api)
            p = self.deserialize(self.fmt, port_res)
            port_id = p['port']['id']
        else:
            port_data = {
                'port': {'device_id': uuidutils.generate_uuid(),
                         'device_owner': 'compute:None',
                         'binding:host_id': hostname}}
            port_req = self.new_update_request('ports', port_data, port_id,
                                               self.fmt)
            port_res = port_req.get_response(self.api)
            self.deserialize(self.fmt, port_res)

        return port_id

    def _verify_vif_details(self, port_id, expected_host_name,
                            expected_vif_type, expected_vif_details):
        port_req = self.new_show_request('ports', port_id)
        port_res = port_req.get_response(self.api)
        p = self.deserialize(self.fmt, port_res)
        self.assertEqual(expected_host_name, p['port']['binding:host_id'])
        self.assertEqual(expected_vif_type, p['port']['binding:vif_type'])
        self.assertEqual(expected_vif_details,
                         p['port']['binding:vif_details'])

    def test_port_binding_create_port(self):
        port_id = self._create_or_update_port(hostname=self.ovs_host)
        self._verify_vif_details(port_id, self.ovs_host, 'ovs',
                                 {'port_filter': True})

        port_id = self._create_or_update_port(hostname=self.dpdk_host)
        expected_vif_details = {'port_filter': False,
                                'vhostuser_mode': self.vhu_mode,
                                'vhostuser_ovs_plug': True}
        expected_vif_details['vhostuser_socket'] = (
            utils.ovn_vhu_sockpath(cfg.CONF.ovn.vhost_sock_dir, port_id))
        self._verify_vif_details(port_id, self.dpdk_host, 'vhostuser',
                                 expected_vif_details)

        port_id = self._create_or_update_port(hostname=self.invalid_dpdk_host)
        self._verify_vif_details(port_id, self.invalid_dpdk_host, 'ovs',
                                 {'port_filter': True})

    def test_port_binding_update_port(self):
        port_id = self._create_or_update_port()
        self._verify_vif_details(port_id, '', 'unbound', {})
        port_id = self._create_or_update_port(port_id=port_id,
                                              hostname=self.ovs_host)
        self._verify_vif_details(port_id, self.ovs_host, 'ovs',
                                 {'port_filter': True})

        port_id = self._create_or_update_port(port_id=port_id,
                                              hostname=self.dpdk_host)
        expected_vif_details = {'port_filter': False,
                                'vhostuser_mode': self.vhu_mode,
                                'vhostuser_ovs_plug': True}
        expected_vif_details['vhostuser_socket'] = (
            utils.ovn_vhu_sockpath(cfg.CONF.ovn.vhost_sock_dir, port_id))
        self._verify_vif_details(port_id, self.dpdk_host, 'vhostuser',
                                 expected_vif_details)

        port_id = self._create_or_update_port(port_id=port_id,
                                              hostname=self.invalid_dpdk_host)
        self._verify_vif_details(port_id, self.invalid_dpdk_host, 'ovs',
                                 {'port_filter': True})


class TestPortBindingOverTcp(TestPortBinding):
    def get_ovsdb_server_protocol(self):
        return 'tcp'


# TODO(mjozefcz): This test class hangs during execution.
class TestPortBindingOverSsl(TestPortBinding):
    def get_ovsdb_server_protocol(self):
        return 'ssl'


class TestNetworkMTUUpdate(base.TestOVNFunctionalBase):

    def setUp(self):
        super(TestNetworkMTUUpdate, self).setUp()
        self._ovn_client = self.mech_driver._ovn_client
        self.n1 = self._make_network(self.fmt, 'n1', True)
        res = self._create_subnet(self.fmt, self.n1['network']['id'],
                                  '10.0.0.0/24')
        self.sub = self.deserialize(self.fmt, res)

    def test_update_network_mtu(self):
        mtu_value = self.n1['network']['mtu'] - 100
        dhcp_options = (
            self.mech_driver._ovn_client._nb_idl.get_subnet_dhcp_options(
                self.sub['subnet']['id'])
        )
        self.assertNotEqual(
            int(dhcp_options['subnet']['options']['mtu']),
            mtu_value)
        data = {'network': {'mtu': mtu_value}}
        req = self.new_update_request(
            'networks', data, self.n1['network']['id'], self.fmt)
        req.get_response(self.api)
        dhcp_options = (
            self.mech_driver._ovn_client._nb_idl.get_subnet_dhcp_options(
                self.sub['subnet']['id'])
        )
        self.assertEqual(
            int(dhcp_options['subnet']['options']['mtu']),
            mtu_value)

    def test_no_update_network_mtu(self):
        mtu_value = self.n1['network']['mtu']
        base_revision = db_rev.get_revision_row(
            self.context,
            self.sub['subnet']['id'])
        data = {'network': {'mtu': mtu_value}}
        req = self.new_update_request(
            'networks', data, self.n1['network']['id'], self.fmt)
        req.get_response(self.api)
        second_revision = db_rev.get_revision_row(
            self.context,
            self.sub['subnet']['id'])
        self.assertEqual(
            base_revision.updated_at,
            second_revision.updated_at)


@mock.patch('neutron.plugins.ml2.drivers.ovn.mech_driver.'
            'ovsdb.ovn_client.OVNClient._is_virtual_port_supported',
            lambda *args: True)
class TestVirtualPorts(base.TestOVNFunctionalBase):

    def setUp(self):
        super(TestVirtualPorts, self).setUp()
        self._ovn_client = self.mech_driver._ovn_client
        self.n1 = self._make_network(self.fmt, 'n1', True)
        res = self._create_subnet(self.fmt, self.n1['network']['id'],
                                  '10.0.0.0/24')
        self.sub = self.deserialize(self.fmt, res)

    def _create_port(self, fixed_ip=None, allowed_address=None):
        port_data = {
            'port': {'network_id': self.n1['network']['id'],
                     'tenant_id': self._tenant_id}}
        if fixed_ip:
            port_data['port']['fixed_ips'] = [{'ip_address': fixed_ip}]

        if allowed_address:
            port_data['port']['allowed_address_pairs'] = [
                {'ip_address': allowed_address}]

        port_req = self.new_create_request('ports', port_data, self.fmt)
        port_res = port_req.get_response(self.api)
        self.assertEqual(201, port_res.status_int)
        return self.deserialize(self.fmt, port_res)['port']

    def _update_allowed_address_pair(self, port_id, data):
        port_data = {
            'port': {'allowed_address_pairs': data}}
        port_req = self.new_update_request('ports', port_data, port_id,
                                           self.fmt)
        port_res = port_req.get_response(self.api)
        self.assertEqual(200, port_res.status_int)
        return self.deserialize(self.fmt, port_res)['port']

    def _set_allowed_address_pair(self, port_id, ip):
        return self._update_allowed_address_pair(port_id, [{'ip_address': ip}])

    def _unset_allowed_address_pair(self, port_id):
        return self._update_allowed_address_pair(port_id, [])

    def _find_port_row(self, port_id):
        cmd = self.nb_api.db_find_rows(
            'Logical_Switch_Port', ('name', '=', port_id))
        rows = cmd.execute(check_error=True)
        return rows[0] if rows else None

    def _is_ovn_port_type(self, port_id, port_type):
        ovn_vport = self._find_port_row(port_id)
        return port_type == ovn_vport.type

    def _check_port_type(self, port_id, type):
        check = functools.partial(self._is_ovn_port_type, port_id, type)
        n_utils.wait_until_true(check, timeout=10)

    @tests_base.unstable_test("bug 1865453")
    def test_virtual_port_created_before(self):
        virt_port = self._create_port()
        virt_ip = virt_port['fixed_ips'][0]['ip_address']

        # Create the primary port with the VIP address already set in
        # the allowed_address_pairs field
        primary = self._create_port(allowed_address=virt_ip)

        # Assert the virt port has the type virtual and primary is set
        # as parent
        self._check_port_type(virt_port['id'], ovn_const.LSP_TYPE_VIRTUAL)
        ovn_vport = self._find_port_row(virt_port['id'])
        self.assertEqual(
            virt_ip,
            ovn_vport.options[ovn_const.LSP_OPTIONS_VIRTUAL_IP_KEY])
        self.assertEqual(
            primary['id'],
            ovn_vport.options[ovn_const.LSP_OPTIONS_VIRTUAL_PARENTS_KEY])

        # Create the backport parent port
        backup = self._create_port(allowed_address=virt_ip)

        # Assert the virt port now also includes the backup port as a parent
        self._check_port_type(virt_port['id'], ovn_const.LSP_TYPE_VIRTUAL)
        ovn_vport = self._find_port_row(virt_port['id'])
        self.assertEqual(
            virt_ip,
            ovn_vport.options[ovn_const.LSP_OPTIONS_VIRTUAL_IP_KEY])
        self.assertIn(
            primary['id'],
            ovn_vport.options[ovn_const.LSP_OPTIONS_VIRTUAL_PARENTS_KEY])
        self.assertIn(
            backup['id'],
            ovn_vport.options[ovn_const.LSP_OPTIONS_VIRTUAL_PARENTS_KEY])

    @tests_base.unstable_test("bug 1865453")
    def test_virtual_port_update_address_pairs(self):
        primary = self._create_port()
        backup = self._create_port()
        virt_port = self._create_port()
        virt_ip = virt_port['fixed_ips'][0]['ip_address']

        # Assert the virt port does not yet have the type virtual (no
        # address pairs were set yet)
        self._check_port_type(virt_port['id'], ''),
        ovn_vport = self._find_port_row(virt_port['id'])
        self.assertNotIn(ovn_const.LSP_OPTIONS_VIRTUAL_PARENTS_KEY,
                         ovn_vport.options)
        self.assertNotIn(ovn_const.LSP_OPTIONS_VIRTUAL_IP_KEY,
                         ovn_vport.options)

        # Set the virt IP to the allowed address pairs of the primary port
        self._set_allowed_address_pair(primary['id'], virt_ip)

        # Assert the virt port is now updated
        self._check_port_type(virt_port['id'], ovn_const.LSP_TYPE_VIRTUAL),
        ovn_vport = self._find_port_row(virt_port['id'])
        self.assertEqual(
            virt_ip,
            ovn_vport.options[ovn_const.LSP_OPTIONS_VIRTUAL_IP_KEY])
        self.assertEqual(
            primary['id'],
            ovn_vport.options[ovn_const.LSP_OPTIONS_VIRTUAL_PARENTS_KEY])

        # Set the virt IP to the allowed address pairs of the backup port
        self._set_allowed_address_pair(backup['id'], virt_ip)

        # Assert the virt port now includes the backup port as a parent
        self._check_port_type(virt_port['id'], ovn_const.LSP_TYPE_VIRTUAL),
        ovn_vport = self._find_port_row(virt_port['id'])
        self.assertEqual(
            virt_ip,
            ovn_vport.options[ovn_const.LSP_OPTIONS_VIRTUAL_IP_KEY])
        self.assertIn(
            primary['id'],
            ovn_vport.options[ovn_const.LSP_OPTIONS_VIRTUAL_PARENTS_KEY])
        self.assertIn(
            backup['id'],
            ovn_vport.options[ovn_const.LSP_OPTIONS_VIRTUAL_PARENTS_KEY])

        # Remove the address pairs from the primary port
        self._unset_allowed_address_pair(primary['id'])

        # Assert the virt port now only has the backup port as a parent
        self._check_port_type(virt_port['id'], ovn_const.LSP_TYPE_VIRTUAL),
        ovn_vport = self._find_port_row(virt_port['id'])
        self.assertEqual(
            virt_ip,
            ovn_vport.options[ovn_const.LSP_OPTIONS_VIRTUAL_IP_KEY])
        self.assertEqual(
            backup['id'],
            ovn_vport.options[ovn_const.LSP_OPTIONS_VIRTUAL_PARENTS_KEY])

        # Remove the address pairs from the backup port
        self._unset_allowed_address_pair(backup['id'])

        # Assert the virt port is not type virtual anymore and the virtual
        # port options are cleared
        self._check_port_type(virt_port['id'], ''),
        ovn_vport = self._find_port_row(virt_port['id'])
        self.assertNotIn(ovn_const.LSP_OPTIONS_VIRTUAL_PARENTS_KEY,
                         ovn_vport.options)
        self.assertNotIn(ovn_const.LSP_OPTIONS_VIRTUAL_IP_KEY,
                         ovn_vport.options)

    @tests_base.unstable_test("bug 1865453")
    def test_virtual_port_created_after(self):
        primary = self._create_port(fixed_ip='10.0.0.11')
        backup = self._create_port(fixed_ip='10.0.0.12')
        virt_ip = '10.0.0.55'

        # Set the virt IP to the primary and backup ports *before* creating
        # the virtual port
        self._set_allowed_address_pair(primary['id'], virt_ip)
        self._set_allowed_address_pair(backup['id'], virt_ip)

        virt_port = self._create_port(fixed_ip=virt_ip)

        # Assert the virtual port has been created with the
        # right type and parents
        ovn_vport = self._find_port_row(virt_port['id'])
        self.assertEqual(ovn_const.LSP_TYPE_VIRTUAL, ovn_vport.type)
        self.assertEqual(
            virt_ip,
            ovn_vport.options[ovn_const.LSP_OPTIONS_VIRTUAL_IP_KEY])
        self.assertIn(
            primary['id'],
            ovn_vport.options[ovn_const.LSP_OPTIONS_VIRTUAL_PARENTS_KEY])
        self.assertIn(
            backup['id'],
            ovn_vport.options[ovn_const.LSP_OPTIONS_VIRTUAL_PARENTS_KEY])

    @tests_base.unstable_test("bug 1865453")
    def test_virtual_port_delete_parents(self):
        primary = self._create_port()
        backup = self._create_port()
        virt_port = self._create_port()
        virt_ip = virt_port['fixed_ips'][0]['ip_address']

        # Assert the virt port does not yet have the type virtual (no
        # address pairs were set yet)
        ovn_vport = self._find_port_row(virt_port['id'])
        self.assertEqual("", ovn_vport.type)
        self.assertNotIn(ovn_const.LSP_OPTIONS_VIRTUAL_PARENTS_KEY,
                         ovn_vport.options)
        self.assertNotIn(ovn_const.LSP_OPTIONS_VIRTUAL_IP_KEY,
                         ovn_vport.options)

        # Set allowed address paris to the primary and backup ports
        self._set_allowed_address_pair(primary['id'], virt_ip)
        self._set_allowed_address_pair(backup['id'], virt_ip)

        # Assert the virtual port is correct
        ovn_vport = self._find_port_row(virt_port['id'])
        self.assertEqual(ovn_const.LSP_TYPE_VIRTUAL, ovn_vport.type)
        self.assertEqual(
            virt_ip,
            ovn_vport.options[ovn_const.LSP_OPTIONS_VIRTUAL_IP_KEY])
        self.assertIn(
            primary['id'],
            ovn_vport.options[ovn_const.LSP_OPTIONS_VIRTUAL_PARENTS_KEY])
        self.assertIn(
            backup['id'],
            ovn_vport.options[ovn_const.LSP_OPTIONS_VIRTUAL_PARENTS_KEY])

        # Delete the backup port
        self._delete('ports', backup['id'])

        # Assert the virt port now only has the primary port as a parent
        ovn_vport = self._find_port_row(virt_port['id'])
        self.assertEqual(ovn_const.LSP_TYPE_VIRTUAL, ovn_vport.type)
        self.assertEqual(
            virt_ip,
            ovn_vport.options[ovn_const.LSP_OPTIONS_VIRTUAL_IP_KEY])
        self.assertEqual(
            primary['id'],
            ovn_vport.options[ovn_const.LSP_OPTIONS_VIRTUAL_PARENTS_KEY])

        # Delete the primary port
        self._delete('ports', primary['id'])

        # Assert the virt port is not type virtual anymore and the virtual
        # port options are cleared
        ovn_vport = self._find_port_row(virt_port['id'])
        self.assertEqual("", ovn_vport.type)
        self.assertNotIn(ovn_const.LSP_OPTIONS_VIRTUAL_PARENTS_KEY,
                         ovn_vport.options)
        self.assertNotIn(ovn_const.LSP_OPTIONS_VIRTUAL_IP_KEY,
                         ovn_vport.options)

    def test_virtual_port_not_set_similiar_address(self):
        # Create one port
        self._create_port(fixed_ip='10.0.0.110')
        # Create second port with similar IP, so that
        # string matching will return True
        second_port = self._create_port(fixed_ip='10.0.0.11')

        # Assert the virtual port has not been set.
        ovn_vport = self._find_port_row(second_port['id'])
        self.assertEqual("", ovn_vport.type)
        self.assertNotIn(ovn_const.LSP_OPTIONS_VIRTUAL_PARENTS_KEY,
                         ovn_vport.options)
        self.assertNotIn(ovn_const.LSP_OPTIONS_VIRTUAL_IP_KEY,
                         ovn_vport.options)


class TestExternalPorts(base.TestOVNFunctionalBase):

    def setUp(self):
        super(TestExternalPorts, self).setUp()
        self._ovn_client = self.mech_driver._ovn_client
        self.n1 = self._make_network(self.fmt, 'n1', True)
        res = self._create_subnet(self.fmt, self.n1['network']['id'],
                                  '10.0.0.0/24')
        self.sub = self.deserialize(self.fmt, res)

        # The default group will be created by the maintenance task (
        # which is disabled in the functional jobs). So let's add it
        self.default_ch_grp = self.nb_api.ha_chassis_group_add(
            ovn_const.HA_CHASSIS_GROUP_DEFAULT_NAME).execute(check_error=True)

    def _find_port_row_by_name(self, name):
        cmd = self.nb_api.db_find_rows(
            'Logical_Switch_Port', ('name', '=', name))
        rows = cmd.execute(check_error=True)
        return rows[0] if rows else None

    def _test_external_port_create(self, vnic_type):
        port_data = {
            'port': {'network_id': self.n1['network']['id'],
                     'tenant_id': self._tenant_id,
                     portbindings.VNIC_TYPE: vnic_type}}

        port_req = self.new_create_request('ports', port_data, self.fmt)
        port_res = port_req.get_response(self.api)
        port = self.deserialize(self.fmt, port_res)['port']

        ovn_port = self._find_port_row_by_name(port['id'])
        self.assertEqual(ovn_const.LSP_TYPE_EXTERNAL, ovn_port.type)
        self.assertEqual(1, len(ovn_port.ha_chassis_group))
        self.assertEqual(str(self.default_ch_grp.uuid),
                         str(ovn_port.ha_chassis_group[0].uuid))

    def test_external_port_create_vnic_direct(self):
        self._test_external_port_create(portbindings.VNIC_DIRECT)

    def test_external_port_create_vnic_direct_physical(self):
        self._test_external_port_create(portbindings.VNIC_DIRECT_PHYSICAL)

    def test_external_port_create_vnic_macvtap(self):
        self._test_external_port_create(portbindings.VNIC_MACVTAP)

    def _test_external_port_update(self, vnic_type):
        port_data = {
            'port': {'network_id': self.n1['network']['id'],
                     'tenant_id': self._tenant_id}}

        port_req = self.new_create_request('ports', port_data, self.fmt)
        port_res = port_req.get_response(self.api)
        port = self.deserialize(self.fmt, port_res)['port']

        ovn_port = self._find_port_row_by_name(port['id'])
        self.assertEqual('', ovn_port.type)
        self.assertEqual([], ovn_port.ha_chassis_group)

        port_upt_data = {
            'port': {portbindings.VNIC_TYPE: vnic_type}}
        port_req = self.new_update_request(
            'ports', port_upt_data, port['id'], self.fmt)
        port_res = port_req.get_response(self.api)
        port = self.deserialize(self.fmt, port_res)['port']

        ovn_port = self._find_port_row_by_name(port['id'])
        self.assertEqual(ovn_const.LSP_TYPE_EXTERNAL, ovn_port.type)
        self.assertEqual(1, len(ovn_port.ha_chassis_group))
        self.assertEqual(str(self.default_ch_grp.uuid),
                         str(ovn_port.ha_chassis_group[0].uuid))

    def test_external_port_update_vnic_direct(self):
        self._test_external_port_update(portbindings.VNIC_DIRECT)

    def test_external_port_update_vnic_direct_physical(self):
        self._test_external_port_update(portbindings.VNIC_DIRECT_PHYSICAL)

    def test_external_port_update_vnic_macvtap(self):
        self._test_external_port_update(portbindings.VNIC_MACVTAP)

    def _test_external_port_create_switchdev(self, vnic_type):
        port_data = {
            'port': {'network_id': self.n1['network']['id'],
                     'tenant_id': self._tenant_id,
                     portbindings.VNIC_TYPE: vnic_type,
                     ovn_const.OVN_PORT_BINDING_PROFILE: {
                     'capabilities': [ovn_const.PORT_CAP_SWITCHDEV]}}}

        port_req = self.new_create_request('ports', port_data, self.fmt)
        port_res = port_req.get_response(self.api)
        port = self.deserialize(self.fmt, port_res)['port']

        ovn_port = self._find_port_row_by_name(port['id'])
        # When "switchdev" is set, we should treat it as a normal
        # port instead of "external" type
        self.assertEqual("", ovn_port.type)
        # Assert the poer hasn't been added to any HA Chassis Group either
        self.assertEqual(0, len(ovn_port.ha_chassis_group))

    def test_external_port_create_switchdev_vnic_direct(self):
        self._test_external_port_create_switchdev(portbindings.VNIC_DIRECT)

    def test_external_port_create_switchdev_vnic_direct_physical(self):
        self._test_external_port_create_switchdev(
            portbindings.VNIC_DIRECT_PHYSICAL)

    def test_external_port_create_switchdev_vnic_macvtap(self):
        self._test_external_port_create_switchdev(portbindings.VNIC_MACVTAP)

    def _test_external_port_update_switchdev(self, vnic_type):
        port_data = {
            'port': {'network_id': self.n1['network']['id'],
                     'tenant_id': self._tenant_id,
                     portbindings.VNIC_TYPE: vnic_type}}

        # Create a VNIC_DIRECT[_PHYSICAL] type port without the "switchdev"
        # capability and assert that it's an "external" port
        port_req = self.new_create_request('ports', port_data, self.fmt)
        port_res = port_req.get_response(self.api)
        port = self.deserialize(self.fmt, port_res)['port']

        ovn_port = self._find_port_row_by_name(port['id'])
        self.assertEqual(ovn_const.LSP_TYPE_EXTERNAL, ovn_port.type)
        self.assertEqual(1, len(ovn_port.ha_chassis_group))
        self.assertEqual(str(self.default_ch_grp.uuid),
                         str(ovn_port.ha_chassis_group[0].uuid))

        # Now, update the port to add a "switchdev" capability and make
        # sure it's not treated as an "external" port anymore nor it's
        # included in a HA Chassis Group
        port_upt_data = {
            'port': {ovn_const.OVN_PORT_BINDING_PROFILE: {
                     'capabilities': [ovn_const.PORT_CAP_SWITCHDEV]}}}
        port_req = self.new_update_request(
            'ports', port_upt_data, port['id'], self.fmt)
        port_res = port_req.get_response(self.api)
        port = self.deserialize(self.fmt, port_res)['port']

        ovn_port = self._find_port_row_by_name(port['id'])
        # When "switchdev" is set, we should treat it as a normal
        # port instead of "external" type
        self.assertEqual("", ovn_port.type)
        # Assert the poer hasn't been added to any HA Chassis Group either
        self.assertEqual(0, len(ovn_port.ha_chassis_group))

    def test_external_port_update_switchdev_vnic_direct(self):
        self._test_external_port_update_switchdev(portbindings.VNIC_DIRECT)

    def test_external_port_update_switchdev_vnic_direct_physical(self):
        self._test_external_port_update_switchdev(
            portbindings.VNIC_DIRECT_PHYSICAL)

    def test_external_port_update_switchdev_vnic_macvtap(self):
        self._test_external_port_update_switchdev(portbindings.VNIC_MACVTAP)


class TestCreateDefaultDropPortGroup(base.BaseLoggingTestCase,
                                     ovs_base.FunctionalTestCase):
    schemas = ['OVN_Southbound', 'OVN_Northbound']
    PG_NAME = ovn_const.OVN_DROP_PORT_GROUP_NAME

    def setUp(self):
        super(TestCreateDefaultDropPortGroup, self).setUp()
        self.api = impl_idl_ovn.OvsdbNbOvnIdl(
            self.connection['OVN_Northbound'])
        self.addCleanup(self.api.pg_del(self.PG_NAME, if_exists=True).execute,
                        check_error=True)

    def test_port_group_exists(self):
        """Test new port group is not added or modified.

        If Port Group was not existent, acls would be added.
        """
        self.api.pg_add(
            self.PG_NAME, acls=[], may_exist=True).execute(check_error=True)
        mech_driver.create_default_drop_port_group(self.api)
        port_group = self.api.get_port_group(self.PG_NAME)
        self.assertFalse(port_group.acls)

    def _test_pg_with_ports(self, expected_ports=None):
        expected_ports = expected_ports or []
        mech_driver.create_default_drop_port_group(self.api)
        port_group = self.api.get_port_group(self.PG_NAME)
        self.assertItemsEqual(
            expected_ports, [port.name for port in port_group.ports])

    def test_with_ports_available(self):
        expected_ports = ['port1', 'port2']
        testing_pg = 'testing'
        testing_ls = 'testing'
        with self.api.transaction(check_error=True) as txn:
            txn.add(self.api.pg_add(
                testing_pg,
                external_ids={ovn_const.OVN_SG_EXT_ID_KEY: 'foo'}))
            txn.add(self.api.ls_add(testing_ls))
            port_uuids = [txn.add(self.api.lsp_add(testing_ls, port))
                          for port in expected_ports]
            txn.add(self.api.pg_add_ports(testing_pg, port_uuids))

        self.addCleanup(self.api.pg_del(testing_pg, if_exists=True).execute,
                        check_error=True)

        self._test_pg_with_ports(expected_ports)

    def test_without_ports(self):
        self._test_pg_with_ports(expected_ports=[])


class TestProvnetPorts(base.TestOVNFunctionalBase):

    def setUp(self):
        super(TestProvnetPorts, self).setUp()
        self._ovn_client = self.mech_driver._ovn_client

    def _find_port_row_by_name(self, name):
        cmd = self.nb_api.db_find_rows(
            'Logical_Switch_Port', ('name', '=', name))
        rows = cmd.execute(check_error=True)
        return rows[0] if rows else None

    def create_segment(self, network_id, physical_network, segmentation_id):
        segment_data = {'network_id': network_id,
                        'physical_network': physical_network,
                        'segmentation_id': segmentation_id,
                        'network_type': 'vlan',
                        'name': constants.ATTR_NOT_SPECIFIED,
                        'description': constants.ATTR_NOT_SPECIFIED}
        return self.segments_plugin.create_segment(
            self.context, segment={'segment': segment_data})

    def delete_segment(self, segment_id):
        return self.segments_plugin.delete_segment(
            self.context, segment_id)

    def get_segments(self, network_id):
        return self.segments_plugin.get_segments(
            self.context, filters={'network_id': [network_id]})

    def test_network_segments_localnet_ports(self):
        n1 = self._make_network(
                self.fmt, 'n1', True,
                arg_list=('provider:network_type',
                          'provider:segmentation_id',
                          'provider:physical_network'),
                **{'provider:network_type': 'vlan',
                   'provider:segmentation_id': 100,
                   'provider:physical_network': 'physnet1'})['network']
        ovn_port = self._find_port_row_by_name(
            utils.ovn_provnet_port_name(n1['id']))
        # Assert that localnet port name is not based
        # on network name.
        self.assertIsNone(ovn_port)
        seg_db = self.get_segments(n1['id'])
        ovn_localnetport = self._find_port_row_by_name(
            utils.ovn_provnet_port_name(seg_db[0]['id']))
        self.assertEqual(ovn_localnetport.tag, [100])
        self.assertEqual(ovn_localnetport.options['network_name'], 'physnet1')
        seg_2 = self.create_segment(n1['id'], 'physnet2', '222')
        ovn_localnetport = self._find_port_row_by_name(
            utils.ovn_provnet_port_name(seg_2['id']))
        self.assertEqual(ovn_localnetport.options['network_name'], 'physnet2')
        self.assertEqual(ovn_localnetport.tag, [222])

        # Delete segments and ensure that localnet
        # ports are deleted.
        self.delete_segment(seg_db[0]['id'])
        ovn_localnetport = self._find_port_row_by_name(
            utils.ovn_provnet_port_name(seg_db[0]['id']))
        self.assertIsNone(ovn_localnetport)

        # Make sure that other localnet port is not touched.
        ovn_localnetport = self._find_port_row_by_name(
            utils.ovn_provnet_port_name(seg_2['id']))
        self.assertIsNotNone(ovn_localnetport)

        # Delete second segment and validate that the
        # second localnet port has been deleted.
        self.delete_segment(seg_2['id'])
        ovn_localnetport = self._find_port_row_by_name(
            utils.ovn_provnet_port_name(seg_2['id']))
        self.assertIsNone(ovn_localnetport)


class AgentWaitEvent(event.WaitEvent):
    """Wait for a list of Chassis to be created"""

    ONETIME = False

    def __init__(self, driver, chassis_names):
        table = driver.agent_chassis_table
        events = (self.ROW_CREATE,)
        self.chassis_names = chassis_names
        super().__init__(events, table, None)
        self.event_name = "AgentWaitEvent"

    def match_fn(self, event, row, old):
        return row.name in self.chassis_names

    def run(self, event, row, old):
        self.chassis_names.remove(row.name)
        if not self.chassis_names:
            self.event.set()


class TestAgentApi(base.TestOVNFunctionalBase):
    TEST_AGENT = 'test'

    def setUp(self):
        super().setUp()
        self.host = n_utils.get_rand_name(prefix='testhost-')
        self.plugin = self.mech_driver._plugin
        mock.patch.object(self.mech_driver, 'ping_all_chassis',
                          return_value=False).start()

        metadata_agent_id = uuidutils.generate_uuid()
        # To be *mostly* sure the agent cache has been updated, we need to
        # wait for the Chassis events to run. So add a new event that should
        # run afterthey do and wait for it. I've only had to do this when
        # adding *a bunch* of Chassis at a time, but better safe than sorry.
        chassis_name = uuidutils.generate_uuid()
        agent_event = AgentWaitEvent(self.mech_driver, [chassis_name])
        self.sb_api.idl.notify_handler.watch_event(agent_event)

        self.chassis = self.add_fake_chassis(self.host, name=chassis_name,
            external_ids={
                ovn_const.OVN_AGENT_METADATA_ID_KEY: metadata_agent_id})

        self.assertTrue(agent_event.wait())

        self.agent_types = {
            self.TEST_AGENT: self._create_test_agent(),
            ovn_const.OVN_CONTROLLER_AGENT: self.chassis,
            ovn_const.OVN_METADATA_AGENT: metadata_agent_id,
        }

    def _create_test_agent(self):
        agent = {'agent_type': self.TEST_AGENT, 'binary': '/bin/test',
                 'host': self.host, 'topic': 'test_topic'}
        _, status = self.plugin.create_or_update_agent(self.context, agent)
        return status['id']

    def test_agent_show(self):
        for agent_id in self.agent_types.values():
            self.assertTrue(self.plugin.get_agent(self.context, agent_id))

    def test_agent_list(self):
        agent_ids = [a['id'] for a in self.plugin.get_agents(
            self.context, filters={'host': self.host})]
        self.assertCountEqual(list(self.agent_types.values()), agent_ids)

    def test_agent_delete(self):
        for agent_id in self.agent_types.values():
            self.plugin.delete_agent(self.context, agent_id)
            self.assertRaises(agent_exc.AgentNotFound, self.plugin.get_agent,
                              self.context, agent_id)
