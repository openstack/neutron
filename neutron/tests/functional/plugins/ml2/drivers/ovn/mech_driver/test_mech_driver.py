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

import copy
import datetime
import functools
import re
import time
from unittest import mock
import uuid

import ddt
import netaddr
from neutron_lib.api.definitions import external_net
from neutron_lib.api.definitions import portbindings
from neutron_lib.api.definitions import qinq as qinq_apidef
from neutron_lib.api.definitions import vlantransparent as vlan_apidef
from neutron_lib import constants
from neutron_lib.db import api as db_api
from neutron_lib.exceptions import agent as agent_exc
from oslo_config import cfg
from oslo_utils import timeutils
from oslo_utils import uuidutils
from ovsdbapp.backend.ovs_idl import event

from neutron.common.ovn import constants as ovn_const
from neutron.common.ovn import utils
from neutron.common import utils as n_utils
from neutron.conf import common as common_conf
from neutron.conf.plugins.ml2.drivers.ovn import ovn_conf
from neutron.db import ovn_hash_ring_db
from neutron.db import ovn_revision_numbers_db as db_rev
from neutron.plugins.ml2 import db as ml2_db
from neutron.plugins.ml2.drivers.ovn.agent import neutron_agent as n_agent
from neutron.plugins.ml2.drivers.ovn.mech_driver.ovsdb import ovsdb_monitor
from neutron.tests.functional import base
from neutron.tests.unit.extensions import test_securitygroup as test_sg

VHU_MODE = 'server'
OVS_VIF_DETAILS = {
    portbindings.CAP_PORT_FILTER: True,
    portbindings.VIF_DETAILS_CONNECTIVITY: portbindings.CONNECTIVITY_L2,
    portbindings.VIF_DETAILS_BOUND_DRIVERS: {'0': 'ovn'},
    portbindings.VIF_DETAILS_BRIDGE_NAME: 'br-int',
    portbindings.OVS_DATAPATH_TYPE: 'system',
}
VHOSTUSER_VIF_DETAILS = {
    portbindings.CAP_PORT_FILTER: False,
    'vhostuser_mode': VHU_MODE,
    'vhostuser_ovs_plug': True,
    portbindings.VIF_DETAILS_CONNECTIVITY: portbindings.CONNECTIVITY_L2,
    portbindings.VIF_DETAILS_BOUND_DRIVERS: {'0': 'ovn'},
    portbindings.VIF_DETAILS_BRIDGE_NAME: 'br-int',
    portbindings.OVS_DATAPATH_TYPE: 'netdev',
}


class TestOVNMechanismDriver(base.TestOVNFunctionalBase):

    def test__init_hash_ring(self):
        # Create a differentiated OVN hash ring name.
        ring_group = uuidutils.generate_uuid()
        self.mech_driver.hash_ring_group = ring_group

        # Create several OVN hash registers left by a previous execution.
        created_at = timeutils.utcnow() - datetime.timedelta(1)
        node_uuids = [uuidutils.generate_uuid(),
                      uuidutils.generate_uuid(),
                      uuidutils.generate_uuid()]
        with db_api.CONTEXT_WRITER.using(self.context):
            for idx in range(3):
                ovn_hash_ring_db.add_node(
                    self.context, ring_group,
                    node_uuids[idx], created_at=created_at)

        # Check the existing OVN hash ring registers.
        ovn_hrs = ovn_hash_ring_db.get_nodes(self.context, ring_group)
        self.assertEqual(3, len(ovn_hrs))

        start_time = timeutils.utcnow()
        self.mech_driver._start_time = int(start_time.timestamp())
        for idx in range(3):
            self.mech_driver._node_uuid = node_uuids[idx]
            self.mech_driver._init_hash_ring(self.context)

        ovn_hrs = ovn_hash_ring_db.get_nodes(self.context, ring_group)
        self.assertEqual(3, len(ovn_hrs))
        for ovn_hr in ovn_hrs:
            self.assertEqual(int(start_time.timestamp()),
                             ovn_hr.created_at.timestamp())


class TestOvsdbPersistUuid(base.TestOVNFunctionalBase):

    def _create_port(self, name, net_id):
        data = {'port': {'name': name,
                         'tenant_id': self._tenant_id,
                         'network_id': net_id}}

        req = self.new_create_request('ports', data, self.fmt)
        res = req.get_response(self.api)
        return self.deserialize(self.fmt, res)['port']['id']

    def test_old_network_new_port(self):
        if not utils.ovs_persist_uuid_supported(self.nb_api):
            self.skipTest("OVS persist_uuid not supported")
        mock_supported = mock.patch.object(utils, 'ovs_persist_uuid_supported',
                                           return_value=False).start()
        network = self._make_network(self.fmt, 'n1', True)
        network_id = network['network']['id']
        self._create_subnet(self.fmt, network_id, '10.0.0.0/24')
        n1_ls = self.nb_api.ls_get(
            utils.ovn_name(network_id)).execute(check_error=True)
        self.assertNotEqual(uuid.UUID(network_id), n1_ls.uuid)
        mock_supported.return_value = True
        port = self._create_port("n1_port", network_id)
        port_lsp = self.nb_api.lsp_get(port).execute(check_error=True)
        self.assertIn(port_lsp, n1_ls.ports)


class TestPortBinding(base.TestOVNFunctionalBase):

    def setUp(self, **kwargs):
        super().setUp(**kwargs)
        self.ovs_host = 'ovs-host'
        self.dpdk_host = 'dpdk-host'
        self.invalid_dpdk_host = 'invalid-host'
        self.insecure_host = 'insecure-host'
        self.smartnic_dpu_host = 'smartnic-dpu-host'
        self.smartnic_dpu_serial = 'fake-smartnic-dpu-serial'
        self.add_fake_chassis(
            self.ovs_host,
            other_config={ovn_const.OVN_DATAPATH_TYPE: 'system'})
        self.add_fake_chassis(
            self.dpdk_host,
            other_config={ovn_const.OVN_DATAPATH_TYPE: 'netdev',
                          'iface-types': 'dummy,dummy-internal,dpdkvhostuser'})

        self.add_fake_chassis(
            self.invalid_dpdk_host,
            other_config={ovn_const.OVN_DATAPATH_TYPE: 'netdev',
                          'iface-types': 'dummy,dummy-internal,geneve,vxlan'})
        self.add_fake_chassis(
            self.smartnic_dpu_host,
            other_config={ovn_const.OVN_CMS_OPTIONS: '{}={}'.format(
                ovn_const.CMS_OPT_CARD_SERIAL_NUMBER,
                self.smartnic_dpu_serial),
                ovn_const.OVN_DATAPATH_TYPE: 'system'})
        self.n1 = self._make_network(self.fmt, 'n1', True)
        res = self._create_subnet(self.fmt, self.n1['network']['id'],
                                  '10.0.0.0/24')
        self.deserialize(self.fmt, res)

    def _create_or_update_port(self, port_id=None, hostname=None,
                               vnic_type=None, binding_profile=None):

        port_data = {'port': {}}
        if hostname:
            port_data['port']['device_id'] = uuidutils.generate_uuid()
            port_data['port']['device_owner'] = 'compute:None'
            port_data['port']['binding:host_id'] = hostname
        if vnic_type:
            port_data['port'][portbindings.VNIC_TYPE] = vnic_type
        if binding_profile:
            port_data['port'][portbindings.PROFILE] = binding_profile

        if port_id is None:
            port_data['port'].update({
                'network_id': self.n1['network']['id'],
                'tenant_id': self._tenant_id})

            port_req = self.new_create_request('ports', port_data, self.fmt,
                                               as_service=True)
            port_res = port_req.get_response(self.api)
            p = self.deserialize(self.fmt, port_res)
            port_id = p['port']['id']
        else:
            port_req = self.new_update_request('ports', port_data, port_id,
                                               self.fmt, as_service=True)
            port_res = port_req.get_response(self.api)
            self.deserialize(self.fmt, port_res)

        return port_id

    def _port_show(self, port_id):
        port_req = self.new_show_request('ports', port_id, as_admin=True)
        port_res = port_req.get_response(self.api)
        return self.deserialize(self.fmt, port_res)

    def _verify_vif_details(self, port_id, expected_host_name,
                            expected_vif_type, expected_vif_details):
        p = self._port_show(port_id)
        self.assertEqual(expected_host_name, p['port']['binding:host_id'])
        self.assertEqual(expected_vif_type, p['port']['binding:vif_type'])
        self.assertEqual(expected_vif_details,
                         p['port']['binding:vif_details'])

    def _find_port_row(self, port_id):
        cmd = self.nb_api.db_find_rows(
            'Logical_Switch_Port', ('name', '=', port_id))
        rows = cmd.execute(check_error=True)
        return rows[0] if rows else None

    def _verify_lsp_details(self, port_id, lsp_options):
        ovn_lsp = self._find_port_row(port_id)
        for key, value in lsp_options.items():
            self.assertEqual(
                value,
                ovn_lsp.options[key])

    def test_port_binding_create_port(self):
        port_id = self._create_or_update_port(hostname=self.ovs_host)
        self._verify_vif_details(port_id, self.ovs_host, 'ovs',
                                 OVS_VIF_DETAILS)

        port_id = self._create_or_update_port(hostname=self.dpdk_host)
        expected_vif_details = copy.deepcopy(VHOSTUSER_VIF_DETAILS)
        expected_vif_details['vhostuser_socket'] = (
            utils.ovn_vhu_sockpath(cfg.CONF.ovn.vhost_sock_dir, port_id))
        self._verify_vif_details(port_id, self.dpdk_host, 'vhostuser',
                                 expected_vif_details)

        expected_vif_details = copy.deepcopy(VHOSTUSER_VIF_DETAILS)
        expected_vif_details.pop('vhostuser_mode')
        expected_vif_details.pop('vhostuser_ovs_plug')
        expected_vif_details[portbindings.CAP_PORT_FILTER] = True
        port_id = self._create_or_update_port(hostname=self.invalid_dpdk_host)
        self._verify_vif_details(port_id, self.invalid_dpdk_host, 'ovs',
                                 expected_vif_details)

    def test_port_binding_create_remote_managed_port(self):
        pci_vendor_info = 'fake-pci-vendor-info'
        pci_slot = 'fake-pci-slot'
        physical_network = None
        pf_mac_address = 'fake-pf-mac'
        vf_num = 42
        port_id = self._create_or_update_port(
            hostname=self.insecure_host,
            vnic_type=portbindings.VNIC_REMOTE_MANAGED,
            binding_profile={
                ovn_const.VIF_DETAILS_PCI_VENDOR_INFO: pci_vendor_info,
                ovn_const.VIF_DETAILS_PCI_SLOT: pci_slot,
                ovn_const.VIF_DETAILS_PHYSICAL_NETWORK: physical_network,
                ovn_const.VIF_DETAILS_CARD_SERIAL_NUMBER: (
                    self.smartnic_dpu_serial),
                ovn_const.VIF_DETAILS_PF_MAC_ADDRESS: pf_mac_address,
                ovn_const.VIF_DETAILS_VF_NUM: vf_num,
            })

        self._verify_vif_details(port_id, self.insecure_host, 'ovs',
                                 OVS_VIF_DETAILS)
        self._verify_lsp_details(port_id, {
            ovn_const.LSP_OPTIONS_REQUESTED_CHASSIS_KEY: (
                self.smartnic_dpu_host),
            ovn_const.LSP_OPTIONS_VIF_PLUG_TYPE_KEY: 'representor',
            ovn_const.LSP_OPTIONS_VIF_PLUG_MTU_REQUEST_KEY: str(
                self.n1['network']['mtu']),
            ovn_const.LSP_OPTIONS_VIF_PLUG_REPRESENTOR_PF_MAC_KEY: (
                pf_mac_address),
            ovn_const.LSP_OPTIONS_VIF_PLUG_REPRESENTOR_VF_NUM_KEY: str(vf_num),
        })

    def test_port_binding_update_port(self):
        port_id = self._create_or_update_port()
        self._verify_vif_details(port_id, '', 'unbound', {})
        port_id = self._create_or_update_port(port_id=port_id,
                                              hostname=self.ovs_host)
        self._verify_vif_details(port_id, self.ovs_host, 'ovs',
                                 OVS_VIF_DETAILS)

        port_id = self._create_or_update_port(port_id=port_id,
                                              hostname=self.dpdk_host)
        expected_vif_details = copy.deepcopy(VHOSTUSER_VIF_DETAILS)
        expected_vif_details['vhostuser_socket'] = (
            utils.ovn_vhu_sockpath(cfg.CONF.ovn.vhost_sock_dir, port_id))
        self._verify_vif_details(port_id, self.dpdk_host, 'vhostuser',
                                 expected_vif_details)

        port_id = self._create_or_update_port(port_id=port_id,
                                              hostname=self.invalid_dpdk_host)
        expected_vif_details = copy.deepcopy(VHOSTUSER_VIF_DETAILS)
        expected_vif_details.pop('vhostuser_mode')
        expected_vif_details.pop('vhostuser_ovs_plug')
        expected_vif_details[portbindings.CAP_PORT_FILTER] = True
        self._verify_vif_details(port_id, self.invalid_dpdk_host, 'ovs',
                                 expected_vif_details)

    def test_port_binding_update_remote_managed_port(self):
        port_id = self._create_or_update_port(
            vnic_type=portbindings.VNIC_REMOTE_MANAGED)
        self._verify_vif_details(port_id, '', 'unbound', {})

        pci_vendor_info = 'fake-pci-vendor-info'
        pci_slot = 'fake-pci-slot'
        physical_network = None
        pf_mac_address = 'fake-pf-mac'
        vf_num = 42
        port_id = self._create_or_update_port(
            port_id=port_id,
            hostname=self.insecure_host,
            vnic_type=portbindings.VNIC_REMOTE_MANAGED,
            binding_profile={
                ovn_const.VIF_DETAILS_PCI_VENDOR_INFO: pci_vendor_info,
                ovn_const.VIF_DETAILS_PCI_SLOT: pci_slot,
                ovn_const.VIF_DETAILS_PHYSICAL_NETWORK: physical_network,
                ovn_const.VIF_DETAILS_CARD_SERIAL_NUMBER: (
                    self.smartnic_dpu_serial),
                ovn_const.VIF_DETAILS_PF_MAC_ADDRESS: pf_mac_address,
                ovn_const.VIF_DETAILS_VF_NUM: vf_num,
            })
        self._verify_vif_details(port_id, self.insecure_host, 'ovs',
                                 OVS_VIF_DETAILS)
        self._verify_lsp_details(port_id, {
            ovn_const.LSP_OPTIONS_REQUESTED_CHASSIS_KEY: (
                self.smartnic_dpu_host),
            ovn_const.LSP_OPTIONS_VIF_PLUG_TYPE_KEY: 'representor',
            ovn_const.LSP_OPTIONS_VIF_PLUG_MTU_REQUEST_KEY: str(
                self.n1['network']['mtu']),
            ovn_const.LSP_OPTIONS_VIF_PLUG_REPRESENTOR_PF_MAC_KEY: (
                pf_mac_address),
            ovn_const.LSP_OPTIONS_VIF_PLUG_REPRESENTOR_VF_NUM_KEY: str(vf_num),
        })

    def _create_router(self):
        e1 = self._make_network(self.fmt, 'e1', True, as_admin=True,
                                arg_list=('router:external',
                                          'provider:network_type',
                                          'provider:physical_network'),
                                **{'router:external': True,
                                   'provider:network_type': 'flat',
                                   'provider:physical_network': 'public'})
        res = self._create_subnet(self.fmt, e1['network']['id'],
                                  '100.0.0.0/24')
        s1 = self.deserialize(self.fmt, res)
        return self.l3_plugin.create_router(
            self.context,
            {'router': {
                'name': uuidutils.generate_uuid(),
                'admin_state_up': True,
                'tenant_id': self._tenant_id,
                'external_gateway_info': {
                    'enable_snat': True,
                    'network_id': e1['network']['id'],
                    'external_fixed_ips': [
                        {'ip_address': '100.0.0.2',
                         'subnet_id': s1['subnet']['id']}]}}})

    def test_lsp_up_event_update_and_creation(self):
        def _check_set_up_called(_mock, lsp_name):
            n_utils.wait_until_true(lambda: _mock.call_count == 1, timeout=10)
            mock_set_up.assert_called_once_with(lsp_name)

        with mock.patch.object(self.mech_driver, 'set_port_status_up') as \
                mock_set_up:
            router = self._create_router()
            lr = self.nb_api.lr_get(utils.ovn_name(router['id'])).execute(
                check_error=True)
            lrp = self.nb_api.lrp_get(lr.ports[0].uuid).execute(
                check_error=True)
            lsp_name = lrp.name.replace('lrp-', '')
            # Check that ``set_port_status_up`` has been called when the port
            # is created.
            _check_set_up_called(mock_set_up, lsp_name)

            # Restart the OVS database that forces the IDL reconnection.
            # Reset the ``mock_set_up`` that needs to be called again.
            with mock.patch.object(self.mech_driver, '_init_hash_ring'), \
                    mock.patch.object(ml2_db, 'get_port') as mock_get_port:
                mock_get_port.return_value = mock.Mock(
                    port_bindings=[mock.Mock(host='host1')],
                    id=lsp_name, device_owner='router')
                mock_set_up.reset_mock()
                self.restart(delete_dbs=False)

            # Check that ``set_port_status_up`` has been called when the IDL
            # reconnects.
            _check_set_up_called(mock_set_up, lsp_name)


class TestPortBindingOverTcp(TestPortBinding):
    def get_ovsdb_server_protocol(self):
        return 'tcp'


# TODO(mjozefcz): This test class hangs during execution.
class TestPortBindingOverSsl(TestPortBinding):
    def get_ovsdb_server_protocol(self):
        return 'ssl'


class TestNetworkMTUUpdate(base.TestOVNFunctionalBase):

    def setUp(self):
        super().setUp()
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


class TestVirtualPorts(base.TestOVNFunctionalBase):

    def setUp(self):
        super().setUp()
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

    def test_virtual_port_update_address_pairs(self):
        primary = self._create_port()
        backup = self._create_port()
        virt_port = self._create_port()
        virt_ip = virt_port['fixed_ips'][0]['ip_address']

        # Assert the virt port does not yet have the type virtual (no
        # address pairs were set yet)
        self._check_port_type(virt_port['id'], '')
        ovn_vport = self._find_port_row(virt_port['id'])
        self.assertNotIn(ovn_const.LSP_OPTIONS_VIRTUAL_PARENTS_KEY,
                         ovn_vport.options)
        self.assertNotIn(ovn_const.LSP_OPTIONS_VIRTUAL_IP_KEY,
                         ovn_vport.options)

        # Set the virt IP to the allowed address pairs of the primary port
        self._set_allowed_address_pair(primary['id'], virt_ip)

        # Assert the virt port is now updated
        self._check_port_type(virt_port['id'], ovn_const.LSP_TYPE_VIRTUAL)
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

        # Remove the address pairs from the primary port
        self._unset_allowed_address_pair(primary['id'])

        # Assert the virt port now only has the backup port as a parent
        self._check_port_type(virt_port['id'], ovn_const.LSP_TYPE_VIRTUAL)
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
        self._check_port_type(virt_port['id'], '')
        ovn_vport = self._find_port_row(virt_port['id'])
        self.assertNotIn(ovn_const.LSP_OPTIONS_VIRTUAL_PARENTS_KEY,
                         ovn_vport.options)
        self.assertNotIn(ovn_const.LSP_OPTIONS_VIRTUAL_IP_KEY,
                         ovn_vport.options)

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


@ddt.ddt
class TestExternalPorts(base.TestOVNFunctionalBase):

    def setUp(self):
        super().setUp()
        self._ovn_client = self.mech_driver._ovn_client
        self.n1 = self._make_network(self.fmt, 'n1', True)
        res = self._create_subnet(self.fmt, self.n1['network']['id'],
                                  '10.0.0.0/24')
        self.sub = self.deserialize(self.fmt, res)

    def _find_port_row_by_name(self, name):
        cmd = self.nb_api.db_find_rows(
            'Logical_Switch_Port', ('name', '=', name))
        rows = cmd.execute(check_error=True)
        return rows[0] if rows else None

    def _test_external_port_create_and_delete(
            self, vnic_type, enable_as_gw):
        for host in ('host1', 'host2', 'host3'):
            self.add_fake_chassis(
                host, enable_chassis_as_gw=enable_as_gw,
                enable_chassis_as_extport=not enable_as_gw)
        net_id = self.n1['network']['id']
        port_data = {
            'port': {'network_id': net_id,
                     'tenant_id': self._tenant_id,
                     portbindings.VNIC_TYPE: vnic_type}}

        port_req = self.new_create_request('ports', port_data, self.fmt)
        port_res = port_req.get_response(self.api)
        port = self.deserialize(self.fmt, port_res)['port']

        ovn_port = self._find_port_row_by_name(port['id'])
        hcg_name = str(ovn_port.ha_chassis_group[0].name)
        self.assertEqual(ovn_const.LSP_TYPE_EXTERNAL, ovn_port.type)
        self.assertEqual(1, len(ovn_port.ha_chassis_group))
        group_name = (utils.ovn_name(net_id) if enable_as_gw else
                      utils.ovn_extport_chassis_group_name(port['id']))
        self.assertEqual(group_name, hcg_name)
        hcg = self.nb_api.lookup('HA_Chassis_Group', hcg_name)
        self.assertEqual(hcg_name, hcg.name)

        port_req = self.new_delete_request('ports', port['id'])
        port_req.get_response(self.api)
        hcg = self.nb_api.lookup('HA_Chassis_Group', hcg_name, None)
        if enable_as_gw:
            self.assertEqual(hcg_name, hcg.name)
        else:
            # If the HCG has been created only for this port (that happens
            # when there are chassis for external ports), it should be deleted
            # along with the port.
            self.assertIsNone(hcg)

    def _create_router_port(self, vnic_type):
        net_id = self.n1['network']['id']
        port_data = {
            'port': {'network_id': net_id,
                     'tenant_id': self._tenant_id,
                     portbindings.VNIC_TYPE: 'normal'}}

        # Create port
        port_req = self.new_create_request('ports', port_data, self.fmt)
        port_res = port_req.get_response(self.api)
        port = self.deserialize(self.fmt, port_res)['port']

        # Update it as lsp port
        port_upt_data = {
            'port': {'device_owner': "network:router_gateway"}
        }
        port_req = self.new_update_request(
            'ports', port_upt_data, port['id'], self.fmt)
        port_res = port_req.get_response(self.api)

    @mock.patch('neutron.objects.router.Router.get_object')
    def test_add_external_port_avoid_flapping(self, gr):
        class LogicalSwitchPortUpdateUpEventTest(event.RowEvent):
            def __init__(self):
                self.count = 0
                table = 'Logical_Switch_Port'
                events = (self.ROW_UPDATE,)
                super().__init__(
                    events, table, (('up', '=', True),),
                    old_conditions=(('up', '!=', True),))

            def run(self, event, row, old):
                self.count += 1

            def get_count(self):
                return self.count

        class LogicalSwitchPortUpdateDownEventTest(event.RowEvent):
            def __init__(self):
                self.count = 0
                table = 'Logical_Switch_Port'
                events = (self.ROW_UPDATE,)
                super().__init__(
                    events, table, (('up', '!=', True),),
                    old_conditions=(('up', '=', True),))

            def run(self, event, row, old):
                self.count += 1

            def get_count(self):
                return self.count

        gr.return_value = {'flavor_id': None}
        og_up_event = ovsdb_monitor.LogicalSwitchPortUpdateUpEvent(None)
        og_down_event = ovsdb_monitor.LogicalSwitchPortUpdateDownEvent(None)
        test_down_event = LogicalSwitchPortUpdateDownEventTest()
        test_up_event = LogicalSwitchPortUpdateUpEventTest()
        self.nb_api.idl.notify_handler.unwatch_events(
            [og_up_event, og_down_event])
        self.nb_api.idl.notify_handler.watch_events(
            [test_down_event, test_up_event])
        # Creating a port the same way as the osp cli cmd
        # openstack router add port ROUTER PORT
        # shouldn't trigger an status flapping (up -> down -> up)
        # it should be created with status false and then change the
        # status as up, triggering only a LogicalSwitchPortUpdateUpEvent.
        self._create_router_port(portbindings.VNIC_DIRECT)
        self.assertEqual(test_down_event.get_count(), 0)
        n_utils.wait_until_true(lambda: test_up_event.get_count() == 1,
                                timeout=10)

    @ddt.data(True, False)
    def test_external_port_create_and_delete_vnic_direct(self, enable_as_gw):
        self._test_external_port_create_and_delete(
            portbindings.VNIC_DIRECT, enable_as_gw)

    @ddt.data(True, False)
    def test_external_port_create_and_delete_direct_physical(
            self, enable_as_gw):
        self._test_external_port_create_and_delete(
            portbindings.VNIC_DIRECT_PHYSICAL, enable_as_gw)

    @ddt.data(True, False)
    def test_external_port_create_and_delete_vnic_macvtap(self, enable_as_gw):
        self._test_external_port_create_and_delete(
            portbindings.VNIC_MACVTAP, enable_as_gw)

    def _test_external_port_update(self, vnic_type):
        net_id = self.n1['network']['id']
        port_data = {
            'port': {'network_id': net_id,
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
        self.assertEqual(utils.ovn_name(net_id),
                         str(ovn_port.ha_chassis_group[0].name))

    def test_external_port_update_vnic_direct(self):
        self._test_external_port_update(portbindings.VNIC_DIRECT)

    def test_external_port_update_vnic_direct_physical(self):
        self._test_external_port_update(portbindings.VNIC_DIRECT_PHYSICAL)

    def test_external_port_update_vnic_macvtap(self):
        self._test_external_port_update(portbindings.VNIC_MACVTAP)

    def _test_external_port_create_switchdev(self, vnic_type):
        port_data = {
            'port': {'network_id': self.n1['network']['id'],
                     portbindings.VNIC_TYPE: vnic_type,
                     ovn_const.OVN_PORT_BINDING_PROFILE: {
                         ovn_const.PORT_CAP_PARAM: [
                             ovn_const.PORT_CAP_SWITCHDEV]}}}

        port_req = self.new_create_request('ports', port_data, self.fmt,
                                           as_service=True)
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
        net_id = self.n1['network']['id']
        port_data = {
            'port': {'network_id': net_id,
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
        self.assertEqual(utils.ovn_name(net_id),
                         str(ovn_port.ha_chassis_group[0].name))

        # Now, update the port to add a "switchdev" capability and make
        # sure it's not treated as an "external" port anymore nor it's
        # included in a HA Chassis Group
        port_upt_data = {
            'port': {ovn_const.OVN_PORT_BINDING_PROFILE: {
                     ovn_const.PORT_CAP_PARAM: [
                         ovn_const.PORT_CAP_SWITCHDEV]}}}
        port_req = self.new_update_request(
            'ports', port_upt_data, port['id'], self.fmt,
            as_service=True)
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

    def test_external_port_network_update(self):
        net_id = self.n1['network']['id']
        port_data = {
            'port': {'network_id': net_id,
                     'tenant_id': self._tenant_id,
                     portbindings.VNIC_TYPE: 'direct'}}

        # Create external port
        port_req = self.new_create_request('ports', port_data, self.fmt)
        port_res = port_req.get_response(self.api)
        port = self.deserialize(self.fmt, port_res)['port']
        ovn_port = self._find_port_row_by_name(port['id'])
        self.assertEqual(ovn_const.LSP_TYPE_EXTERNAL, ovn_port.type)
        # Update MTU of network with external port
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


class TestSecurityGroup(base.TestOVNFunctionalBase):

    def setUp(self):
        super().setUp()
        self._ovn_client = self.mech_driver._ovn_client
        self.plugin = self.mech_driver._plugin
        self.sg_data = {
            'name': 'testsg',
            'description': 'Test Security Group',
            'tenant_id': self._tenant_id,
            'is_default': True,
        }
        mock.patch.object(
            self.plugin, 'get_default_security_group_rules',
            return_value=copy.deepcopy(
                test_sg.RULES_TEMPLATE_FOR_CUSTOM_SG)).start()

    def _find_acls_for_sg(self, sg_id):
        rows = self.nb_api.db_find_rows('ACL').execute(check_error=True)
        if rows:
            rule_ids = {
                r['id'] for r in self.plugin.get_security_group_rules(
                    self.context, {'security_group_id': [sg_id]})
            }

            def get_api_id(r):
                return r.external_ids.get(
                    ovn_const.OVN_SG_RULE_EXT_ID_KEY, '')

            return [r for r in rows if get_api_id(r) in rule_ids]
        return []

    def _find_acl_remote_sg(self, remote_sg_id):
        # NOTE: the ACL to be found has ethertype=IPv4 and protocol=ICMP.
        sg_match = '$pg_' + remote_sg_id.replace('-', '_') + '_ip4 && icmp4'
        for row in self.nb_api.db_find_rows('ACL').execute(check_error=True):
            if sg_match in row.match:
                return row

    def test_sg_stateful_toggle_updates_ovn_acls(self):
        def check_acl_actions(sg_id, expected):
            self.assertEqual(
                {expected},
                {a.action for a in self._find_acls_for_sg(sg_id)}
            )

        sg = self.plugin.create_security_group(
            self.context, security_group={'security_group': self.sg_data})
        check_acl_actions(sg['id'], 'allow-related')

        def update_sg(stateful):
            self.sg_data['stateful'] = stateful
            self.plugin.update_security_group(
                self.context, sg['id'],
                security_group={'security_group': self.sg_data})

        update_sg(False)
        check_acl_actions(sg['id'], 'allow-stateless')

        update_sg(True)
        check_acl_actions(sg['id'], 'allow-related')

        update_sg(False)
        check_acl_actions(sg['id'], 'allow-stateless')

    def test_remove_sg_with_related_rule_remote_sg(self):
        self.sg_data['is_default'] = False
        sg1 = self.plugin.create_security_group(
            self.context, security_group={'security_group': self.sg_data})
        sg2 = self.plugin.create_security_group(
            self.context, security_group={'security_group': self.sg_data})
        rule_data = {'direction': constants.INGRESS_DIRECTION,
                     'ethertype': constants.IPv4,
                     'protocol': constants.PROTO_NAME_ICMP,
                     'port_range_max': None,
                     'port_range_min': None,
                     'remote_ip_prefix': None,
                     'tenant_id': sg1['project_id'],
                     'remote_address_group_id': None,
                     'security_group_id': sg1['id'],
                     'remote_group_id': sg2['id']}
        sg_rule = {'security_group_rule': rule_data}
        rule = self.plugin.create_security_group_rule(self.context, sg_rule)
        acl = self._find_acl_remote_sg(sg2['id'])
        self.assertEqual(rule['id'],
                         acl.external_ids[ovn_const.OVN_SG_RULE_EXT_ID_KEY])
        acls = self._find_acls_for_sg(sg1['id'])
        self.assertEqual(3, len(acls))

        self.plugin.delete_security_group(self.context, sg2['id'])
        self.assertIsNone(self._find_acl_remote_sg(sg2['id']))
        acls = self._find_acls_for_sg(sg1['id'])
        self.assertEqual(2, len(acls))


class TestProvnetPorts(base.TestOVNFunctionalBase):

    def setUp(self):
        super().setUp()
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
                self.fmt, 'n1', True, as_admin=True,
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


class TestVlanTransparencyOptions(base.TestOVNFunctionalBase):

    """Tests for the vlan_transparent and vlan_qinq network params.

    This class contains tests which tests both "vlan_transparent" and
    "vlan_qinq" options. The reason why those 2 are tested together is that
    both options are using the same options on the OVN side and are mutually
    exclusive.
    """

    def setUp(self):
        common_conf.register_core_common_config_opts()
        super().setUp()
        self._ovn_client = self.mech_driver._ovn_client

    def _find_row_by_name(self, row_name, name):
        cmd = self.nb_api.db_find_rows(row_name, ('name', '=', name))
        rows = cmd.execute(check_error=True)
        return rows[0] if rows else None

    def _find_port_row_by_name(self, name):
        return self._find_row_by_name('Logical_Switch_Port', name)

    def _find_network_row_by_name(self, name):
        return self._find_row_by_name('Logical_Switch', name)

    def _test_network_with_qinq_and_vlan_transparent(
            self, vlan_qinq, vlan_transparent):
        net = self._make_network(
            self.fmt, 'n1', True, as_admin=True,
            arg_list=('provider:network_type',
                      'provider:segmentation_id',
                      'provider:physical_network',
                      qinq_apidef.QINQ_FIELD,
                      vlan_apidef.VLANTRANSPARENT),
            **{'provider:network_type': 'vlan',
               'provider:segmentation_id': 100,
               'provider:physical_network': 'physnet1',
               qinq_apidef.QINQ_FIELD: vlan_qinq,
               vlan_apidef.VLANTRANSPARENT: vlan_transparent}
        )['network']

        seg_db = self.segments_plugin.get_segments(
            self.context, filters={'network_id': [net['id']]})
        ovn_network = self._find_network_row_by_name(utils.ovn_name(net['id']))
        ovn_localnetport = self._find_port_row_by_name(
            utils.ovn_provnet_port_name(seg_db[0]['id']))

        if vlan_qinq:
            self.assertEqual(ovn_const.ETHTYPE_8021ad,
                             ovn_localnetport.options[ovn_const.VLAN_ETHTYPE])
            # This means that "vlan-passthru" should be set to "true" for
            # the LS
            self.assertEqual('true',
                             ovn_network.other_config[ovn_const.VLAN_PASSTHRU])
        else:
            self.assertNotIn(ovn_const.VLAN_ETHTYPE, ovn_localnetport.options)
            if vlan_transparent:
                # This means that "vlan-passthru" should be set to "true" for
                # the LS, in case of vlan-transparent network there is no need
                # to set ethtype on the localnet port as 802.1q is default
                # value for this field in the OVN db
                self.assertEqual(
                    'true', ovn_network.other_config[ovn_const.VLAN_PASSTHRU])
            else:
                self.assertEqual(
                    'false', ovn_network.other_config[ovn_const.VLAN_PASSTHRU])

    def test_network_with_qinq_enabled_vlan_transparent_disabled(self):
        self._test_network_with_qinq_and_vlan_transparent(
            True, False)

    def test_network_with_qinq_disabled_vlan_transparent_enabled(self):
        self._test_network_with_qinq_and_vlan_transparent(
            False, True)

    def test_network_with_qinq_and_vlan_transparent_disabled(self):
        self._test_network_with_qinq_and_vlan_transparent(
            False, False)


class TestMetadataPorts(base.TestOVNFunctionalBase):

    def setUp(self, *args, **kwargs):
        super().setUp(*args, **kwargs)
        self.plugin = self.mech_driver._plugin
        self._ovn_client = self.mech_driver._ovn_client
        self.meta_regex = re.compile(r'%s,(\d+\.\d+\.\d+\.\d+)' %
                                     constants.METADATA_V4_CIDR)

    def _create_network_ovn(self, metadata_enabled=True):
        self.mock_is_ovn_metadata_enabled = mock.patch.object(
            ovn_conf, 'is_ovn_metadata_enabled').start()
        self.mock_is_ovn_metadata_enabled.return_value = metadata_enabled
        self.n1 = self._make_network(self.fmt, 'n1', True)
        self.n1_id = self.n1['network']['id']

    def _create_subnet_ovn(self, cidr, enable_dhcp=True):
        _cidr = netaddr.IPNetwork(cidr)
        res = self._create_subnet(self.fmt, self.n1_id, cidr,
                                  enable_dhcp=enable_dhcp,
                                  ip_version=_cidr.version)
        return self.deserialize(self.fmt, res)['subnet']

    def _list_ports_ovn(self, net_id=None):
        res = self._list_ports(self.fmt, net_id=net_id)
        return self.deserialize(self.fmt, res)['ports']

    def _check_metadata_port(self, net_id, fixed_ip, fail=True):
        for port in self._list_ports_ovn(net_id=net_id):
            if utils.is_ovn_metadata_port(port):
                self.assertEqual(net_id, port['network_id'])
                if fixed_ip:
                    self.assertIn(fixed_ip, port['fixed_ips'])
                else:
                    self.assertEqual([], port['fixed_ips'])
                return port['id']

        if fail:
            self.fail('Metadata port is not present in network %s or data is '
                      'not correct' % self.n1_id)

    def _check_subnet_dhcp_options(self, subnet_id, cidr):
        # This method checks DHCP options for a subnet ID, and if they exist,
        # verifies the CIDR matches. Returns the metadata port IP address
        # if it is included in the classless static routes, else returns None.
        dhcp_opts = self._ovn_client._nb_idl.get_subnet_dhcp_options(subnet_id)
        if not dhcp_opts['subnet']:
            return
        self.assertEqual(cidr, dhcp_opts['subnet']['cidr'])
        routes = dhcp_opts['subnet']['options'].get('classless_static_route')
        if not routes:
            return

        match = self.meta_regex.search(routes)
        if match:
            return match.group(1)

    def test_subnet_ipv4(self):
        self._create_network_ovn(metadata_enabled=True)
        subnet = self._create_subnet_ovn('10.0.0.0/24')
        metatada_ip = self._check_subnet_dhcp_options(subnet['id'],
                                                      '10.0.0.0/24')
        fixed_ip = {'subnet_id': subnet['id'], 'ip_address': metatada_ip}
        port_id = self._check_metadata_port(self.n1_id, fixed_ip)

        # Update metatada port IP address to 10.0.0.5
        data = {'port': {'fixed_ips': [{'subnet_id': subnet['id'],
                                        'ip_address': '10.0.0.5'}]}}
        req = self.new_update_request('ports', data, port_id)
        req.get_response(self.api)
        metatada_ip = self._check_subnet_dhcp_options(subnet['id'],
                                                      '10.0.0.0/24')
        self.assertEqual('10.0.0.5', metatada_ip)
        fixed_ip = {'subnet_id': subnet['id'], 'ip_address': metatada_ip}
        self._check_metadata_port(self.n1_id, fixed_ip)

    def test_update_subnet_ipv4(self):
        self._create_network_ovn(metadata_enabled=True)
        subnet = self._create_subnet_ovn('10.0.0.0/24')
        metatada_ip = self._check_subnet_dhcp_options(subnet['id'],
                                                      '10.0.0.0/24')
        fixed_ip = {'subnet_id': subnet['id'], 'ip_address': metatada_ip}
        port_id = self._check_metadata_port(self.n1_id, fixed_ip)

        # Disable DHCP, port should still be present
        subnet['enable_dhcp'] = False
        self._ovn_client.update_subnet(self.context, subnet,
                                       self.n1['network'])
        port_id = self._check_metadata_port(self.n1_id, None)
        self.assertIsNone(self._check_subnet_dhcp_options(subnet['id'], []))

        # Delete metadata port
        self.plugin.delete_port(self.context, port_id)
        port_id = self._check_metadata_port(self.n1_id, None, fail=False)
        self.assertIsNone(port_id)

        # Enable DHCP, metadata port should have been re-created
        subnet['enable_dhcp'] = True
        self._ovn_client.update_subnet(self.context, subnet,
                                       self.n1['network'])
        metatada_ip = self._check_subnet_dhcp_options(subnet['id'],
                                                      '10.0.0.0/24')
        fixed_ip = {'subnet_id': subnet['id'], 'ip_address': metatada_ip}
        port_id = self._check_metadata_port(self.n1_id, fixed_ip)

    def test_subnet_ipv4_no_metadata(self):
        self._create_network_ovn(metadata_enabled=False)
        subnet = self._create_subnet_ovn('10.0.0.0/24')
        self.assertIsNone(self._check_subnet_dhcp_options(subnet['id'],
                                                          '10.0.0.0/24'))
        self.assertEqual([], self._list_ports_ovn(self.n1_id))

    def test_subnet_ipv6(self):
        self._create_network_ovn(metadata_enabled=True)
        subnet = self._create_subnet_ovn('2001:db8::/64')
        self.assertIsNone(self._check_subnet_dhcp_options(subnet['id'],
                                                          '2001:db8::/64'))
        self._check_metadata_port(self.n1_id, [])


class AgentWaitEvent(event.WaitEvent):
    """Wait for a list of Chassis to be created"""

    ONETIME = False

    def __init__(self, driver, chassis_names, events=None):
        events = events or (self.ROW_CREATE,)
        self.chassis_names = chassis_names
        super().__init__(events, 'Chassis_Private', None)
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

        self.chassis = self.add_fake_chassis(
            self.host, name=chassis_name,
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
        # Ensure the non OVN agent has been correctly created.
        self.assertEqual(
            status['id'],
            self.plugin.get_agent(self.context, status['id'])['id']
        )
        return status['id']

    def _check_chassis_registers(self, present=True):
        chassis = self.sb_api.lookup('Chassis', self.chassis, default=None)
        chassis_name = chassis.name if chassis else None
        ch_private = self.sb_api.lookup(
            'Chassis_Private', self.chassis, default=None)
        ch_private_name = ch_private.name if ch_private else None
        self.assertEqual(chassis_name, ch_private_name)
        if present:
            self.assertEqual(self.chassis, chassis_name)
        else:
            self.assertIsNone(chassis)

    def test_agent_show(self):
        for agent_id in self.agent_types.values():
            self.assertTrue(self.plugin.get_agent(self.context, agent_id))

    def test_agent_show_real_heartbeat_timestamp(self):
        agent_id = self.agent_types[ovn_const.OVN_CONTROLLER_AGENT]
        agent = self.plugin.get_agent(self.context, agent_id)
        heartbeat_timestamp = agent['heartbeat_timestamp']
        chassis_ts = self.sb_api.db_get(
            'Chassis_Private', self.chassis, 'nb_cfg_timestamp'
        ).execute(check_error=True)
        updated_at = datetime.datetime.fromtimestamp(int(chassis_ts / 1000))
        self.assertEqual(updated_at, heartbeat_timestamp)
        time.sleep(1)
        # if chassis is not updated, agent's heartbeat_timestamp shouldn't
        # be updated.
        n_agent = self.plugin.get_agent(self.context, agent['id'])
        self.assertEqual(heartbeat_timestamp, n_agent['heartbeat_timestamp'])

    def test_agent_list(self):
        agent_ids = [a['id'] for a in self.plugin.get_agents(
            self.context, filters={'host': self.host})]
        self.assertCountEqual(list(self.agent_types.values()), agent_ids)

        # "ovn-controller" ends without deleting "Chassis" and
        # "Chassis_Private" registers. If "Chassis" register is deleted,
        # then Chassis_Private.chassis = []; both metadata and controller
        # agents will still be present in the agent list.
        agent_event = AgentWaitEvent(self.mech_driver, [self.chassis],
                                     events=(event.RowEvent.ROW_DELETE,))
        self.sb_api.idl.notify_handler.watch_event(agent_event)
        self.del_fake_chassis(self.chassis)
        self.assertTrue(agent_event.wait())
        agent_ids = [a['id'] for a in self.plugin.get_agents(
            self.context, filters={'host': self.host})]
        self.assertCountEqual(list(self.agent_types.values()), agent_ids)

    def test_agent_delete(self):
        agent_cache = n_agent.AgentCache(mock.ANY)

        def wait_until_removed(agent_id):
            n_utils.wait_until_true(
                lambda: agent_cache.agents.get(agent_id) is None,
                timeout=5)

        # Non OVN agent deletion.
        agent_id = self.agent_types[self.TEST_AGENT]
        self.plugin.delete_agent(self.context, agent_id)
        self.assertRaises(agent_exc.AgentNotFound, self.plugin.get_agent,
                          self.context, agent_id)

        # OVN controller agent deletion, that triggers the "Chassis" and
        # "Chassis_Private" registers deletion. The registers deletion triggers
        # the host OVN agents deletion, both controller and metadata if
        # present.
        controller_id = self.agent_types[ovn_const.OVN_CONTROLLER_AGENT]
        metadata_id = self.agent_types[ovn_const.OVN_METADATA_AGENT]
        self._check_chassis_registers()
        self.plugin.delete_agent(self.context, controller_id)
        self._check_chassis_registers(present=False)
        wait_until_removed(controller_id)
        self.assertRaises(agent_exc.AgentNotFound, self.plugin.get_agent,
                          self.context, controller_id)
        self.assertEqual(
            metadata_id,
            self.plugin.get_agent(self.context, metadata_id)['id'])

        self.plugin.delete_agent(self.context, metadata_id)
        wait_until_removed(metadata_id)
        self.assertRaises(agent_exc.AgentNotFound, self.plugin.get_agent,
                          self.context, metadata_id)


class _TestRouter(base.TestOVNFunctionalBase):

    def setUp(self, **kwargs):
        super().setUp(**kwargs)
        self._ovn_client = self.mech_driver._ovn_client

    def _create_router(self, name, external_gateway_info=None):
        data = {'router': {'name': name, 'tenant_id': self._tenant_id,
                           'external_gateway_info': external_gateway_info}}
        as_admin = bool(external_gateway_info.get('enable_snat'))
        req = self.new_create_request('routers', data, self.fmt,
                                      as_admin=as_admin)
        res = req.get_response(self.api)
        return self.deserialize(self.fmt, res)['router']

    def _update_router(self, router_id, router_dict):
        data = {'router': router_dict}
        req = self.new_update_request('routers', data, router_id, self.fmt)
        res = req.get_response(self.api)
        return self.deserialize(self.fmt, res)['router']

    def _process_router_interface(self, action, router_id, subnet_id):
        req = self.new_action_request(
            'routers', {'subnet_id': subnet_id}, router_id,
            '%s_router_interface' % action)
        res = req.get_response(self.api)
        return self.deserialize(self.fmt, res)

    def _add_router_interface(self, router_id, subnet_id):
        return self._process_router_interface('add', router_id, subnet_id)


class TestNATRuleGatewayPort(_TestRouter):

    def deserialize(self, content_type, response):
        ctype = 'application/%s' % content_type
        data = self._deserializers[ctype].deserialize(response.body)['body']
        return data

    def _create_port(self, name, net_id, security_groups=None,
                     device_owner=None):
        data = {'port': {'name': name,
                         'tenant_id': self._tenant_id,
                         'network_id': net_id}}

        if security_groups is not None:
            data['port']['security_groups'] = security_groups

        if device_owner is not None:
            data['port']['device_owner'] = device_owner

        req = self.new_create_request('ports', data, self.fmt)
        res = req.get_response(self.api)
        return self.deserialize(self.fmt, res)['port']

    def test_create_floatingip(self):
        ext_net = self._make_network(
            self.fmt, 'ext_networktest', True, as_admin=True,
            arg_list=('router:external',
                      'provider:network_type',
                      'provider:physical_network'),
            **{'router:external': True,
               'provider:network_type': 'flat',
               'provider:physical_network': 'public'})['network']
        res = self._create_subnet(self.fmt, ext_net['id'],
                                  '100.0.0.0/24', gateway_ip='100.0.0.254',
                                  allocation_pools=[{'start': '100.0.0.2',
                                                     'end': '100.0.0.253'}],
                                  enable_dhcp=False)
        ext_subnet = self.deserialize(self.fmt, res)['subnet']
        net1 = self._make_network(
            self.fmt, 'network1test', True)['network']
        res = self._create_subnet(self.fmt, net1['id'],
                                  '192.168.0.0/24', gateway_ip='192.168.0.1',
                                  allocation_pools=[{'start': '192.168.0.2',
                                                     'end': '192.168.0.253'}],
                                  enable_dhcp=False)
        subnet1 = self.deserialize(self.fmt, res)['subnet']
        external_gateway_info = {
            'enable_snat': True,
            'network_id': ext_net['id'],
            'external_fixed_ips': [
                {'ip_address': '100.0.0.2', 'subnet_id': ext_subnet['id']}]}
        router = self._create_router(
            'routertest', external_gateway_info=external_gateway_info)
        self._add_router_interface(router['id'], subnet1['id'])

        p1 = self._create_port('testp1', net1['id'])
        logical_ip = p1['fixed_ips'][0]['ip_address']
        fip_info = {'floatingip': {
            'tenant_id': self._tenant_id,
            'description': 'test_fip',
            'floating_network_id': ext_net['id'],
            'port_id': p1['id'],
            'fixed_ip_address': logical_ip}}

        fip = self.l3_plugin.create_floatingip(self.context, fip_info)

        self.assertEqual(router['id'], fip['router_id'])
        self.assertEqual('testp1', fip['port_details']['name'])
        self.assertIsNotNone(self.nb_api.get_lswitch_port(fip['port_id']))

        rules = self.nb_api.get_all_logical_routers_with_rports()[0]
        fip_rule = rules['dnat_and_snats'][0]

        if utils.is_nat_gateway_port_supported(self.nb_api):
            self.assertNotEqual([], fip_rule['gateway_port'])
        else:
            self.assertNotIn('gateway_port', fip_rule)


class TestRouterGWPort(_TestRouter):

    def _test_create_and_delete_router_gw_port(self, nested_snat=False):
        ext_net = self._make_network(
            self.fmt, 'ext_networktest', True, as_admin=True,
            arg_list=('router:external',
                      'provider:network_type',
                      'provider:physical_network'),
            **{'router:external': True,
               'provider:network_type': 'flat',
               'provider:physical_network': 'public'})['network']
        res = self._create_subnet(self.fmt, ext_net['id'], '100.0.0.0/24')
        ext_subnet = self.deserialize(self.fmt, res)['subnet']
        external_gateway_info = {
            'enable_snat': True,
            'network_id': ext_net['id'],
            'external_fixed_ips': [
                {'ip_address': '100.0.0.2', 'subnet_id': ext_subnet['id']}]}
        router = self._create_router(
            uuidutils.generate_uuid(),
            external_gateway_info=external_gateway_info)

        inner_network = self._make_network(
            self.fmt, 'inner_network', True)['network']
        subnet_cidr = '192.168.0.0/24'
        res = self._create_subnet(self.fmt, inner_network['id'],
                                  '192.168.0.0/24', gateway_ip='192.168.0.1',
                                  allocation_pools=[{'start': '192.168.0.2',
                                                     'end': '192.168.0.253'}],
                                  enable_dhcp=False)
        inner_subnet = self.deserialize(self.fmt, res)['subnet']
        self._add_router_interface(router['id'], inner_subnet['id'])

        # Check GW LRP.
        lr = self._ovn_client._nb_idl.lookup('Logical_Router',
                                             utils.ovn_name(router['id']))

        def _find_ext_gw_lrp(lr):
            for lrp in lr.ports:
                if (lrp.external_ids[ovn_const.OVN_ROUTER_IS_EXT_GW] ==
                        str(True)):
                    return lrp

        self.assertIsNotNone(_find_ext_gw_lrp(lr))

        nats = lr.nat
        self.assertEqual(1, len(nats))
        expected_logical_ip = (
            constants.IPv4_ANY if nested_snat else subnet_cidr
        )
        self.assertEqual(expected_logical_ip, nats[0].logical_ip)

        # Remove LR GW port and check.
        self._update_router(router['id'], {'external_gateway_info': {}})
        lr = self._ovn_client._nb_idl.lookup('Logical_Router',
                                             utils.ovn_name(router['id']))
        self.assertEqual([], lr.nat)
        self.assertIsNone(_find_ext_gw_lrp(lr))

    def test_create_and_delete_router_gw_port(self):
        self._test_create_and_delete_router_gw_port()

    def test_create_and_delete_router_gw_port_nested_snat(self):
        ovn_conf.cfg.CONF.set_override('ovn_router_indirect_snat', True, 'ovn')
        self._test_create_and_delete_router_gw_port(nested_snat=True)


class TestHAChassisGroupSync(base.TestOVNFunctionalBase):
    def test_ha_chassis_keep_priority_external_ports(self):
        for i in range(5):
            self.add_fake_chassis('host%d' % i, enable_chassis_as_gw=True,
                                  azs=[])
        net_arg = {external_net.EXTERNAL: True}
        with self.network('test-ovn-client', as_admin=True,
                          arg_list=tuple(net_arg.keys()), **net_arg) as net:
            with self.subnet(net) as subnet:
                port_arg = {
                    portbindings.VNIC_TYPE: portbindings.VNIC_BAREMETAL}
                with self.port(subnet,
                               arg_list=tuple(port_arg.keys()), **port_arg):
                    hcg1 = self.mech_driver._ovn_client._nb_idl.lookup(
                        'HA_Chassis_Group',
                        utils.ovn_name(net['network']['id']))
                    self.assertIsNotNone(hcg1)
                    master_ch1 = max(hcg1.ha_chassis, key=lambda x: x.priority,
                                     default=None)
                    with self.port(subnet, arg_list=tuple(port_arg.keys()),
                                   **port_arg):
                        hcg2 = self.mech_driver._ovn_client._nb_idl.lookup(
                            'HA_Chassis_Group',
                            utils.ovn_name(net['network']['id']))
                        master_ch2 = max(hcg2.ha_chassis,
                                         key=lambda x: x.priority,
                                         default=None)
                        # A second port created on this network will have the
                        # same HCG assigned and the same highest priority
                        # chassis.
                        self.assertEqual(master_ch1.chassis_name,
                                         master_ch2.chassis_name)
