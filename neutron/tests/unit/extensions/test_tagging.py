# Copyright 2024 Red Hat, Inc.
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

import netaddr
from neutron_lib import constants as n_const
from neutron_lib import context
from neutron_lib.utils import net as net_utils
from oslo_utils import uuidutils

from neutron.extensions import tagging
from neutron.objects import network as network_obj
from neutron.objects import network_segment_range as network_segment_range_obj
from neutron.objects import ports as ports_obj
from neutron.objects.qos import policy as policy_obj
from neutron.objects import router as router_obj
from neutron.objects import securitygroup as securitygroup_obj
from neutron.objects import subnet as subnet_obj
from neutron.objects import subnetpool as subnetpool_obj
from neutron.objects import trunk as trunk_obj
from neutron.tests.unit import testlib_api


class TaggingControllerDbTestCase(testlib_api.WebTestCase):
    def setUp(self):
        super().setUp()
        self.user_id = uuidutils.generate_uuid()
        self.project_id = uuidutils.generate_uuid()
        self.ctx = context.Context(user_id=self.user_id,
                                   tenant_id=self.project_id,
                                   is_admin=False)
        self.tc = tagging.TaggingController()

    def test_all_parents_have_a_reference(self):
        tc_supported_resources = set(self.tc.supported_resources.keys())
        parent_resources = set(tagging.PARENTS.keys())
        self.assertEqual(tc_supported_resources, parent_resources)

    def _check_resource_info(self, parent_id, parent_type,
                             upper_parent_id=None, upper_parent_type=None):
        p_id = self.tc.supported_resources[parent_type] + '_id'
        res = self.tc._get_resource_info(self.ctx, {p_id: parent_id})
        reference = tagging.ResourceInfo(
            self.project_id, parent_type, parent_id,
            upper_parent_type, upper_parent_id)
        self.assertEqual(reference, res)

    def test__get_resource_info_floatingips(self):
        ext_net_id = uuidutils.generate_uuid()
        fip_port_id = uuidutils.generate_uuid()
        fip_id = uuidutils.generate_uuid()
        network_obj.Network(
            self.ctx, id=ext_net_id, project_id=self.project_id).create()
        network_obj.ExternalNetwork(
            self.ctx, project_id=self.project_id,
            network_id=ext_net_id).create()
        mac_str = next(net_utils.random_mac_generator(
            ['ca', 'fe', 'ca', 'fe']))
        mac = netaddr.EUI(mac_str)
        ports_obj.Port(
            self.ctx, id=fip_port_id, project_id=self.project_id,
            mac_address=mac, network_id=ext_net_id, admin_state_up=True,
            status='UP', device_id='', device_owner='').create()
        ip_address = netaddr.IPAddress('1.2.3.4')
        router_obj.FloatingIP(
            self.ctx, id=fip_id, project_id=self.project_id,
            floating_network_id=ext_net_id, floating_port_id=fip_port_id,
            floating_ip_address=ip_address).create()
        self._check_resource_info(fip_id, 'floatingips')

    def test__get_resource_info_network_segment_ranges(self):
        srange_id = uuidutils.generate_uuid()
        network_segment_range_obj.NetworkSegmentRange(
            self.ctx, id=srange_id, project_id=self.project_id,
            shared=False, network_type=n_const.TYPE_GENEVE).create()
        self._check_resource_info(srange_id, 'network_segment_ranges')

    def test__get_resource_info_networks(self):
        net_id = uuidutils.generate_uuid()
        network_obj.Network(
            self.ctx, id=net_id, project_id=self.project_id).create()
        self._check_resource_info(net_id, 'networks')

    def test__get_resource_info_policies(self):
        qos_id = uuidutils.generate_uuid()
        policy_obj.QosPolicy(
            self.ctx, id=qos_id, project_id=self.project_id).create()
        self._check_resource_info(qos_id, 'policies')

    def test__get_resource_info_ports(self):
        net_id = uuidutils.generate_uuid()
        port_id = uuidutils.generate_uuid()
        network_obj.Network(
            self.ctx, id=net_id, project_id=self.project_id).create()
        mac_str = next(net_utils.random_mac_generator(
            ['ca', 'fe', 'ca', 'fe']))
        mac = netaddr.EUI(mac_str)
        ports_obj.Port(
            self.ctx, id=port_id, project_id=self.project_id,
            mac_address=mac, network_id=net_id, admin_state_up=True,
            status='UP', device_id='', device_owner='').create()
        self._check_resource_info(port_id, 'ports')

    def test__get_resource_info_routers(self):
        router_id = uuidutils.generate_uuid()
        router_obj.Router(
            self.ctx, id=router_id, project_id=self.project_id).create()
        self._check_resource_info(router_id, 'routers')

    def test__get_resource_info_security_groups(self):
        sg_id = uuidutils.generate_uuid()
        securitygroup_obj.SecurityGroup(
            self.ctx, id=sg_id, project_id=self.project_id,
            is_default=True).create()
        self._check_resource_info(sg_id, 'security_groups')

    def test__get_resource_info_subnets(self):
        net_id = uuidutils.generate_uuid()
        subnet_id = uuidutils.generate_uuid()
        network_obj.Network(
            self.ctx, id=net_id, project_id=self.project_id).create()
        cidr = netaddr.IPNetwork('1.2.3.0/24')
        subnet_obj.Subnet(
            self.ctx, id=subnet_id, project_id=self.project_id,
            ip_version=n_const.IP_VERSION_4, cidr=cidr,
            network_id=net_id).create()
        self._check_resource_info(subnet_id, 'subnets',
                                  upper_parent_id=net_id,
                                  upper_parent_type='networks')

    def test__get_resource_info_subnetpools(self):
        sp_id = uuidutils.generate_uuid()
        subnetpool_obj.SubnetPool(
            self.ctx, id=sp_id, project_id=self.project_id,
            ip_version=n_const.IP_VERSION_4, default_prefixlen=26,
            min_prefixlen=28, max_prefixlen=26).create()
        self._check_resource_info(sp_id, 'subnetpools')

    def test__get_resource_info_trunks(self):
        trunk_id = uuidutils.generate_uuid()
        net_id = uuidutils.generate_uuid()
        port_id = uuidutils.generate_uuid()
        network_obj.Network(
            self.ctx, id=net_id, project_id=self.project_id).create()
        mac_str = next(net_utils.random_mac_generator(
            ['ca', 'fe', 'ca', 'fe']))
        mac = netaddr.EUI(mac_str)
        ports_obj.Port(
            self.ctx, id=port_id, project_id=self.project_id,
            mac_address=mac, network_id=net_id, admin_state_up=True,
            status='UP', device_id='', device_owner='').create()
        trunk_obj.Trunk(
            self.ctx, id=trunk_id, project_id=self.project_id,
            port_id=port_id).create()
        self._check_resource_info(trunk_id, 'trunks')

    def test__get_resource_info_parent_not_present(self):
        missing_id = uuidutils.generate_uuid()
        p_id = self.tc.supported_resources['trunks'] + '_id'
        res = self.tc._get_resource_info(self.ctx, {p_id: missing_id})
        self.assertEqual(tagging.EMPTY_RESOURCE_INFO, res)

    def test__get_resource_info_wrong_resource(self):
        missing_id = uuidutils.generate_uuid()
        res = self.tc._get_resource_info(self.ctx,
                                         {'wrong_resource_id': missing_id})
        self.assertEqual(tagging.EMPTY_RESOURCE_INFO, res)
