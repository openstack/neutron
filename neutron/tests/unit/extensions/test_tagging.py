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

from unittest import mock

import netaddr
from neutron_lib.api import attributes
from neutron_lib import constants as n_const
from neutron_lib import context
from neutron_lib import exceptions
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
        mock.patch.dict(
            attributes.RESOURCES,
            {
                'floatingips': {
                    'id': {'primary_key': True},
                    'router_id': {'required_by_policy': True},
                    'tenant_id': {'required_by_policy': True}
                },
                'network_segment_ranges': {
                    'id': {'primary_key': True},
                    'project_id': {'required_by_policy': True}
                },
                'policies':
                {
                    'id': {'primary_key': True},
                    'tenant_id': {'required_by_policy': True}
                },
                'routers':
                {
                    'id': {'primary_key': True},
                    'tenant_id': {'required_by_policy': True}
                },
                'security_groups':
                {
                    'id': {'primary_key': True},
                    'tenant_id': {'required_by_policy': True}
                },
                'trunks':
                {
                    'id': {'primary_key': True},
                    'port_id': {'required_by_policy': True},
                    'tenant_id': {'required_by_policy': True}
                }
            }
        ).start()

    def test_all_ovo_cls_have_a_reference(self):
        tc_supported_resources = set(self.tc.supported_resources.keys())
        ovo_resources = set(tagging.OVO_CLS.keys())
        self.assertEqual(tc_supported_resources, ovo_resources)

    def _check_resource_info(self, obj, obj_type):
        id_key = self.tc.supported_resources[obj_type] + '_id'
        res = self.tc._get_resource_info(self.ctx, {id_key: obj['id']})
        reference = tagging.ResourceInfo(self.project_id, obj_type, obj)
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
        expected_fip = {
            'attributes_to_update': ['tags'],
            'id': fip_id,
            'tenant_id': self.project_id,
            'project_id': self.project_id
        }
        self._check_resource_info(expected_fip, 'floatingips')

    def test__get_resource_info_network_segment_ranges(self):
        srange_id = uuidutils.generate_uuid()
        network_segment_range_obj.NetworkSegmentRange(
            self.ctx, id=srange_id, project_id=self.project_id,
            shared=False, network_type=n_const.TYPE_GENEVE,
            minimum=1, maximum=100).create()
        expected_segment = {
            'attributes_to_update': ['tags'],
            'id': srange_id,
            'project_id': self.project_id
        }
        self._check_resource_info(expected_segment, 'network_segment_ranges')

    def test__get_resource_info_networks(self):
        net_id = uuidutils.generate_uuid()
        network_obj.Network(
            self.ctx, id=net_id, project_id=self.project_id).create()
        expected_net = {
            'attributes_to_update': ['tags'],
            'id': net_id,
            'tenant_id': self.project_id,
            'project_id': self.project_id,
            'shared': False,
        }
        self._check_resource_info(expected_net, 'networks')

    def test__get_resource_info_policies(self):
        qos_id = uuidutils.generate_uuid()
        policy_obj.QosPolicy(
            self.ctx, id=qos_id, project_id=self.project_id).create()
        expected_qos = {
            'attributes_to_update': ['tags'],
            'id': qos_id,
            'tenant_id': self.project_id,
            'project_id': self.project_id
        }
        self._check_resource_info(expected_qos, 'policies')

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
        expected_port = {
            'attributes_to_update': ['tags'],
            'id': port_id,
            'tenant_id': self.project_id,
            'project_id': self.project_id,
            'network_id': net_id,
            'status': 'UP',
        }
        self._check_resource_info(expected_port, 'ports')

    def test__get_resource_info_routers(self):
        router_id = uuidutils.generate_uuid()
        router_obj.Router(
            self.ctx, id=router_id, project_id=self.project_id).create()
        expected_router = {
            'attributes_to_update': ['tags'],
            'id': router_id,
            'tenant_id': self.project_id,
            'project_id': self.project_id
        }
        self._check_resource_info(expected_router, 'routers')

    def test__get_resource_info_security_groups(self):
        sg_id = uuidutils.generate_uuid()
        securitygroup_obj.SecurityGroup(
            self.ctx, id=sg_id, project_id=self.project_id,
            is_default=True).create()
        expected_sg = {
            'attributes_to_update': ['tags'],
            'id': sg_id,
            'tenant_id': self.project_id,
            'project_id': self.project_id
        }
        self._check_resource_info(expected_sg, 'security_groups')

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
        expected_subnet = {
            'attributes_to_update': ['tags'],
            'id': subnet_id,
            'ip_version': n_const.IP_VERSION_4,
            'shared': False,
            'network_id': net_id,
            'tenant_id': self.project_id,
            'project_id': self.project_id
        }
        self._check_resource_info(expected_subnet, 'subnets')

    def test__get_resource_info_subnetpools(self):
        sp_id = uuidutils.generate_uuid()
        subnetpool_obj.SubnetPool(
            self.ctx, id=sp_id, project_id=self.project_id,
            ip_version=n_const.IP_VERSION_4, default_prefixlen=26,
            min_prefixlen=28, max_prefixlen=26).create()
        expected_sp = {
            'attributes_to_update': ['tags'],
            'id': sp_id,
            'tenant_id': self.project_id,
            'project_id': self.project_id,
            'ip_version': n_const.IP_VERSION_4,
            'shared': False,
            'is_default': False,
            'prefixes': [],
        }
        self._check_resource_info(expected_sp, 'subnetpools')

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
        expected_trunk = {
            'attributes_to_update': ['tags'],
            'id': trunk_id,
            'tenant_id': self.project_id,
            'project_id': self.project_id,
            'port_id': port_id
        }
        self._check_resource_info(expected_trunk, 'trunks')

    def test__get_resource_info_object_not_present(self):
        missing_id = uuidutils.generate_uuid()
        p_id = self.tc.supported_resources['trunks'] + '_id'
        res = self.tc._get_resource_info(self.ctx, {p_id: missing_id})
        self.assertEqual(tagging.EMPTY_RESOURCE_INFO, res)

    def test__get_resource_info_wrong_resource(self):
        missing_id = uuidutils.generate_uuid()
        res = self.tc._get_resource_info(self.ctx,
                                         {'wrong_resource_id': missing_id})
        self.assertEqual(tagging.EMPTY_RESOURCE_INFO, res)

    def test_create_tags_for_resource_below_max_tags_limit(self):
        req = mock.Mock(context=self.ctx)
        tags = ['tag-%i' % i for i in range(tagging.MAX_TAGS_COUNT - 1)]
        body = {'tags': tags}
        obj_mock = {
            'id': uuidutils.generate_uuid()
        }
        with mock.patch.object(self.tc, '_get_resource_info') as get_res, \
                mock.patch('neutron.policy.enforce') as policy_enforce, \
                mock.patch.object(tagging, 'notify_tag_action') as notify:
            self.tc.plugin = mock.Mock()
            get_res.return_value = mock.MagicMock(obj_type='networks',
                                                  obj=obj_mock)

            self.tc.create(req, body)

            get_res.assert_called_once_with(self.ctx, mock.ANY, tags=tags)
            policy_enforce.assert_called_once_with(
                self.ctx, mock.ANY, obj_mock)
            self.tc.plugin.create_tags.assert_called_once_with(
                self.ctx, mock.ANY, mock.ANY, body)
            notify.assert_has_calls([
                mock.call(self.ctx, 'create.start', mock.ANY, mock.ANY, tags),
                mock.call(self.ctx, 'create.end', mock.ANY, mock.ANY, tags)])

    def test_create_tags_for_resource_over_max_tags_limit(self):
        req = mock.Mock(context=self.ctx)
        tags = ['tag-%i' % i for i in range(tagging.MAX_TAGS_COUNT + 1)]
        body = {'tags': tags}
        obj_mock = {
            'id': uuidutils.generate_uuid()
        }
        with mock.patch.object(self.tc, '_get_resource_info') as get_res, \
                mock.patch('neutron.policy.enforce') as policy_enforce, \
                mock.patch.object(tagging, 'notify_tag_action') as notify:
            self.tc.plugin = mock.Mock()
            get_res.return_value = mock.MagicMock(obj_type='networks',
                                                  obj=obj_mock)

            self.assertRaises(
                exceptions.BadRequest,
                self.tc.create, req, body)

            get_res.assert_called_once_with(self.ctx, mock.ANY, tags=tags)
            policy_enforce.assert_called_once_with(
                self.ctx, mock.ANY, obj_mock)
            self.tc.plugin.create_tags.assert_not_called()
            notify.assert_not_called()

    def test_update_tag_for_resource_below_max_tags_limit(self):
        req = mock.Mock(context=self.ctx)
        kwargs = {'network_id': uuidutils.generate_uuid()}
        existing_tags = [
            'tag-%i' % i for i in range(tagging.MAX_TAGS_COUNT - 2)]
        new_tag = 'new-tag'
        obj_mock = {
            'id': uuidutils.generate_uuid()
        }
        with mock.patch.object(self.tc, '_get_resource_info') as get_res, \
                mock.patch('neutron.policy.enforce') as policy_enforce, \
                mock.patch.object(tagging, 'notify_tag_action') as notify:
            self.tc.plugin = mock.Mock()
            self.tc.plugin.get_tags.return_value = {'tags': existing_tags}
            get_res.return_value = mock.MagicMock(obj_type='networks',
                                                  obj=obj_mock)

            self.tc.update(req, new_tag, **kwargs)

            get_res.assert_called_once_with(self.ctx, kwargs, tags=[new_tag])
            policy_enforce.assert_called_once_with(
                self.ctx, mock.ANY, obj_mock)
            self.tc.plugin.get_tags.assert_called_once_with(
                self.ctx, mock.ANY, mock.ANY)
            self.tc.plugin.update_tag.assert_called_once_with(
                self.ctx, mock.ANY, mock.ANY, new_tag)
            notify.assert_has_calls([
                mock.call(
                    self.ctx, 'create.start', mock.ANY, mock.ANY, [new_tag]),
                mock.call(
                    self.ctx, 'create.end', mock.ANY, mock.ANY, [new_tag])])

    def test_update_exising_tag_for_resource_above_max_tags_limit(self):
        """Test to ensure that TaggingController.update() method is idempotent.
        """

        req = mock.Mock(context=self.ctx)
        kwargs = {'network_id': uuidutils.generate_uuid()}
        existing_tags = [
            'tag-%i' % i for i in range(tagging.MAX_TAGS_COUNT)]
        new_tag = existing_tags[0]
        obj_mock = {
            'id': uuidutils.generate_uuid()
        }
        with mock.patch.object(self.tc, '_get_resource_info') as get_res, \
                mock.patch('neutron.policy.enforce') as policy_enforce, \
                mock.patch.object(tagging, 'notify_tag_action') as notify:
            self.tc.plugin = mock.Mock()
            self.tc.plugin.get_tags.return_value = {'tags': existing_tags}
            get_res.return_value = mock.MagicMock(obj_type='networks',
                                                  obj=obj_mock)

            self.tc.update(req, new_tag, **kwargs)

            get_res.assert_called_once_with(self.ctx, kwargs, tags=[new_tag])
            policy_enforce.assert_called_once_with(
                self.ctx, mock.ANY, obj_mock)
            self.tc.plugin.get_tags.assert_called_once_with(
                self.ctx, mock.ANY, mock.ANY)
            self.tc.plugin.update_tag.assert_called_once_with(
                self.ctx, mock.ANY, mock.ANY, new_tag)
            notify.assert_has_calls([
                mock.call(
                    self.ctx, 'create.start', mock.ANY, mock.ANY, [new_tag]),
                mock.call(
                    self.ctx, 'create.end', mock.ANY, mock.ANY, [new_tag])])

    def test_update_tag_for_resource_over_max_tags_limit(self):
        req = mock.Mock(context=self.ctx)
        kwargs = {'network_id': uuidutils.generate_uuid()}
        existing_tags = ['tag-%i' % i for i in range(tagging.MAX_TAGS_COUNT)]
        new_tag = 'new-tag'
        obj_mock = {
            'id': uuidutils.generate_uuid()
        }
        with mock.patch.object(self.tc, '_get_resource_info') as get_res, \
                mock.patch('neutron.policy.enforce') as policy_enforce, \
                mock.patch.object(tagging, 'notify_tag_action') as notify:
            self.tc.plugin = mock.Mock()
            self.tc.plugin.get_tags.return_value = {'tags': existing_tags}
            get_res.return_value = mock.MagicMock(obj_type='networks',
                                                  obj=obj_mock)

            self.assertRaises(
                exceptions.BadRequest,
                self.tc.update, req, new_tag, **kwargs)

            get_res.assert_called_once_with(self.ctx, kwargs, tags=[new_tag])
            policy_enforce.assert_called_once_with(
                self.ctx, mock.ANY, obj_mock)
            self.tc.plugin.get_tags.assert_called_once_with(
                self.ctx, mock.ANY, mock.ANY)
            self.tc.plugin.update_tag.assert_not_called()
            notify.assert_not_called()

    def test_update_all_tags_for_resource_below_max_tags_limit(self):
        req = mock.Mock(context=self.ctx)
        tags = ['tag-%i' % i for i in range(tagging.MAX_TAGS_COUNT - 1)]
        body = {'tags': tags}
        obj_mock = {
            'id': uuidutils.generate_uuid()
        }
        with mock.patch.object(self.tc, '_get_resource_info') as get_res, \
                mock.patch('neutron.policy.enforce') as policy_enforce, \
                mock.patch.object(tagging, 'notify_tag_action') as notify:
            self.tc.plugin = mock.Mock()
            get_res.return_value = mock.MagicMock(obj_type='networks',
                                                  obj=obj_mock)

            self.tc.update_all(req, body)

            get_res.assert_called_once_with(self.ctx, mock.ANY, tags=tags)
            policy_enforce.assert_called_once_with(
                self.ctx, mock.ANY, obj_mock)
            self.tc.plugin.update_tags.assert_called_once_with(
                self.ctx, mock.ANY, mock.ANY, body)
            notify.assert_has_calls([
                mock.call(self.ctx, 'update.start', mock.ANY, mock.ANY, tags),
                mock.call(self.ctx, 'update.end', mock.ANY, mock.ANY, tags)])

    def test_update_all_tags_for_resource_over_max_tags_limit(self):
        req = mock.Mock(context=self.ctx)
        tags = ['tag-%i' % i for i in range(tagging.MAX_TAGS_COUNT + 1)]
        body = {'tags': tags}
        obj_mock = {
            'id': uuidutils.generate_uuid()
        }
        with mock.patch.object(self.tc, '_get_resource_info') as get_res, \
                mock.patch('neutron.policy.enforce') as policy_enforce, \
                mock.patch.object(tagging, 'notify_tag_action') as notify:
            self.tc.plugin = mock.Mock()
            get_res.return_value = mock.MagicMock(obj_type='networks',
                                                  obj=obj_mock)

            self.assertRaises(
                exceptions.BadRequest,
                self.tc.update_all, req, body)

            get_res.assert_called_once_with(self.ctx, mock.ANY, tags=tags)
            policy_enforce.assert_called_once_with(
                self.ctx, mock.ANY, obj_mock)
            self.tc.plugin.update_tags.assert_not_called()
            notify.assert_not_called()
