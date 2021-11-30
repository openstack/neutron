# Copyright 2021 Huawei, Inc.
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

from unittest import mock

from neutron_lib.callbacks import events as lib_events
from neutron_lib.callbacks import registry as lib_registry
from neutron_lib import context
from oslo_utils import uuidutils

from neutron.agent.l2.extensions import local_ip as local_ip_ext
from neutron.api.rpc.callbacks import events
from neutron.api.rpc.callbacks import resources
from neutron.objects import local_ip as lip_obj
from neutron.plugins.ml2.drivers.openvswitch.agent \
    import ovs_agent_extension_api as ovs_ext_api
from neutron.tests import base


class LocalIPAgentExtensionTestCase(base.BaseTestCase):

    def setUp(self):
        super(LocalIPAgentExtensionTestCase, self).setUp()
        self.context = context.get_admin_context_without_session()
        self.local_ip_ext = local_ip_ext.LocalIPAgentExtension()

        self.int_br = mock.Mock()
        self.tun_br = mock.Mock()
        self.plugin_rpc = mock.Mock()
        self.agent_api = ovs_ext_api.OVSAgentExtensionAPI(
            self.int_br,
            self.tun_br,
            phys_brs=None,
            plugin_rpc=self.plugin_rpc)
        self.local_ip_ext.consume_api(self.agent_api)
        with mock.patch.object(
                self.local_ip_ext, '_pull_all_local_ip_associations'):
            self.local_ip_ext.initialize(mock.Mock(), 'ovs')

    def _generate_test_lip_associations(self, count=2):
        return [lip_obj.LocalIPAssociation(
            fixed_port_id=uuidutils.generate_uuid(),
            local_ip_id=uuidutils.generate_uuid(),
            local_ip=lip_obj.LocalIP()) for _ in range(count)
        ]

    def test_pulling_lip_associations_on_init(self):
        res_rpc = mock.Mock()
        lip_assocs = self._generate_test_lip_associations()
        with mock.patch('neutron.api.rpc.handlers.'
                        'resources_rpc.ResourcesPullRpcApi') as res_rpc_cls:
            res_rpc_cls.return_value = res_rpc
            res_rpc.bulk_pull.return_value = lip_assocs
            self.local_ip_ext.initialize(mock.Mock(), 'ovs')

        res_rpc.bulk_pull.assert_called_once_with(
            mock.ANY, resources.LOCAL_IP_ASSOCIATION)

        for assoc in lip_assocs:
            self.assertEqual(
                assoc, self.local_ip_ext.local_ip_updates[
                    'added'][assoc.fixed_port_id][assoc.local_ip_id])

    def test_notify_port_updated(self):
        with mock.patch.object(lib_registry, "publish") as publish_mock:
            port_id = 'test'
            self.local_ip_ext._notify_port_updated(
                self.context, port_id=port_id)
            publish_mock.assert_called_once_with(
                resources.PORT, lib_events.AFTER_UPDATE,
                self.local_ip_ext, payload=mock.ANY)
            actual_payload = publish_mock.call_args[1]['payload']
            self.assertEqual(port_id, actual_payload.resource_id)
            self.assertEqual({'changed_fields': {'local_ip'}},
                             actual_payload.metadata)

    def test_handle_updated_notification(self):
        lip_assocs = self._generate_test_lip_associations()
        with mock.patch.object(
                self.local_ip_ext,
                "_notify_port_updated") as port_update_notify:
            self.local_ip_ext._handle_notification(
                self.context, resources.LOCAL_IP_ASSOCIATION,
                lip_assocs, events.UPDATED)

        for assoc in lip_assocs:
            self.assertEqual(
                assoc, self.local_ip_ext.local_ip_updates[
                    'added'][assoc.fixed_port_id][assoc.local_ip_id])
            port_update_notify.assert_any_call(
                self.context, assoc.fixed_port_id)

        return lip_assocs

    def test_handle_deleted_notification(self, lip_assocs=None):
        lip_assocs = lip_assocs or self.test_handle_updated_notification()
        with mock.patch.object(
                self.local_ip_ext,
                "_notify_port_updated") as port_update_notify:
            self.local_ip_ext._handle_notification(
                self.context, resources.LOCAL_IP_ASSOCIATION,
                lip_assocs, events.DELETED)
            for assoc in lip_assocs:
                self.assertEqual({}, self.local_ip_ext.local_ip_updates[
                    'added'][assoc.fixed_port_id])
                self.assertEqual(
                    assoc, self.local_ip_ext.local_ip_updates[
                        'deleted'][assoc.fixed_port_id][assoc.local_ip_id])
                port_update_notify.assert_any_call(
                    self.context, assoc.fixed_port_id)

    def test_handle_port(self):
        lip_assocs = self.test_handle_updated_notification()
        for assoc in lip_assocs:
            port = {'port_id': assoc.fixed_port_id}
            self.local_ip_ext.handle_port(self.context, port)
            self.assertEqual({}, self.local_ip_ext.local_ip_updates[
                'added'][assoc.fixed_port_id])
        self.test_handle_deleted_notification(lip_assocs)
        for assoc in lip_assocs:
            port = {'port_id': assoc.fixed_port_id}
            self.local_ip_ext.handle_port(self.context, port)
            self.assertEqual({}, self.local_ip_ext.local_ip_updates[
                'deleted'][assoc.fixed_port_id])

    def test_delete_port(self):
        lip_assocs = self.test_handle_updated_notification()
        for assoc in lip_assocs:
            port = {'port_id': assoc.fixed_port_id}
            self.local_ip_ext.delete_port(self.context, port)

        self.assertEqual({}, self.local_ip_ext.local_ip_updates['added'])
        self.assertEqual({}, self.local_ip_ext.local_ip_updates['added'])
