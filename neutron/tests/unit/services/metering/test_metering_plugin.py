# Copyright (C) 2013 eNovance SAS <licensing@enovance.com>
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from unittest import mock

from neutron_lib.agent import topics
from neutron_lib.api.definitions import metering as metering_apidef
from neutron_lib import context
from neutron_lib.db import api as db_api
from neutron_lib.plugins import constants
from neutron_lib.plugins import directory
from neutron_lib.tests import tools
from neutron_lib.utils import net as net_utils

from oslo_serialization import jsonutils
from oslo_utils import uuidutils

from neutron.api.rpc.agentnotifiers import metering_rpc_agent_api
from neutron.db.metering import metering_rpc
from neutron.extensions import l3 as ext_l3
from neutron.extensions import metering as ext_metering
from neutron.objects import agent as agent_obj
from neutron.tests.common import helpers
from neutron.tests.unit.db.metering import test_metering_db
from neutron.tests.unit.db import test_db_base_plugin_v2
from neutron.tests.unit.extensions import test_l3


_uuid = uuidutils.generate_uuid

METERING_SERVICE_PLUGIN_KLASS = (
    "neutron.services.metering."
    "metering_plugin.MeteringPlugin"
)


class MeteringTestExtensionManager(object):

    def get_resources(self):
        l3_res = ext_l3.L3.get_resources()
        metering_res = ext_metering.Metering.get_resources()

        return l3_res + metering_res

    def get_actions(self):
        return []

    def get_request_extensions(self):
        return []


# TODO(akamyshnikova):we need this temporary FakeContext class while Context
# checking for existence of session attribute.
class FakeContext(context.ContextBaseWithSession):
    def __init__(self, *args, **kwargs):
        super(FakeContext, self).__init__(*args, **kwargs)
        self._session = None

    @property
    def session(self):
        if self._session is None:
            self._session = db_api.get_writer_session()
        return self._session


class TestMeteringPlugin(test_db_base_plugin_v2.NeutronDbPluginV2TestCase,
                         test_l3.L3NatTestCaseMixin,
                         test_metering_db.MeteringPluginDbTestCaseMixin):

    resource_prefix_map = dict(
        (k.replace('_', '-'), "/metering")
        for k in metering_apidef.RESOURCE_ATTRIBUTE_MAP.keys()
    )

    def setUp(self):
        plugin = 'neutron.tests.unit.extensions.test_l3.TestL3NatIntPlugin'
        service_plugins = {'metering_plugin_name':
                           METERING_SERVICE_PLUGIN_KLASS}
        ext_mgr = MeteringTestExtensionManager()
        super(TestMeteringPlugin, self).setUp(plugin=plugin, ext_mgr=ext_mgr,
                                              service_plugins=service_plugins)

        self.uuid = '654f6b9d-0f36-4ae5-bd1b-01616794ca60'

        uuid = 'oslo_utils.uuidutils.generate_uuid'
        self.uuid_patch = mock.patch(uuid, return_value=self.uuid)
        self.mock_uuid = self.uuid_patch.start()

        self.project_id = 'a7e61382-47b8-4d40-bae3-f95981b5637b'
        self.ctx = FakeContext('', self.project_id, is_admin=True)
        self.context_patch = mock.patch('neutron_lib.context.Context',
                                        return_value=self.ctx)
        self.mock_context = self.context_patch.start()

        self.topic = topics.METERING_AGENT

        add = ('neutron.api.rpc.agentnotifiers.' +
               'metering_rpc_agent_api.MeteringAgentNotifyAPI' +
               '.add_metering_label')
        self.add_patch = mock.patch(add)
        self.mock_add = self.add_patch.start()

        remove = ('neutron.api.rpc.agentnotifiers.' +
                  'metering_rpc_agent_api.MeteringAgentNotifyAPI' +
                  '.remove_metering_label')
        self.remove_patch = mock.patch(remove)
        self.mock_remove = self.remove_patch.start()

        update = ('neutron.api.rpc.agentnotifiers.' +
                  'metering_rpc_agent_api.MeteringAgentNotifyAPI' +
                  '.update_metering_label_rules')
        self.update_patch = mock.patch(update)
        self.mock_update = self.update_patch.start()

        add_rule = ('neutron.api.rpc.agentnotifiers.' +
                    'metering_rpc_agent_api.MeteringAgentNotifyAPI' +
                    '.add_metering_label_rule')
        self.add_rule_patch = mock.patch(add_rule)
        self.mock_add_rule = self.add_rule_patch.start()

        remove_rule = ('neutron.api.rpc.agentnotifiers.' +
                       'metering_rpc_agent_api.MeteringAgentNotifyAPI' +
                       '.remove_metering_label_rule')
        self.remove_rule_patch = mock.patch(remove_rule)
        self.mock_remove_rule = self.remove_rule_patch.start()

    def test_routers_updated_on_host_rpc_call(self):
        router_test = {
            'id': 'xyz',
            'name': 'testrouter'}
        notify_host = ('neutron.api.rpc.agentnotifiers.' +
                       'metering_rpc_agent_api.MeteringAgentNotifyAPI' +
                       '._notification_host')
        self.notify_patch = mock.patch(notify_host)
        self.mock_notify_host = self.notify_patch.start()
        metering_rpc_handle = metering_rpc_agent_api.MeteringAgentNotifyAPI()
        metering_rpc_handle.routers_updated_on_host(
            self.ctx,
            [router_test['id']],
            'test_host')
        self.mock_notify_host.assert_called_with(self.ctx, 'routers_updated',
                                                 'test_host', routers=['xyz'])

    def test_add_metering_label_rpc_call(self):
        second_uuid = 'e27fe2df-376e-4ac7-ae13-92f050a21f84'
        expected = [{'status': 'ACTIVE',
                     'name': 'router1',
                     'gw_port_id': None,
                     'admin_state_up': True,
                     'distributed': False,
                     'project_id': self.project_id,
                     '_metering_labels': [
                         {'rules': [],
                          'id': self.uuid, 'shared': False,
                          'name': 'label'}],
                     'id': self.uuid}]

        tenant_id_2 = '8a268a58-1610-4890-87e0-07abb8231206'
        self.mock_uuid.return_value = second_uuid
        with self.router(name='router2', tenant_id=tenant_id_2,
                         set_context=True):
            self.mock_uuid.return_value = self.uuid
            with self.router(name='router1', tenant_id=self.project_id,
                             set_context=True):
                with self.metering_label(tenant_id=self.project_id,
                                         set_context=True):
                    self.mock_add.assert_called_with(self.ctx, expected)

    def test_add_metering_label_shared_rpc_call(self):
        second_uuid = 'e27fe2df-376e-4ac7-ae13-92f050a21f84'
        expected = [{'status': 'ACTIVE',
                     'name': 'router1',
                     'gw_port_id': None,
                     'admin_state_up': True,
                     'distributed': False,
                     'project_id': self.project_id,
                     '_metering_labels': [
                         {'rules': [],
                          'id': self.uuid, 'shared': False,
                          'name': 'label'},
                         {'rules': [],
                          'id': second_uuid, 'shared': True,
                          'name': 'label'}],
                     'id': self.uuid}]

        tenant_id_2 = '8a268a58-1610-4890-87e0-07abb8231206'
        with self.router(name='router1', tenant_id=self.project_id,
                         shared=True, set_context=True):
            with self.metering_label(tenant_id=self.project_id,
                                     set_context=True):
                self.mock_uuid.return_value = second_uuid
                with self.metering_label(tenant_id=tenant_id_2, shared=True,
                                         set_context=True):
                    self.mock_add.assert_called_with(self.ctx, expected)

    def test_remove_metering_label_rpc_call(self):
        expected = [{'status': 'ACTIVE',
                     'name': 'router1',
                     'gw_port_id': None,
                     'admin_state_up': True,
                     'distributed': False,
                     'project_id': self.project_id,
                     '_metering_labels': [
                         {'rules': [],
                          'id': self.uuid, 'shared': False,
                          'name': 'label'}],
                     'id': self.uuid}]

        with self.router(tenant_id=self.project_id, set_context=True):
            with self.metering_label(tenant_id=self.project_id,
                                     set_context=True) as label:
                self.mock_add.assert_called_with(self.ctx, expected)
                self._delete('metering-labels',
                             label['metering_label']['id'])
            self.mock_remove.assert_called_with(self.ctx, expected)

    def test_remove_one_metering_label_rpc_call(self):
        second_uuid = 'e27fe2df-376e-4ac7-ae13-92f050a21f84'
        expected_add = [{'status': 'ACTIVE',
                         'name': 'router1',
                         'gw_port_id': None,
                         'admin_state_up': True,
                         'distributed': False,
                         'project_id': self.project_id,
                         '_metering_labels': [
                             {'rules': [],
                              'id': self.uuid, 'shared': False,
                              'name': 'label'},
                             {'rules': [],
                              'id': second_uuid, 'shared': False,
                              'name': 'label'}],
                         'id': self.uuid}]
        expected_remove = [{'status': 'ACTIVE',
                            'name': 'router1',
                            'gw_port_id': None,
                            'admin_state_up': True,
                            'distributed': False,
                            'project_id': self.project_id,
                            '_metering_labels': [
                                {'rules': [],
                                 'id': second_uuid, 'shared': False,
                                 'name': 'label'}],
                            'id': self.uuid}]

        with self.router(tenant_id=self.project_id, set_context=True):
            with self.metering_label(tenant_id=self.project_id,
                                     set_context=True):
                self.mock_uuid.return_value = second_uuid
                with self.metering_label(tenant_id=self.project_id,
                                         set_context=True) as label:
                    self.mock_add.assert_called_with(self.ctx, expected_add)
                    self._delete('metering-labels',
                                 label['metering_label']['id'])
                self.mock_remove.assert_called_with(self.ctx, expected_remove)

    def test_add_and_remove_metering_label_rule_rpc_call(self):
        second_uuid = 'e27fe2df-376e-4ac7-ae13-92f050a21f84'
        expected_add = [{'status': 'ACTIVE',
                         'name': 'router1',
                         'gw_port_id': None,
                         'admin_state_up': True,
                         'distributed': False,
                         'project_id': self.project_id,
                         '_metering_labels': [
                             {'rule': {
                                 'remote_ip_prefix':
                                     net_utils.AuthenticIPNetwork(
                                         '10.0.0.0/24'),
                                 'destination_ip_prefix': None,
                                 'source_ip_prefix': None,
                                 'direction': 'ingress',
                                 'metering_label_id': self.uuid,
                                 'excluded': False,
                                 'id': second_uuid},
                             'id': self.uuid}],
                         'id': self.uuid}]

        expected_del = [{'status': 'ACTIVE',
                         'name': 'router1',
                         'gw_port_id': None,
                         'admin_state_up': True,
                         'distributed': False,
                         'project_id': self.project_id,
                         '_metering_labels': [
                             {'rule': {
                                 'remote_ip_prefix':
                                     net_utils.AuthenticIPNetwork(
                                         '10.0.0.0/24'),
                                 'destination_ip_prefix': None,
                                 'source_ip_prefix': None,
                                 'direction': 'ingress',
                                 'metering_label_id': self.uuid,
                                 'excluded': False,
                                 'id': second_uuid},
                                 'id': self.uuid}],
                         'id': self.uuid}]

        remote_ip_prefix = {'remote_ip_prefix': '10.0.0.0/24'}
        with self.router(tenant_id=self.project_id, set_context=True):
            with self.metering_label(tenant_id=self.project_id,
                                     set_context=True) as label:
                la = label['metering_label']
                self.mock_uuid.return_value = second_uuid
                with self.metering_label_rule(la['id'], **remote_ip_prefix):
                    self.mock_add_rule.assert_called_with(self.ctx,
                                                          expected_add)
                    self._delete('metering-label-rules', second_uuid)
                self.mock_remove_rule.assert_called_with(self.ctx,
                                                         expected_del)

    def test_add_and_remove_metering_label_rule_source_ip_only(self):
        second_uuid = 'e27fe2df-376e-4ac7-ae13-92f050a21f84'
        expected_add = [{'status': 'ACTIVE',
                         'name': 'router1',
                         'gw_port_id': None,
                         'admin_state_up': True,
                         'distributed': False,
                         'project_id': self.project_id,
                         '_metering_labels': [
                             {'rule': {
                                 'source_ip_prefix':
                                     net_utils.AuthenticIPNetwork(
                                         '10.0.0.0/24'),
                                 'destination_ip_prefix': None,
                                 'remote_ip_prefix': None,
                                 'direction': 'ingress',
                                 'metering_label_id': self.uuid,
                                 'excluded': False,
                                 'id': second_uuid},
                              'id': self.uuid}],
                         'id': self.uuid}]

        expected_del = [{'status': 'ACTIVE',
                         'name': 'router1',
                         'gw_port_id': None,
                         'admin_state_up': True,
                         'distributed': False,
                         'project_id': self.project_id,
                         '_metering_labels': [
                             {'rule': {
                                 'source_ip_prefix':
                                     net_utils.AuthenticIPNetwork(
                                         '10.0.0.0/24'),
                                 'destination_ip_prefix': None,
                                 'remote_ip_prefix': None,
                                 'direction': 'ingress',
                                 'metering_label_id': self.uuid,
                                 'excluded': False,
                                 'id': second_uuid},
                              'id': self.uuid}],
                         'id': self.uuid}]

        source_ip_prefix = {'source_ip_prefix': '10.0.0.0/24'}
        with self.router(tenant_id=self.project_id, set_context=True):
            with self.metering_label(tenant_id=self.project_id,
                                     set_context=True) as label:
                la = label['metering_label']
                self.mock_uuid.return_value = second_uuid
                with self.metering_label_rule(la['id'],
                                              **source_ip_prefix):
                    self.mock_add_rule.assert_called_with(self.ctx,
                                                          expected_add)
                    self._delete('metering-label-rules', second_uuid)
                self.mock_remove_rule.assert_called_with(self.ctx,
                                                         expected_del)

    def test_add_and_remove_metering_label_rule_dest_ip_only(self):
        second_uuid = 'e27fe2df-376e-4ac7-ae13-92f050a21f84'
        expected_add = [{'status': 'ACTIVE',
                         'name': 'router1',
                         'gw_port_id': None,
                         'admin_state_up': True,
                         'distributed': False,
                         'project_id': self.project_id,
                         '_metering_labels': [
                             {'rule': {
                                 'destination_ip_prefix':
                                     net_utils.AuthenticIPNetwork(
                                         '10.0.0.0/24'),
                                 'source_ip_prefix': None,
                                 'remote_ip_prefix': None,
                                 'direction': 'ingress',
                                 'metering_label_id': self.uuid,
                                 'excluded': False,
                                 'id': second_uuid},
                              'id': self.uuid}],
                         'id': self.uuid}]

        expected_del = [{'status': 'ACTIVE',
                         'name': 'router1',
                         'gw_port_id': None,
                         'admin_state_up': True,
                         'distributed': False,
                         'project_id': self.project_id,
                         '_metering_labels': [
                             {'rule': {
                                 'destination_ip_prefix':
                                     net_utils.AuthenticIPNetwork(
                                         '10.0.0.0/24'),
                                 'source_ip_prefix': None,
                                 'remote_ip_prefix': None,
                                 'direction': 'ingress',
                                 'metering_label_id': self.uuid,
                                 'excluded': False,
                                 'id': second_uuid},
                              'id': self.uuid}],
                         'id': self.uuid}]

        source_ip_prefix = {'destination_ip_prefix': '10.0.0.0/24'}
        with self.router(tenant_id=self.project_id, set_context=True):
            with self.metering_label(tenant_id=self.project_id,
                                     set_context=True) as label:
                la = label['metering_label']
                self.mock_uuid.return_value = second_uuid
                with self.metering_label_rule(la['id'],
                                              **source_ip_prefix):
                    self.mock_add_rule.assert_called_with(self.ctx,
                                                          expected_add)
                    self._delete('metering-label-rules', second_uuid)
                self.mock_remove_rule.assert_called_with(self.ctx,
                                                         expected_del)

    def test_add_and_remove_metering_label_rule_src_and_dest_ip_only(self):
        second_uuid = 'e27fe2df-376e-4ac7-ae13-92f050a21f84'
        expected_add = [{'status': 'ACTIVE',
                         'name': 'router1',
                         'gw_port_id': None,
                         'admin_state_up': True,
                         'distributed': False,
                         'project_id': self.project_id,
                         '_metering_labels': [
                             {'rule': {
                                 'destination_ip_prefix':
                                     net_utils.AuthenticIPNetwork('0.0.0.0/0'),
                                 'source_ip_prefix':
                                     net_utils.AuthenticIPNetwork(
                                         '10.0.0.0/24'),
                                 'remote_ip_prefix': None,
                                 'direction': 'ingress',
                                 'metering_label_id': self.uuid,
                                 'excluded': False,
                                 'id': second_uuid},
                              'id': self.uuid}],
                         'id': self.uuid}]

        expected_del = [{'status': 'ACTIVE',
                         'name': 'router1',
                         'gw_port_id': None,
                         'admin_state_up': True,
                         'distributed': False,
                         'project_id': self.project_id,
                         '_metering_labels': [
                             {'rule': {
                                 'destination_ip_prefix':
                                     net_utils.AuthenticIPNetwork('0.0.0.0/0'),
                                 'source_ip_prefix':
                                     net_utils.AuthenticIPNetwork(
                                         '10.0.0.0/24'),
                                 'remote_ip_prefix': None,
                                 'direction': 'ingress',
                                 'metering_label_id': self.uuid,
                                 'excluded': False,
                                 'id': second_uuid},
                              'id': self.uuid}],
                         'id': self.uuid}]

        ip_prefixes = {'source_ip_prefix': '10.0.0.0/24',
                       'destination_ip_prefix': '0.0.0.0/0'}
        with self.router(tenant_id=self.project_id, set_context=True):
            with self.metering_label(tenant_id=self.project_id,
                                     set_context=True) as label:
                la = label['metering_label']
                self.mock_uuid.return_value = second_uuid
                with self.metering_label_rule(la['id'],
                                              **ip_prefixes):
                    self.mock_add_rule.assert_called_with(self.ctx,
                                                          expected_add)
                    self._delete('metering-label-rules', second_uuid)
                self.mock_remove_rule.assert_called_with(self.ctx,
                                                         expected_del)

    def test_add_and_remove_metering_label_rule_src_and_remote_ip(self):
        with self.router(tenant_id=self.project_id, set_context=True):
            with self.metering_label(tenant_id=self.project_id,
                                     set_context=True) as label:
                la = label['metering_label']

                res = self._create_metering_label_rule(
                    self.fmt, la['id'], 'ingress', False,
                    remote_ip_prefix='0.0.0.0/0',
                    source_ip_prefix='10.0.0.0/24')

                expected_error_code = 500
                self.assertEqual(expected_error_code, res.status_int)

                expected_error_message = "Cannot use 'remote-ip-prefix' in " \
                                         "conjunction with " \
                                         "'source-ip-prefix' or " \
                                         "'destination-ip-prefix'."

                self.assertEqual(
                    expected_error_message, jsonutils.loads(res.body)[
                        "NeutronError"]["message"])

    def test_add_and_remove_metering_label_rule_dest_and_remote_ip(self):
        with self.router(tenant_id=self.project_id, set_context=True):
            with self.metering_label(tenant_id=self.project_id,
                                     set_context=True) as label:
                la = label['metering_label']

                res = self._create_metering_label_rule(
                    self.fmt, la['id'], 'ingress', False,
                    remote_ip_prefix='0.0.0.0/0',
                    destination_ip_prefix='8.8.8.8/32')

                expected_error_code = 500
                self.assertEqual(expected_error_code, res.status_int)

                expected_error_message = "Cannot use 'remote-ip-prefix' in " \
                                         "conjunction with " \
                                         "'source-ip-prefix' or " \
                                         "'destination-ip-prefix'."

                self.assertEqual(
                    expected_error_message, jsonutils.loads(res.body)[
                        "NeutronError"]["message"])

    def test_add_and_remove_metering_label_rule_no_ip_prefix_entered(self):
        with self.router(tenant_id=self.project_id, set_context=True):
            with self.metering_label(tenant_id=self.project_id,
                                     set_context=True) as label:
                la = label['metering_label']

                res = self._create_metering_label_rule(
                    self.fmt, la['id'], 'ingress', False)

                expected_error_code = 500
                self.assertEqual(expected_error_code, res.status_int)

                expected_error_message = "You must define at least one of " \
                                         "the following parameters " \
                                         "'remote_ip_prefix', or " \
                                         "'source_ip_prefix' or " \
                                         "'destination_ip_prefix'."

                self.assertEqual(
                    expected_error_message, jsonutils.loads(res.body)[
                        "NeutronError"]["message"])

    def test_delete_metering_label_does_not_clear_router_tenant_id(self):
        tenant_id = '654f6b9d-0f36-4ae5-bd1b-01616794ca60'
        with self.metering_label(tenant_id=tenant_id) as metering_label:
            with self.router(tenant_id=tenant_id, set_context=True) as r:
                router = self._show('routers', r['router']['id'])
                self.assertEqual(tenant_id, router['router']['tenant_id'])
                metering_label_id = metering_label['metering_label']['id']
                self._delete('metering-labels', metering_label_id, 204)
                router = self._show('routers', r['router']['id'])
                self.assertEqual(tenant_id, router['router']['tenant_id'])


class TestMeteringPluginL3AgentScheduler(
        test_db_base_plugin_v2.NeutronDbPluginV2TestCase,
        test_l3.L3NatTestCaseMixin,
        test_metering_db.MeteringPluginDbTestCaseMixin):

    resource_prefix_map = dict(
        (k.replace('_', '-'), "/metering")
        for k in metering_apidef.RESOURCE_ATTRIBUTE_MAP.keys()
    )

    def setUp(self, plugin_str=None, service_plugins=None, scheduler=None):
        if not plugin_str:
            plugin_str = ('neutron.tests.unit.extensions.test_l3.'
                          'TestL3NatIntAgentSchedulingPlugin')

        if not service_plugins:
            service_plugins = {'metering_plugin_name':
                               METERING_SERVICE_PLUGIN_KLASS}

        if not scheduler:
            scheduler = plugin_str

        ext_mgr = MeteringTestExtensionManager()
        super(TestMeteringPluginL3AgentScheduler,
              self).setUp(plugin=plugin_str, ext_mgr=ext_mgr,
                          service_plugins=service_plugins)

        self.uuid = '654f6b9d-0f36-4ae5-bd1b-01616794ca60'

        uuid = 'oslo_utils.uuidutils.generate_uuid'
        self.uuid_patch = mock.patch(uuid, return_value=self.uuid)
        self.mock_uuid = self.uuid_patch.start()

        self.project_id = 'a7e61382-47b8-4d40-bae3-f95981b5637b'
        self.ctx = FakeContext('', self.project_id, is_admin=True)
        self.context_patch = mock.patch('neutron_lib.context.Context',
                                        return_value=self.ctx)
        self.mock_context = self.context_patch.start()

        self.l3routers_patch = mock.patch(scheduler +
                                          '.get_l3_agents_hosting_routers')
        self.l3routers_mock = self.l3routers_patch.start()

        self.topic = topics.METERING_AGENT

        add = ('neutron.api.rpc.agentnotifiers.' +
               'metering_rpc_agent_api.MeteringAgentNotifyAPI' +
               '.add_metering_label')
        self.add_patch = mock.patch(add)
        self.mock_add = self.add_patch.start()

        remove = ('neutron.api.rpc.agentnotifiers.' +
                  'metering_rpc_agent_api.MeteringAgentNotifyAPI' +
                  '.remove_metering_label')
        self.remove_patch = mock.patch(remove)
        self.mock_remove = self.remove_patch.start()

    def test_add_metering_label_rpc_call(self):
        second_uuid = 'e27fe2df-376e-4ac7-ae13-92f050a21f84'
        expected = [{'status': 'ACTIVE',
                     'name': 'router1',
                     'gw_port_id': None,
                     'admin_state_up': True,
                     'distributed': False,
                     'project_id': self.project_id,
                     '_metering_labels': [
                         {'rules': [],
                          'id': second_uuid, 'shared': False,
                          'name': 'label'}],
                     'id': self.uuid},
                    {'status': 'ACTIVE',
                     'name': 'router2',
                     'gw_port_id': None,
                     'admin_state_up': True,
                     'distributed': False,
                     'project_id': self.project_id,
                     '_metering_labels': [
                         {'rules': [],
                          'id': second_uuid, 'shared': False,
                          'name': 'label'}],
                     'id': second_uuid}]

        # bind each router to a specific agent
        agent1 = agent_obj.Agent(mock.ANY, host='agent1')
        agent2 = agent_obj.Agent(mock.ANY, host='agent2')

        agents = {self.uuid: agent1,
                  second_uuid: agent2}

        def side_effect(context, routers, admin_state_up, active):
            return [agents[routers[0]]]

        self.l3routers_mock.side_effect = side_effect

        with self.router(name='router1', tenant_id=self.project_id,
                         set_context=True):
            self.mock_uuid.return_value = second_uuid
            with self.router(name='router2', tenant_id=self.project_id,
                             set_context=True):
                with self.metering_label(tenant_id=self.project_id,
                                         set_context=True):
                    self.mock_add.assert_called_with(
                        self.ctx, tools.UnorderedList(expected))


class TestMeteringPluginL3AgentSchedulerServicePlugin(
        TestMeteringPluginL3AgentScheduler):

    """Unit tests for the case where separate service plugin
    implements L3 routing.
    """

    def setUp(self):
        l3_plugin = ('neutron.tests.unit.extensions.test_l3.'
                     'TestL3NatAgentSchedulingServicePlugin')
        service_plugins = {'metering_plugin_name':
                           METERING_SERVICE_PLUGIN_KLASS,
                           'l3_plugin_name': l3_plugin}

        plugin_str = ('neutron.tests.unit.extensions.test_l3.'
                      'TestNoL3NatPlugin')

        super(TestMeteringPluginL3AgentSchedulerServicePlugin, self).setUp(
            plugin_str=plugin_str, service_plugins=service_plugins,
            scheduler=l3_plugin)


class TestMeteringPluginRpcFromL3Agent(
        test_db_base_plugin_v2.NeutronDbPluginV2TestCase,
        test_l3.L3NatTestCaseMixin,
        test_metering_db.MeteringPluginDbTestCaseMixin):

    resource_prefix_map = dict(
        (k.replace('_', '-'), "/metering")
        for k in metering_apidef.RESOURCE_ATTRIBUTE_MAP
    )

    def setUp(self):
        service_plugins = {'metering_plugin_name':
                           METERING_SERVICE_PLUGIN_KLASS}

        plugin = ('neutron.tests.unit.extensions.test_l3.'
                  'TestL3NatIntAgentSchedulingPlugin')

        ext_mgr = MeteringTestExtensionManager()
        super(TestMeteringPluginRpcFromL3Agent,
              self).setUp(plugin=plugin, service_plugins=service_plugins,
                          ext_mgr=ext_mgr)

        self.meter_plugin = directory.get_plugin(constants.METERING)

        self.tenant_id = 'admin_tenant_id'
        self.tenant_id_1 = 'tenant_id_1'
        self.tenant_id_2 = 'tenant_id_2'

        self.adminContext = context.get_admin_context()
        helpers.register_l3_agent(host='agent1')

    def test_get_sync_data_metering(self):
        with self.subnet() as subnet:
            s = subnet['subnet']
            self._set_net_external(s['network_id'])
            with self.router(name='router1', subnet=subnet) as router:
                r = router['router']
                self._add_external_gateway_to_router(r['id'], s['network_id'])
                with self.metering_label(tenant_id=r['tenant_id']):
                    callbacks = metering_rpc.MeteringRpcCallbacks(
                        self.meter_plugin)
                    data = callbacks.get_sync_data_metering(self.adminContext,
                                                            host='agent1')
                    self.assertEqual('router1', data[0]['name'])

                    helpers.register_l3_agent(host='agent2')
                    data = callbacks.get_sync_data_metering(self.adminContext,
                                                            host='agent2')
                    self.assertFalse(data)

                self._remove_external_gateway_from_router(
                    r['id'], s['network_id'])

    def test_get_sync_data_metering_shared(self):
        with self.router(name='router1', tenant_id=self.tenant_id_1):
            with self.router(name='router2', tenant_id=self.tenant_id_2):
                with self.metering_label(tenant_id=self.tenant_id,
                                         shared=True):
                    callbacks = metering_rpc.MeteringRpcCallbacks(
                        self.meter_plugin)
                    data = callbacks.get_sync_data_metering(self.adminContext)

                    routers = [router['name'] for router in data]

                    self.assertIn('router1', routers)
                    self.assertIn('router2', routers)

    def test_get_sync_data_metering_not_shared(self):
        with self.router(name='router1', tenant_id=self.tenant_id_1):
            with self.router(name='router2', tenant_id=self.tenant_id_2):
                with self.metering_label(tenant_id=self.tenant_id):
                    callbacks = metering_rpc.MeteringRpcCallbacks(
                        self.meter_plugin)
                    data = callbacks.get_sync_data_metering(self.adminContext)

                    routers = [router['name'] for router in data]

                    self.assertEqual([], routers)

    def test_get_sync_data_metering_with_unscheduled_router(self):
        with self.subnet() as subnet:
            s = subnet['subnet']
            self._set_net_external(s['network_id'])
            with self.router(
                name='router1', tenant_id=self.tenant_id
            ) as router1:
                self._add_external_gateway_to_router(
                    router1['router']['id'], s['network_id'])
                with self.router(name='router2', tenant_id=self.tenant_id):
                    with self.metering_label(tenant_id=self.tenant_id):
                        callbacks = metering_rpc.MeteringRpcCallbacks(
                            self.meter_plugin)
                        data = callbacks.get_sync_data_metering(
                            self.adminContext, host='agent1')
                        self.assertEqual(
                            set(['router1']), set([r['name'] for r in data]))

                self._remove_external_gateway_from_router(
                    router1['router']['id'], s['network_id'])

    def test_get_sync_data_metering_with_inactive_router(self):
        with self.subnet() as subnet:
            s = subnet['subnet']
            self._set_net_external(s['network_id'])
            with self.router(
                name='router1', tenant_id=self.tenant_id
            ) as router1:
                self._add_external_gateway_to_router(
                    router1['router']['id'], s['network_id'])
                with self.router(
                    name='router2', tenant_id=self.tenant_id,
                    admin_state_up=False
                ) as router2:
                    self._add_external_gateway_to_router(
                        router2['router']['id'], s['network_id'])
                    with self.metering_label(tenant_id=self.tenant_id):
                        callbacks = metering_rpc.MeteringRpcCallbacks(
                            self.meter_plugin)
                        data = callbacks.get_sync_data_metering(
                            self.adminContext, host='agent1')
                        self.assertEqual(
                            set(['router1']), set([r['name'] for r in data]))

                    self._remove_external_gateway_from_router(
                        router2['router']['id'], s['network_id'])

                self._remove_external_gateway_from_router(
                    router1['router']['id'], s['network_id'])
