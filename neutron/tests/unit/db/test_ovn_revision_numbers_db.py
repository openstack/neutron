# Copyright 2019 Red Hat, Inc.
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

from neutron_lib.api.definitions import security_groups_remote_address_group \
    as sgag_def
from neutron_lib import constants as n_const
from neutron_lib import context
from neutron_lib.db import api as db_api
from oslo_db import exception as db_exc

from neutron.api import extensions
from neutron.common import config
from neutron.db.models import ovn as ovn_models
from neutron.db import ovn_revision_numbers_db as ovn_rn_db
import neutron.extensions
from neutron.services.revisions import revision_plugin
from neutron.tests.unit.db import test_db_base_plugin_v2
from neutron.tests.unit.extensions import test_l3
from neutron.tests.unit.extensions import test_securitygroup


EXTENSIONS_PATH = ':'.join(neutron.extensions.__path__)
PLUGIN_CLASS = (
    'neutron.tests.unit.db.test_ovn_revision_numbers_db.TestMaintenancePlugin')


class TestRevisionNumber(test_db_base_plugin_v2.NeutronDbPluginV2TestCase):

    def setUp(self):
        super(TestRevisionNumber, self).setUp()
        self.ctx = context.get_admin_context()
        self.addCleanup(self._delete_objs)
        res = self._create_network(fmt=self.fmt, name='net',
                                   admin_state_up=True)
        self.net = self.deserialize(self.fmt, res)['network']

    def _delete_objs(self):
        with db_api.CONTEXT_WRITER.using(self.ctx):
            self.ctx.session.query(
                ovn_models.OVNRevisionNumbers).delete()

    def _create_initial_revision(self, resource_uuid, resource_type,
                                 revision_number=ovn_rn_db.INITIAL_REV_NUM,
                                 may_exist=False):
        ovn_rn_db.create_initial_revision(
            self.ctx, resource_uuid, resource_type,
            revision_number=revision_number, may_exist=may_exist)

    def test_bump_revision(self):
        with db_api.CONTEXT_WRITER.using(self.ctx):
            self._create_initial_revision(self.net['id'],
                                          ovn_rn_db.TYPE_NETWORKS)
            self.net['revision_number'] = 123
            ovn_rn_db.bump_revision(self.ctx, self.net,
                                    ovn_rn_db.TYPE_NETWORKS)
            row = ovn_rn_db.get_revision_row(self.ctx, self.net['id'])
            self.assertEqual(123, row.revision_number)

    def test_bump_older_revision(self):
        with db_api.CONTEXT_WRITER.using(self.ctx):
            self._create_initial_revision(
                self.net['id'], ovn_rn_db.TYPE_NETWORKS,
                revision_number=124)
            self.net['revision_number'] = 1
            ovn_rn_db.bump_revision(self.ctx, self.net,
                                    ovn_rn_db.TYPE_NETWORKS)
            row = ovn_rn_db.get_revision_row(self.ctx, self.net['id'])
            self.assertEqual(124, row.revision_number)

    @mock.patch.object(ovn_rn_db.LOG, 'warning')
    def test_bump_revision_row_not_found(self, mock_log):
        with db_api.CONTEXT_WRITER.using(self.ctx):
            self.net['revision_number'] = 123
            ovn_rn_db.bump_revision(self.ctx, self.net,
                                    ovn_rn_db.TYPE_NETWORKS)
            # Assert the revision number wasn't bumped
            row = ovn_rn_db.get_revision_row(self.ctx, self.net['id'])
            self.assertEqual(123, row.revision_number)
            self.assertIn('No revision row found for',
                          mock_log.call_args[0][0])

    def test_delete_revision(self):
        with db_api.CONTEXT_WRITER.using(self.ctx):
            self._create_initial_revision(self.net['id'],
                                          ovn_rn_db.TYPE_NETWORKS)
            ovn_rn_db.delete_revision(self.ctx, self.net['id'],
                                      ovn_rn_db.TYPE_NETWORKS)
            row = ovn_rn_db.get_revision_row(self.ctx, self.net['id'])
            self.assertIsNone(row)

    def test_create_initial_revision_may_exist_duplicated_entry(self):
        try:
            with db_api.CONTEXT_WRITER.using(self.ctx):
                args = (self.net['id'], ovn_rn_db.TYPE_NETWORKS)
                self._create_initial_revision(*args)
                # DBDuplicateEntry is raised when may_exist is False (default)
                self._create_initial_revision(*args)
        except Exception as exc:
            if type(exc) is not db_exc.DBDuplicateEntry:
                self.fail("create_initial_revision with the same parameters "
                          "should have raised a DBDuplicateEntry exception")

        with db_api.CONTEXT_WRITER.using(self.ctx):
            args = (self.net['id'], ovn_rn_db.TYPE_NETWORKS)
            self._create_initial_revision(*args)
            try:
                self._create_initial_revision(*args, may_exist=True)
            except db_exc.DBDuplicateEntry:
                self.fail("create_initial_revision shouldn't raise "
                          "DBDuplicateEntry when may_exist is True")


class TestMaintenancePlugin(test_securitygroup.SecurityGroupTestPlugin,
                            test_l3.TestL3NatBasePlugin):

    __native_pagination_support = True
    __native_sorting_support = True

    supported_extension_aliases = ['external-net', 'security-group',
                                   sgag_def.ALIAS]


# Needed to extend resources for revision number tests, this is the
# least invasive way
class TestExtensionManager(extensions.PluginAwareExtensionManager):

    def get_resources(self):
        resources = super(TestExtensionManager, self).get_resources()
        sg_ext_mgr = test_securitygroup.SecurityGroupTestExtensionManager
        sg_resources = sg_ext_mgr.get_resources(self)
        sg_resources_collection_names = [
            res.collection for res in sg_resources]
        resources = [r for r in resources
                     if r.collection not in sg_resources_collection_names]
        return resources + sg_resources


class TestRevisionNumberMaintenance(test_securitygroup.SecurityGroupsTestCase,
                                    test_l3.L3NatTestCaseMixin):

    def setUp(self):
        service_plugins = {
            'router':
            'neutron.tests.unit.extensions.test_l3.TestL3NatServicePlugin'}
        super(TestRevisionNumberMaintenance, self).setUp(
              plugin=PLUGIN_CLASS, service_plugins=service_plugins)
        l3_plugin = test_l3.TestL3NatServicePlugin()
        sec_plugin = test_securitygroup.SecurityGroupTestPlugin()
        ext_mgr = TestExtensionManager(
            EXTENSIONS_PATH, {'router': l3_plugin, 'sec': sec_plugin}
        )
        app = config.load_paste_app('extensions_test_app')
        self.ext_api = extensions.ExtensionMiddleware(app, ext_mgr=ext_mgr)
        self.session = db_api.get_writer_session()
        revision_plugin.RevisionPlugin()
        self.net = self._make_network(self.fmt, 'net1', True)['network']

        # Mock the default value for INCONSISTENCIES_OLDER_THAN so
        # tests won't need to wait for the timeout in order to validate
        # the database inconsistencies
        self.older_than_mock = mock.patch(
            'neutron.db.ovn_revision_numbers_db.INCONSISTENCIES_OLDER_THAN',
            -1)
        self.older_than_mock.start()
        self.addCleanup(self.older_than_mock.stop)
        self.ctx = context.get_admin_context()

    def _create_initial_revision(self, resource_uuid, resource_type,
                                 revision_number=ovn_rn_db.INITIAL_REV_NUM,
                                 may_exist=False):
        with db_api.CONTEXT_WRITER.using(self.ctx):
            ovn_rn_db.create_initial_revision(
                self.ctx, resource_uuid, resource_type,
                revision_number=revision_number, may_exist=may_exist)

    def test_get_inconsistent_resources(self):
        # Set the intial revision to -1 to force it to be incosistent
        self._create_initial_revision(
            self.net['id'], ovn_rn_db.TYPE_NETWORKS, revision_number=-1)
        res = ovn_rn_db.get_inconsistent_resources(self.ctx)
        self.assertEqual(1, len(res))
        self.assertEqual(self.net['id'], res[0].resource_uuid)

    def test_get_inconsistent_resources_older_than(self):
        # Stop the mock so the INCONSISTENCIES_OLDER_THAN will have
        # it's default value
        self.older_than_mock.stop()
        self._create_initial_revision(
            self.net['id'], ovn_rn_db.TYPE_NETWORKS, revision_number=-1)
        res = ovn_rn_db.get_inconsistent_resources(self.ctx)

        # Assert that nothing is returned because the entry is not old
        # enough to be picked as an inconsistency
        self.assertEqual(0, len(res))

        # Start the mock again and make sure it nows shows up as an
        # inconsistency
        self.older_than_mock.start()
        res = ovn_rn_db.get_inconsistent_resources(self.ctx)
        self.assertEqual(1, len(res))
        self.assertEqual(self.net['id'], res[0].resource_uuid)

    def test_get_inconsistent_resources_consistent(self):
        # Set the initial revision to 0 which is the initial revision_number
        # for recently created resources
        self._create_initial_revision(
            self.net['id'], ovn_rn_db.TYPE_NETWORKS, revision_number=0)
        res = ovn_rn_db.get_inconsistent_resources(self.ctx)
        # Assert nothing is inconsistent
        self.assertEqual([], res)

    def test_get_deleted_resources(self):
        self._create_initial_revision(
            self.net['id'], ovn_rn_db.TYPE_NETWORKS, revision_number=0)
        self._delete('networks', self.net['id'])
        res = ovn_rn_db.get_deleted_resources(self.ctx)
        self.assertEqual(1, len(res))
        self.assertEqual(self.net['id'], res[0].resource_uuid)
        self.assertIsNone(res[0].standard_attr_id)

    def _prepare_resources_for_ordering_test(self, delete=False):
        subnet = self._make_subnet(self.fmt, {'network': self.net}, '10.0.0.1',
                                   '10.0.0.0/24')['subnet']
        self._set_net_external(self.net['id'])
        info = {'network_id': self.net['id']}
        router = self._make_router(self.fmt, None,
                                   external_gateway_info=info)['router']
        fip = self._make_floatingip(self.fmt, self.net['id'])['floatingip']
        port = self._make_port(self.fmt, self.net['id'])['port']
        sg = self._make_security_group(self.fmt, 'sg1', '')['security_group']
        rule = self._build_security_group_rule(
            sg['id'], 'ingress', n_const.PROTO_NUM_TCP)
        sg_rule = self._make_security_group_rule(
            self.fmt, rule)['security_group_rule']

        self._create_initial_revision(router['id'], ovn_rn_db.TYPE_ROUTERS)
        self._create_initial_revision(subnet['id'], ovn_rn_db.TYPE_SUBNETS)
        self._create_initial_revision(fip['id'], ovn_rn_db.TYPE_FLOATINGIPS)
        self._create_initial_revision(port['id'], ovn_rn_db.TYPE_PORTS)
        self._create_initial_revision(port['id'], ovn_rn_db.TYPE_ROUTER_PORTS)
        self._create_initial_revision(sg['id'], ovn_rn_db.TYPE_SECURITY_GROUPS)
        self._create_initial_revision(sg_rule['id'],
                                      ovn_rn_db.TYPE_SECURITY_GROUP_RULES)
        self._create_initial_revision(self.net['id'], ovn_rn_db.TYPE_NETWORKS)

        if delete:
            self._delete('security-group-rules', sg_rule['id'])
            self._delete('floatingips', fip['id'])
            self._delete('ports', port['id'])
            self._delete('security-groups', sg['id'])
            self._delete('routers', router['id'])
            self._delete('subnets', subnet['id'])
            self._delete('networks', self.net['id'])

    def test_get_inconsistent_resources_order(self):
        self._prepare_resources_for_ordering_test()
        res = ovn_rn_db.get_inconsistent_resources(self.ctx)
        actual_order = tuple(r.resource_type for r in res)
        self.assertEqual(ovn_rn_db._TYPES_PRIORITY_ORDER, actual_order)

    def test_get_deleted_resources_order(self):
        self._prepare_resources_for_ordering_test(delete=True)
        res = ovn_rn_db.get_deleted_resources(self.ctx)
        actual_order = tuple(r.resource_type for r in res)
        self.assertEqual(tuple(reversed(ovn_rn_db._TYPES_PRIORITY_ORDER)),
                         actual_order)
