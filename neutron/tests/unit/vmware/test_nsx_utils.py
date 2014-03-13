# Copyright (c) 2013 VMware.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import mock

from neutron.db import api as db_api
from neutron.openstack.common import uuidutils
from neutron.plugins.vmware.api_client import exception as api_exc
from neutron.plugins.vmware.common import exceptions as nsx_exc
from neutron.plugins.vmware.common import nsx_utils
from neutron.plugins.vmware.common import utils
from neutron.plugins.vmware import nsxlib
from neutron.tests import base
from neutron.tests.unit.vmware import nsx_method
from neutron.tests.unit.vmware.nsxlib import base as nsx_base


class NsxUtilsTestCase(base.BaseTestCase):

    def _mock_port_mapping_db_calls(self, ret_value):
        # Mock relevant db calls
        # This will allow for avoiding setting up the plugin
        # for creating db entries
        mock.patch(nsx_method('get_nsx_switch_and_port_id',
                              module_name='dbexts.db'),
                   return_value=ret_value).start()
        mock.patch(nsx_method('add_neutron_nsx_port_mapping',
                              module_name='dbexts.db')).start()
        mock.patch(nsx_method('delete_neutron_nsx_port_mapping',
                              module_name='dbexts.db')).start()

    def _mock_network_mapping_db_calls(self, ret_value):
        # Mock relevant db calls
        # This will allow for avoiding setting up the plugin
        # for creating db entries
        mock.patch(nsx_method('get_nsx_switch_ids',
                              module_name='dbexts.db'),
                   return_value=ret_value).start()
        mock.patch(nsx_method('add_neutron_nsx_network_mapping',
                              module_name='dbexts.db')).start()

    def _mock_router_mapping_db_calls(self, ret_value):
        # Mock relevant db calls
        # This will allow for avoiding setting up the plugin
        # for creating db entries
        mock.patch(nsx_method('get_nsx_router_id',
                              module_name='dbexts.db'),
                   return_value=ret_value).start()
        mock.patch(nsx_method('add_neutron_nsx_router_mapping',
                              module_name='dbexts.db')).start()

    def _verify_get_nsx_switch_and_port_id(self, exp_ls_uuid, exp_lp_uuid):
        # The nsxlib and db calls are mocked, therefore the cluster
        # and the neutron_port_id parameters can be set to None
        ls_uuid, lp_uuid = nsx_utils.get_nsx_switch_and_port_id(
            db_api.get_session(), None, None)
        self.assertEqual(exp_ls_uuid, ls_uuid)
        self.assertEqual(exp_lp_uuid, lp_uuid)

    def _verify_get_nsx_switch_ids(self, exp_ls_uuids):
        # The nsxlib and db calls are mocked, therefore the cluster
        # and the neutron_router_id parameters can be set to None
        ls_uuids = nsx_utils.get_nsx_switch_ids(
            db_api.get_session(), None, None)
        for ls_uuid in ls_uuids or []:
            self.assertIn(ls_uuid, exp_ls_uuids)
            exp_ls_uuids.remove(ls_uuid)
        self.assertFalse(exp_ls_uuids)

    def _verify_get_nsx_router_id(self, exp_lr_uuid):
        # The nsxlib and db calls are  mocked, therefore the cluster
        # and the neutron_router_id parameters can be set to None
        lr_uuid = nsx_utils.get_nsx_router_id(db_api.get_session(), None, None)
        self.assertEqual(exp_lr_uuid, lr_uuid)

    def test_get_nsx_switch_and_port_id_from_db_mappings(self):
        # This test is representative of the 'standard' case in which both the
        # switch and the port mappings were stored in the neutron db
        exp_ls_uuid = uuidutils.generate_uuid()
        exp_lp_uuid = uuidutils.generate_uuid()
        ret_value = exp_ls_uuid, exp_lp_uuid
        self._mock_port_mapping_db_calls(ret_value)
        self._verify_get_nsx_switch_and_port_id(exp_ls_uuid, exp_lp_uuid)

    def test_get_nsx_switch_and_port_id_only_port_db_mapping(self):
        # This test is representative of the case in which a port with a nsx
        # db mapping in the havana db was upgraded to icehouse
        exp_ls_uuid = uuidutils.generate_uuid()
        exp_lp_uuid = uuidutils.generate_uuid()
        ret_value = None, exp_lp_uuid
        self._mock_port_mapping_db_calls(ret_value)
        with mock.patch(nsx_method('query_lswitch_lports',
                                   module_name='nsxlib.switch'),
                        return_value=[{'uuid': exp_lp_uuid,
                                       '_relations': {
                                           'LogicalSwitchConfig': {
                                               'uuid': exp_ls_uuid}
                                       }}]):
            self._verify_get_nsx_switch_and_port_id(exp_ls_uuid, exp_lp_uuid)

    def test_get_nsx_switch_and_port_id_no_db_mapping(self):
        # This test is representative of the case where db mappings where not
        # found for a given port identifier
        exp_ls_uuid = uuidutils.generate_uuid()
        exp_lp_uuid = uuidutils.generate_uuid()
        ret_value = None, None
        self._mock_port_mapping_db_calls(ret_value)
        with mock.patch(nsx_method('query_lswitch_lports',
                                   module_name='nsxlib.switch'),
                        return_value=[{'uuid': exp_lp_uuid,
                                       '_relations': {
                                           'LogicalSwitchConfig': {
                                               'uuid': exp_ls_uuid}
                                       }}]):
            self._verify_get_nsx_switch_and_port_id(exp_ls_uuid, exp_lp_uuid)

    def test_get_nsx_switch_and_port_id_no_mappings_returns_none(self):
        # This test verifies that the function return (None, None) if the
        # mappings are not found both in the db and the backend
        ret_value = None, None
        self._mock_port_mapping_db_calls(ret_value)
        with mock.patch(nsx_method('query_lswitch_lports',
                                   module_name='nsxlib.switch'),
                        return_value=[]):
            self._verify_get_nsx_switch_and_port_id(None, None)

    def test_get_nsx_switch_ids_from_db_mappings(self):
        # This test is representative of the 'standard' case in which the
        # lswitch mappings were stored in the neutron db
        exp_ls_uuids = [uuidutils.generate_uuid()]
        self._mock_network_mapping_db_calls(exp_ls_uuids)
        self._verify_get_nsx_switch_ids(exp_ls_uuids)

    def test_get_nsx_switch_ids_no_db_mapping(self):
        # This test is representative of the case where db mappings where not
        # found for a given network identifier
        exp_ls_uuids = [uuidutils.generate_uuid()]
        self._mock_network_mapping_db_calls(None)
        with mock.patch(nsx_method('get_lswitches',
                                   module_name='nsxlib.switch'),
                        return_value=[{'uuid': uuid}
                                      for uuid in exp_ls_uuids]):
            self._verify_get_nsx_switch_ids(exp_ls_uuids)

    def test_get_nsx_switch_ids_no_mapping_returns_None(self):
        # This test verifies that the function returns None if the mappings
        # are not found both in the db and in the backend
        self._mock_network_mapping_db_calls(None)
        with mock.patch(nsx_method('get_lswitches',
                                   module_name='nsxlib.switch'),
                        return_value=[]):
            self._verify_get_nsx_switch_ids(None)

    def test_get_nsx_router_id_from_db_mappings(self):
        # This test is representative of the 'standard' case in which the
        # router mapping was stored in the neutron db
        exp_lr_uuid = uuidutils.generate_uuid()
        self._mock_router_mapping_db_calls(exp_lr_uuid)
        self._verify_get_nsx_router_id(exp_lr_uuid)

    def test_get_nsx_router_id_no_db_mapping(self):
        # This test is representative of the case where db mappings where not
        # found for a given port identifier
        exp_lr_uuid = uuidutils.generate_uuid()
        self._mock_router_mapping_db_calls(None)
        with mock.patch(nsx_method('query_lrouters',
                                   module_name='nsxlib.router'),
                        return_value=[{'uuid': exp_lr_uuid}]):
            self._verify_get_nsx_router_id(exp_lr_uuid)

    def test_get_nsx_router_id_no_mapping_returns_None(self):
        # This test verifies that the function returns None if the mapping
        # are not found both in the db and in the backend
        self._mock_router_mapping_db_calls(None)
        with mock.patch(nsx_method('query_lrouters',
                                   module_name='nsxlib.router'),
                        return_value=[]):
            self._verify_get_nsx_router_id(None)

    def test_check_and_truncate_name_with_none(self):
        name = None
        result = utils.check_and_truncate(name)
        self.assertEqual('', result)

    def test_check_and_truncate_name_with_short_name(self):
        name = 'foo_port_name'
        result = utils.check_and_truncate(name)
        self.assertEqual(name, result)

    def test_check_and_truncate_name_long_name(self):
        name = 'this_is_a_port_whose_name_is_longer_than_40_chars'
        result = utils.check_and_truncate(name)
        self.assertEqual(len(result), utils.MAX_DISPLAY_NAME_LEN)

    def test_build_uri_path_plain(self):
        result = nsxlib._build_uri_path('RESOURCE')
        self.assertEqual("%s/%s" % (nsxlib.URI_PREFIX, 'RESOURCE'), result)

    def test_build_uri_path_with_field(self):
        result = nsxlib._build_uri_path('RESOURCE', fields='uuid')
        expected = "%s/%s?fields=uuid" % (nsxlib.URI_PREFIX, 'RESOURCE')
        self.assertEqual(expected, result)

    def test_build_uri_path_with_filters(self):
        filters = {"tag": 'foo', "tag_scope": "scope_foo"}
        result = nsxlib._build_uri_path('RESOURCE', filters=filters)
        expected = (
            "%s/%s?tag_scope=scope_foo&tag=foo" %
            (nsxlib.URI_PREFIX, 'RESOURCE'))
        self.assertEqual(expected, result)

    def test_build_uri_path_with_resource_id(self):
        res = 'RESOURCE'
        res_id = 'resource_id'
        result = nsxlib._build_uri_path(res, resource_id=res_id)
        expected = "%s/%s/%s" % (nsxlib.URI_PREFIX, res, res_id)
        self.assertEqual(expected, result)

    def test_build_uri_path_with_parent_and_resource_id(self):
        parent_res = 'RESOURCE_PARENT'
        child_res = 'RESOURCE_CHILD'
        res = '%s/%s' % (child_res, parent_res)
        par_id = 'parent_resource_id'
        res_id = 'resource_id'
        result = nsxlib._build_uri_path(
            res, parent_resource_id=par_id, resource_id=res_id)
        expected = ("%s/%s/%s/%s/%s" %
                    (nsxlib.URI_PREFIX, parent_res, par_id, child_res, res_id))
        self.assertEqual(expected, result)

    def test_build_uri_path_with_attachment(self):
        parent_res = 'RESOURCE_PARENT'
        child_res = 'RESOURCE_CHILD'
        res = '%s/%s' % (child_res, parent_res)
        par_id = 'parent_resource_id'
        res_id = 'resource_id'
        result = nsxlib._build_uri_path(res, parent_resource_id=par_id,
                                        resource_id=res_id, is_attachment=True)
        expected = ("%s/%s/%s/%s/%s/%s" %
                    (nsxlib.URI_PREFIX, parent_res,
                     par_id, child_res, res_id, 'attachment'))
        self.assertEqual(expected, result)

    def test_build_uri_path_with_extra_action(self):
        parent_res = 'RESOURCE_PARENT'
        child_res = 'RESOURCE_CHILD'
        res = '%s/%s' % (child_res, parent_res)
        par_id = 'parent_resource_id'
        res_id = 'resource_id'
        result = nsxlib._build_uri_path(res, parent_resource_id=par_id,
                                        resource_id=res_id, extra_action='doh')
        expected = ("%s/%s/%s/%s/%s/%s" %
                    (nsxlib.URI_PREFIX, parent_res,
                     par_id, child_res, res_id, 'doh'))
        self.assertEqual(expected, result)

    def _mock_sec_group_mapping_db_calls(self, ret_value):
        mock.patch(nsx_method('get_nsx_security_group_id',
                              module_name='dbexts.db'),
                   return_value=ret_value).start()
        mock.patch(nsx_method('add_neutron_nsx_security_group_mapping',
                              module_name='dbexts.db')).start()

    def _verify_get_nsx_sec_profile_id(self, exp_sec_prof_uuid):
        # The nsxlib and db calls are  mocked, therefore the cluster
        # and the neutron_id parameters can be set to None
        sec_prof_uuid = nsx_utils.get_nsx_security_group_id(
            db_api.get_session(), None, None)
        self.assertEqual(exp_sec_prof_uuid, sec_prof_uuid)

    def test_get_nsx_sec_profile_id_from_db_mappings(self):
        # This test is representative of the 'standard' case in which the
        # security group mapping was stored in the neutron db
        exp_sec_prof_uuid = uuidutils.generate_uuid()
        self._mock_sec_group_mapping_db_calls(exp_sec_prof_uuid)
        self._verify_get_nsx_sec_profile_id(exp_sec_prof_uuid)

    def test_get_nsx_sec_profile_id_no_db_mapping(self):
        # This test is representative of the case where db mappings where not
        # found for a given security profile identifier
        exp_sec_prof_uuid = uuidutils.generate_uuid()
        self._mock_sec_group_mapping_db_calls(None)
        with mock.patch(nsx_method('query_security_profiles',
                                   module_name='nsxlib.secgroup'),
                        return_value=[{'uuid': exp_sec_prof_uuid}]):
            self._verify_get_nsx_sec_profile_id(exp_sec_prof_uuid)

    def test_get_nsx_sec_profile_id_no_mapping_returns_None(self):
        # This test verifies that the function returns None if the mapping
        # are not found both in the db and in the backend
        self._mock_sec_group_mapping_db_calls(None)
        with mock.patch(nsx_method('query_security_profiles',
                                   module_name='nsxlib.secgroup'),
                        return_value=[]):
            self._verify_get_nsx_sec_profile_id(None)


class ClusterManagementTestCase(nsx_base.NsxlibTestCase):

    def test_cluster_in_readonly_mode(self):
        with mock.patch.object(self.fake_cluster.api_client,
                               'request',
                               side_effect=api_exc.ReadOnlyMode):
            self.assertRaises(nsx_exc.MaintenanceInProgress,
                              nsxlib.do_request, cluster=self.fake_cluster)

    def test_cluster_method_not_implemented(self):
        self.assertRaises(api_exc.NsxApiException,
                          nsxlib.do_request,
                          nsxlib.HTTP_GET,
                          nsxlib._build_uri_path('MY_FAKE_RESOURCE',
                                                 resource_id='foo'),
                          cluster=self.fake_cluster)
