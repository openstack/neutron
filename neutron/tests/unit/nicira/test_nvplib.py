# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright (c) 2013 OpenStack Foundation.
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
#
# @author: Salvatore Orlando, VMware

import mock

from neutron.common import exceptions
from neutron.plugins.nicira.common import config  # noqa
from neutron.plugins.nicira.common import exceptions as nvp_exc
from neutron.plugins.nicira.common import utils
from neutron.plugins.nicira import nsx_cluster
from neutron.plugins.nicira import NvpApiClient
from neutron.plugins.nicira import nvplib
from neutron.tests import base
from neutron.tests.unit.nicira import fake_nvpapiclient
from neutron.tests.unit.nicira import NVPAPI_NAME
from neutron.tests.unit.nicira import STUBS_PATH
from neutron.tests.unit import test_api_v2


_uuid = test_api_v2._uuid


class NvplibTestCase(base.BaseTestCase):

    def setUp(self):
        # mock nvp api client
        self.fc = fake_nvpapiclient.FakeClient(STUBS_PATH)
        self.mock_nvpapi = mock.patch(NVPAPI_NAME, autospec=True)
        instance = self.mock_nvpapi.start()
        instance.return_value.login.return_value = "the_cookie"
        fake_version = getattr(self, 'fake_version', "3.0")
        instance.return_value.get_nvp_version.return_value = (
            NvpApiClient.NVPVersion(fake_version))

        def _fake_request(*args, **kwargs):
            return self.fc.fake_request(*args, **kwargs)

        instance.return_value.request.side_effect = _fake_request
        self.fake_cluster = nsx_cluster.NSXCluster(
            name='fake-cluster', nsx_controllers=['1.1.1.1:999'],
            default_tz_uuid=_uuid(), nsx_user='foo', nsx_password='bar')
        self.fake_cluster.api_client = NvpApiClient.NVPApiHelper(
            ('1.1.1.1', '999', True),
            self.fake_cluster.nsx_user, self.fake_cluster.nsx_password,
            self.fake_cluster.req_timeout, self.fake_cluster.http_timeout,
            self.fake_cluster.retries, self.fake_cluster.redirects)

        super(NvplibTestCase, self).setUp()
        self.addCleanup(self.fc.reset_all)
        self.addCleanup(self.mock_nvpapi.stop)

    def _build_tag_dict(self, tags):
        # This syntax is needed for python 2.6 compatibility
        return dict((t['scope'], t['tag']) for t in tags)


class NsxlibNegativeBaseTestCase(base.BaseTestCase):

    def setUp(self):
        # mock nvp api client
        self.fc = fake_nvpapiclient.FakeClient(STUBS_PATH)
        self.mock_nvpapi = mock.patch(NVPAPI_NAME, autospec=True)
        instance = self.mock_nvpapi.start()
        instance.return_value.login.return_value = "the_cookie"
        # Choose 3.0, but the version is irrelevant for the aim of
        # these tests as calls are throwing up errors anyway
        fake_version = getattr(self, 'fake_version', "3.0")
        instance.return_value.get_nvp_version.return_value = (
            NvpApiClient.NVPVersion(fake_version))

        def _faulty_request(*args, **kwargs):
            raise nvplib.NvpApiClient.NvpApiException

        instance.return_value.request.side_effect = _faulty_request
        self.fake_cluster = nsx_cluster.NSXCluster(
            name='fake-cluster', nsx_controllers=['1.1.1.1:999'],
            default_tz_uuid=_uuid(), nsx_user='foo', nsx_password='bar')
        self.fake_cluster.api_client = NvpApiClient.NVPApiHelper(
            ('1.1.1.1', '999', True),
            self.fake_cluster.nsx_user, self.fake_cluster.nsx_password,
            self.fake_cluster.req_timeout, self.fake_cluster.http_timeout,
            self.fake_cluster.retries, self.fake_cluster.redirects)

        super(NsxlibNegativeBaseTestCase, self).setUp()
        self.addCleanup(self.fc.reset_all)
        self.addCleanup(self.mock_nvpapi.stop)


class TestNvplibSecurityProfile(NvplibTestCase):

    def test_create_and_get_security_profile(self):
        sec_prof = nvplib.create_security_profile(self.fake_cluster,
                                                  'pippo', {'name': 'test'})
        sec_prof_res = nvplib.do_request(
            nvplib.HTTP_GET,
            nvplib._build_uri_path('security-profile',
                                   resource_id=sec_prof['uuid']),
            cluster=self.fake_cluster)
        self.assertEqual(sec_prof['uuid'], sec_prof_res['uuid'])
        # Check for builtin rules
        self.assertEqual(len(sec_prof_res['logical_port_egress_rules']), 1)
        self.assertEqual(len(sec_prof_res['logical_port_ingress_rules']), 2)

    def test_create_and_get_default_security_profile(self):
        sec_prof = nvplib.create_security_profile(self.fake_cluster,
                                                  'pippo',
                                                  {'name': 'default'})
        sec_prof_res = nvplib.do_request(
            nvplib.HTTP_GET,
            nvplib._build_uri_path('security-profile',
                                   resource_id=sec_prof['uuid']),
            cluster=self.fake_cluster)
        self.assertEqual(sec_prof['uuid'], sec_prof_res['uuid'])
        # Check for builtin rules
        self.assertEqual(len(sec_prof_res['logical_port_egress_rules']), 3)
        self.assertEqual(len(sec_prof_res['logical_port_ingress_rules']), 2)

    def test_update_security_profile_rules(self):
        sec_prof = nvplib.create_security_profile(self.fake_cluster,
                                                  'pippo', {'name': 'test'})
        ingress_rule = {'ethertype': 'IPv4'}
        egress_rule = {'ethertype': 'IPv4', 'profile_uuid': 'xyz'}
        new_rules = {'logical_port_egress_rules': [egress_rule],
                     'logical_port_ingress_rules': [ingress_rule]}
        nvplib.update_security_group_rules(self.fake_cluster,
                                           sec_prof['uuid'],
                                           new_rules)
        sec_prof_res = nvplib.do_request(
            nvplib.HTTP_GET,
            nvplib._build_uri_path('security-profile',
                                   resource_id=sec_prof['uuid']),
            cluster=self.fake_cluster)
        self.assertEqual(sec_prof['uuid'], sec_prof_res['uuid'])
        # Check for builtin rules
        self.assertEqual(len(sec_prof_res['logical_port_egress_rules']), 2)
        self.assertIn(egress_rule,
                      sec_prof_res['logical_port_egress_rules'])
        self.assertEqual(len(sec_prof_res['logical_port_ingress_rules']), 1)
        self.assertIn(ingress_rule,
                      sec_prof_res['logical_port_ingress_rules'])

    def test_update_security_profile_rules_noingress(self):
        sec_prof = nvplib.create_security_profile(self.fake_cluster,
                                                  'pippo', {'name': 'test'})
        hidden_ingress_rule = {'ethertype': 'IPv4',
                               'ip_prefix': '127.0.0.1/32'}
        egress_rule = {'ethertype': 'IPv4', 'profile_uuid': 'xyz'}
        new_rules = {'logical_port_egress_rules': [egress_rule],
                     'logical_port_ingress_rules': []}
        nvplib.update_security_group_rules(self.fake_cluster,
                                           sec_prof['uuid'],
                                           new_rules)
        sec_prof_res = nvplib.do_request(
            nvplib.HTTP_GET,
            nvplib._build_uri_path('security-profile',
                                   resource_id=sec_prof['uuid']),
            cluster=self.fake_cluster)
        self.assertEqual(sec_prof['uuid'], sec_prof_res['uuid'])
        # Check for builtin rules
        self.assertEqual(len(sec_prof_res['logical_port_egress_rules']), 2)
        self.assertIn(egress_rule,
                      sec_prof_res['logical_port_egress_rules'])
        self.assertEqual(len(sec_prof_res['logical_port_ingress_rules']), 1)
        self.assertIn(hidden_ingress_rule,
                      sec_prof_res['logical_port_ingress_rules'])

    def test_update_non_existing_securityprofile_raises(self):
        self.assertRaises(exceptions.NeutronException,
                          nvplib.update_security_group_rules,
                          self.fake_cluster, 'whatever',
                          {'logical_port_egress_rules': [],
                           'logical_port_ingress_rules': []})

    def test_delete_security_profile(self):
        sec_prof = nvplib.create_security_profile(self.fake_cluster,
                                                  'pippo', {'name': 'test'})
        nvplib.delete_security_profile(self.fake_cluster, sec_prof['uuid'])
        self.assertRaises(exceptions.NotFound,
                          nvplib.do_request,
                          nvplib.HTTP_GET,
                          nvplib._build_uri_path(
                              'security-profile',
                              resource_id=sec_prof['uuid']),
                          cluster=self.fake_cluster)

    def test_delete_non_existing_securityprofile_raises(self):
        self.assertRaises(exceptions.NeutronException,
                          nvplib.delete_security_profile,
                          self.fake_cluster, 'whatever')


class TestNvplibClusterManagement(NvplibTestCase):

    def test_get_cluster_version(self):

        def fakedorequest(*args, **kwargs):
            uri = args[1]
            if 'node/xyz' in uri:
                return {'version': '3.0.9999'}
            elif 'node' in uri:
                return {'result_count': 1,
                        'results': [{'uuid': 'xyz'}]}

        with mock.patch.object(nvplib, 'do_request', new=fakedorequest):
            version = nvplib.get_cluster_version('whatever')
            self.assertEqual(version, '3.0')

    def test_get_cluster_version_no_nodes(self):
        def fakedorequest(*args, **kwargs):
            uri = args[1]
            if 'node' in uri:
                return {'result_count': 0}

        with mock.patch.object(nvplib, 'do_request', new=fakedorequest):
            version = nvplib.get_cluster_version('whatever')
            self.assertIsNone(version)

    def test_cluster_in_readonly_mode(self):
        with mock.patch.object(self.fake_cluster.api_client,
                               'request',
                               side_effect=NvpApiClient.ReadOnlyMode):
            self.assertRaises(nvp_exc.MaintenanceInProgress,
                              nvplib.do_request, cluster=self.fake_cluster)

    def test_cluster_method_not_implemetned(self):
        self.assertRaises(NvpApiClient.NvpApiException,
                          nvplib.do_request,
                          nvplib.HTTP_GET,
                          nvplib._build_uri_path('MY_FAKE_RESOURCE',
                                                 resource_id='foo'),
                          cluster=self.fake_cluster)


class NvplibMiscTestCase(base.BaseTestCase):

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
        result = nvplib._build_uri_path('RESOURCE')
        self.assertEqual("%s/%s" % (nvplib.URI_PREFIX, 'RESOURCE'), result)

    def test_build_uri_path_with_field(self):
        result = nvplib._build_uri_path('RESOURCE', fields='uuid')
        expected = "%s/%s?fields=uuid" % (nvplib.URI_PREFIX, 'RESOURCE')
        self.assertEqual(expected, result)

    def test_build_uri_path_with_filters(self):
        filters = {"tag": 'foo', "tag_scope": "scope_foo"}
        result = nvplib._build_uri_path('RESOURCE', filters=filters)
        expected = (
            "%s/%s?tag_scope=scope_foo&tag=foo" %
            (nvplib.URI_PREFIX, 'RESOURCE'))
        self.assertEqual(expected, result)

    def test_build_uri_path_with_resource_id(self):
        res = 'RESOURCE'
        res_id = 'resource_id'
        result = nvplib._build_uri_path(res, resource_id=res_id)
        expected = "%s/%s/%s" % (nvplib.URI_PREFIX, res, res_id)
        self.assertEqual(expected, result)

    def test_build_uri_path_with_parent_and_resource_id(self):
        parent_res = 'RESOURCE_PARENT'
        child_res = 'RESOURCE_CHILD'
        res = '%s/%s' % (child_res, parent_res)
        par_id = 'parent_resource_id'
        res_id = 'resource_id'
        result = nvplib._build_uri_path(
            res, parent_resource_id=par_id, resource_id=res_id)
        expected = ("%s/%s/%s/%s/%s" %
                    (nvplib.URI_PREFIX, parent_res, par_id, child_res, res_id))
        self.assertEqual(expected, result)

    def test_build_uri_path_with_attachment(self):
        parent_res = 'RESOURCE_PARENT'
        child_res = 'RESOURCE_CHILD'
        res = '%s/%s' % (child_res, parent_res)
        par_id = 'parent_resource_id'
        res_id = 'resource_id'
        result = nvplib._build_uri_path(res, parent_resource_id=par_id,
                                        resource_id=res_id, is_attachment=True)
        expected = ("%s/%s/%s/%s/%s/%s" %
                    (nvplib.URI_PREFIX, parent_res,
                     par_id, child_res, res_id, 'attachment'))
        self.assertEqual(expected, result)

    def test_build_uri_path_with_extra_action(self):
        parent_res = 'RESOURCE_PARENT'
        child_res = 'RESOURCE_CHILD'
        res = '%s/%s' % (child_res, parent_res)
        par_id = 'parent_resource_id'
        res_id = 'resource_id'
        result = nvplib._build_uri_path(res, parent_resource_id=par_id,
                                        resource_id=res_id, extra_action='doh')
        expected = ("%s/%s/%s/%s/%s/%s" %
                    (nvplib.URI_PREFIX, parent_res,
                     par_id, child_res, res_id, 'doh'))
        self.assertEqual(expected, result)
