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

import hashlib
import mock

from neutron.common import constants
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


class L2GatewayNegativeTestCase(NsxlibNegativeBaseTestCase):

    def test_create_l2_gw_service_on_failure(self):
        self.assertRaises(nvplib.NvpApiClient.NvpApiException,
                          nvplib.create_l2_gw_service,
                          self.fake_cluster,
                          'fake-tenant',
                          'fake-gateway',
                          [{'id': _uuid(),
                           'interface_name': 'xxx'}])

    def test_delete_l2_gw_service_on_failure(self):
        self.assertRaises(nvplib.NvpApiClient.NvpApiException,
                          nvplib.delete_l2_gw_service,
                          self.fake_cluster,
                          'fake-gateway')

    def test_get_l2_gw_service_on_failure(self):
        self.assertRaises(nvplib.NvpApiClient.NvpApiException,
                          nvplib.get_l2_gw_service,
                          self.fake_cluster,
                          'fake-gateway')

    def test_update_l2_gw_service_on_failure(self):
        self.assertRaises(nvplib.NvpApiClient.NvpApiException,
                          nvplib.update_l2_gw_service,
                          self.fake_cluster,
                          'fake-gateway',
                          'pluto')


class TestNvplibL2Gateway(NvplibTestCase):

    def _create_gw_service(self, node_uuid, display_name,
                           tenant_id='fake_tenant'):
        return nvplib.create_l2_gw_service(self.fake_cluster,
                                           tenant_id,
                                           display_name,
                                           [{'id': node_uuid,
                                             'interface_name': 'xxx'}])

    def test_create_l2_gw_service(self):
        display_name = 'fake-gateway'
        node_uuid = _uuid()
        response = self._create_gw_service(node_uuid, display_name)
        self.assertEqual(response.get('type'), 'L2GatewayServiceConfig')
        self.assertEqual(response.get('display_name'), display_name)
        gateways = response.get('gateways', [])
        self.assertEqual(len(gateways), 1)
        self.assertEqual(gateways[0]['type'], 'L2Gateway')
        self.assertEqual(gateways[0]['device_id'], 'xxx')
        self.assertEqual(gateways[0]['transport_node_uuid'], node_uuid)

    def test_update_l2_gw_service(self):
        display_name = 'fake-gateway'
        new_display_name = 'still-fake-gateway'
        node_uuid = _uuid()
        res1 = self._create_gw_service(node_uuid, display_name)
        gw_id = res1['uuid']
        res2 = nvplib.update_l2_gw_service(self.fake_cluster, gw_id,
                                           new_display_name)
        self.assertEqual(res2['display_name'], new_display_name)

    def test_get_l2_gw_service(self):
        display_name = 'fake-gateway'
        node_uuid = _uuid()
        gw_id = self._create_gw_service(node_uuid, display_name)['uuid']
        response = nvplib.get_l2_gw_service(self.fake_cluster, gw_id)
        self.assertEqual(response.get('type'), 'L2GatewayServiceConfig')
        self.assertEqual(response.get('display_name'), display_name)
        self.assertEqual(response.get('uuid'), gw_id)

    def test_list_l2_gw_service(self):
        gw_ids = []
        for name in ('fake-1', 'fake-2'):
            gw_ids.append(self._create_gw_service(_uuid(), name)['uuid'])
        results = nvplib.get_l2_gw_services(self.fake_cluster)
        self.assertEqual(len(results), 2)
        self.assertEqual(sorted(gw_ids), sorted([r['uuid'] for r in results]))

    def test_list_l2_gw_service_by_tenant(self):
        gw_ids = [self._create_gw_service(
                  _uuid(), name, tenant_id=name)['uuid']
                  for name in ('fake-1', 'fake-2')]
        results = nvplib.get_l2_gw_services(self.fake_cluster,
                                            tenant_id='fake-1')
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]['uuid'], gw_ids[0])

    def test_delete_l2_gw_service(self):
        display_name = 'fake-gateway'
        node_uuid = _uuid()
        gw_id = self._create_gw_service(node_uuid, display_name)['uuid']
        nvplib.delete_l2_gw_service(self.fake_cluster, gw_id)
        results = nvplib.get_l2_gw_services(self.fake_cluster)
        self.assertEqual(len(results), 0)

    def test_plug_l2_gw_port_attachment(self):
        tenant_id = 'pippo'
        node_uuid = _uuid()
        transport_zones_config = [{'zone_uuid': _uuid(),
                                   'transport_type': 'stt'}]
        lswitch = nvplib.create_lswitch(self.fake_cluster, _uuid(), tenant_id,
                                        'fake-switch', transport_zones_config)
        gw_id = self._create_gw_service(node_uuid, 'fake-gw')['uuid']
        lport = nvplib.create_lport(self.fake_cluster,
                                    lswitch['uuid'],
                                    tenant_id,
                                    _uuid(),
                                    'fake-gw-port',
                                    gw_id,
                                    True)
        nvplib.plug_l2_gw_service(self.fake_cluster,
                                  lswitch['uuid'],
                                  lport['uuid'],
                                  gw_id)
        uri = nvplib._build_uri_path(nvplib.LSWITCHPORT_RESOURCE,
                                     lport['uuid'],
                                     lswitch['uuid'],
                                     is_attachment=True)
        resp_obj = nvplib.do_request("GET", uri,
                                     cluster=self.fake_cluster)
        self.assertIn('LogicalPortAttachment', resp_obj)
        self.assertEqual(resp_obj['LogicalPortAttachment']['type'],
                         'L2GatewayAttachment')


class TestNvplibLogicalSwitches(NvplibTestCase):

    def test_create_and_get_lswitches_single(self):
        tenant_id = 'pippo'
        transport_zones_config = [{'zone_uuid': _uuid(),
                                   'transport_type': 'stt'}]
        lswitch = nvplib.create_lswitch(self.fake_cluster,
                                        _uuid(),
                                        tenant_id,
                                        'fake-switch',
                                        transport_zones_config)
        res_lswitch = nvplib.get_lswitches(self.fake_cluster,
                                           lswitch['uuid'])
        self.assertEqual(len(res_lswitch), 1)
        self.assertEqual(res_lswitch[0]['uuid'],
                         lswitch['uuid'])

    def test_create_and_get_lswitches_single_name_exceeds_40_chars(self):
        tenant_id = 'pippo'
        transport_zones_config = [{'zone_uuid': _uuid(),
                                   'transport_type': 'stt'}]
        lswitch = nvplib.create_lswitch(self.fake_cluster,
                                        tenant_id,
                                        _uuid(),
                                        '*' * 50,
                                        transport_zones_config)
        res_lswitch = nvplib.get_lswitches(self.fake_cluster,
                                           lswitch['uuid'])
        self.assertEqual(len(res_lswitch), 1)
        self.assertEqual(res_lswitch[0]['uuid'], lswitch['uuid'])
        self.assertEqual(res_lswitch[0]['display_name'], '*' * 40)

    def test_create_and_get_lswitches_multiple(self):
        tenant_id = 'pippo'
        transport_zones_config = [{'zone_uuid': _uuid(),
                                   'transport_type': 'stt'}]
        network_id = _uuid()
        main_lswitch = nvplib.create_lswitch(
            self.fake_cluster, network_id,
            tenant_id, 'fake-switch', transport_zones_config,
            tags=[{'scope': 'multi_lswitch', 'tag': 'True'}])
        # Create secondary lswitch
        second_lswitch = nvplib.create_lswitch(
            self.fake_cluster, network_id,
            tenant_id, 'fake-switch-2', transport_zones_config)
        res_lswitch = nvplib.get_lswitches(self.fake_cluster,
                                           network_id)
        self.assertEqual(len(res_lswitch), 2)
        switch_uuids = [ls['uuid'] for ls in res_lswitch]
        self.assertIn(main_lswitch['uuid'], switch_uuids)
        self.assertIn(second_lswitch['uuid'], switch_uuids)
        for ls in res_lswitch:
            if ls['uuid'] == main_lswitch['uuid']:
                main_ls = ls
            else:
                second_ls = ls
        main_ls_tags = self._build_tag_dict(main_ls['tags'])
        second_ls_tags = self._build_tag_dict(second_ls['tags'])
        self.assertIn('multi_lswitch', main_ls_tags)
        self.assertNotIn('multi_lswitch', second_ls_tags)
        self.assertIn('quantum_net_id', main_ls_tags)
        self.assertIn('quantum_net_id', second_ls_tags)
        self.assertEqual(main_ls_tags['quantum_net_id'],
                         network_id)
        self.assertEqual(second_ls_tags['quantum_net_id'],
                         network_id)

    def test_update_lswitch(self):
        new_name = 'new-name'
        new_tags = [{'scope': 'new_tag', 'tag': 'xxx'}]
        transport_zones_config = [{'zone_uuid': _uuid(),
                                   'transport_type': 'stt'}]
        lswitch = nvplib.create_lswitch(self.fake_cluster,
                                        _uuid(),
                                        'pippo',
                                        'fake-switch',
                                        transport_zones_config)
        nvplib.update_lswitch(self.fake_cluster, lswitch['uuid'],
                              new_name, tags=new_tags)
        res_lswitch = nvplib.get_lswitches(self.fake_cluster,
                                           lswitch['uuid'])
        self.assertEqual(len(res_lswitch), 1)
        self.assertEqual(res_lswitch[0]['display_name'], new_name)
        switch_tags = self._build_tag_dict(res_lswitch[0]['tags'])
        self.assertIn('new_tag', switch_tags)
        self.assertEqual(switch_tags['new_tag'], 'xxx')

    def test_update_non_existing_lswitch_raises(self):
        self.assertRaises(exceptions.NetworkNotFound,
                          nvplib.update_lswitch,
                          self.fake_cluster, 'whatever',
                          'foo', 'bar')

    def test_delete_networks(self):
        transport_zones_config = [{'zone_uuid': _uuid(),
                                   'transport_type': 'stt'}]
        lswitch = nvplib.create_lswitch(self.fake_cluster,
                                        _uuid(),
                                        'pippo',
                                        'fake-switch',
                                        transport_zones_config)
        nvplib.delete_networks(self.fake_cluster, lswitch['uuid'],
                               [lswitch['uuid']])
        self.assertRaises(exceptions.NotFound,
                          nvplib.get_lswitches,
                          self.fake_cluster,
                          lswitch['uuid'])

    def test_delete_non_existing_lswitch_raises(self):
        self.assertRaises(exceptions.NetworkNotFound,
                          nvplib.delete_networks,
                          self.fake_cluster, 'whatever', ['whatever'])


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


class TestNvplibLogicalPorts(NvplibTestCase):

    def _create_switch_and_port(self, tenant_id='pippo',
                                neutron_port_id='whatever',
                                name='name', device_id='device_id'):
        transport_zones_config = [{'zone_uuid': _uuid(),
                                   'transport_type': 'stt'}]
        lswitch = nvplib.create_lswitch(self.fake_cluster,
                                        _uuid(), tenant_id, 'fake-switch',
                                        transport_zones_config)
        lport = nvplib.create_lport(self.fake_cluster, lswitch['uuid'],
                                    tenant_id, neutron_port_id,
                                    name, device_id, True)
        return lswitch, lport

    def test_create_and_get_port(self):
        lswitch, lport = self._create_switch_and_port()
        lport_res = nvplib.get_port(self.fake_cluster,
                                    lswitch['uuid'], lport['uuid'])
        self.assertEqual(lport['uuid'], lport_res['uuid'])
        # Try again with relation
        lport_res = nvplib.get_port(self.fake_cluster,
                                    lswitch['uuid'], lport['uuid'],
                                    relations='LogicalPortStatus')
        self.assertEqual(lport['uuid'], lport_res['uuid'])

    def test_plug_interface(self):
        lswitch, lport = self._create_switch_and_port()
        nvplib.plug_interface(self.fake_cluster, lswitch['uuid'],
                              lport['uuid'], 'VifAttachment', 'fake')
        lport_res = nvplib.get_port(self.fake_cluster,
                                    lswitch['uuid'], lport['uuid'])
        self.assertEqual(lport['uuid'], lport_res['uuid'])

    def test_get_port_by_tag(self):
        lswitch, lport = self._create_switch_and_port()
        lport2 = nvplib.get_port_by_neutron_tag(self.fake_cluster,
                                                lswitch['uuid'],
                                                'whatever')
        self.assertIsNotNone(lport2)
        self.assertEqual(lport['uuid'], lport2['uuid'])

    def test_get_port_by_tag_not_found_returns_None(self):
        tenant_id = 'pippo'
        neutron_port_id = 'whatever'
        transport_zones_config = [{'zone_uuid': _uuid(),
                                   'transport_type': 'stt'}]
        lswitch = nvplib.create_lswitch(self.fake_cluster, tenant_id, _uuid(),
                                        'fake-switch', transport_zones_config)
        lport = nvplib.get_port_by_neutron_tag(self.fake_cluster,
                                               lswitch['uuid'],
                                               neutron_port_id)
        self.assertIsNone(lport)

    def test_get_port_status(self):
        lswitch, lport = self._create_switch_and_port()
        status = nvplib.get_port_status(self.fake_cluster,
                                        lswitch['uuid'],
                                        lport['uuid'])
        self.assertEqual(constants.PORT_STATUS_ACTIVE, status)

    def test_get_port_status_non_existent_raises(self):
        self.assertRaises(exceptions.PortNotFoundOnNetwork,
                          nvplib.get_port_status,
                          self.fake_cluster,
                          'boo', 'boo')

    def test_update_port(self):
        lswitch, lport = self._create_switch_and_port()
        nvplib.update_port(
            self.fake_cluster, lswitch['uuid'], lport['uuid'],
            'neutron_port_id', 'pippo2', 'new_name', 'device_id', False)
        lport_res = nvplib.get_port(self.fake_cluster,
                                    lswitch['uuid'], lport['uuid'])
        self.assertEqual(lport['uuid'], lport_res['uuid'])
        self.assertEqual('new_name', lport_res['display_name'])
        self.assertEqual('False', lport_res['admin_status_enabled'])
        port_tags = self._build_tag_dict(lport_res['tags'])
        self.assertIn('os_tid', port_tags)
        self.assertIn('q_port_id', port_tags)
        self.assertIn('vm_id', port_tags)

    def test_create_port_device_id_less_than_40_chars(self):
        lswitch, lport = self._create_switch_and_port()
        lport_res = nvplib.get_port(self.fake_cluster,
                                    lswitch['uuid'], lport['uuid'])
        port_tags = self._build_tag_dict(lport_res['tags'])
        self.assertEqual('device_id', port_tags['vm_id'])

    def test_create_port_device_id_more_than_40_chars(self):
        dev_id = "this_is_a_very_long_device_id_with_lots_of_characters"
        lswitch, lport = self._create_switch_and_port(device_id=dev_id)
        lport_res = nvplib.get_port(self.fake_cluster,
                                    lswitch['uuid'], lport['uuid'])
        port_tags = self._build_tag_dict(lport_res['tags'])
        self.assertNotEqual(len(dev_id), len(port_tags['vm_id']))

    def test_get_ports_with_obsolete_and_new_vm_id_tag(self):
        def obsolete(device_id, obfuscate=False):
            return hashlib.sha1(device_id).hexdigest()

        with mock.patch.object(nvplib, 'device_id_to_vm_id', new=obsolete):
            dev_id1 = "short-dev-id-1"
            _, lport1 = self._create_switch_and_port(device_id=dev_id1)
        dev_id2 = "short-dev-id-2"
        _, lport2 = self._create_switch_and_port(device_id=dev_id2)

        lports = nvplib.get_ports(self.fake_cluster, None, [dev_id1])
        port_tags = self._build_tag_dict(lports['whatever']['tags'])
        self.assertNotEqual(dev_id1, port_tags['vm_id'])

        lports = nvplib.get_ports(self.fake_cluster, None, [dev_id2])
        port_tags = self._build_tag_dict(lports['whatever']['tags'])
        self.assertEqual(dev_id2, port_tags['vm_id'])

    def test_update_non_existent_port_raises(self):
        self.assertRaises(exceptions.PortNotFoundOnNetwork,
                          nvplib.update_port, self.fake_cluster,
                          'boo', 'boo', 'boo', 'boo', 'boo', 'boo', False)

    def test_delete_port(self):
        lswitch, lport = self._create_switch_and_port()
        nvplib.delete_port(self.fake_cluster,
                           lswitch['uuid'], lport['uuid'])
        self.assertRaises(exceptions.PortNotFoundOnNetwork,
                          nvplib.get_port, self.fake_cluster,
                          lswitch['uuid'], lport['uuid'])

    def test_delete_non_existent_port_raises(self):
        lswitch = self._create_switch_and_port()[0]
        self.assertRaises(exceptions.PortNotFoundOnNetwork,
                          nvplib.delete_port, self.fake_cluster,
                          lswitch['uuid'], 'bad_port_uuid')

    def test_query_lswitch_ports(self):
        lswitch, lport = self._create_switch_and_port()
        switch_port_uuids = [
            nvplib.create_lport(
                self.fake_cluster, lswitch['uuid'], 'pippo', 'qportid-%s' % k,
                'port-%s' % k, 'deviceid-%s' % k, True)['uuid']
            for k in range(2)]
        switch_port_uuids.append(lport['uuid'])
        ports = nvplib.query_lswitch_lports(self.fake_cluster, lswitch['uuid'])
        self.assertEqual(len(ports), 3)
        for res_port in ports:
            self.assertIn(res_port['uuid'], switch_port_uuids)


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
