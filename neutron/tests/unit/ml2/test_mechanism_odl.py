# Copyright (c) 2013-2014 OpenStack Foundation
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

import mock
import requests

from neutron.openstack.common import jsonutils
from neutron.plugins.common import constants
from neutron.plugins.ml2 import config as config
from neutron.plugins.ml2 import driver_api as api
from neutron.plugins.ml2.drivers import mechanism_odl
from neutron.plugins.ml2 import plugin
from neutron.tests import base
from neutron.tests.unit import test_db_plugin as test_plugin
from neutron.tests.unit import testlib_api

PLUGIN_NAME = 'neutron.plugins.ml2.plugin.Ml2Plugin'


class OpenDaylightTestCase(test_plugin.NeutronDbPluginV2TestCase):

    def setUp(self):
        # Enable the test mechanism driver to ensure that
        # we can successfully call through to all mechanism
        # driver apis.
        config.cfg.CONF.set_override('mechanism_drivers',
                                     ['logger', 'opendaylight'],
                                     'ml2')
        # Set URL/user/pass so init doesn't throw a cfg required error.
        # They are not used in these tests since sendjson is overwritten.
        config.cfg.CONF.set_override('url', 'http://127.0.0.1:9999', 'ml2_odl')
        config.cfg.CONF.set_override('username', 'someuser', 'ml2_odl')
        config.cfg.CONF.set_override('password', 'somepass', 'ml2_odl')

        super(OpenDaylightTestCase, self).setUp(PLUGIN_NAME)
        self.port_create_status = 'DOWN'
        self.segment = {'api.NETWORK_TYPE': ""}
        self.mech = mechanism_odl.OpenDaylightMechanismDriver()
        mechanism_odl.OpenDaylightMechanismDriver.sendjson = (
            self.check_sendjson)

    def check_sendjson(self, method, urlpath, obj, ignorecodes=[]):
        self.assertFalse(urlpath.startswith("http://"))

    def test_check_segment(self):
        """Validate the check_segment call."""
        self.segment[api.NETWORK_TYPE] = constants.TYPE_LOCAL
        self.assertTrue(self.mech.check_segment(self.segment))
        self.segment[api.NETWORK_TYPE] = constants.TYPE_FLAT
        self.assertFalse(self.mech.check_segment(self.segment))
        self.segment[api.NETWORK_TYPE] = constants.TYPE_VLAN
        self.assertTrue(self.mech.check_segment(self.segment))
        self.segment[api.NETWORK_TYPE] = constants.TYPE_GRE
        self.assertTrue(self.mech.check_segment(self.segment))
        self.segment[api.NETWORK_TYPE] = constants.TYPE_VXLAN
        self.assertTrue(self.mech.check_segment(self.segment))
        # Validate a network type not currently supported
        self.segment[api.NETWORK_TYPE] = 'mpls'
        self.assertFalse(self.mech.check_segment(self.segment))


class OpenDayLightMechanismConfigTests(testlib_api.SqlTestCase):

    def _set_config(self, url='http://127.0.0.1:9999', username='someuser',
                    password='somepass'):
        config.cfg.CONF.set_override('mechanism_drivers',
                                     ['logger', 'opendaylight'],
                                     'ml2')
        config.cfg.CONF.set_override('url', url, 'ml2_odl')
        config.cfg.CONF.set_override('username', username, 'ml2_odl')
        config.cfg.CONF.set_override('password', password, 'ml2_odl')

    def _test_missing_config(self, **kwargs):
        self._set_config(**kwargs)
        self.assertRaises(config.cfg.RequiredOptError,
                          plugin.Ml2Plugin)

    def test_valid_config(self):
        self._set_config()
        plugin.Ml2Plugin()

    def test_missing_url_raises_exception(self):
        self._test_missing_config(url=None)

    def test_missing_username_raises_exception(self):
        self._test_missing_config(username=None)

    def test_missing_password_raises_exception(self):
        self._test_missing_config(password=None)


class OpenDaylightMechanismTestBasicGet(test_plugin.TestBasicGet,
                                        OpenDaylightTestCase):
    pass


class OpenDaylightMechanismTestNetworksV2(test_plugin.TestNetworksV2,
                                          OpenDaylightTestCase):
    pass


class OpenDaylightMechanismTestSubnetsV2(test_plugin.TestSubnetsV2,
                                         OpenDaylightTestCase):
    pass


class OpenDaylightMechanismTestPortsV2(test_plugin.TestPortsV2,
                                       OpenDaylightTestCase):
    pass


class AuthMatcher(object):

    def __eq__(self, obj):
        return (obj.username == config.cfg.CONF.ml2_odl.username and
                obj.password == config.cfg.CONF.ml2_odl.password)


class DataMatcher(object):

    def __init__(self, operation, object_type, context):
        self._data = context.current.copy()
        self._object_type = object_type
        filter_map = getattr(mechanism_odl.OpenDaylightMechanismDriver,
                             '%s_object_map' % operation)
        attr_filter = filter_map["%ss" % object_type]
        attr_filter(self._data, context)

    def __eq__(self, s):
        data = jsonutils.loads(s)
        return self._data == data[self._object_type]


class OpenDaylightMechanismDriverTestCase(base.BaseTestCase):

    def setUp(self):
        super(OpenDaylightMechanismDriverTestCase, self).setUp()
        config.cfg.CONF.set_override('mechanism_drivers',
                                     ['logger', 'opendaylight'], 'ml2')
        config.cfg.CONF.set_override('url', 'http://127.0.0.1:9999', 'ml2_odl')
        config.cfg.CONF.set_override('username', 'someuser', 'ml2_odl')
        config.cfg.CONF.set_override('password', 'somepass', 'ml2_odl')
        self.mech = mechanism_odl.OpenDaylightMechanismDriver()
        self.mech.initialize()

    @staticmethod
    def _get_mock_network_operation_context():
        current = {'status': 'ACTIVE',
                   'subnets': [],
                   'name': 'net1',
                   'provider:physical_network': None,
                   'admin_state_up': True,
                   'tenant_id': 'test-tenant',
                   'provider:network_type': 'local',
                   'router:external': False,
                   'shared': False,
                   'id': 'd897e21a-dfd6-4331-a5dd-7524fa421c3e',
                   'provider:segmentation_id': None}
        context = mock.Mock(current=current)
        return context

    @staticmethod
    def _get_mock_subnet_operation_context():
        current = {'ipv6_ra_mode': None,
                   'allocation_pools': [{'start': '10.0.0.2',
                                         'end': '10.0.1.254'}],
                   'host_routes': [],
                   'ipv6_address_mode': None,
                   'cidr': '10.0.0.0/23',
                   'id': '72c56c48-e9b8-4dcf-b3a7-0813bb3bd839',
                   'name': '',
                   'enable_dhcp': True,
                   'network_id': 'd897e21a-dfd6-4331-a5dd-7524fa421c3e',
                   'tenant_id': 'test-tenant',
                   'dns_nameservers': [],
                   'gateway_ip': '10.0.0.1',
                   'ip_version': 4,
                   'shared': False}
        context = mock.Mock(current=current)
        return context

    @staticmethod
    def _get_mock_port_operation_context():
        current = {'status': 'DOWN',
                   'binding:host_id': '',
                   'allowed_address_pairs': [],
                   'device_owner': 'fake_owner',
                   'binding:profile': {},
                   'fixed_ips': [],
                   'id': '72c56c48-e9b8-4dcf-b3a7-0813bb3bd839',
                   'security_groups': ['2f9244b4-9bee-4e81-bc4a-3f3c2045b3d7'],
                   'device_id': 'fake_device',
                   'name': '',
                   'admin_state_up': True,
                   'network_id': 'c13bba05-eb07-45ba-ace2-765706b2d701',
                   'tenant_id': 'bad_tenant_id',
                   'binding:vif_details': {},
                   'binding:vnic_type': 'normal',
                   'binding:vif_type': 'unbound',
                   'mac_address': '12:34:56:78:21:b6'}
        context = mock.Mock(current=current)
        context._plugin.get_security_group = mock.Mock(return_value={})
        return context

    @classmethod
    def _get_mock_operation_context(cls, object_type):
        getter = getattr(cls, '_get_mock_%s_operation_context' % object_type)
        return getter()

    _status_code_msgs = {
        200: '',
        201: '',
        204: '',
        400: '400 Client Error: Bad Request',
        401: '401 Client Error: Unauthorized',
        403: '403 Client Error: Forbidden',
        404: '404 Client Error: Not Found',
        409: '409 Client Error: Conflict',
        501: '501 Server Error: Not Implemented',
        503: '503 Server Error: Service Unavailable',
    }

    @classmethod
    def _get_mock_request_response(cls, status_code):
        response = mock.Mock(status_code=status_code)
        response.raise_for_status = mock.Mock() if status_code < 400 else (
            mock.Mock(side_effect=requests.exceptions.HTTPError(
                cls._status_code_msgs[status_code])))
        return response

    def _test_single_operation(self, method, context, status_code,
                               exc_class=None, *args, **kwargs):
        self.mech.out_of_sync = False
        request_response = self._get_mock_request_response(status_code)
        with mock.patch('requests.request',
                        return_value=request_response) as mock_method:
            if exc_class is not None:
                self.assertRaises(exc_class, method, context)
            else:
                method(context)
        mock_method.assert_called_once_with(
            headers={'Content-Type': 'application/json'}, auth=AuthMatcher(),
            timeout=config.cfg.CONF.ml2_odl.timeout, *args, **kwargs)

    def _test_create_resource_postcommit(self, object_type, status_code,
                                         exc_class=None):
        method = getattr(self.mech, 'create_%s_postcommit' % object_type)
        context = self._get_mock_operation_context(object_type)
        url = '%s/%ss' % (config.cfg.CONF.ml2_odl.url, object_type)
        kwargs = {'url': url,
                  'data': DataMatcher('create', object_type, context)}
        self._test_single_operation(method, context, status_code, exc_class,
                                    'post', **kwargs)

    def _test_update_resource_postcommit(self, object_type, status_code,
                                         exc_class=None):
        method = getattr(self.mech, 'update_%s_postcommit' % object_type)
        context = self._get_mock_operation_context(object_type)
        url = '%s/%ss/%s' % (config.cfg.CONF.ml2_odl.url, object_type,
                             context.current['id'])
        kwargs = {'url': url,
                  'data': DataMatcher('update', object_type, context)}
        self._test_single_operation(method, context, status_code, exc_class,
                                    'put', **kwargs)

    def _test_delete_resource_postcommit(self, object_type, status_code,
                                         exc_class=None):
        method = getattr(self.mech, 'delete_%s_postcommit' % object_type)
        context = self._get_mock_operation_context(object_type)
        url = '%s/%ss/%s' % (config.cfg.CONF.ml2_odl.url, object_type,
                             context.current['id'])
        kwargs = {'url': url, 'data': None}
        self._test_single_operation(method, context, status_code, exc_class,
                                    'delete', **kwargs)

    def test_create_network_postcommit(self):
        self._test_create_resource_postcommit('network',
                                              requests.codes.created)
        for status_code in (requests.codes.bad_request,
                            requests.codes.unauthorized):
            self._test_create_resource_postcommit(
                'network', status_code, requests.exceptions.HTTPError)

    def test_create_subnet_postcommit(self):
        self._test_create_resource_postcommit('subnet', requests.codes.created)
        for status_code in (requests.codes.bad_request,
                            requests.codes.unauthorized,
                            requests.codes.forbidden,
                            requests.codes.not_found,
                            requests.codes.conflict,
                            requests.codes.not_implemented):
            self._test_create_resource_postcommit(
                'subnet', status_code, requests.exceptions.HTTPError)

    def test_create_port_postcommit(self):
        self._test_create_resource_postcommit('port', requests.codes.created)
        for status_code in (requests.codes.bad_request,
                            requests.codes.unauthorized,
                            requests.codes.forbidden,
                            requests.codes.not_found,
                            requests.codes.conflict,
                            requests.codes.not_implemented,
                            requests.codes.service_unavailable):
            self._test_create_resource_postcommit(
                'port', status_code, requests.exceptions.HTTPError)

    def test_update_network_postcommit(self):
        self._test_update_resource_postcommit('network', requests.codes.ok)
        for status_code in (requests.codes.bad_request,
                            requests.codes.forbidden,
                            requests.codes.not_found):
            self._test_update_resource_postcommit(
                'network', status_code, requests.exceptions.HTTPError)

    def test_update_subnet_postcommit(self):
        self._test_update_resource_postcommit('subnet', requests.codes.ok)
        for status_code in (requests.codes.bad_request,
                            requests.codes.unauthorized,
                            requests.codes.forbidden,
                            requests.codes.not_found,
                            requests.codes.not_implemented):
            self._test_update_resource_postcommit(
                'subnet', status_code, requests.exceptions.HTTPError)

    def test_update_port_postcommit(self):
        self._test_update_resource_postcommit('port', requests.codes.ok)
        for status_code in (requests.codes.bad_request,
                            requests.codes.unauthorized,
                            requests.codes.forbidden,
                            requests.codes.not_found,
                            requests.codes.conflict,
                            requests.codes.not_implemented):
            self._test_update_resource_postcommit(
                'port', status_code, requests.exceptions.HTTPError)

    def test_delete_network_postcommit(self):
        self._test_delete_resource_postcommit('network',
                                              requests.codes.no_content)
        for status_code in (requests.codes.unauthorized,
                            requests.codes.not_found,
                            requests.codes.conflict):
            self._test_delete_resource_postcommit(
                'network', status_code, requests.exceptions.HTTPError)

    def test_delete_subnet_postcommit(self):
        self._test_delete_resource_postcommit('subnet',
                                              requests.codes.no_content)
        for status_code in (requests.codes.unauthorized,
                            requests.codes.not_found,
                            requests.codes.conflict,
                            requests.codes.not_implemented):
            self._test_delete_resource_postcommit(
                'subnet', status_code, requests.exceptions.HTTPError)

    def test_delete_port_postcommit(self):
        self._test_delete_resource_postcommit('port',
                                              requests.codes.no_content)
        for status_code in (requests.codes.unauthorized,
                            requests.codes.forbidden,
                            requests.codes.not_found,
                            requests.codes.not_implemented):
            self._test_delete_resource_postcommit(
                'port', status_code, requests.exceptions.HTTPError)
