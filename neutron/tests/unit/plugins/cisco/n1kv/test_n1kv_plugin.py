# Copyright 2013 Cisco Systems, Inc.
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
import webob.exc

from neutron.api import extensions as neutron_extensions
from neutron.api.v2 import attributes
from neutron import context
import neutron.db.api as db
from neutron.extensions import portbindings
from neutron import manager
from neutron.plugins.cisco.common import cisco_constants as c_const
from neutron.plugins.cisco.common import cisco_exceptions as c_exc
from neutron.plugins.cisco.common import config as c_conf
from neutron.plugins.cisco.db import n1kv_db_v2
from neutron.plugins.cisco.db import n1kv_models_v2
from neutron.plugins.cisco.db import network_db_v2 as cdb
from neutron.plugins.cisco import extensions
from neutron.plugins.cisco.extensions import n1kv
from neutron.plugins.cisco.extensions import network_profile
from neutron.plugins.cisco.extensions import policy_profile
from neutron.plugins.cisco.n1kv import n1kv_client
from neutron.plugins.cisco.n1kv import n1kv_neutron_plugin
from neutron.tests.unit import _test_extension_portbindings as test_bindings
from neutron.tests.unit.api.v2 import test_base
from neutron.tests.unit.db import test_db_base_plugin_v2 as test_plugin
from neutron.tests.unit.extensions import test_l3
from neutron.tests.unit.plugins.cisco.n1kv import fake_client
from neutron.tests.unit.scheduler import test_l3_agent_scheduler


PHYS_NET = 'some-phys-net'
VLAN_MIN = 100
VLAN_MAX = 110
TENANT_NOT_ADMIN = 'not_admin'
TENANT_TEST = 'test'


class FakeResponse(object):

    """
    This object is returned by mocked requests lib instead of normal response.

    Initialize it with the status code, header and buffer contents you wish to
    return.

    """
    def __init__(self, status, response_text, headers):
        self.buffer = response_text
        self.status_code = status
        self.headers = headers

    def json(self, *args, **kwargs):
        return self.buffer


def _fake_setup_vsm(self):
    """Fake establish Communication with Cisco Nexus1000V VSM."""
    self.agent_vsm = True
    self._populate_policy_profiles()


class NetworkProfileTestExtensionManager(object):

    def get_resources(self):
        # Add the resources to the global attribute map
        # This is done here as the setup process won't
        # initialize the main API router which extends
        # the global attribute map
        attributes.RESOURCE_ATTRIBUTE_MAP.update(
            network_profile.RESOURCE_ATTRIBUTE_MAP)
        return network_profile.Network_profile.get_resources()

    def get_actions(self):
        return []

    def get_request_extensions(self):
        return []


class PolicyProfileTestExtensionManager(object):

    def get_resources(self):
        # Add the resources to the global attribute map
        # This is done here as the setup process won't
        # initialize the main API router which extends
        # the global attribute map
        attributes.RESOURCE_ATTRIBUTE_MAP.update(
            policy_profile.RESOURCE_ATTRIBUTE_MAP)
        return policy_profile.Policy_profile.get_resources()

    def get_actions(self):
        return []

    def get_request_extensions(self):
        return []


class N1kvPluginTestCase(test_plugin.NeutronDbPluginV2TestCase):

    _plugin_name = ('neutron.plugins.cisco.n1kv.'
                    'n1kv_neutron_plugin.N1kvNeutronPluginV2')

    tenant_id = "some_tenant"

    DEFAULT_RESP_BODY = ""
    DEFAULT_RESP_CODE = 200
    DEFAULT_CONTENT_TYPE = ""
    fmt = "json"

    def _make_test_policy_profile(self, name='service_profile'):
        """
        Create a policy profile record for testing purpose.

        :param name: string representing the name of the policy profile to
                     create. Default argument value chosen to correspond to the
                     default name specified in config.py file.
        """
        uuid = test_base._uuid()
        profile = {'id': uuid,
                   'name': name}
        return n1kv_db_v2.create_policy_profile(profile)

    def _make_test_profile(self,
                           name='default_network_profile',
                           segment_type=c_const.NETWORK_TYPE_VLAN,
                           segment_range='386-400'):
        """
        Create a profile record for testing purposes.

        :param name: string representing the name of the network profile to
                     create. Default argument value chosen to correspond to the
                     default name specified in config.py file.
        :param segment_type: string representing the type of network segment.
        :param segment_range: string representing the segment range for network
                              profile.
        """
        db_session = db.get_session()
        profile = {'name': name,
                   'segment_type': segment_type,
                   'tenant_id': self.tenant_id,
                   'segment_range': segment_range}
        if segment_type == c_const.NETWORK_TYPE_OVERLAY:
            profile['sub_type'] = 'unicast'
            profile['multicast_ip_range'] = '0.0.0.0'
            net_p = n1kv_db_v2.create_network_profile(db_session, profile)
            n1kv_db_v2.sync_vxlan_allocations(db_session, net_p)
        elif segment_type == c_const.NETWORK_TYPE_VLAN:
            profile['physical_network'] = PHYS_NET
            net_p = n1kv_db_v2.create_network_profile(db_session, profile)
            n1kv_db_v2.sync_vlan_allocations(db_session, net_p)
        n1kv_db_v2.create_profile_binding(db_session, self.tenant_id,
                                          net_p['id'], c_const.NETWORK)
        n1kv_db_v2.create_profile_binding(db_session, TENANT_NOT_ADMIN,
                                          net_p['id'], c_const.NETWORK)
        n1kv_db_v2.create_profile_binding(db_session, TENANT_TEST,
                                          net_p['id'], c_const.NETWORK)
        return net_p

    def setUp(self, ext_mgr=NetworkProfileTestExtensionManager()):
        """
        Setup method for n1kv plugin tests.

        First step is to define an acceptable response from the VSM to
        our requests. This needs to be done BEFORE the setUp() function
        of the super-class is called.

        This default here works for many cases. If you need something
        extra, please define your own setUp() function in your test class,
        and set your DEFAULT_RESPONSE value also BEFORE calling the
        setUp() of the super-function (this one here). If you have set
        a value already, it will not be overwritten by this code.

        """
        if not self.DEFAULT_RESP_BODY:
            self.DEFAULT_RESP_BODY = {
                "icehouse-pp": {"properties": {"name": "icehouse-pp",
                                               "id": "some-uuid-1"}},
                "havana_pp": {"properties": {"name": "havana_pp",
                                             "id": "some-uuid-2"}},
                "dhcp_pp": {"properties": {"name": "dhcp_pp",
                                           "id": "some-uuid-3"}},
            }
        # Creating a mock HTTP connection object for requests lib. The N1KV
        # client interacts with the VSM via HTTP. Since we don't have a VSM
        # running in the unit tests, we need to 'fake' it by patching the HTTP
        # library itself. We install a patch for a fake HTTP connection class.
        # Using __name__ to avoid having to enter the full module path.
        http_patcher = mock.patch(n1kv_client.requests.__name__ + ".request")
        FakeHttpConnection = http_patcher.start()
        # Now define the return values for a few functions that may be called
        # on any instance of the fake HTTP connection class.
        self.resp_headers = {"content-type": "application/json"}
        FakeHttpConnection.return_value = (FakeResponse(
                                           self.DEFAULT_RESP_CODE,
                                           self.DEFAULT_RESP_BODY,
                                           self.resp_headers))

        # Patch some internal functions in a few other parts of the system.
        # These help us move along, without having to mock up even more systems
        # in the background.

        # Return a dummy VSM IP address
        mock.patch(n1kv_client.__name__ + ".Client._get_vsm_hosts",
                   new=lambda self: "127.0.0.1").start()

        # Return dummy user profiles
        mock.patch(cdb.__name__ + ".get_credential_name",
                   new=lambda self: {"user_name": "admin",
                                     "password": "admin_password"}).start()

        n1kv_neutron_plugin.N1kvNeutronPluginV2._setup_vsm = _fake_setup_vsm

        neutron_extensions.append_api_extensions_path(extensions.__path__)

        # Save the original RESOURCE_ATTRIBUTE_MAP
        self.saved_attr_map = {}
        for resource, attrs in attributes.RESOURCE_ATTRIBUTE_MAP.items():
            self.saved_attr_map[resource] = attrs.copy()
        # Update the RESOURCE_ATTRIBUTE_MAP with n1kv specific extended attrs.
        attributes.RESOURCE_ATTRIBUTE_MAP["networks"].update(
            n1kv.EXTENDED_ATTRIBUTES_2_0["networks"])
        attributes.RESOURCE_ATTRIBUTE_MAP["ports"].update(
            n1kv.EXTENDED_ATTRIBUTES_2_0["ports"])
        self.addCleanup(self.restore_resource_attribute_map)
        super(N1kvPluginTestCase, self).setUp(self._plugin_name,
                                              ext_mgr=ext_mgr)
        # Create some of the database entries that we require.
        self._make_test_profile()
        self._make_test_policy_profile()

    def restore_resource_attribute_map(self):
        # Restore the original RESOURCE_ATTRIBUTE_MAP
        attributes.RESOURCE_ATTRIBUTE_MAP = self.saved_attr_map


class TestN1kvNetworkProfiles(N1kvPluginTestCase):
    def _prepare_net_profile_data(self,
                                  segment_type,
                                  sub_type=None,
                                  segment_range=None,
                                  mcast_ip_range=None):
        netp = {'name': 'netp1',
                'segment_type': segment_type,
                'tenant_id': self.tenant_id}
        if segment_type == c_const.NETWORK_TYPE_VLAN:
            netp['segment_range'] = segment_range or '100-110'
            netp['physical_network'] = PHYS_NET
        elif segment_type == c_const.NETWORK_TYPE_OVERLAY:
            netp['segment_range'] = segment_range or '10000-10010'
            netp['sub_type'] = sub_type or 'enhanced'
            netp['multicast_ip_range'] = (mcast_ip_range or
                                          "224.1.1.1-224.1.1.10")
        elif segment_type == c_const.NETWORK_TYPE_TRUNK:
            netp['sub_type'] = c_const.NETWORK_TYPE_VLAN
        data = {"network_profile": netp}
        return data

    def test_create_network_profile_vlan(self):
        data = self._prepare_net_profile_data(c_const.NETWORK_TYPE_VLAN)
        net_p_req = self.new_create_request('network_profiles', data)
        res = net_p_req.get_response(self.ext_api)
        self.assertEqual(res.status_int, 201)

    def test_create_network_profile_overlay(self):
        data = self._prepare_net_profile_data(c_const.NETWORK_TYPE_OVERLAY)
        net_p_req = self.new_create_request('network_profiles', data)
        res = net_p_req.get_response(self.ext_api)
        self.assertEqual(res.status_int, 201)

    def test_create_network_profile_overlay_missing_subtype(self):
        data = self._prepare_net_profile_data(c_const.NETWORK_TYPE_OVERLAY)
        data['network_profile'].pop('sub_type')
        net_p_req = self.new_create_request('network_profiles', data)
        res = net_p_req.get_response(self.ext_api)
        self.assertEqual(res.status_int, 400)

    def test_create_network_profile_trunk(self):
        data = self._prepare_net_profile_data(c_const.NETWORK_TYPE_TRUNK)
        net_p_req = self.new_create_request('network_profiles', data)
        res = net_p_req.get_response(self.ext_api)
        self.assertEqual(res.status_int, 201)

    def test_create_network_profile_trunk_missing_subtype(self):
        data = self._prepare_net_profile_data(c_const.NETWORK_TYPE_TRUNK)
        data['network_profile'].pop('sub_type')
        net_p_req = self.new_create_request('network_profiles', data)
        res = net_p_req.get_response(self.ext_api)
        self.assertEqual(res.status_int, 400)

    def test_create_network_profile_overlay_unreasonable_seg_range(self):
        data = self._prepare_net_profile_data(c_const.NETWORK_TYPE_OVERLAY,
                                              segment_range='10000-1000000001')
        net_p_req = self.new_create_request('network_profiles', data)
        res = net_p_req.get_response(self.ext_api)
        self.assertEqual(res.status_int, 400)

    def test_update_network_profile_plugin(self):
        net_p_dict = (self.
                      _prepare_net_profile_data(c_const.NETWORK_TYPE_OVERLAY))
        net_p_req = self.new_create_request('network_profiles', net_p_dict)
        net_p = self.deserialize(self.fmt,
                                 net_p_req.get_response(self.ext_api))
        data = {'network_profile': {'name': 'netp2'}}
        update_req = self.new_update_request('network_profiles',
                                             data,
                                             net_p['network_profile']['id'])
        update_res = update_req.get_response(self.ext_api)
        self.assertEqual(update_res.status_int, 200)

    def test_update_network_profile_physical_network_fail(self):
        net_p = self._make_test_profile(name='netp1')
        data = {'network_profile': {'physical_network': PHYS_NET}}
        net_p_req = self.new_update_request('network_profiles',
                                            data,
                                            net_p['id'])
        res = net_p_req.get_response(self.ext_api)
        self.assertEqual(res.status_int, 400)

    def test_update_network_profile_segment_type_fail(self):
        net_p = self._make_test_profile(name='netp1')
        data = {'network_profile': {
                'segment_type': c_const.NETWORK_TYPE_OVERLAY}}
        net_p_req = self.new_update_request('network_profiles',
                                            data,
                                            net_p['id'])
        res = net_p_req.get_response(self.ext_api)
        self.assertEqual(res.status_int, 400)

    def test_update_network_profile_sub_type_fail(self):
        net_p_dict = (self.
                      _prepare_net_profile_data(c_const.NETWORK_TYPE_OVERLAY))
        net_p_req = self.new_create_request('network_profiles', net_p_dict)
        net_p = self.deserialize(self.fmt,
                                 net_p_req.get_response(self.ext_api))
        data = {'network_profile': {'sub_type': c_const.NETWORK_TYPE_VLAN}}
        update_req = self.new_update_request('network_profiles',
                                             data,
                                             net_p['network_profile']['id'])
        update_res = update_req.get_response(self.ext_api)
        self.assertEqual(update_res.status_int, 400)

    def test_update_network_profiles_with_networks_fail(self):
        net_p = self._make_test_profile(name='netp1')
        data = {'network_profile': {'segment_range': '200-210'}}
        update_req = self.new_update_request('network_profiles',
                                             data,
                                             net_p['id'])
        update_res = update_req.get_response(self.ext_api)
        self.assertEqual(update_res.status_int, 200)
        net_data = {'network': {'name': 'net1',
                                n1kv.PROFILE_ID: net_p['id'],
                                'tenant_id': 'some_tenant'}}
        network_req = self.new_create_request('networks', net_data)
        network_res = network_req.get_response(self.api)
        self.assertEqual(network_res.status_int, 201)
        data = {'network_profile': {'segment_range': '300-310'}}
        update_req = self.new_update_request('network_profiles',
                                             data,
                                             net_p['id'])
        update_res = update_req.get_response(self.ext_api)
        self.assertEqual(update_res.status_int, 409)

    def test_create_overlay_network_profile_invalid_multicast_fail(self):
        data = self._prepare_net_profile_data(c_const.NETWORK_TYPE_OVERLAY,
                                              sub_type=(c_const.
                                              NETWORK_SUBTYPE_NATIVE_VXLAN),
                                              mcast_ip_range='1.1.1.1')
        net_p_req = self.new_create_request('network_profiles', data)
        res = net_p_req.get_response(self.ext_api)
        self.assertEqual(res.status_int, 400)

    def test_create_overlay_network_profile_no_multicast_fail(self):
        data = self._prepare_net_profile_data(c_const.NETWORK_TYPE_OVERLAY,
                                              sub_type=(c_const.
                                              NETWORK_SUBTYPE_NATIVE_VXLAN))
        data['network_profile']['multicast_ip_range'] = ''
        net_p_req = self.new_create_request('network_profiles', data)
        res = net_p_req.get_response(self.ext_api)
        self.assertEqual(res.status_int, 400)

    def test_create_overlay_network_profile_wrong_split_multicast_fail(self):
        data = self._prepare_net_profile_data(c_const.NETWORK_TYPE_OVERLAY,
                                              sub_type=(c_const.
                                              NETWORK_SUBTYPE_NATIVE_VXLAN),
                                              mcast_ip_range=
                                              '224.1.1.1.224.1.1.3')
        net_p_req = self.new_create_request('network_profiles', data)
        res = net_p_req.get_response(self.ext_api)
        self.assertEqual(res.status_int, 400)

    def test_create_overlay_network_profile_invalid_minip_multicast_fail(self):
        data = self._prepare_net_profile_data(c_const.NETWORK_TYPE_OVERLAY,
                                              sub_type=(c_const.
                                              NETWORK_SUBTYPE_NATIVE_VXLAN),
                                              mcast_ip_range=
                                              '10.0.0.1-224.1.1.3')
        net_p_req = self.new_create_request('network_profiles', data)
        res = net_p_req.get_response(self.ext_api)
        self.assertEqual(res.status_int, 400)

    def test_create_overlay_network_profile_invalid_maxip_multicast_fail(self):
        data = self._prepare_net_profile_data(c_const.NETWORK_TYPE_OVERLAY,
                                              sub_type=(c_const.
                                              NETWORK_SUBTYPE_NATIVE_VXLAN),
                                              mcast_ip_range=
                                              '224.1.1.1-20.0.0.1')
        net_p_req = self.new_create_request('network_profiles', data)
        res = net_p_req.get_response(self.ext_api)
        self.assertEqual(res.status_int, 400)

    def test_create_overlay_network_profile_correct_multicast_pass(self):
        data = self._prepare_net_profile_data(c_const.NETWORK_TYPE_OVERLAY)
        net_p_req = self.new_create_request('network_profiles', data)
        res = net_p_req.get_response(self.ext_api)
        self.assertEqual(res.status_int, 201)

    def test_update_overlay_network_profile_correct_multicast_pass(self):
        data = self._prepare_net_profile_data(c_const.NETWORK_TYPE_OVERLAY)
        net_p_req = self.new_create_request('network_profiles', data)
        res = net_p_req.get_response(self.ext_api)
        self.assertEqual(res.status_int, 201)
        net_p = self.deserialize(self.fmt, res)
        data = {'network_profile': {'multicast_ip_range':
                                    '224.0.1.0-224.0.1.100'}}
        update_req = self.new_update_request('network_profiles',
                                             data,
                                             net_p['network_profile']['id'])
        update_res = update_req.get_response(self.ext_api)
        self.assertEqual(update_res.status_int, 200)

    def test_create_overlay_network_profile_reservedip_multicast_fail(self):
        data = self._prepare_net_profile_data(c_const.NETWORK_TYPE_OVERLAY,
                                              sub_type=(c_const.
                                              NETWORK_SUBTYPE_NATIVE_VXLAN),
                                              mcast_ip_range=
                                              '224.0.0.100-224.0.1.100')
        net_p_req = self.new_create_request('network_profiles', data)
        res = net_p_req.get_response(self.ext_api)
        self.assertEqual(res.status_int, 400)

    def test_update_overlay_network_profile_reservedip_multicast_fail(self):
        data = self._prepare_net_profile_data(c_const.NETWORK_TYPE_OVERLAY)
        net_p_req = self.new_create_request('network_profiles', data)
        res = net_p_req.get_response(self.ext_api)
        self.assertEqual(res.status_int, 201)
        net_p = self.deserialize(self.fmt, res)
        data = {'network_profile': {'multicast_ip_range':
                                    '224.0.0.11-224.0.0.111'}}
        update_req = self.new_update_request('network_profiles',
                                             data,
                                             net_p['network_profile']['id'])
        update_res = update_req.get_response(self.ext_api)
        self.assertEqual(update_res.status_int, 400)

    def test_update_vlan_network_profile_multicast_fail(self):
        net_p = self._make_test_profile(name='netp1')
        data = {'network_profile': {'multicast_ip_range':
                                    '224.0.1.0-224.0.1.100'}}
        update_req = self.new_update_request('network_profiles',
                                             data,
                                             net_p['id'])
        update_res = update_req.get_response(self.ext_api)
        self.assertEqual(update_res.status_int, 400)

    def test_update_trunk_network_profile_segment_range_fail(self):
        data = self._prepare_net_profile_data(c_const.NETWORK_TYPE_TRUNK)
        net_p_req = self.new_create_request('network_profiles', data)
        res = net_p_req.get_response(self.ext_api)
        self.assertEqual(res.status_int, 201)
        net_p = self.deserialize(self.fmt, res)
        data = {'network_profile': {'segment_range':
                                    '100-200'}}
        update_req = self.new_update_request('network_profiles',
                                             data,
                                             net_p['network_profile']['id'])
        update_res = update_req.get_response(self.ext_api)
        self.assertEqual(update_res.status_int, 400)

    def test_update_trunk_network_profile_multicast_fail(self):
        data = self._prepare_net_profile_data(c_const.NETWORK_TYPE_TRUNK)
        net_p_req = self.new_create_request('network_profiles', data)
        res = net_p_req.get_response(self.ext_api)
        self.assertEqual(res.status_int, 201)
        net_p = self.deserialize(self.fmt, res)
        data = {'network_profile': {'multicast_ip_range':
                                    '224.0.1.0-224.0.1.100'}}
        update_req = self.new_update_request('network_profiles',
                                             data,
                                             net_p['network_profile']['id'])
        update_res = update_req.get_response(self.ext_api)
        self.assertEqual(update_res.status_int, 400)

    def test_create_network_profile_populate_vlan_segment_pool(self):
        db_session = db.get_session()
        net_p_dict = self._prepare_net_profile_data(c_const.NETWORK_TYPE_VLAN)
        net_p_req = self.new_create_request('network_profiles', net_p_dict)
        self.deserialize(self.fmt,
                         net_p_req.get_response(self.ext_api))
        for vlan in range(VLAN_MIN, VLAN_MAX + 1):
            self.assertIsNotNone(n1kv_db_v2.get_vlan_allocation(db_session,
                                                                PHYS_NET,
                                                                vlan))
            self.assertFalse(n1kv_db_v2.get_vlan_allocation(db_session,
                                                            PHYS_NET,
                                                            vlan).allocated)
        self.assertRaises(c_exc.VlanIDNotFound,
                          n1kv_db_v2.get_vlan_allocation,
                          db_session,
                          PHYS_NET,
                          VLAN_MIN - 1)
        self.assertRaises(c_exc.VlanIDNotFound,
                          n1kv_db_v2.get_vlan_allocation,
                          db_session,
                          PHYS_NET,
                          VLAN_MAX + 1)

    def test_delete_network_profile_with_network_fail(self):
        net_p = self._make_test_profile(name='netp1')
        net_data = {'network': {'name': 'net1',
                                n1kv.PROFILE_ID: net_p['id'],
                                'tenant_id': 'some_tenant'}}
        network_req = self.new_create_request('networks', net_data)
        network_res = network_req.get_response(self.api)
        self.assertEqual(network_res.status_int, 201)
        self._delete('network_profiles', net_p['id'],
                     expected_code=409)

    def test_delete_network_profile_deallocate_vlan_segment_pool(self):
        db_session = db.get_session()
        net_p_dict = self._prepare_net_profile_data(c_const.NETWORK_TYPE_VLAN)
        net_p_req = self.new_create_request('network_profiles', net_p_dict)
        net_p = self.deserialize(self.fmt,
                                 net_p_req.get_response(self.ext_api))
        self.assertIsNotNone(n1kv_db_v2.get_vlan_allocation(db_session,
                                                            PHYS_NET,
                                                            VLAN_MIN))
        self._delete('network_profiles', net_p['network_profile']['id'])
        for vlan in range(VLAN_MIN, VLAN_MAX + 1):
            self.assertRaises(c_exc.VlanIDNotFound,
                              n1kv_db_v2.get_vlan_allocation,
                              db_session,
                              PHYS_NET,
                              vlan)

    def test_create_network_profile_rollback_profile_binding(self):
        """Test rollback of profile binding if network profile create fails."""
        db_session = db.get_session()
        client_patch = mock.patch(n1kv_client.__name__ + ".Client",
                                  new=fake_client.TestClientInvalidResponse)
        client_patch.start()
        net_p_dict = self._prepare_net_profile_data(c_const.NETWORK_TYPE_VLAN)
        self.new_create_request('network_profiles', net_p_dict)
        bindings = (db_session.query(n1kv_models_v2.ProfileBinding).filter_by(
                    profile_type="network"))
        self.assertEqual(3, bindings.count())

    def test_create_network_profile_with_old_add_tenant_fail(self):
        data = self._prepare_net_profile_data('vlan')
        data['network_profile']['add_tenant'] = 'tenant1'
        net_p_req = self.new_create_request('network_profiles', data)
        res = net_p_req.get_response(self.ext_api)
        self.assertEqual(400, res.status_int)

    def test_create_network_profile_multi_tenants(self):
        data = self._prepare_net_profile_data('vlan')
        data['network_profile'][c_const.ADD_TENANTS] = ['tenant1', 'tenant2']
        del data['network_profile']['tenant_id']
        net_p_req = self.new_create_request('network_profiles', data)
        net_p_req.environ['neutron.context'] = context.Context('',
                                                               self.tenant_id,
                                                               is_admin=True)
        res = net_p_req.get_response(self.ext_api)
        self.assertEqual(201, res.status_int)
        net_p = self.deserialize(self.fmt, res)
        db_session = db.get_session()
        tenant_id = n1kv_db_v2.get_profile_binding(db_session, self.tenant_id,
                                                net_p['network_profile']['id'])
        tenant1 = n1kv_db_v2.get_profile_binding(db_session, 'tenant1',
                                                net_p['network_profile']['id'])
        tenant2 = n1kv_db_v2.get_profile_binding(db_session, 'tenant2',
                                                net_p['network_profile']['id'])
        self.assertIsNotNone(tenant_id)
        self.assertIsNotNone(tenant1)
        self.assertIsNotNone(tenant2)
        return net_p

    def test_update_network_profile_multi_tenants(self):
        net_p = self.test_create_network_profile_multi_tenants()
        data = {'network_profile': {c_const.ADD_TENANTS:
                                    ['tenant1', 'tenant3']}}
        update_req = self.new_update_request('network_profiles',
                                             data,
                                             net_p['network_profile']['id'])
        update_req.environ['neutron.context'] = context.Context('',
                                                               self.tenant_id,
                                                               is_admin=True)
        update_res = update_req.get_response(self.ext_api)
        self.assertEqual(200, update_res.status_int)
        db_session = db.get_session()
        # current tenant_id should always present
        tenant_id = n1kv_db_v2.get_profile_binding(db_session, self.tenant_id,
                                                net_p['network_profile']['id'])
        tenant1 = n1kv_db_v2.get_profile_binding(db_session, 'tenant1',
                                                net_p['network_profile']['id'])
        self.assertRaises(c_exc.ProfileTenantBindingNotFound,
                          n1kv_db_v2.get_profile_binding,
                          db_session, 'tenant4',
                          net_p['network_profile']['id'])
        tenant3 = n1kv_db_v2.get_profile_binding(db_session, 'tenant3',
                                                net_p['network_profile']['id'])
        self.assertIsNotNone(tenant_id)
        self.assertIsNotNone(tenant1)
        self.assertIsNotNone(tenant3)
        data = {'network_profile': {c_const.REMOVE_TENANTS: [self.tenant_id,
                                                       'tenant1']}}
        update_req = self.new_update_request('network_profiles',
                                             data,
                                             net_p['network_profile']['id'])
        update_req.environ['neutron.context'] = context.Context('',
                                                               self.tenant_id,
                                                               is_admin=True)
        update_res = update_req.get_response(self.ext_api)
        self.assertEqual(200, update_res.status_int)
        # current tenant_id should always present
        tenant_id = n1kv_db_v2.get_profile_binding(db_session, self.tenant_id,
                                                net_p['network_profile']['id'])
        self.assertIsNotNone(tenant_id)
        self.assertRaises(c_exc.ProfileTenantBindingNotFound,
                          n1kv_db_v2.get_profile_binding,
                          db_session, 'tenant1',
                          net_p['network_profile']['id'])
        self.assertRaises(c_exc.ProfileTenantBindingNotFound,
                          n1kv_db_v2.get_profile_binding,
                          db_session, 'tenant4',
                          net_p['network_profile']['id'])
        tenant3 = n1kv_db_v2.get_profile_binding(db_session, 'tenant3',
                                                net_p['network_profile']['id'])
        self.assertIsNotNone(tenant3)
        # Add new tenant4 to network profile and make sure existing tenants
        # are not deleted.
        data = {'network_profile': {c_const.ADD_TENANTS:
                                    ['tenant4']}}
        update_req = self.new_update_request('network_profiles',
                                             data,
                                             net_p['network_profile']['id'])
        update_req.environ['neutron.context'] = context.Context('',
                                                               self.tenant_id,
                                                               is_admin=True)
        update_res = update_req.get_response(self.ext_api)
        self.assertEqual(200, update_res.status_int)
        tenant4 = n1kv_db_v2.get_profile_binding(db_session, 'tenant4',
                                                net_p['network_profile']['id'])
        self.assertIsNotNone(tenant4)

    def test_get_network_profile_restricted(self):
        c_conf.CONF.set_override('restrict_network_profiles', True,
                                 'CISCO_N1K')
        ctx1 = context.Context(user_id='admin',
                        tenant_id='tenant1',
                        is_admin=True)
        sess1 = db.get_session()
        net_p = self._make_test_profile(name='netp1')
        n1kv_db_v2.create_profile_binding(sess1, ctx1.tenant_id,
                                          net_p['id'], c_const.NETWORK)
        #network profile binding with creator tenant should always exist
        profile = n1kv_db_v2.get_network_profile(sess1, net_p['id'],
                                                 ctx1.tenant_id)
        self.assertIsNotNone(profile)
        ctx2 = context.Context(user_id='non_admin',
                               tenant_id='tenant2',
                               is_admin=False)
        sess2 = db.get_session()
        self.assertRaises(c_exc.ProfileTenantBindingNotFound,
                          n1kv_db_v2.get_network_profile,
                          sess2, net_p['id'], ctx2.tenant_id)

    def test_get_network_profile_unrestricted(self):
        c_conf.CONF.set_override('restrict_network_profiles', False,
                                 'CISCO_N1K')
        ctx1 = context.Context(user_id='admin',
                               tenant_id='tenant1',
                               is_admin=True)
        sess1 = db.get_session()
        net_p = self._make_test_profile(name='netp1')
        n1kv_db_v2.create_profile_binding(sess1, ctx1.tenant_id,
                                          net_p['id'], c_const.NETWORK)
        # network profile binding with creator tenant should always exist
        profile = n1kv_db_v2.get_network_profile(sess1, net_p['id'],
                                                 ctx1.tenant_id)
        self.assertIsNotNone(profile)
        ctx2 = context.Context(user_id='non_admin',
                               tenant_id='tenant2',
                               is_admin=False)
        sess2 = db.get_session()
        profile = n1kv_db_v2.get_network_profile(sess2, net_p['id'],
                                                 ctx2.tenant_id)
        #network profile will be returned even though the profile is
        #not bound to tenant of sess2
        self.assertIsNotNone(profile)


class TestN1kvBasicGet(test_plugin.TestBasicGet,
                       N1kvPluginTestCase):

    pass


class TestN1kvHTTPResponse(test_plugin.TestV2HTTPResponse,
                           N1kvPluginTestCase):

    pass


class TestN1kvPorts(test_plugin.TestPortsV2,
                    N1kvPluginTestCase,
                    test_bindings.PortBindingsTestCase):
    VIF_TYPE = portbindings.VIF_TYPE_OVS
    HAS_PORT_FILTER = False

    _unsupported = ('test_delete_network_if_port_exists',
                    'test_requested_subnet_id_v4_and_v6')

    def setUp(self):
        if self._testMethodName in self._unsupported:
            self.skipTest("Unsupported test case")
        super(TestN1kvPorts, self).setUp()

    def test_create_port_with_default_n1kv_policy_profile_id(self):
        """Test port create without passing policy profile id."""
        with self.port() as port:
            db_session = db.get_session()
            pp = n1kv_db_v2.get_policy_profile(
                db_session, port['port'][n1kv.PROFILE_ID])
            self.assertEqual(pp['name'], 'service_profile')

    def test_create_port_with_n1kv_policy_profile_id(self):
        """Test port create with policy profile id."""
        profile_obj = self._make_test_policy_profile(name='test_profile')
        with self.network() as network:
            data = {'port': {n1kv.PROFILE_ID: profile_obj.id,
                             'tenant_id': self.tenant_id,
                             'network_id': network['network']['id']}}
            port_req = self.new_create_request('ports', data)
            port = self.deserialize(self.fmt,
                                    port_req.get_response(self.api))
            self.assertEqual(port['port'][n1kv.PROFILE_ID],
                             profile_obj.id)
            self._delete('ports', port['port']['id'])

    def test_update_port_with_n1kv_policy_profile_id(self):
        """Test port update failure while updating policy profile id."""
        with self.port() as port:
            data = {'port': {n1kv.PROFILE_ID: 'some-profile-uuid'}}
            port_req = self.new_update_request('ports',
                                               data,
                                               port['port']['id'])
            res = port_req.get_response(self.api)
            # Port update should fail to update policy profile id.
            self.assertEqual(res.status_int, 400)

    def test_create_first_port_invalid_parameters_fail(self):
        """Test parameters for first port create sent to the VSM."""
        profile_obj = self._make_test_policy_profile(name='test_profile')
        with self.network() as network:
            client_patch = mock.patch(n1kv_client.__name__ + ".Client",
                                      new=fake_client.TestClientInvalidRequest)
            client_patch.start()
            data = {'port': {n1kv.PROFILE_ID: profile_obj.id,
                             'tenant_id': self.tenant_id,
                             'network_id': network['network']['id'],
                             }}
            port_req = self.new_create_request('ports', data)
            res = port_req.get_response(self.api)
            self.assertEqual(res.status_int, 500)
            client_patch.stop()

    def test_create_next_port_invalid_parameters_fail(self):
        """Test parameters for subsequent port create sent to the VSM."""
        with self.port() as port:
            client_patch = mock.patch(n1kv_client.__name__ + ".Client",
                                      new=fake_client.TestClientInvalidRequest)
            client_patch.start()
            data = {'port': {n1kv.PROFILE_ID: port['port']['n1kv:profile_id'],
                             'tenant_id': port['port']['tenant_id'],
                             'network_id': port['port']['network_id']}}
            port_req = self.new_create_request('ports', data)
            res = port_req.get_response(self.api)
            self.assertEqual(res.status_int, 500)
            client_patch.stop()

    def test_create_first_port_rollback_vmnetwork(self):
        """Test whether VMNetwork is cleaned up if port create fails on VSM."""
        db_session = db.get_session()
        profile_obj = self._make_test_policy_profile(name='test_profile')
        with self.network() as network:
            client_patch = mock.patch(n1kv_client.__name__ + ".Client",
                                      new=fake_client.
                                      TestClientInvalidResponse)
            client_patch.start()
            data = {'port': {n1kv.PROFILE_ID: profile_obj.id,
                             'tenant_id': self.tenant_id,
                             'network_id': network['network']['id'],
                             }}
            self.new_create_request('ports', data)
            self.assertRaises(c_exc.VMNetworkNotFound,
                              n1kv_db_v2.get_vm_network,
                              db_session,
                              profile_obj.id,
                              network['network']['id'])
            # Explicit stop of failure response mock from controller required
            # for network object clean up to succeed.
            client_patch.stop()

    def test_create_next_port_rollback_vmnetwork_count(self):
        """Test whether VMNetwork count if port create fails on VSM."""
        db_session = db.get_session()
        with self.port() as port:
            pt = port['port']
            old_vmn = n1kv_db_v2.get_vm_network(db_session,
                                                pt['n1kv:profile_id'],
                                                pt['network_id'])
            client_patch = mock.patch(n1kv_client.__name__ + ".Client",
                                      new=fake_client.
                                      TestClientInvalidResponse)
            client_patch.start()
            data = {'port': {n1kv.PROFILE_ID: pt['n1kv:profile_id'],
                             'tenant_id': pt['tenant_id'],
                             'network_id': pt['network_id']}}
            self.new_create_request('ports', data)
            new_vmn = n1kv_db_v2.get_vm_network(db_session,
                                                pt['n1kv:profile_id'],
                                                pt['network_id'])
            self.assertEqual(old_vmn.port_count, new_vmn.port_count)
            # Explicit stop of failure response mock from controller required
            # for network object clean up to succeed.
            client_patch.stop()

    def test_delete_last_port_vmnetwork_cleanup(self):
        """Test whether VMNetwork is cleaned up from db on last port delete."""
        db_session = db.get_session()
        with self.port() as port:
            pt = port['port']
            self.assertIsNotNone(n1kv_db_v2.
                                 get_vm_network(db_session,
                                                pt['n1kv:profile_id'],
                                                pt['network_id']))
            req = self.new_delete_request('ports', port['port']['id'])
            req.get_response(self.api)
            # Verify VMNetwork is cleaned up from the database on port delete.
            self.assertRaises(c_exc.VMNetworkNotFound,
                              n1kv_db_v2.get_vm_network,
                              db_session,
                              pt['n1kv:profile_id'],
                              pt['network_id'])


class TestN1kvPolicyProfiles(N1kvPluginTestCase):
    def setUp(self):
        """
        Setup function for policy profile tests.

        We need to use the policy profile extension manager for these
        test cases, so call the super class setup, but pass in the
        policy profile extension manager.
        """
        super(TestN1kvPolicyProfiles, self).setUp(
                    ext_mgr=PolicyProfileTestExtensionManager())

    def test_populate_policy_profile(self):
        client_patch = mock.patch(n1kv_client.__name__ + ".Client",
                                  new=fake_client.TestClient)
        client_patch.start()
        instance = n1kv_neutron_plugin.N1kvNeutronPluginV2()
        instance._populate_policy_profiles()
        db_session = db.get_session()
        profile = n1kv_db_v2.get_policy_profile(
            db_session, '00000000-0000-0000-0000-000000000001')
        self.assertEqual('pp-1', profile['name'])
        client_patch.stop()

    def test_populate_policy_profile_delete(self):
        # Patch the Client class with the TestClient class
        with mock.patch(n1kv_client.__name__ + ".Client",
                        new=fake_client.TestClient):
            # Patch the _get_total_profiles() method to return a custom value
            with mock.patch(fake_client.__name__ +
                            '.TestClient._get_total_profiles') as obj_inst:
                # Return 3 policy profiles
                obj_inst.return_value = 3
                plugin = manager.NeutronManager.get_plugin()
                plugin._populate_policy_profiles()
                db_session = db.get_session()
                profile = n1kv_db_v2.get_policy_profile(
                    db_session, '00000000-0000-0000-0000-000000000001')
                # Verify that DB contains only 3 policy profiles
                self.assertEqual('pp-1', profile['name'])
                profile = n1kv_db_v2.get_policy_profile(
                    db_session, '00000000-0000-0000-0000-000000000002')
                self.assertEqual('pp-2', profile['name'])
                profile = n1kv_db_v2.get_policy_profile(
                    db_session, '00000000-0000-0000-0000-000000000003')
                self.assertEqual('pp-3', profile['name'])
                self.assertRaises(c_exc.PolicyProfileIdNotFound,
                                  n1kv_db_v2.get_policy_profile,
                                  db_session,
                                  '00000000-0000-0000-0000-000000000004')
                # Return 2 policy profiles
                obj_inst.return_value = 2
                plugin._populate_policy_profiles()
                # Verify that the third policy profile is deleted
                self.assertRaises(c_exc.PolicyProfileIdNotFound,
                                  n1kv_db_v2.get_policy_profile,
                                  db_session,
                                  '00000000-0000-0000-0000-000000000003')

    def _init_get_policy_profiles(self):
        # Get the profiles
        mock.patch(n1kv_client.__name__ + ".Client",
                   new=fake_client.TestClient).start()
        instance = n1kv_neutron_plugin.N1kvNeutronPluginV2()
        instance._populate_policy_profiles()
        db_session = db.get_session()
        return [
            n1kv_db_v2.get_policy_profile(
                    db_session, '00000000-0000-0000-0000-000000000001'),
            n1kv_db_v2.get_policy_profile(
                    db_session, '00000000-0000-0000-0000-000000000002')
        ]

    def _test_get_policy_profiles(self, expected_profiles, admin):
        resource = 'policy_profiles'
        if admin:
            ctx = context.Context(user_id='admin',
                                  tenant_id='tenant1',
                                  is_admin=True)
        else:
            ctx = context.Context(user_id='non_admin',
                                  tenant_id='tenant1',
                                  is_admin=False)
        res = self._list(resource, neutron_context=ctx)
        self.assertEqual(len(expected_profiles), len(res[resource]))
        profiles = sorted(res[resource])
        for i in range(len(profiles)):
            self.assertEqual(expected_profiles[i].id,
                             profiles[i]['id'])
            self.assertEqual(expected_profiles[i].name,
                             profiles[i]['name'])

    def test_get_profiles_unrestricted(self):
        """
        Test unrestricted policy profile retrieval.

        Test getting policy profiles using the normal unrestricted
        behavior. We set the flag and attempt to retrieve the port
        profiles. It should work for both admin and non-admin.
        """
        # Get the profiles
        profiles = self._init_get_policy_profiles()
        # Set the restriction flag
        c_conf.CONF.set_override('restrict_policy_profiles', False,
                                 'CISCO_N1K')
        # Request the list using non-admin and verify it returns
        self._test_get_policy_profiles(expected_profiles=profiles, admin=False)
        # Request the list using admin and verify it returns
        self._test_get_policy_profiles(expected_profiles=profiles, admin=True)

    def test_get_profiles_restricted(self):
        """
        Test restricted policy profile retrieval.

        Test getting policy profiles using the restricted behavior.
        We set the flag and attempt to retrieve the port profiles. It
        should work for admin and fail for non-admin.
        """
        # Get the profiles
        profiles = self._init_get_policy_profiles()
        # Set the restriction flag
        c_conf.CONF.set_override('restrict_policy_profiles', True,
                                 'CISCO_N1K')
        # Request the list using non-admin and verify it returns no data
        self._test_get_policy_profiles(expected_profiles=[], admin=False)
        # Request the list using admin and verify it returns
        self._test_get_policy_profiles(expected_profiles=profiles, admin=True)

    def test_get_policy_profiles_by_name(self):
        with mock.patch(n1kv_client.__name__ + ".Client",
                        new=fake_client.TestClient):
            instance = n1kv_neutron_plugin.N1kvNeutronPluginV2()
            profile = instance._get_policy_profile_by_name('pp-1')
            self.assertEqual('pp-1', profile['name'])
            self.assertEqual('00000000-0000-0000-0000-000000000001',
                             profile['id'])
            self.assertRaises(c_exc.PolicyProfileNameNotFound,
                              instance._get_policy_profile_by_name,
                              "name")


class TestN1kvNetworks(test_plugin.TestNetworksV2,
                       N1kvPluginTestCase):

    def test_plugin(self):
        self._make_network('json',
                           'some_net',
                           True,
                           tenant_id=self.tenant_id,
                           set_context=True)

        req = self.new_list_request('networks', params="fields=tenant_id")
        req.environ['neutron.context'] = context.Context('', self.tenant_id)
        res = req.get_response(self.api)
        self.assertEqual(res.status_int, 200)
        body = self.deserialize('json', res)
        self.assertIn('tenant_id', body['networks'][0])

    def _prepare_net_data(self, net_profile_id):
        return {'network': {'name': 'net1',
                            n1kv.PROFILE_ID: net_profile_id,
                            'tenant_id': self.tenant_id}}

    def test_create_network_with_default_n1kv_network_profile_id(self):
        """Test network create without passing network profile id."""
        with self.network() as network:
            db_session = db.get_session()
            np = n1kv_db_v2.get_network_profile(
                db_session, network['network'][n1kv.PROFILE_ID])
            self.assertEqual(np['name'], 'default_network_profile')

    def test_create_network_with_n1kv_network_profile_id(self):
        """Test network create with network profile id."""
        profile_obj = self._make_test_profile(name='test_profile')
        data = self._prepare_net_data(profile_obj.id)
        network_req = self.new_create_request('networks', data)
        network = self.deserialize(self.fmt,
                                   network_req.get_response(self.api))
        self.assertEqual(network['network'][n1kv.PROFILE_ID],
                         profile_obj.id)

    def test_update_network_with_n1kv_network_profile_id(self):
        """Test network update failure while updating network profile id."""
        with self.network() as network:
            data = {'network': {n1kv.PROFILE_ID: 'some-profile-uuid'}}
            network_req = self.new_update_request('networks',
                                                  data,
                                                  network['network']['id'])
            res = network_req.get_response(self.api)
            # Network update should fail to update network profile id.
            self.assertEqual(res.status_int, 400)

    def test_create_network_rollback_deallocate_vlan_segment(self):
        """Test vlan segment deallocation on network create failure."""
        profile_obj = self._make_test_profile(name='test_profile',
                                              segment_range='20-23')
        data = self._prepare_net_data(profile_obj.id)
        client_patch = mock.patch(n1kv_client.__name__ + ".Client",
                                  new=fake_client.TestClientInvalidResponse)
        client_patch.start()
        self.new_create_request('networks', data)
        db_session = db.get_session()
        self.assertFalse(n1kv_db_v2.get_vlan_allocation(db_session,
                                                        PHYS_NET,
                                                        20).allocated)

    def test_create_network_rollback_deallocate_overlay_segment(self):
        """Test overlay segment deallocation on network create failure."""
        profile_obj = self._make_test_profile('test_np',
                                              c_const.NETWORK_TYPE_OVERLAY,
                                              '10000-10001')
        data = self._prepare_net_data(profile_obj.id)
        client_patch = mock.patch(n1kv_client.__name__ + ".Client",
                                  new=fake_client.TestClientInvalidResponse)
        client_patch.start()
        self.new_create_request('networks', data)
        db_session = db.get_session()
        self.assertFalse(n1kv_db_v2.get_vxlan_allocation(db_session,
                                                         10000).allocated)

    def test_delete_network(self):
        """Regular test case of network deletion. Should return successful."""
        res = self._create_network(self.fmt, name='net', admin_state_up=True)
        network = self.deserialize(self.fmt, res)
        req = self.new_delete_request('networks', network['network']['id'])
        res = req.get_response(self.api)
        self.assertEqual(res.status_int, webob.exc.HTTPNoContent.code)

    def test_delete_network_with_subnet(self):
        """Network deletion fails when a subnet is present on the network."""
        with self.subnet() as subnet:
            net_id = subnet['subnet']['network_id']
            req = self.new_delete_request('networks', net_id)
            res = req.get_response(self.api)
            self.assertEqual(res.status_int, webob.exc.HTTPBadRequest.code)

    def test_update_network_set_not_shared_multi_tenants2_returns_409(self):
        """
           Verifies that updating a network which cannot be shared,
           returns a conflict error.
        """
        with self.network(shared=True) as network:
            res = self._create_port(self.fmt, network['network']['id'],
                                    webob.exc.HTTPCreated.code,
                                    tenant_id='somebody_else',
                                    set_context=True)
            data = {'network': {'shared': False}}
            req = self.new_update_request('networks', data,
                                          network['network']['id'])
            self.assertEqual(req.get_response(self.api).status_int,
                             webob.exc.HTTPConflict.code)
            port = self.deserialize(self.fmt, res)
            self._delete('ports', port['port']['id'])

    def test_delete_network_if_port_exists(self):
        """Verify that a network with a port attached cannot be removed."""
        res = self._create_network(self.fmt, name='net1', admin_state_up=True)
        network = self.deserialize(self.fmt, res)
        net_id = network['network']['id']
        res = self._create_port(self.fmt, net_id,
                                webob.exc.HTTPCreated.code)
        req = self.new_delete_request('networks', net_id)
        self.assertEqual(req.get_response(self.api).status_int,
                         webob.exc.HTTPConflict.code)


class TestN1kvSubnets(test_plugin.TestSubnetsV2,
                      N1kvPluginTestCase):

    _unsupported = (
        'test_delete_network',
        'test_create_subnets_bulk_emulated',
        'test_create_subnets_bulk_emulated_plugin_failure')

    def setUp(self):
        if self._testMethodName in self._unsupported:
            self.skipTest("Unsupported test")
        super(TestN1kvSubnets, self).setUp()

    def test_port_prevents_network_deletion(self):
        self.skipTest("plugin does not return standard conflict code")

    def test_create_subnet_with_invalid_parameters(self):
        """Test subnet creation with invalid parameters sent to the VSM"""
        with self.network() as network:
            client_patch = mock.patch(n1kv_client.__name__ + ".Client",
                                      new=fake_client.TestClientInvalidRequest)
            client_patch.start()
            data = {'subnet': {'network_id': network['network']['id'],
                               'cidr': "10.0.0.0/24"}}
            subnet_req = self.new_create_request('subnets', data)
            subnet_resp = subnet_req.get_response(self.api)
            # Subnet creation should fail due to invalid network name
            self.assertEqual(subnet_resp.status_int, 400)

    def test_update_subnet_adding_additional_host_routes_and_dns(self):
        host_routes = [{'destination': '172.16.0.0/24',
                        'nexthop': '10.0.2.2'}]
        with self.network() as network:
            data = {'subnet': {'network_id': network['network']['id'],
                               'cidr': '10.0.2.0/24',
                               'ip_version': 4,
                               'dns_nameservers': ['192.168.0.1'],
                               'host_routes': host_routes,
                               'tenant_id': network['network']['tenant_id']}}
            req = self.new_create_request('subnets', data)
            subnet = self.deserialize(self.fmt, req.get_response(self.api))

            host_routes = [{'destination': '172.16.0.0/24',
                            'nexthop': '10.0.2.2'},
                           {'destination': '192.168.0.0/24',
                            'nexthop': '10.0.2.3'}]

            dns_nameservers = ['192.168.0.1', '192.168.0.2']
            data = {'subnet': {'host_routes': host_routes,
                               'dns_nameservers': dns_nameservers}}
            req = self.new_update_request('subnets', data,
                                          subnet['subnet']['id'])
            subnet = self.deserialize(self.fmt, req.get_response(self.api))
            self.assertEqual(sorted(subnet['subnet']['host_routes']),
                             sorted(host_routes))
            self.assertEqual(sorted(subnet['subnet']['dns_nameservers']),
                             sorted(dns_nameservers))
            # In N1K we need to delete the subnet before the network
            req = self.new_delete_request('subnets', subnet['subnet']['id'])
            self.assertEqual(req.get_response(self.api).status_int,
                             webob.exc.HTTPNoContent.code)

    def test_subnet_with_allocation_range(self):
        with self.network() as network:
            net_id = network['network']['id']
            data = {'subnet': {'network_id': net_id,
                               'cidr': '10.0.0.0/24',
                               'ip_version': 4,
                               'gateway_ip': '10.0.0.1',
                               'tenant_id': network['network']['tenant_id'],
                               'allocation_pools': [{'start': '10.0.0.100',
                                                    'end': '10.0.0.120'}]}}
            req = self.new_create_request('subnets', data)
            subnet = self.deserialize(self.fmt, req.get_response(self.api))
            # Check fixed IP not in allocation range
            kwargs = {"fixed_ips": [{'subnet_id': subnet['subnet']['id'],
                                     'ip_address': '10.0.0.10'}]}
            res = self._create_port(self.fmt, net_id=net_id, **kwargs)
            self.assertEqual(res.status_int, webob.exc.HTTPCreated.code)
            port = self.deserialize(self.fmt, res)
            # delete the port
            self._delete('ports', port['port']['id'])
            # Check when fixed IP is gateway
            kwargs = {"fixed_ips": [{'subnet_id': subnet['subnet']['id'],
                                     'ip_address': '10.0.0.1'}]}
            res = self._create_port(self.fmt, net_id=net_id, **kwargs)
            self.assertEqual(res.status_int, webob.exc.HTTPCreated.code)
            port = self.deserialize(self.fmt, res)
            # delete the port
            self._delete('ports', port['port']['id'])
            req = self.new_delete_request('subnets', subnet['subnet']['id'])
            self.assertEqual(req.get_response(self.api).status_int,
                             webob.exc.HTTPNoContent.code)

    def test_requested_subnet_id_v4_and_v6(self):
        with self.network() as network:
            net_id = network['network']['id']
            res = self._create_subnet(self.fmt, tenant_id='tenant1',
                                      net_id=net_id, cidr='10.0.0.0/24',
                                      ip_version=4,
                                      gateway_ip=attributes.ATTR_NOT_SPECIFIED)
            subnet1 = self.deserialize(self.fmt, res)
            res = self._create_subnet(self.fmt, tenant_id='tenant1',
                                      net_id=net_id,
                                      cidr='2607:f0d0:1002:51::/124',
                                      ip_version=6,
                                      gateway_ip=attributes.ATTR_NOT_SPECIFIED)
            subnet2 = self.deserialize(self.fmt, res)
            kwargs = {"fixed_ips": [{'subnet_id': subnet1['subnet']['id']},
                                    {'subnet_id': subnet2['subnet']['id']}]}
            res = self._create_port(self.fmt, net_id=net_id, **kwargs)
            port3 = self.deserialize(self.fmt, res)
            ips = port3['port']['fixed_ips']
            self.assertEqual(len(ips), 2)
            self.assertIn({'ip_address': '10.0.0.2',
                           'subnet_id': subnet1['subnet']['id']}, ips)
            self.assertIn({'ip_address': '2607:f0d0:1002:51::2',
                           'subnet_id': subnet2['subnet']['id']}, ips)
            res = self._create_port(self.fmt, net_id=net_id)
            port4 = self.deserialize(self.fmt, res)
            # Check that a v4 and a v6 address are allocated
            ips = port4['port']['fixed_ips']
            self.assertEqual(len(ips), 2)
            self.assertIn({'ip_address': '10.0.0.3',
                           'subnet_id': subnet1['subnet']['id']}, ips)
            self.assertIn({'ip_address': '2607:f0d0:1002:51::3',
                           'subnet_id': subnet2['subnet']['id']}, ips)
            self._delete('ports', port3['port']['id'])
            self._delete('ports', port4['port']['id'])
            req = self.new_delete_request('subnets', subnet1['subnet']['id'])
            self.assertEqual(req.get_response(self.api).status_int,
                             webob.exc.HTTPNoContent.code)
            req = self.new_delete_request('subnets', subnet2['subnet']['id'])
            self.assertEqual(req.get_response(self.api).status_int,
                             webob.exc.HTTPNoContent.code)

    def test_schedule_network_with_subnet_create(self):
        """Test invocation of explicit scheduling for networks."""
        with mock.patch.object(n1kv_neutron_plugin.N1kvNeutronPluginV2,
                               'schedule_network') as mock_method:
            # Test with network auto-scheduling disabled
            c_conf.CONF.set_override('network_auto_schedule', False)
            # Subnet creation should trigger scheduling for networks
            with self.subnet():
                pass
        self.assertEqual(1, mock_method.call_count)


class TestN1kvL3Test(test_l3.L3NatExtensionTestCase):

    pass


class TestN1kvL3SchedulersTest(test_l3_agent_scheduler.L3SchedulerTestCase):

    pass
