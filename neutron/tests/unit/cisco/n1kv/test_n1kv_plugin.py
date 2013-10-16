# vim: tabstop=4 shiftwidth=4 softtabstop=4

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
#
# @author: Juergen Brendel, Cisco Systems Inc.
# @author: Abhishek Raut, Cisco Systems Inc.

from mock import patch
import os
from oslo.config import cfg

from neutron.api.v2 import attributes
from neutron.common.test_lib import test_config
from neutron import context
import neutron.db.api as db
from neutron.plugins.cisco.db import n1kv_db_v2
from neutron.plugins.cisco.db import network_db_v2 as cdb
from neutron.plugins.cisco import extensions
from neutron.plugins.cisco.extensions import n1kv_profile
from neutron.plugins.cisco.extensions import network_profile
from neutron.plugins.cisco.n1kv import n1kv_client
from neutron.plugins.cisco.n1kv import n1kv_neutron_plugin
from neutron.tests import base
from neutron.tests.unit import test_api_v2
from neutron.tests.unit import test_db_plugin as test_plugin


class FakeResponse(object):

    """
    This object is returned by mocked httplib instead of a normal response.

    Initialize it with the status code, content type and buffer contents
    you wish to return.

    """
    def __init__(self, status, response_text, content_type):
        self.buffer = response_text
        self.status = status

    def __getitem__(cls, val):
        return "application/xml"

    def read(self, *args, **kwargs):
        return self.buffer


def _fake_setup_vsm(self):
    """Fake establish Communication with Cisco Nexus1000V VSM."""
    self.agent_vsm = True
    self._poll_policies(event_type="port_profile")


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
        uuid = test_api_v2._uuid()
        profile = {'id': uuid,
                   'name': name}
        return n1kv_db_v2.create_policy_profile(profile)

    def _make_test_profile(self, name='default_network_profile'):
        """
        Create a profile record for testing purposes.

        :param name: string representing the name of the network profile to
                     create. Default argument value chosen to correspond to the
                     default name specified in config.py file.
        """
        db_session = db.get_session()
        profile = {'name': name,
                   'segment_type': 'vlan',
                   'physical_network': 'phsy1',
                   'segment_range': '3968-4047'}
        self.network_vlan_ranges = {profile[
            'physical_network']: [(3968, 4047)]}
        n1kv_db_v2.sync_vlan_allocations(db_session, self.network_vlan_ranges)
        return n1kv_db_v2.create_network_profile(db_session, profile)

    def setUp(self):
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
            self.DEFAULT_RESP_BODY = (
                """<?xml version="1.0" encoding="utf-8"?>
                <set name="events_set">
                <instance name="1" url="/api/hyper-v/events/1">
                <properties>
                <cmd>configure terminal ; port-profile type vethernet grizzlyPP
                    (SUCCESS)
                </cmd>
                <id>42227269-e348-72ed-bdb7-7ce91cd1423c</id>
                <time>1369223611</time>
                <name>grizzlyPP</name>
                </properties>
                </instance>
                <instance name="2" url="/api/hyper-v/events/2">
                <properties>
                <cmd>configure terminal ; port-profile type vethernet havanaPP
                    (SUCCESS)
                </cmd>
                <id>3fc83608-ae36-70e7-9d22-dec745623d06</id>
                <time>1369223661</time>
                <name>havanaPP</name>
                </properties>
                </instance>
                </set>
                """)
        # Creating a mock HTTP connection object for httplib. The N1KV client
        # interacts with the VSM via HTTP. Since we don't have a VSM running
        # in the unit tests, we need to 'fake' it by patching the HTTP library
        # itself. We install a patch for a fake HTTP connection class.
        # Using __name__ to avoid having to enter the full module path.
        http_patcher = patch(n1kv_client.httplib2.__name__ + ".Http")
        FakeHttpConnection = http_patcher.start()
        self.addCleanup(http_patcher.stop)
        # Now define the return values for a few functions that may be called
        # on any instance of the fake HTTP connection class.
        instance = FakeHttpConnection.return_value
        instance.getresponse.return_value = (FakeResponse(
                                             self.DEFAULT_RESP_CODE,
                                             self.DEFAULT_RESP_BODY,
                                             'application/xml'))
        instance.request.return_value = (instance.getresponse.return_value,
                                         self.DEFAULT_RESP_BODY)

        # Patch some internal functions in a few other parts of the system.
        # These help us move along, without having to mock up even more systems
        # in the background.

        # Return a dummy VSM IP address
        get_vsm_hosts_patcher = patch(n1kv_client.__name__ +
                                      ".Client._get_vsm_hosts")
        fake_get_vsm_hosts = get_vsm_hosts_patcher.start()
        self.addCleanup(get_vsm_hosts_patcher.stop)
        fake_get_vsm_hosts.return_value = ["127.0.0.1"]

        # Return dummy user profiles
        get_cred_name_patcher = patch(cdb.__name__ + ".get_credential_name")
        fake_get_cred_name = get_cred_name_patcher.start()
        self.addCleanup(get_cred_name_patcher.stop)
        fake_get_cred_name.return_value = {"user_name": "admin",
                                           "password": "admin_password"}

        n1kv_neutron_plugin.N1kvNeutronPluginV2._setup_vsm = _fake_setup_vsm

        test_config['plugin_name_v2'] = self._plugin_name
        cfg.CONF.set_override('api_extensions_path',
                              os.path.dirname(extensions.__file__))
        self.addCleanup(cfg.CONF.reset)
        ext_mgr = NetworkProfileTestExtensionManager()
        test_config['extension_manager'] = ext_mgr
        self.addCleanup(self.restore_test_config)

        # Save the original RESOURCE_ATTRIBUTE_MAP
        self.saved_attr_map = {}
        for resource, attrs in attributes.RESOURCE_ATTRIBUTE_MAP.items():
            self.saved_attr_map[resource] = attrs.copy()
        # Update the RESOURCE_ATTRIBUTE_MAP with n1kv specific extended attrs.
        attributes.RESOURCE_ATTRIBUTE_MAP["networks"].update(
            n1kv_profile.EXTENDED_ATTRIBUTES_2_0["networks"])
        attributes.RESOURCE_ATTRIBUTE_MAP["ports"].update(
            n1kv_profile.EXTENDED_ATTRIBUTES_2_0["ports"])
        self.addCleanup(self.restore_resource_attribute_map)
        self.addCleanup(db.clear_db)
        super(N1kvPluginTestCase, self).setUp(self._plugin_name)
        # Create some of the database entries that we require.
        self._make_test_profile()
        self._make_test_policy_profile()

    def restore_resource_attribute_map(self):
        # Restore the original RESOURCE_ATTRIBUTE_MAP
        attributes.RESOURCE_ATTRIBUTE_MAP = self.saved_attr_map

    def restore_test_config(self):
        # Restore the original test_config
        del test_config['plugin_name_v2']

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


class TestN1kvNetworkProfiles(N1kvPluginTestCase):
    def _prepare_net_profile_data(self, segment_type):
        netp = {'network_profile': {'name': 'netp1',
                                    'segment_type': segment_type,
                                    'tenant_id': self.tenant_id}}
        if segment_type == 'vlan':
            netp['network_profile']['segment_range'] = '100-200'
            netp['network_profile']['physical_network'] = 'phys1'
        elif segment_type == 'overlay':
            netp['network_profile']['segment_range'] = '10000-10010'
            netp['network_profile']['sub_type'] = 'enhanced'
        return netp

    def test_create_network_profile_plugin(self):
        data = self._prepare_net_profile_data('vlan')
        net_p_req = self.new_create_request('network_profiles', data)
        res = net_p_req.get_response(self.ext_api)
        self.assertEqual(res.status_int, 201)

    def test_update_network_profile_physical_network_fail(self):
        net_p = self._make_test_profile(name='netp1')
        data = {'network_profile': {'physical_network': 'some-phys-net'}}
        net_p_req = self.new_update_request('network_profiles',
                                            data,
                                            net_p['id'])
        res = net_p_req.get_response(self.ext_api)
        self.assertEqual(res.status_int, 400)

    def test_update_network_profile_segment_type_fail(self):
        net_p = self._make_test_profile(name='netp1')
        data = {'network_profile': {'segment_type': 'overlay'}}
        net_p_req = self.new_update_request('network_profiles',
                                            data,
                                            net_p['id'])
        res = net_p_req.get_response(self.ext_api)
        self.assertEqual(res.status_int, 400)

    def test_update_network_profile_sub_type_fail(self):
        net_p_dict = self._prepare_net_profile_data('overlay')
        net_p_req = self.new_create_request('network_profiles', net_p_dict)
        net_p = self.deserialize(self.fmt,
                                 net_p_req.get_response(self.ext_api))
        data = {'network_profile': {'sub_type': 'vlan'}}
        update_req = self.new_update_request('network_profiles',
                                             data,
                                             net_p['network_profile']['id'])
        update_res = update_req.get_response(self.ext_api)
        self.assertEqual(update_res.status_int, 400)


class TestN1kvBasicGet(test_plugin.TestBasicGet,
                       N1kvPluginTestCase):

    pass


class TestN1kvHTTPResponse(test_plugin.TestV2HTTPResponse,
                           N1kvPluginTestCase):

    pass


class TestN1kvPorts(test_plugin.TestPortsV2,
                    N1kvPluginTestCase):

    def test_create_port_with_default_n1kv_profile_id(self):
        """Test port create without passing policy profile id."""
        with self.port() as port:
            db_session = db.get_session()
            pp = n1kv_db_v2.get_policy_profile(
                db_session, port['port'][n1kv_profile.PROFILE_ID])
            self.assertEqual(pp['name'], 'service_profile')

    def test_create_port_with_n1kv_profile_id(self):
        """Test port create with policy profile id."""
        profile_obj = self._make_test_policy_profile(name='test_profile')
        with self.network() as network:
            data = {'port': {n1kv_profile.PROFILE_ID: profile_obj.id,
                             'tenant_id': self.tenant_id,
                             'network_id': network['network']['id']}}
            port_req = self.new_create_request('ports', data)
            port = self.deserialize(self.fmt,
                                    port_req.get_response(self.api))
            self.assertEqual(port['port'][n1kv_profile.PROFILE_ID],
                             profile_obj.id)
            self._delete('ports', port['port']['id'])

    def test_update_port_with_n1kv_profile_id(self):
        """Test port update failure while updating policy profile id."""
        with self.port() as port:
            data = {'port': {n1kv_profile.PROFILE_ID: 'some-profile-uuid'}}
            port_req = self.new_update_request('ports',
                                               data,
                                               port['port']['id'])
            res = port_req.get_response(self.api)
            # Port update should fail to update policy profile id.
            self.assertEqual(res.status_int, 400)


class TestN1kvNetworks(test_plugin.TestNetworksV2,
                       N1kvPluginTestCase):

    def _prepare_net_data(self, net_profile_id):
        return {'network': {'name': 'net1',
                            n1kv_profile.PROFILE_ID: net_profile_id,
                            'tenant_id': self.tenant_id}}

    def test_create_network_with_default_n1kv_profile_id(self):
        """Test network create without passing network profile id."""
        with self.network() as network:
            db_session = db.get_session()
            np = n1kv_db_v2.get_network_profile(
                db_session, network['network'][n1kv_profile.PROFILE_ID])
            self.assertEqual(np['name'], 'default_network_profile')

    def test_create_network_with_n1kv_profile_id(self):
        """Test network create with network profile id."""
        profile_obj = self._make_test_profile(name='test_profile')
        data = self._prepare_net_data(profile_obj.id)
        network_req = self.new_create_request('networks', data)
        network = self.deserialize(self.fmt,
                                   network_req.get_response(self.api))
        self.assertEqual(network['network'][n1kv_profile.PROFILE_ID],
                         profile_obj.id)

    def test_update_network_with_n1kv_profile_id(self):
        """Test network update failure while updating network profile id."""
        with self.network() as network:
            data = {'network': {n1kv_profile.PROFILE_ID: 'some-profile-uuid'}}
            network_req = self.new_update_request('networks',
                                                  data,
                                                  network['network']['id'])
            res = network_req.get_response(self.api)
            # Network update should fail to update network profile id.
            self.assertEqual(res.status_int, 400)


class TestN1kvNonDbTest(base.BaseTestCase):

    """
    This test class here can be used to test the plugin directly,
    without going through the DB plugin test cases.

    None of the set-up done in N1kvPluginTestCase applies here.

    """
    def test_db(self):
        n1kv_db_v2.initialize()
