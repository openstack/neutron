#    (c) Copyright 2013 Hewlett-Packard Development Company, L.P.
#    All Rights Reserved.
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

import contextlib
import os

from oslo.config import cfg
import webob.exc

from neutron.api import extensions as api_extensions
from neutron.common import config
from neutron import context
from neutron.db import agentschedulers_db
from neutron.db import l3_agentschedulers_db
from neutron.db import servicetype_db as sdb
from neutron.db.vpn import vpn_db
from neutron import extensions
from neutron.extensions import vpnaas
from neutron import manager
from neutron.openstack.common import uuidutils
from neutron.plugins.common import constants
from neutron.scheduler import l3_agent_scheduler
from neutron.services.vpn import plugin as vpn_plugin
from neutron.tests.unit import test_db_plugin
from neutron.tests.unit import test_l3_plugin

DB_CORE_PLUGIN_KLASS = 'neutron.db.db_base_plugin_v2.NeutronDbPluginV2'
DB_VPN_PLUGIN_KLASS = "neutron.services.vpn.plugin.VPNPlugin"
ROOTDIR = os.path.normpath(os.path.join(
    os.path.dirname(__file__),
    '..', '..', '..', '..'))

extensions_path = ':'.join(extensions.__path__)


class TestVpnCorePlugin(test_l3_plugin.TestL3NatIntPlugin,
                        l3_agentschedulers_db.L3AgentSchedulerDbMixin,
                        agentschedulers_db.DhcpAgentSchedulerDbMixin):
    def __init__(self, configfile=None):
        super(TestVpnCorePlugin, self).__init__()
        self.router_scheduler = l3_agent_scheduler.ChanceScheduler()


class VPNTestMixin(object):
    resource_prefix_map = dict(
        (k.replace('_', '-'),
         constants.COMMON_PREFIXES[constants.VPN])
        for k in vpnaas.RESOURCE_ATTRIBUTE_MAP
    )

    def _create_ikepolicy(self, fmt,
                          name='ikepolicy1',
                          auth_algorithm='sha1',
                          encryption_algorithm='aes-128',
                          phase1_negotiation_mode='main',
                          lifetime_units='seconds',
                          lifetime_value=3600,
                          ike_version='v1',
                          pfs='group5',
                          expected_res_status=None, **kwargs):

        data = {'ikepolicy': {
                'name': name,
                'auth_algorithm': auth_algorithm,
                'encryption_algorithm': encryption_algorithm,
                'phase1_negotiation_mode': phase1_negotiation_mode,
                'lifetime': {
                    'units': lifetime_units,
                    'value': lifetime_value},
                'ike_version': ike_version,
                'pfs': pfs,
                'tenant_id': self._tenant_id
                }}
        if kwargs.get('description') is not None:
            data['ikepolicy']['description'] = kwargs['description']

        ikepolicy_req = self.new_create_request('ikepolicies', data, fmt)
        ikepolicy_res = ikepolicy_req.get_response(self.ext_api)
        if expected_res_status:
            self.assertEqual(ikepolicy_res.status_int, expected_res_status)

        return ikepolicy_res

    @contextlib.contextmanager
    def ikepolicy(self, fmt=None,
                  name='ikepolicy1',
                  auth_algorithm='sha1',
                  encryption_algorithm='aes-128',
                  phase1_negotiation_mode='main',
                  lifetime_units='seconds',
                  lifetime_value=3600,
                  ike_version='v1',
                  pfs='group5',
                  do_delete=True,
                  **kwargs):
        if not fmt:
            fmt = self.fmt
        res = self._create_ikepolicy(fmt,
                                     name,
                                     auth_algorithm,
                                     encryption_algorithm,
                                     phase1_negotiation_mode,
                                     lifetime_units,
                                     lifetime_value,
                                     ike_version,
                                     pfs,
                                     **kwargs)
        if res.status_int >= 400:
            raise webob.exc.HTTPClientError(code=res.status_int)
        ikepolicy = self.deserialize(fmt or self.fmt, res)
        yield ikepolicy
        if do_delete:
            self._delete('ikepolicies', ikepolicy['ikepolicy']['id'])

    def _create_ipsecpolicy(self, fmt,
                            name='ipsecpolicy1',
                            auth_algorithm='sha1',
                            encryption_algorithm='aes-128',
                            encapsulation_mode='tunnel',
                            transform_protocol='esp',
                            lifetime_units='seconds',
                            lifetime_value=3600,
                            pfs='group5',
                            expected_res_status=None,
                            **kwargs):

        data = {'ipsecpolicy': {'name': name,
                                'auth_algorithm': auth_algorithm,
                                'encryption_algorithm': encryption_algorithm,
                                'encapsulation_mode': encapsulation_mode,
                                'transform_protocol': transform_protocol,
                                'lifetime': {'units': lifetime_units,
                                             'value': lifetime_value},
                                'pfs': pfs,
                                'tenant_id': self._tenant_id}}
        if kwargs.get('description') is not None:
            data['ipsecpolicy']['description'] = kwargs['description']
        ipsecpolicy_req = self.new_create_request('ipsecpolicies', data, fmt)
        ipsecpolicy_res = ipsecpolicy_req.get_response(self.ext_api)
        if expected_res_status:
            self.assertEqual(ipsecpolicy_res.status_int, expected_res_status)

        return ipsecpolicy_res

    @contextlib.contextmanager
    def ipsecpolicy(self, fmt=None,
                    name='ipsecpolicy1',
                    auth_algorithm='sha1',
                    encryption_algorithm='aes-128',
                    encapsulation_mode='tunnel',
                    transform_protocol='esp',
                    lifetime_units='seconds',
                    lifetime_value=3600,
                    pfs='group5',
                    do_delete=True, **kwargs):
        if not fmt:
            fmt = self.fmt
        res = self._create_ipsecpolicy(fmt,
                                       name,
                                       auth_algorithm,
                                       encryption_algorithm,
                                       encapsulation_mode,
                                       transform_protocol,
                                       lifetime_units,
                                       lifetime_value,
                                       pfs,
                                       **kwargs)
        if res.status_int >= 400:
            raise webob.exc.HTTPClientError(code=res.status_int)
        ipsecpolicy = self.deserialize(fmt or self.fmt, res)
        yield ipsecpolicy
        if do_delete:
            self._delete('ipsecpolicies', ipsecpolicy['ipsecpolicy']['id'])

    def _create_vpnservice(self, fmt, name,
                           admin_state_up,
                           router_id, subnet_id,
                           expected_res_status=None, **kwargs):
        tenant_id = kwargs.get('tenant_id', self._tenant_id)
        data = {'vpnservice': {'name': name,
                               'subnet_id': subnet_id,
                               'router_id': router_id,
                               'admin_state_up': admin_state_up,
                               'tenant_id': tenant_id}}
        if kwargs.get('description') is not None:
            data['vpnservice']['description'] = kwargs['description']
        vpnservice_req = self.new_create_request('vpnservices', data, fmt)
        if (kwargs.get('set_context') and
                'tenant_id' in kwargs):
            # create a specific auth context for this request
            vpnservice_req.environ['neutron.context'] = context.Context(
                '', kwargs['tenant_id'])
        vpnservice_res = vpnservice_req.get_response(self.ext_api)
        if expected_res_status:
            self.assertEqual(vpnservice_res.status_int, expected_res_status)
        return vpnservice_res

    @contextlib.contextmanager
    def vpnservice(self, fmt=None, name='vpnservice1',
                   subnet=None,
                   router=None,
                   admin_state_up=True,
                   do_delete=True,
                   plug_subnet=True,
                   external_subnet_cidr='192.168.100.0/24',
                   external_router=True,
                   **kwargs):
        if not fmt:
            fmt = self.fmt
        with contextlib.nested(
            test_db_plugin.optional_ctx(subnet, self.subnet),
            test_db_plugin.optional_ctx(router, self.router),
            self.subnet(cidr=external_subnet_cidr)) as (tmp_subnet,
                                                        tmp_router,
                                                        public_sub):
            if external_router:
                self._set_net_external(
                    public_sub['subnet']['network_id'])
                self._add_external_gateway_to_router(
                    tmp_router['router']['id'],
                    public_sub['subnet']['network_id'])
                tmp_router['router']['external_gateway_info'] = {
                    'network_id': public_sub['subnet']['network_id']}
            if plug_subnet:
                self._router_interface_action(
                    'add',
                    tmp_router['router']['id'],
                    tmp_subnet['subnet']['id'], None)

            res = self._create_vpnservice(fmt,
                                          name,
                                          admin_state_up,
                                          router_id=(tmp_router['router']
                                                     ['id']),
                                          subnet_id=(tmp_subnet['subnet']
                                                     ['id']),
                                          **kwargs)
            vpnservice = self.deserialize(fmt or self.fmt, res)
            if res.status_int < 400:
                yield vpnservice

            if do_delete and vpnservice.get('vpnservice'):
                self._delete('vpnservices',
                             vpnservice['vpnservice']['id'])
            if plug_subnet:
                self._router_interface_action(
                    'remove',
                    tmp_router['router']['id'],
                    tmp_subnet['subnet']['id'], None)
            if external_router:
                external_gateway = tmp_router['router'].get(
                    'external_gateway_info')
                if external_gateway:
                    network_id = external_gateway['network_id']
                    self._remove_external_gateway_from_router(
                        tmp_router['router']['id'], network_id)
            if res.status_int >= 400:
                raise webob.exc.HTTPClientError(
                    code=res.status_int, detail=vpnservice)
            self._delete('subnets', public_sub['subnet']['id'])
        if not subnet:
            self._delete('subnets', tmp_subnet['subnet']['id'])

    def _create_ipsec_site_connection(self, fmt, name='test',
                                      peer_address='192.168.1.10',
                                      peer_id='192.168.1.10',
                                      peer_cidrs=None,
                                      mtu=1500,
                                      psk='abcdefg',
                                      initiator='bi-directional',
                                      dpd_action='hold',
                                      dpd_interval=30,
                                      dpd_timeout=120,
                                      vpnservice_id='fake_id',
                                      ikepolicy_id='fake_id',
                                      ipsecpolicy_id='fake_id',
                                      admin_state_up=True,
                                      expected_res_status=None, **kwargs):
        data = {
            'ipsec_site_connection': {'name': name,
                                      'peer_address': peer_address,
                                      'peer_id': peer_id,
                                      'peer_cidrs': peer_cidrs,
                                      'mtu': mtu,
                                      'psk': psk,
                                      'initiator': initiator,
                                      'dpd': {
                                          'action': dpd_action,
                                          'interval': dpd_interval,
                                          'timeout': dpd_timeout,
                                      },
                                      'vpnservice_id': vpnservice_id,
                                      'ikepolicy_id': ikepolicy_id,
                                      'ipsecpolicy_id': ipsecpolicy_id,
                                      'admin_state_up': admin_state_up,
                                      'tenant_id': self._tenant_id}
        }
        if kwargs.get('description') is not None:
            data['ipsec_site_connection'][
                'description'] = kwargs['description']

        ipsec_site_connection_req = self.new_create_request(
            'ipsec-site-connections', data, fmt
        )
        ipsec_site_connection_res = ipsec_site_connection_req.get_response(
            self.ext_api
        )
        if expected_res_status:
            self.assertEqual(
                ipsec_site_connection_res.status_int, expected_res_status
            )

        return ipsec_site_connection_res

    @contextlib.contextmanager
    def ipsec_site_connection(self, fmt=None, name='ipsec_site_connection1',
                              peer_address='192.168.1.10',
                              peer_id='192.168.1.10',
                              peer_cidrs=None,
                              mtu=1500,
                              psk='abcdefg',
                              initiator='bi-directional',
                              dpd_action='hold',
                              dpd_interval=30,
                              dpd_timeout=120,
                              vpnservice=None,
                              ikepolicy=None,
                              ipsecpolicy=None,
                              admin_state_up=True, do_delete=True,
                              **kwargs):
        if not fmt:
            fmt = self.fmt
        with contextlib.nested(
            test_db_plugin.optional_ctx(vpnservice,
                                        self.vpnservice),
            test_db_plugin.optional_ctx(ikepolicy,
                                        self.ikepolicy),
            test_db_plugin.optional_ctx(ipsecpolicy,
                                        self.ipsecpolicy)
        ) as (tmp_vpnservice, tmp_ikepolicy, tmp_ipsecpolicy):
            vpnservice_id = tmp_vpnservice['vpnservice']['id']
            ikepolicy_id = tmp_ikepolicy['ikepolicy']['id']
            ipsecpolicy_id = tmp_ipsecpolicy['ipsecpolicy']['id']
            res = self._create_ipsec_site_connection(fmt,
                                                     name,
                                                     peer_address,
                                                     peer_id,
                                                     peer_cidrs,
                                                     mtu,
                                                     psk,
                                                     initiator,
                                                     dpd_action,
                                                     dpd_interval,
                                                     dpd_timeout,
                                                     vpnservice_id,
                                                     ikepolicy_id,
                                                     ipsecpolicy_id,
                                                     admin_state_up,
                                                     **kwargs)
            if res.status_int >= 400:
                raise webob.exc.HTTPClientError(code=res.status_int)

            ipsec_site_connection = self.deserialize(
                fmt or self.fmt, res
            )
            yield ipsec_site_connection

            if do_delete:
                self._delete(
                    'ipsec-site-connections',
                    ipsec_site_connection[
                        'ipsec_site_connection']['id']
                )

    def _check_ipsec_site_connection(self, ipsec_site_connection, keys, dpd):
        self.assertEqual(
            keys,
            dict((k, v) for k, v
                 in ipsec_site_connection.items()
                 if k in keys))
        self.assertEqual(
            dpd,
            dict((k, v) for k, v
                 in ipsec_site_connection['dpd'].items()
                 if k in dpd))

    def _set_active(self, model, resource_id):
        service_plugin = manager.NeutronManager.get_service_plugins()[
            constants.VPN]
        adminContext = context.get_admin_context()
        with adminContext.session.begin(subtransactions=True):
            resource_db = service_plugin._get_resource(
                adminContext,
                model,
                resource_id)
            resource_db.status = constants.ACTIVE


class VPNPluginDbTestCase(VPNTestMixin,
                          test_l3_plugin.L3NatTestCaseMixin,
                          test_db_plugin.NeutronDbPluginV2TestCase):
    def setUp(self, core_plugin=None, vpnaas_plugin=DB_VPN_PLUGIN_KLASS,
              vpnaas_provider=None):
        if not vpnaas_provider:
            vpnaas_provider = (
                constants.VPN +
                ':vpnaas:neutron.services.vpn.'
                'service_drivers.ipsec.IPsecVPNDriver:default')

        cfg.CONF.set_override('service_provider',
                              [vpnaas_provider],
                              'service_providers')
        # force service type manager to reload configuration:
        sdb.ServiceTypeManager._instance = None

        service_plugins = {'vpnaas_plugin': vpnaas_plugin}
        plugin_str = ('neutron.tests.unit.db.vpn.'
                      'test_db_vpnaas.TestVpnCorePlugin')

        super(VPNPluginDbTestCase, self).setUp(
            plugin_str,
            service_plugins=service_plugins
        )
        self._subnet_id = uuidutils.generate_uuid()
        self.core_plugin = TestVpnCorePlugin
        self.plugin = vpn_plugin.VPNPlugin()
        ext_mgr = api_extensions.PluginAwareExtensionManager(
            extensions_path,
            {constants.CORE: self.core_plugin,
             constants.VPN: self.plugin}
        )
        app = config.load_paste_app('extensions_test_app')
        self.ext_api = api_extensions.ExtensionMiddleware(app, ext_mgr=ext_mgr)


class TestVpnaas(VPNPluginDbTestCase):

    def _check_policy(self, policy, keys, lifetime):
        for k, v in keys:
            self.assertEqual(policy[k], v)
        for k, v in lifetime.iteritems():
            self.assertEqual(policy['lifetime'][k], v)

    def test_create_ikepolicy(self):
        """Test case to create an ikepolicy."""
        name = "ikepolicy1"
        description = 'ipsec-ikepolicy'
        keys = [('name', name),
                ('description', 'ipsec-ikepolicy'),
                ('auth_algorithm', 'sha1'),
                ('encryption_algorithm', 'aes-128'),
                ('phase1_negotiation_mode', 'main'),
                ('ike_version', 'v1'),
                ('pfs', 'group5'),
                ('tenant_id', self._tenant_id)]
        lifetime = {
            'units': 'seconds',
            'value': 3600}
        with self.ikepolicy(name=name, description=description) as ikepolicy:
            self._check_policy(ikepolicy['ikepolicy'], keys, lifetime)

    def test_delete_ikepolicy(self):
        """Test case to delete an ikepolicy."""
        with self.ikepolicy(do_delete=False) as ikepolicy:
            req = self.new_delete_request('ikepolicies',
                                          ikepolicy['ikepolicy']['id'])
            res = req.get_response(self.ext_api)
            self.assertEqual(res.status_int, 204)

    def test_show_ikepolicy(self):
        """Test case to show or get an ikepolicy."""
        name = "ikepolicy1"
        description = 'ipsec-ikepolicy'
        keys = [('name', name),
                ('auth_algorithm', 'sha1'),
                ('encryption_algorithm', 'aes-128'),
                ('phase1_negotiation_mode', 'main'),
                ('ike_version', 'v1'),
                ('pfs', 'group5'),
                ('tenant_id', self._tenant_id)]
        lifetime = {
            'units': 'seconds',
            'value': 3600}
        with self.ikepolicy(name=name, description=description) as ikepolicy:
            req = self.new_show_request('ikepolicies',
                                        ikepolicy['ikepolicy']['id'],
                                        fmt=self.fmt)
            res = self.deserialize(self.fmt, req.get_response(self.ext_api))
            self._check_policy(res['ikepolicy'], keys, lifetime)

    def test_list_ikepolicies(self):
        """Test case to list all ikepolicies."""
        name = "ikepolicy_list"
        keys = [('name', name),
                ('auth_algorithm', 'sha1'),
                ('encryption_algorithm', 'aes-128'),
                ('phase1_negotiation_mode', 'main'),
                ('ike_version', 'v1'),
                ('pfs', 'group5'),
                ('tenant_id', self._tenant_id)]
        lifetime = {
            'units': 'seconds',
            'value': 3600}
        with self.ikepolicy(name=name) as ikepolicy:
            keys.append(('id', ikepolicy['ikepolicy']['id']))
            req = self.new_list_request('ikepolicies')
            res = self.deserialize(self.fmt, req.get_response(self.ext_api))
            self.assertEqual(len(res), 1)
            for k, v in keys:
                self.assertEqual(res['ikepolicies'][0][k], v)
            for k, v in lifetime.iteritems():
                self.assertEqual(res['ikepolicies'][0]['lifetime'][k], v)

    def test_list_ikepolicies_with_sort_emulated(self):
        """Test case to list all ikepolicies."""
        with contextlib.nested(self.ikepolicy(name='ikepolicy1'),
                               self.ikepolicy(name='ikepolicy2'),
                               self.ikepolicy(name='ikepolicy3')
                               ) as (ikepolicy1, ikepolicy2, ikepolicy3):
            self._test_list_with_sort('ikepolicy', (ikepolicy3,
                                                    ikepolicy2,
                                                    ikepolicy1),
                                      [('name', 'desc')],
                                      'ikepolicies')

    def test_list_ikepolicies_with_pagination_emulated(self):
        """Test case to list all ikepolicies with pagination."""
        with contextlib.nested(self.ikepolicy(name='ikepolicy1'),
                               self.ikepolicy(name='ikepolicy2'),
                               self.ikepolicy(name='ikepolicy3')
                               ) as (ikepolicy1, ikepolicy2, ikepolicy3):
            self._test_list_with_pagination('ikepolicy',
                                            (ikepolicy1,
                                             ikepolicy2,
                                             ikepolicy3),
                                            ('name', 'asc'), 2, 2,
                                            'ikepolicies')

    def test_list_ikepolicies_with_pagination_reverse_emulated(self):
        """Test case to list all ikepolicies with reverse pagination."""
        with contextlib.nested(self.ikepolicy(name='ikepolicy1'),
                               self.ikepolicy(name='ikepolicy2'),
                               self.ikepolicy(name='ikepolicy3')
                               ) as (ikepolicy1, ikepolicy2, ikepolicy3):
            self._test_list_with_pagination_reverse('ikepolicy',
                                                    (ikepolicy1,
                                                     ikepolicy2,
                                                     ikepolicy3),
                                                    ('name', 'asc'), 2, 2,
                                                    'ikepolicies')

    def test_update_ikepolicy(self):
        """Test case to update an ikepolicy."""
        name = "new_ikepolicy1"
        keys = [('name', name),
                ('auth_algorithm', 'sha1'),
                ('encryption_algorithm', 'aes-128'),
                ('phase1_negotiation_mode', 'main'),
                ('ike_version', 'v1'),
                ('pfs', 'group5'),
                ('tenant_id', self._tenant_id),
                ('lifetime', {'units': 'seconds',
                              'value': 60})]
        with self.ikepolicy(name=name) as ikepolicy:
            data = {'ikepolicy': {'name': name,
                                  'lifetime': {'units': 'seconds',
                                               'value': 60}}}
            req = self.new_update_request("ikepolicies",
                                          data,
                                          ikepolicy['ikepolicy']['id'])
            res = self.deserialize(self.fmt, req.get_response(self.ext_api))
            for k, v in keys:
                self.assertEqual(res['ikepolicy'][k], v)

    def test_create_ikepolicy_with_invalid_values(self):
        """Test case to test invalid values."""
        name = 'ikepolicy1'
        self._create_ikepolicy(name=name,
                               fmt=self.fmt,
                               auth_algorithm='md5',
                               expected_res_status=400)
        self._create_ikepolicy(name=name,
                               fmt=self.fmt,
                               auth_algorithm=200,
                               expected_res_status=400)
        self._create_ikepolicy(name=name,
                               fmt=self.fmt,
                               encryption_algorithm='des',
                               expected_res_status=400)
        self._create_ikepolicy(name=name,
                               fmt=self.fmt,
                               encryption_algorithm=100,
                               expected_res_status=400)
        self._create_ikepolicy(name=name,
                               fmt=self.fmt,
                               phase1_negotiation_mode='aggressive',
                               expected_res_status=400)
        self._create_ikepolicy(name=name,
                               fmt=self.fmt,
                               phase1_negotiation_mode=-100,
                               expected_res_status=400)
        self._create_ikepolicy(name=name,
                               fmt=self.fmt,
                               ike_version='v6',
                               expected_res_status=400)
        self._create_ikepolicy(name=name,
                               fmt=self.fmt,
                               ike_version=500,
                               expected_res_status=400)
        self._create_ikepolicy(name=name,
                               fmt=self.fmt,
                               pfs='group1',
                               expected_res_status=400)
        self._create_ikepolicy(name=name,
                               fmt=self.fmt,
                               pfs=120,
                               expected_res_status=400)
        self._create_ikepolicy(name=name,
                               fmt=self.fmt,
                               lifetime_units='Megabytes',
                               expected_res_status=400)
        self._create_ikepolicy(name=name,
                               fmt=self.fmt,
                               lifetime_units=20000,
                               expected_res_status=400)
        self._create_ikepolicy(name=name,
                               fmt=self.fmt,
                               lifetime_value=-20,
                               expected_res_status=400)
        self._create_ikepolicy(name=name,
                               fmt=self.fmt,
                               lifetime_value='Megabytes',
                               expected_res_status=400)

    def test_create_ipsecpolicy(self):
        """Test case to create an ipsecpolicy."""
        name = "ipsecpolicy1"
        description = 'my-ipsecpolicy'
        keys = [('name', name),
                ('description', 'my-ipsecpolicy'),
                ('auth_algorithm', 'sha1'),
                ('encryption_algorithm', 'aes-128'),
                ('encapsulation_mode', 'tunnel'),
                ('transform_protocol', 'esp'),
                ('pfs', 'group5'),
                ('tenant_id', self._tenant_id)]
        lifetime = {
            'units': 'seconds',
            'value': 3600}
        with self.ipsecpolicy(name=name,
                              description=description) as ipsecpolicy:
            self._check_policy(ipsecpolicy['ipsecpolicy'], keys, lifetime)

    def test_delete_ipsecpolicy(self):
        """Test case to delete an ipsecpolicy."""
        with self.ipsecpolicy(do_delete=False) as ipsecpolicy:
            req = self.new_delete_request('ipsecpolicies',
                                          ipsecpolicy['ipsecpolicy']['id'])
            res = req.get_response(self.ext_api)
            self.assertEqual(res.status_int, 204)

    def test_show_ipsecpolicy(self):
        """Test case to show or get an ipsecpolicy."""
        name = "ipsecpolicy1"
        keys = [('name', name),
                ('auth_algorithm', 'sha1'),
                ('encryption_algorithm', 'aes-128'),
                ('encapsulation_mode', 'tunnel'),
                ('transform_protocol', 'esp'),
                ('pfs', 'group5'),
                ('tenant_id', self._tenant_id)]
        lifetime = {
            'units': 'seconds',
            'value': 3600}
        with self.ipsecpolicy(name=name) as ipsecpolicy:
            req = self.new_show_request('ipsecpolicies',
                                        ipsecpolicy['ipsecpolicy']['id'],
                                        fmt=self.fmt)
            res = self.deserialize(self.fmt, req.get_response(self.ext_api))
            self._check_policy(res['ipsecpolicy'], keys, lifetime)

    def test_list_ipsecpolicies(self):
        """Test case to list all ipsecpolicies."""
        name = "ipsecpolicy_list"
        keys = [('name', name),
                ('auth_algorithm', 'sha1'),
                ('encryption_algorithm', 'aes-128'),
                ('encapsulation_mode', 'tunnel'),
                ('transform_protocol', 'esp'),
                ('pfs', 'group5'),
                ('tenant_id', self._tenant_id)]
        lifetime = {
            'units': 'seconds',
            'value': 3600}
        with self.ipsecpolicy(name=name) as ipsecpolicy:
            keys.append(('id', ipsecpolicy['ipsecpolicy']['id']))
            req = self.new_list_request('ipsecpolicies')
            res = self.deserialize(self.fmt, req.get_response(self.ext_api))
            self.assertEqual(len(res), 1)
            self._check_policy(res['ipsecpolicies'][0], keys, lifetime)

    def test_list_ipsecpolicies_with_sort_emulated(self):
        """Test case to list all ipsecpolicies."""
        with contextlib.nested(self.ipsecpolicy(name='ipsecpolicy1'),
                               self.ipsecpolicy(name='ipsecpolicy2'),
                               self.ipsecpolicy(name='ipsecpolicy3')
                               ) as(ipsecpolicy1, ipsecpolicy2, ipsecpolicy3):
            self._test_list_with_sort('ipsecpolicy', (ipsecpolicy3,
                                                      ipsecpolicy2,
                                                      ipsecpolicy1),
                                      [('name', 'desc')],
                                      'ipsecpolicies')

    def test_list_ipsecpolicies_with_pagination_emulated(self):
        """Test case to list all ipsecpolicies with pagination."""
        with contextlib.nested(self.ipsecpolicy(name='ipsecpolicy1'),
                               self.ipsecpolicy(name='ipsecpolicy2'),
                               self.ipsecpolicy(name='ipsecpolicy3')
                               ) as(ipsecpolicy1, ipsecpolicy2, ipsecpolicy3):
            self._test_list_with_pagination('ipsecpolicy',
                                            (ipsecpolicy1,
                                             ipsecpolicy2,
                                             ipsecpolicy3),
                                            ('name', 'asc'), 2, 2,
                                            'ipsecpolicies')

    def test_list_ipsecpolicies_with_pagination_reverse_emulated(self):
        """Test case to list all ipsecpolicies with reverse pagination."""
        with contextlib.nested(self.ipsecpolicy(name='ipsecpolicy1'),
                               self.ipsecpolicy(name='ipsecpolicy2'),
                               self.ipsecpolicy(name='ipsecpolicy3')
                               ) as(ipsecpolicy1, ipsecpolicy2, ipsecpolicy3):
            self._test_list_with_pagination_reverse('ipsecpolicy',
                                                    (ipsecpolicy1,
                                                     ipsecpolicy2,
                                                     ipsecpolicy3),
                                                    ('name', 'asc'), 2, 2,
                                                    'ipsecpolicies')

    def test_update_ipsecpolicy(self):
        """Test case to update an ipsecpolicy."""
        name = "new_ipsecpolicy1"
        keys = [('name', name),
                ('auth_algorithm', 'sha1'),
                ('encryption_algorithm', 'aes-128'),
                ('encapsulation_mode', 'tunnel'),
                ('transform_protocol', 'esp'),
                ('pfs', 'group5'),
                ('tenant_id', self._tenant_id),
                ('lifetime', {'units': 'seconds',
                              'value': 60})]
        with self.ipsecpolicy(name=name) as ipsecpolicy:
            data = {'ipsecpolicy': {'name': name,
                                    'lifetime': {'units': 'seconds',
                                                 'value': 60}}}
            req = self.new_update_request("ipsecpolicies",
                                          data,
                                          ipsecpolicy['ipsecpolicy']['id'])
            res = self.deserialize(self.fmt, req.get_response(self.ext_api))
            for k, v in keys:
                self.assertEqual(res['ipsecpolicy'][k], v)

    def test_update_ipsecpolicy_lifetime(self):
        with self.ipsecpolicy() as ipsecpolicy:
            data = {'ipsecpolicy': {'lifetime': {'units': 'seconds'}}}
            req = self.new_update_request("ipsecpolicies",
                                          data,
                                          ipsecpolicy['ipsecpolicy']['id'])
            res = self.deserialize(self.fmt, req.get_response(self.ext_api))
            self.assertEqual(res['ipsecpolicy']['lifetime']['units'],
                             'seconds')

            data = {'ipsecpolicy': {'lifetime': {'value': 60}}}
            req = self.new_update_request("ipsecpolicies",
                                          data,
                                          ipsecpolicy['ipsecpolicy']['id'])
            res = self.deserialize(self.fmt, req.get_response(self.ext_api))
            self.assertEqual(res['ipsecpolicy']['lifetime']['value'], 60)

    def test_create_ipsecpolicy_with_invalid_values(self):
        """Test case to test invalid values."""
        name = 'ipsecpolicy1'

        self._create_ipsecpolicy(
            fmt=self.fmt,
            name=name, auth_algorithm='md5', expected_res_status=400)
        self._create_ipsecpolicy(
            fmt=self.fmt,
            name=name, auth_algorithm=100, expected_res_status=400)

        self._create_ipsecpolicy(
            fmt=self.fmt,
            name=name, encryption_algorithm='des', expected_res_status=400)
        self._create_ipsecpolicy(
            fmt=self.fmt,
            name=name, encryption_algorithm=200, expected_res_status=400)

        self._create_ipsecpolicy(
            fmt=self.fmt,
            name=name, transform_protocol='abcd', expected_res_status=400)
        self._create_ipsecpolicy(
            fmt=self.fmt,
            name=name, transform_protocol=500, expected_res_status=400)

        self._create_ipsecpolicy(
            fmt=self.fmt,
            name=name,
            encapsulation_mode='unsupported', expected_res_status=400)
        self._create_ipsecpolicy(name=name,
                                 fmt=self.fmt,
                                 encapsulation_mode=100,
                                 expected_res_status=400)

        self._create_ipsecpolicy(name=name,
                                 fmt=self.fmt,
                                 pfs='group9', expected_res_status=400)
        self._create_ipsecpolicy(
            fmt=self.fmt, name=name, pfs=-1, expected_res_status=400)

        self._create_ipsecpolicy(
            fmt=self.fmt, name=name, lifetime_units='minutes',
            expected_res_status=400)

        self._create_ipsecpolicy(fmt=self.fmt, name=name, lifetime_units=100,
                                 expected_res_status=400)

        self._create_ipsecpolicy(fmt=self.fmt, name=name,
                                 lifetime_value=-800, expected_res_status=400)
        self._create_ipsecpolicy(fmt=self.fmt, name=name,
                                 lifetime_value='Megabytes',
                                 expected_res_status=400)

    def test_create_vpnservice(self, **extras):
        """Test case to create a vpnservice."""
        description = 'my-vpn-service'
        expected = {'name': 'vpnservice1',
                    'description': 'my-vpn-service',
                    'admin_state_up': True,
                    'status': 'PENDING_CREATE',
                    'tenant_id': self._tenant_id, }

        expected.update(extras)
        with self.subnet(cidr='10.2.0.0/24') as subnet:
            with self.router() as router:
                expected['router_id'] = router['router']['id']
                expected['subnet_id'] = subnet['subnet']['id']
                name = expected['name']
                with self.vpnservice(name=name,
                                     subnet=subnet,
                                     router=router,
                                     description=description,
                                     **extras) as vpnservice:
                    self.assertEqual(dict((k, v) for k, v in
                                          vpnservice['vpnservice'].items()
                                          if k in expected),
                                     expected)

    def test_update_vpnservice(self):
        """Test case to update a vpnservice."""
        name = 'new_vpnservice1'
        keys = [('name', name)]
        with contextlib.nested(
            self.subnet(cidr='10.2.0.0/24'),
            self.router()) as (subnet, router):
            with self.vpnservice(name=name,
                                 subnet=subnet,
                                 router=router) as vpnservice:
                keys.append(('subnet_id',
                             vpnservice['vpnservice']['subnet_id']))
                keys.append(('router_id',
                             vpnservice['vpnservice']['router_id']))
                data = {'vpnservice': {'name': name}}
                self._set_active(vpn_db.VPNService,
                                 vpnservice['vpnservice']['id'])
                req = self.new_update_request(
                    'vpnservices',
                    data,
                    vpnservice['vpnservice']['id'])
                res = self.deserialize(self.fmt,
                                       req.get_response(self.ext_api))
                for k, v in keys:
                    self.assertEqual(res['vpnservice'][k], v)

    def test_update_vpnservice_with_invalid_state(self):
        """Test case to update a vpnservice in invalid state ."""
        name = 'new_vpnservice1'
        keys = [('name', name)]
        with contextlib.nested(
            self.subnet(cidr='10.2.0.0/24'),
            self.router()) as (subnet, router):
            with self.vpnservice(name=name,
                                 subnet=subnet,
                                 router=router) as vpnservice:
                keys.append(('subnet_id',
                             vpnservice['vpnservice']['subnet_id']))
                keys.append(('router_id',
                             vpnservice['vpnservice']['router_id']))
                data = {'vpnservice': {'name': name}}
                req = self.new_update_request(
                    'vpnservices',
                    data,
                    vpnservice['vpnservice']['id'])
                res = req.get_response(self.ext_api)
                self.assertEqual(400, res.status_int)
                res = self.deserialize(self.fmt, res)
                self.assertIn(vpnservice['vpnservice']['id'],
                              res['NeutronError']['message'])

    def test_delete_vpnservice(self):
        """Test case to delete a vpnservice."""
        with self.vpnservice(name='vpnserver',
                             do_delete=False) as vpnservice:
            req = self.new_delete_request('vpnservices',
                                          vpnservice['vpnservice']['id'])
            res = req.get_response(self.ext_api)
            self.assertEqual(res.status_int, 204)

    def test_show_vpnservice(self):
        """Test case to show or get a vpnservice."""
        name = "vpnservice1"
        keys = [('name', name),
                ('description', ''),
                ('admin_state_up', True),
                ('status', 'PENDING_CREATE')]
        with self.vpnservice(name=name) as vpnservice:
            req = self.new_show_request('vpnservices',
                                        vpnservice['vpnservice']['id'])
            res = self.deserialize(self.fmt, req.get_response(self.ext_api))
            for k, v in keys:
                self.assertEqual(res['vpnservice'][k], v)

    def test_list_vpnservices(self):
        """Test case to list all vpnservices."""
        name = "vpnservice_list"
        keys = [('name', name),
                ('description', ''),
                ('admin_state_up', True),
                ('status', 'PENDING_CREATE')]
        with self.vpnservice(name=name) as vpnservice:
            keys.append(('subnet_id', vpnservice['vpnservice']['subnet_id']))
            keys.append(('router_id', vpnservice['vpnservice']['router_id']))
            req = self.new_list_request('vpnservices')
            res = self.deserialize(self.fmt, req.get_response(self.ext_api))
            self.assertEqual(len(res), 1)
            for k, v in keys:
                self.assertEqual(res['vpnservices'][0][k], v)

    def test_list_vpnservices_with_sort_emulated(self):
        """Test case to list all vpnservices with sorting."""
        with self.subnet() as subnet:
            with self.router() as router:
                with contextlib.nested(
                    self.vpnservice(name='vpnservice1',
                                    subnet=subnet,
                                    router=router,
                                    external_subnet_cidr='192.168.10.0/24',),
                    self.vpnservice(name='vpnservice2',
                                    subnet=subnet,
                                    router=router,
                                    plug_subnet=False,
                                    external_router=False,
                                    external_subnet_cidr='192.168.11.0/24',),
                    self.vpnservice(name='vpnservice3',
                                    subnet=subnet,
                                    router=router,
                                    plug_subnet=False,
                                    external_router=False,
                                    external_subnet_cidr='192.168.13.0/24',)
                ) as(vpnservice1, vpnservice2, vpnservice3):
                    self._test_list_with_sort('vpnservice', (vpnservice3,
                                                             vpnservice2,
                                                             vpnservice1),
                                              [('name', 'desc')])

    def test_list_vpnservice_with_pagination_emulated(self):
        """Test case to list all vpnservices with pagination."""
        with self.subnet() as subnet:
            with self.router() as router:
                with contextlib.nested(
                    self.vpnservice(name='vpnservice1',
                                    subnet=subnet,
                                    router=router,
                                    external_subnet_cidr='192.168.10.0/24'),
                    self.vpnservice(name='vpnservice2',
                                    subnet=subnet,
                                    router=router,
                                    plug_subnet=False,
                                    external_subnet_cidr='192.168.20.0/24',
                                    external_router=False),
                    self.vpnservice(name='vpnservice3',
                                    subnet=subnet,
                                    router=router,
                                    plug_subnet=False,
                                    external_subnet_cidr='192.168.30.0/24',
                                    external_router=False)
                ) as(vpnservice1, vpnservice2, vpnservice3):
                    self._test_list_with_pagination('vpnservice',
                                                    (vpnservice1,
                                                     vpnservice2,
                                                     vpnservice3),
                                                    ('name', 'asc'), 2, 2)

    def test_list_vpnservice_with_pagination_reverse_emulated(self):
        """Test case to list all vpnservices with reverse pagination."""
        with self.subnet() as subnet:
            with self.router() as router:
                with contextlib.nested(
                    self.vpnservice(name='vpnservice1',
                                    subnet=subnet,
                                    router=router,
                                    external_subnet_cidr='192.168.10.0/24'),
                    self.vpnservice(name='vpnservice2',
                                    subnet=subnet,
                                    router=router,
                                    plug_subnet=False,
                                    external_subnet_cidr='192.168.11.0/24',
                                    external_router=False),
                    self.vpnservice(name='vpnservice3',
                                    subnet=subnet,
                                    router=router,
                                    plug_subnet=False,
                                    external_subnet_cidr='192.168.12.0/24',
                                    external_router=False)
                ) as(vpnservice1, vpnservice2, vpnservice3):
                    self._test_list_with_pagination_reverse('vpnservice',
                                                            (vpnservice1,
                                                             vpnservice2,
                                                             vpnservice3),
                                                            ('name', 'asc'),
                                                            2, 2)

    def test_create_ipsec_site_connection_with_invalid_values(self):
        """Test case to create an ipsec_site_connection with invalid values."""
        name = 'connection1'
        self._create_ipsec_site_connection(
            fmt=self.fmt,
            name=name, peer_cidrs='myname', expected_status_int=400)
        self._create_ipsec_site_connection(
            fmt=self.fmt,
            name=name, mtu=-100, expected_status_int=400)
        self._create_ipsec_site_connection(
            fmt=self.fmt,
            name=name, dpd_action='unsupported', expected_status_int=400)
        self._create_ipsec_site_connection(
            fmt=self.fmt,
            name=name, dpd_interval=-1, expected_status_int=400)
        self._create_ipsec_site_connection(
            fmt=self.fmt,
            name=name, dpd_timeout=-200, expected_status_int=400)
        self._create_ipsec_site_connection(
            fmt=self.fmt,
            name=name, initiator='unsupported', expected_status_int=400)

    def _test_create_ipsec_site_connection(self, key_overrides=None,
                                           setup_overrides=None,
                                           expected_status_int=200):
        """Create ipsec_site_connection and check results."""
        params = {'ikename': 'ikepolicy1',
                  'ipsecname': 'ipsecpolicy1',
                  'vpnsname': 'vpnservice1',
                  'subnet_cidr': '10.2.0.0/24',
                  'subnet_version': 4}
        if setup_overrides is not None:
            params.update(setup_overrides)
        keys = {'name': 'connection1',
                'description': 'my-ipsec-connection',
                'peer_address': '192.168.1.10',
                'peer_id': '192.168.1.10',
                'peer_cidrs': ['192.168.2.0/24', '192.168.3.0/24'],
                'initiator': 'bi-directional',
                'mtu': 1500,
                'tenant_id': self._tenant_id,
                'psk': 'abcd',
                'status': 'PENDING_CREATE',
                'admin_state_up': True}
        if key_overrides is not None:
            keys.update(key_overrides)
        dpd = {'action': 'hold',
               'interval': 40,
               'timeout': 120}
        with contextlib.nested(
            self.ikepolicy(name=params['ikename']),
            self.ipsecpolicy(name=params['ipsecname']),
            self.subnet(cidr=params['subnet_cidr'],
                        ip_version=params['subnet_version']),
            self.router()) as (
                ikepolicy, ipsecpolicy, subnet, router):
                with self.vpnservice(name=params['vpnsname'], subnet=subnet,
                                     router=router) as vpnservice1:
                    keys['ikepolicy_id'] = ikepolicy['ikepolicy']['id']
                    keys['ipsecpolicy_id'] = (
                        ipsecpolicy['ipsecpolicy']['id']
                    )
                    keys['vpnservice_id'] = (
                        vpnservice1['vpnservice']['id']
                    )
                    try:
                        with self.ipsec_site_connection(
                                self.fmt,
                                keys['name'],
                                keys['peer_address'],
                                keys['peer_id'],
                                keys['peer_cidrs'],
                                keys['mtu'],
                                keys['psk'],
                                keys['initiator'],
                                dpd['action'],
                                dpd['interval'],
                                dpd['timeout'],
                                vpnservice1,
                                ikepolicy,
                                ipsecpolicy,
                                keys['admin_state_up'],
                                description=keys['description']
                        ) as ipsec_site_connection:
                            if expected_status_int != 200:
                                self.fail("Expected failure on create")
                            self._check_ipsec_site_connection(
                                ipsec_site_connection['ipsec_site_connection'],
                                keys,
                                dpd)
                    except webob.exc.HTTPClientError as ce:
                        self.assertEqual(ce.code, expected_status_int)
        self._delete('subnets', subnet['subnet']['id'])

    def test_create_ipsec_site_connection(self, **extras):
        """Test case to create an ipsec_site_connection."""
        self._test_create_ipsec_site_connection(key_overrides=extras)

    def test_delete_ipsec_site_connection(self):
        """Test case to delete a ipsec_site_connection."""
        with self.ipsec_site_connection(
                do_delete=False) as ipsec_site_connection:
            req = self.new_delete_request(
                'ipsec-site-connections',
                ipsec_site_connection['ipsec_site_connection']['id']
            )
            res = req.get_response(self.ext_api)
            self.assertEqual(res.status_int, 204)

    def test_update_ipsec_site_connection(self):
        """Test case for valid updates to IPSec site connection."""
        dpd = {'action': 'hold',
               'interval': 40,
               'timeout': 120}
        self._test_update_ipsec_site_connection(update={'dpd': dpd})
        self._test_update_ipsec_site_connection(update={'mtu': 2000})
        ipv6_settings = {
            'peer_address': 'fe80::c0a8:10a',
            'peer_id': 'fe80::c0a8:10a',
            'peer_cidrs': ['fe80::c0a8:200/120', 'fe80::c0a8:300/120'],
            'subnet_cidr': 'fe80::a02:0/120',
            'subnet_version': 6}
        self._test_update_ipsec_site_connection(update={'mtu': 2000},
                                                overrides=ipv6_settings)

    def test_update_ipsec_site_connection_with_invalid_state(self):
        """Test updating an ipsec_site_connection in invalid state."""
        self._test_update_ipsec_site_connection(
            overrides={'make_active': False},
            expected_status_int=400)

    def test_update_ipsec_site_connection_peer_cidrs(self):
        """Test updating an ipsec_site_connection for peer_cidrs."""
        new_peers = {'peer_cidrs': ['192.168.4.0/24',
                                    '192.168.5.0/24']}
        self._test_update_ipsec_site_connection(
            update=new_peers)

    def _test_update_ipsec_site_connection(self,
                                           update={'name': 'new name'},
                                           overrides=None,
                                           expected_status_int=200):
        """Creates and then updates ipsec_site_connection."""
        keys = {'name': 'new_ipsec_site_connection',
                'ikename': 'ikepolicy1',
                'ipsecname': 'ipsecpolicy1',
                'vpnsname': 'vpnservice1',
                'description': 'my-ipsec-connection',
                'peer_address': '192.168.1.10',
                'peer_id': '192.168.1.10',
                'peer_cidrs': ['192.168.2.0/24', '192.168.3.0/24'],
                'initiator': 'bi-directional',
                'mtu': 1500,
                'tenant_id': self._tenant_id,
                'psk': 'abcd',
                'status': 'ACTIVE',
                'admin_state_up': True,
                'action': 'hold',
                'interval': 40,
                'timeout': 120,
                'subnet_cidr': '10.2.0.0/24',
                'subnet_version': 4,
                'make_active': True}
        if overrides is not None:
            keys.update(overrides)

        with contextlib.nested(
                self.ikepolicy(name=keys['ikename']),
                self.ipsecpolicy(name=keys['ipsecname']),
                self.subnet(cidr=keys['subnet_cidr'],
                            ip_version=keys['subnet_version']),
                self.router()) as (
                    ikepolicy, ipsecpolicy, subnet, router):
            with self.vpnservice(name=keys['vpnsname'], subnet=subnet,
                                 router=router) as vpnservice1:
                keys['vpnservice_id'] = vpnservice1['vpnservice']['id']
                keys['ikepolicy_id'] = ikepolicy['ikepolicy']['id']
                keys['ipsecpolicy_id'] = ipsecpolicy['ipsecpolicy']['id']
                with self.ipsec_site_connection(
                    self.fmt,
                    keys['name'],
                    keys['peer_address'],
                    keys['peer_id'],
                    keys['peer_cidrs'],
                    keys['mtu'],
                    keys['psk'],
                    keys['initiator'],
                    keys['action'],
                    keys['interval'],
                    keys['timeout'],
                    vpnservice1,
                    ikepolicy,
                    ipsecpolicy,
                    keys['admin_state_up'],
                    description=keys['description']
                ) as ipsec_site_connection:
                    data = {'ipsec_site_connection': update}
                    if keys.get('make_active', None):
                        self._set_active(
                            vpn_db.IPsecSiteConnection,
                            (ipsec_site_connection['ipsec_site_connection']
                             ['id']))
                    req = self.new_update_request(
                        'ipsec-site-connections',
                        data,
                        ipsec_site_connection['ipsec_site_connection']['id'])
                    res = req.get_response(self.ext_api)
                    self.assertEqual(expected_status_int, res.status_int)
                    if expected_status_int == 200:
                        res_dict = self.deserialize(self.fmt, res)
                        actual = res_dict['ipsec_site_connection']
                        for k, v in update.items():
                            # Sort lists before checking equality
                            if isinstance(actual[k], list):
                                self.assertEqual(v, sorted(actual[k]))
                            else:
                                self.assertEqual(v, actual[k])
        self._delete('networks', subnet['subnet']['network_id'])

    def test_show_ipsec_site_connection(self):
        """Test case to show a ipsec_site_connection."""
        ikename = "ikepolicy1"
        ipsecname = "ipsecpolicy1"
        vpnsname = "vpnservice1"
        name = "connection1"
        description = "my-ipsec-connection"
        keys = {'name': name,
                'description': "my-ipsec-connection",
                'peer_address': '192.168.1.10',
                'peer_id': '192.168.1.10',
                'peer_cidrs': ['192.168.2.0/24', '192.168.3.0/24'],
                'initiator': 'bi-directional',
                'mtu': 1500,
                'tenant_id': self._tenant_id,
                'psk': 'abcd',
                'status': 'PENDING_CREATE',
                'admin_state_up': True}
        dpd = {'action': 'hold',
               'interval': 40,
               'timeout': 120}
        with contextlib.nested(
            self.ikepolicy(name=ikename),
            self.ipsecpolicy(name=ipsecname),
            self.subnet(),
            self.router()) as (
                ikepolicy, ipsecpolicy, subnet, router):
            with self.vpnservice(name=vpnsname, subnet=subnet,
                                 router=router) as vpnservice1:
                keys['ikepolicy_id'] = ikepolicy['ikepolicy']['id']
                keys['ipsecpolicy_id'] = ipsecpolicy['ipsecpolicy']['id']
                keys['vpnservice_id'] = vpnservice1['vpnservice']['id']
                with self.ipsec_site_connection(
                    self.fmt,
                    name,
                    keys['peer_address'],
                    keys['peer_id'],
                    keys['peer_cidrs'],
                    keys['mtu'],
                    keys['psk'],
                    keys['initiator'],
                    dpd['action'],
                    dpd['interval'],
                    dpd['timeout'],
                    vpnservice1,
                    ikepolicy,
                    ipsecpolicy,
                    keys['admin_state_up'],
                    description=description,
                ) as ipsec_site_connection:

                    req = self.new_show_request(
                        'ipsec-site-connections',
                        ipsec_site_connection[
                            'ipsec_site_connection']['id'],
                        fmt=self.fmt
                    )
                    res = self.deserialize(
                        self.fmt,
                        req.get_response(self.ext_api)
                    )

                    self._check_ipsec_site_connection(
                        res['ipsec_site_connection'],
                        keys,
                        dpd)

    def test_list_ipsec_site_connections_with_sort_emulated(self):
        """Test case to list all ipsec_site_connections with sort."""
        with self.subnet(cidr='10.2.0.0/24') as subnet:
            with self.router() as router:
                with self.vpnservice(subnet=subnet,
                                     router=router
                                     ) as vpnservice:
                    with contextlib.nested(
                        self.ipsec_site_connection(
                            name='connection1', vpnservice=vpnservice
                        ),
                        self.ipsec_site_connection(
                            name='connection2', vpnservice=vpnservice
                        ),
                        self.ipsec_site_connection(
                            name='connection3', vpnservice=vpnservice
                        )
                    ) as(ipsec_site_connection1,
                         ipsec_site_connection2,
                         ipsec_site_connection3):
                        self._test_list_with_sort('ipsec-site-connection',
                                                  (ipsec_site_connection3,
                                                   ipsec_site_connection2,
                                                   ipsec_site_connection1),
                                                  [('name', 'desc')])

    def test_list_ipsec_site_connections_with_pagination_emulated(self):
        """Test case to list all ipsec_site_connections with pagination."""
        with self.subnet(cidr='10.2.0.0/24') as subnet:
            with self.router() as router:
                with self.vpnservice(subnet=subnet,
                                     router=router
                                     ) as vpnservice:
                    with contextlib.nested(
                        self.ipsec_site_connection(
                            name='ipsec_site_connection1',
                            vpnservice=vpnservice
                        ),
                        self.ipsec_site_connection(
                            name='ipsec_site_connection1',
                            vpnservice=vpnservice
                        ),
                        self.ipsec_site_connection(
                            name='ipsec_site_connection1',
                            vpnservice=vpnservice
                        )
                    ) as(ipsec_site_connection1,
                         ipsec_site_connection2,
                         ipsec_site_connection3):
                        self._test_list_with_pagination(
                            'ipsec-site-connection',
                            (ipsec_site_connection1,
                             ipsec_site_connection2,
                             ipsec_site_connection3),
                            ('name', 'asc'), 2, 2)

    def test_list_ipsec_site_conns_with_pagination_reverse_emulated(self):
        """Test to list all ipsec_site_connections with reverse pagination."""
        with self.subnet(cidr='10.2.0.0/24') as subnet:
            with self.router() as router:
                with self.vpnservice(subnet=subnet,
                                     router=router
                                     ) as vpnservice:
                    with contextlib.nested(
                        self.ipsec_site_connection(
                            name='connection1', vpnservice=vpnservice
                        ),
                        self.ipsec_site_connection(
                            name='connection2', vpnservice=vpnservice
                        ),
                        self.ipsec_site_connection(
                            name='connection3', vpnservice=vpnservice
                        )
                    ) as(ipsec_site_connection1,
                         ipsec_site_connection2,
                         ipsec_site_connection3):
                        self._test_list_with_pagination_reverse(
                            'ipsec-site-connection',
                            (ipsec_site_connection1,
                             ipsec_site_connection2,
                             ipsec_site_connection3),
                            ('name', 'asc'), 2, 2
                        )

    def test_create_vpn(self):
        """Test case to create a vpn."""
        vpns_name = "vpnservice1"
        ike_name = "ikepolicy1"
        ipsec_name = "ipsecpolicy1"
        name1 = "ipsec_site_connection1"
        with contextlib.nested(
            self.ikepolicy(name=ike_name),
            self.ipsecpolicy(name=ipsec_name),
            self.vpnservice(name=vpns_name)) as (
                ikepolicy, ipsecpolicy, vpnservice):
            vpnservice_id = vpnservice['vpnservice']['id']
            ikepolicy_id = ikepolicy['ikepolicy']['id']
            ipsecpolicy_id = ipsecpolicy['ipsecpolicy']['id']
            with self.ipsec_site_connection(
                self.fmt,
                name1,
                '192.168.1.10',
                '192.168.1.10',
                ['192.168.2.0/24',
                 '192.168.3.0/24'],
                1500,
                'abcdef',
                'bi-directional',
                'hold',
                30,
                120,
                vpnservice,
                ikepolicy,
                ipsecpolicy,
                True
            ) as vpnconn1:

                vpnservice_req = self.new_show_request(
                    'vpnservices',
                    vpnservice_id,
                    fmt=self.fmt)
                vpnservice_updated = self.deserialize(
                    self.fmt,
                    vpnservice_req.get_response(self.ext_api)
                )
                self.assertEqual(
                    vpnservice_updated['vpnservice']['id'],
                    vpnconn1['ipsec_site_connection']['vpnservice_id']
                )
                ikepolicy_req = self.new_show_request('ikepolicies',
                                                      ikepolicy_id,
                                                      fmt=self.fmt)
                ikepolicy_res = self.deserialize(
                    self.fmt,
                    ikepolicy_req.get_response(self.ext_api)
                )
                self.assertEqual(
                    ikepolicy_res['ikepolicy']['id'],
                    vpnconn1['ipsec_site_connection']['ikepolicy_id'])
                ipsecpolicy_req = self.new_show_request(
                    'ipsecpolicies',
                    ipsecpolicy_id,
                    fmt=self.fmt)
                ipsecpolicy_res = self.deserialize(
                    self.fmt,
                    ipsecpolicy_req.get_response(self.ext_api)
                )
                self.assertEqual(
                    ipsecpolicy_res['ipsecpolicy']['id'],
                    vpnconn1['ipsec_site_connection']['ipsecpolicy_id']
                )

    def test_delete_ikepolicy_inuse(self):
        """Test case to delete an ikepolicy, that is in use."""
        vpns_name = "vpnservice1"
        ike_name = "ikepolicy1"
        ipsec_name = "ipsecpolicy1"
        name1 = "ipsec_site_connection1"
        with self.ikepolicy(name=ike_name) as ikepolicy:
            with self.ipsecpolicy(name=ipsec_name) as ipsecpolicy:
                with self.vpnservice(name=vpns_name) as vpnservice:
                    with self.ipsec_site_connection(
                        self.fmt,
                        name1,
                        '192.168.1.10',
                        '192.168.1.10',
                        ['192.168.2.0/24',
                         '192.168.3.0/24'],
                        1500,
                        'abcdef',
                        'bi-directional',
                        'hold',
                        30,
                        120,
                        vpnservice,
                        ikepolicy,
                        ipsecpolicy,
                        True
                    ):
                        delete_req = self.new_delete_request(
                            'ikepolicies',
                            ikepolicy['ikepolicy']['id']
                        )
                        delete_res = delete_req.get_response(self.ext_api)
                        self.assertEqual(409, delete_res.status_int)

    def test_delete_ipsecpolicy_inuse(self):
        """Test case to delete an ipsecpolicy, that is in use."""
        vpns_name = "vpnservice1"
        ike_name = "ikepolicy1"
        ipsec_name = "ipsecpolicy1"
        name1 = "ipsec_site_connection1"
        with self.ikepolicy(name=ike_name) as ikepolicy:
            with self.ipsecpolicy(name=ipsec_name) as ipsecpolicy:
                with self.vpnservice(name=vpns_name) as vpnservice:
                    with self.ipsec_site_connection(
                        self.fmt,
                        name1,
                        '192.168.1.10',
                        '192.168.1.10',
                        ['192.168.2.0/24',
                         '192.168.3.0/24'],
                        1500,
                        'abcdef',
                        'bi-directional',
                        'hold',
                        30,
                        120,
                        vpnservice,
                        ikepolicy,
                        ipsecpolicy,
                        True
                    ):

                        delete_req = self.new_delete_request(
                            'ipsecpolicies',
                            ipsecpolicy['ipsecpolicy']['id']
                        )
                        delete_res = delete_req.get_response(self.ext_api)
                        self.assertEqual(409, delete_res.status_int)


class TestVpnaasXML(TestVpnaas):
    fmt = 'xml'
