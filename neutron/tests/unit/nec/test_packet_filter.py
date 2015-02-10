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

import contextlib

import mock
import webob.exc

from neutron.api.v2 import attributes
from neutron import context
from neutron.plugins.nec.common import exceptions as nexc
from neutron.plugins.nec.extensions import packetfilter as ext_pf
from neutron.tests.unit.nec import test_nec_plugin
from neutron.tests.unit import test_db_plugin as test_plugin


NEC_PLUGIN_PF_INI = """
[DEFAULT]
api_extensions_path = neutron/plugins/nec/extensions
[OFC]
driver = neutron.tests.unit.nec.stub_ofc_driver.StubOFCDriver
enable_packet_filter = True
"""


class PacketfilterExtensionManager(ext_pf.Packetfilter):

    @classmethod
    def get_resources(cls):
        # Add the resources to the global attribute map
        # This is done here as the setup process won't
        # initialize the main API router which extends
        # the global attribute map
        attributes.RESOURCE_ATTRIBUTE_MAP.update(
            {'packet_filters': ext_pf.PACKET_FILTER_ATTR_MAP})
        return super(PacketfilterExtensionManager, cls).get_resources()


class TestNecPluginPacketFilterBase(test_nec_plugin.NecPluginV2TestCase):

    _nec_ini = NEC_PLUGIN_PF_INI

    def setUp(self):
        ext_mgr = PacketfilterExtensionManager()
        super(TestNecPluginPacketFilterBase, self).setUp(ext_mgr=ext_mgr)

    def _create_packet_filter(self, fmt, net_id, expected_res_status=None,
                              arg_list=None, **kwargs):
        data = {'packet_filter': {'network_id': net_id,
                                  'tenant_id': self._tenant_id,
                                  'priority': '1',
                                  'action': 'ALLOW'}}

        for arg in (('name', 'admin_state_up', 'action', 'priority', 'in_port',
                     'src_mac', 'dst_mac', 'eth_type', 'src_cidr', 'dst_cidr',
                     'protocol', 'src_port', 'dst_port') +
                    (arg_list or ())):
            # Arg must be present
            if arg in kwargs:
                data['packet_filter'][arg] = kwargs[arg]
        pf_req = self.new_create_request('packet_filters', data, fmt)
        if (kwargs.get('set_context') and 'tenant_id' in kwargs):
            # create a specific auth context for this request
            pf_req.environ['neutron.context'] = context.Context(
                '', kwargs['tenant_id'])

        pf_res = pf_req.get_response(self.ext_api)
        if expected_res_status:
            self.assertEqual(pf_res.status_int, expected_res_status)
        return pf_res

    def _make_packet_filter(self, fmt, net_id, expected_res_status=None,
                            **kwargs):
        res = self._create_packet_filter(fmt, net_id, expected_res_status,
                                         **kwargs)
        # Things can go wrong - raise HTTP exc with res code only
        # so it can be caught by unit tests
        if res.status_int >= 400:
            raise webob.exc.HTTPClientError(code=res.status_int)
        return self.deserialize(fmt, res)

    @contextlib.contextmanager
    def packet_filter_on_network(self, network=None, fmt=None, **kwargs):
        with test_plugin.optional_ctx(network, self.network) as network_to_use:
            net_id = network_to_use['network']['id']
            pf = self._make_packet_filter(fmt or self.fmt, net_id, **kwargs)
            yield pf
            if not network:
                self._delete('networks', network_to_use['network']['id'])

    @contextlib.contextmanager
    def packet_filter_on_port(self, port=None, fmt=None, set_portinfo=True,
                              **kwargs):
        with test_plugin.optional_ctx(port, self.port) as port_to_use:
            net_id = port_to_use['port']['network_id']
            port_id = port_to_use['port']['id']

            if set_portinfo:
                portinfo = {'id': port_id,
                            'port_no': kwargs.get('port_no', 123)}
                kw = {'added': [portinfo]}
                if 'datapath_id' in kwargs:
                    kw['datapath_id'] = kwargs['datapath_id']
                self.rpcapi_update_ports(**kw)

            kwargs['in_port'] = port_id
            pf = self._make_packet_filter(fmt or self.fmt, net_id, **kwargs)
            self.assertEqual(port_id, pf['packet_filter']['in_port'])
            yield pf


class TestNecPluginPacketFilter(TestNecPluginPacketFilterBase):

    def setUp(self):
        super(TestNecPluginPacketFilter, self).setUp()
        # Remove attributes explicitly from mock object to check
        # a case where there are no update_filter and validate_*.
        del self.ofc.driver.update_filter
        del self.ofc.driver.validate_filter_create
        del self.ofc.driver.validate_filter_update

    def test_list_packet_filters(self):
        self._list('packet_filters')

    def test_create_pf_on_network_no_ofc_creation(self):
        with self.packet_filter_on_network(admin_state_up=False) as pf:
            self.assertEqual(pf['packet_filter']['status'], 'DOWN')

        self.assertFalse(self.ofc.create_ofc_packet_filter.called)
        self.assertFalse(self.ofc.delete_ofc_packet_filter.called)

    def test_create_pf_on_port_no_ofc_creation(self):
        with self.packet_filter_on_port(admin_state_up=False,
                                        set_portinfo=False) as pf:
            self.assertEqual(pf['packet_filter']['status'], 'DOWN')

        self.assertFalse(self.ofc.create_ofc_packet_filter.called)
        self.assertFalse(self.ofc.delete_ofc_packet_filter.called)

    def test_create_pf_on_network_with_ofc_creation(self):
        with self.packet_filter_on_network() as pf:
            pf_id = pf['packet_filter']['id']
            self.assertEqual(pf['packet_filter']['status'], 'ACTIVE')

        ctx = mock.ANY
        pf_dict = mock.ANY
        expected = [
            mock.call.exists_ofc_packet_filter(ctx, pf_id),
            mock.call.create_ofc_packet_filter(ctx, pf_id, pf_dict),
            mock.call.exists_ofc_packet_filter(ctx, pf_id),
            mock.call.delete_ofc_packet_filter(ctx, pf_id),
        ]
        self.ofc.assert_has_calls(expected)
        self.assertEqual(self.ofc.create_ofc_packet_filter.call_count, 1)
        self.assertEqual(self.ofc.delete_ofc_packet_filter.call_count, 1)

    def test_create_pf_on_port_with_ofc_creation(self):
        with self.packet_filter_on_port() as pf:
            pf_id = pf['packet_filter']['id']
            self.assertEqual(pf['packet_filter']['status'], 'ACTIVE')
            self._delete('packet_filters', pf_id)

        ctx = mock.ANY
        pf_dict = mock.ANY
        expected = [
            mock.call.exists_ofc_packet_filter(ctx, pf_id),
            mock.call.create_ofc_packet_filter(ctx, pf_id, pf_dict),
            mock.call.exists_ofc_packet_filter(ctx, pf_id),
            mock.call.delete_ofc_packet_filter(ctx, pf_id),
        ]
        self.ofc.assert_has_calls(expected)
        self.assertEqual(self.ofc.create_ofc_packet_filter.call_count, 1)
        self.assertEqual(self.ofc.delete_ofc_packet_filter.call_count, 1)

    def _test_create_pf_with_protocol(self, protocol, expected_eth_type):
        with self.packet_filter_on_network(protocol=protocol) as pf:
            pf_data = pf['packet_filter']
            self.assertEqual(protocol, pf_data['protocol'])
            self.assertEqual(expected_eth_type, pf_data['eth_type'])

    def test_create_pf_with_protocol_tcp(self):
        self._test_create_pf_with_protocol('TCP', 0x800)

    def test_create_pf_with_protocol_udp(self):
        self._test_create_pf_with_protocol('UDP', 0x800)

    def test_create_pf_with_protocol_icmp(self):
        self._test_create_pf_with_protocol('ICMP', 0x800)

    def test_create_pf_with_protocol_arp(self):
        self._test_create_pf_with_protocol('ARP', 0x806)

    def test_create_pf_with_inconsistent_protocol_and_eth_type(self):
        with self.packet_filter_on_network(protocol='TCP') as pf:
            pf_data = pf['packet_filter']
            pf_id = pf_data['id']
            self.assertEqual('TCP', pf_data['protocol'])
            self.assertEqual(0x800, pf_data['eth_type'])
            data = {'packet_filter': {'eth_type': 0x806}}
            self._update('packet_filters', pf_id, data,
                         expected_code=409)

    def test_create_pf_with_invalid_priority(self):
        with self.network() as net:
            net_id = net['network']['id']
            kwargs = {'priority': 'high'}
            self._create_packet_filter(self.fmt, net_id,
                                       webob.exc.HTTPBadRequest.code,
                                       **kwargs)
        self.assertFalse(self.ofc.create_ofc_packet_filter.called)

    def test_create_pf_with_ofc_creation_failure(self):
        self.ofc.set_raise_exc('create_ofc_packet_filter',
                               nexc.OFCException(reason='hoge'))

        with self.packet_filter_on_network() as pf:
            pf_id = pf['packet_filter']['id']
            pf_ref = self._show('packet_filters', pf_id)
            self.assertEqual(pf_ref['packet_filter']['status'], 'ERROR')

            self.ofc.set_raise_exc('create_ofc_packet_filter', None)

            # Retry activate packet_filter (even if there is no change).
            data = {'packet_filter': {}}
            self._update('packet_filters', pf_id, data)

            pf_ref = self._show('packet_filters', pf_id)
            self.assertEqual(pf_ref['packet_filter']['status'], 'ACTIVE')

        ctx = mock.ANY
        pf_dict = mock.ANY
        expected = [
            mock.call.exists_ofc_packet_filter(ctx, pf_id),
            mock.call.create_ofc_packet_filter(ctx, pf_id, pf_dict),

            mock.call.exists_ofc_packet_filter(ctx, pf_id),

            mock.call.exists_ofc_packet_filter(ctx, pf_id),
            mock.call.create_ofc_packet_filter(ctx, pf_id, pf_dict),
        ]
        self.ofc.assert_has_calls(expected)
        self.assertEqual(self.ofc.create_ofc_packet_filter.call_count, 2)

    def test_show_pf_on_network(self):
        kwargs = {
            'name': 'test-pf-net',
            'admin_state_up': False,
            'action': 'DENY',
            'priority': '102',
            'src_mac': '00:11:22:33:44:55',
            'dst_mac': '66:77:88:99:aa:bb',
            'eth_type': '2048',
            'src_cidr': '192.168.1.0/24',
            'dst_cidr': '192.168.2.0/24',
            'protocol': 'TCP',
            'src_port': '35001',
            'dst_port': '22'
        }

        with self.packet_filter_on_network(**kwargs) as pf:
            pf_id = pf['packet_filter']['id']
            pf_ref = self._show('packet_filters', pf_id)

            # convert string to int.
            kwargs.update({'priority': 102, 'eth_type': 2048,
                           'src_port': 35001, 'dst_port': 22,
                           'in_port': None})

            self.assertEqual(pf_id, pf_ref['packet_filter']['id'])
            for key in kwargs:
                self.assertEqual(kwargs[key], pf_ref['packet_filter'][key])

    def test_show_pf_on_network_with_wildcards(self):
        kwargs = {
            'name': 'test-pf-net',
            'admin_state_up': False,
            'action': 'DENY',
            'priority': '102',
        }

        with self.packet_filter_on_network(**kwargs) as pf:
            pf_id = pf['packet_filter']['id']
            pf_ref = self._show('packet_filters', pf_id)

            # convert string to int.
            kwargs.update({'priority': 102,
                           'in_port': None,
                           'src_mac': None,
                           'dst_mac': None,
                           'eth_type': None,
                           'src_cidr': None,
                           'dst_cidr': None,
                           'protocol': None,
                           'src_port': None,
                           'dst_port': None})

            self.assertEqual(pf_id, pf_ref['packet_filter']['id'])
            for key in kwargs:
                self.assertEqual(kwargs[key], pf_ref['packet_filter'][key])

    def test_show_pf_on_port(self):
        kwargs = {
            'name': 'test-pf-port',
            'admin_state_up': False,
            'action': 'DENY',
            'priority': '0o147',
            'src_mac': '00:11:22:33:44:55',
            'dst_mac': '66:77:88:99:aa:bb',
            'eth_type': 2048,
            'src_cidr': '192.168.1.0/24',
            'dst_cidr': '192.168.2.0/24',
            'protocol': 'TCP',
            'dst_port': '0x50'
        }

        with self.packet_filter_on_port(**kwargs) as pf:
            pf_id = pf['packet_filter']['id']
            pf_ref = self._show('packet_filters', pf_id)

            # convert string to int.
            kwargs.update({'priority': 103, 'eth_type': 2048,
                           'dst_port': 80,
                           # wildcard field is None in a response.
                           'src_port': None})

            self.assertEqual(pf_id, pf_ref['packet_filter']['id'])
            self.assertTrue(pf_ref['packet_filter']['in_port'])
            for key in kwargs:
                self.assertEqual(kwargs[key], pf_ref['packet_filter'][key])

    def test_show_pf_not_found(self):
        pf_id = '00000000-ffff-ffff-ffff-000000000000'

        self._show('packet_filters', pf_id,
                   expected_code=webob.exc.HTTPNotFound.code)

    def test_update_pf_on_network(self):
        ctx = mock.ANY
        pf_dict = mock.ANY
        with self.packet_filter_on_network(admin_state_up=False) as pf:
            pf_id = pf['packet_filter']['id']

            self.assertFalse(self.ofc.create_ofc_packet_filter.called)
            data = {'packet_filter': {'admin_state_up': True}}
            self._update('packet_filters', pf_id, data)
            self.ofc.create_ofc_packet_filter.assert_called_once_with(
                ctx, pf_id, pf_dict)

            self.assertFalse(self.ofc.delete_ofc_packet_filter.called)
            data = {'packet_filter': {'admin_state_up': False}}
            self._update('packet_filters', pf_id, data)
            self.ofc.delete_ofc_packet_filter.assert_called_once_with(
                ctx, pf_id)

    def test_update_pf_on_port(self):
        ctx = mock.ANY
        pf_dict = mock.ANY
        with self.packet_filter_on_port(admin_state_up=False) as pf:
            pf_id = pf['packet_filter']['id']

            self.assertFalse(self.ofc.create_ofc_packet_filter.called)
            data = {'packet_filter': {'admin_state_up': True}}
            self._update('packet_filters', pf_id, data)
            self.ofc.create_ofc_packet_filter.assert_called_once_with(
                ctx, pf_id, pf_dict)

            self.assertFalse(self.ofc.delete_ofc_packet_filter.called)
            data = {'packet_filter': {'admin_state_up': False}}
            self._update('packet_filters', pf_id, data)
            self.ofc.delete_ofc_packet_filter.assert_called_once_with(
                ctx, pf_id)

    def test_delete_pf_with_error_status(self):
        self.ofc.set_raise_exc('create_ofc_packet_filter',
                               nexc.OFCException(reason='fake'))
        with self.packet_filter_on_network() as pf:
            pf_id = pf['packet_filter']['id']
            pf_ref = self._show('packet_filters', pf_id)
            self.assertEqual(pf_ref['packet_filter']['status'], 'ERROR')

        ctx = mock.ANY
        pf_dict = mock.ANY
        expected = [
            mock.call.exists_ofc_packet_filter(ctx, pf_id),
            mock.call.create_ofc_packet_filter(ctx, pf_id, pf_dict),
            mock.call.exists_ofc_packet_filter(ctx, pf_id),
        ]
        self.ofc.assert_has_calls(expected)
        self.assertEqual(1, self.ofc.create_ofc_packet_filter.call_count)
        self.assertEqual(0, self.ofc.delete_ofc_packet_filter.call_count)

    def test_activate_pf_on_port_triggered_by_update_port(self):
        ctx = mock.ANY
        pf_dict = mock.ANY
        self.ofc.set_raise_exc('create_ofc_packet_filter',
                               nexc.PortInfoNotFound(id='fake_id'))
        with self.packet_filter_on_port(set_portinfo=False) as pf:
            pf_id = pf['packet_filter']['id']
            in_port_id = pf['packet_filter']['in_port']

            # create_ofc_packet_filter is now called even when
            # in_port does not exists yet. In this case
            # PortInfoNotFound exception is raised.
            self.assertEqual(1, self.ofc.create_ofc_packet_filter.call_count)
            portinfo = {'id': in_port_id, 'port_no': 123}
            kw = {'added': [portinfo]}
            self.ofc.set_raise_exc('create_ofc_packet_filter', None)
            self.rpcapi_update_ports(**kw)
            self.assertEqual(2, self.ofc.create_ofc_packet_filter.call_count)
            self.ofc.assert_has_calls([
                mock.call.create_ofc_packet_filter(ctx, pf_id, pf_dict),
            ])

            self.assertFalse(self.ofc.delete_ofc_packet_filter.called)
            kw = {'removed': [in_port_id]}
            self.rpcapi_update_ports(**kw)
            self.ofc.delete_ofc_packet_filter.assert_called_once_with(
                ctx, pf_id)

        # Ensure pf was created before in_port has activated.
        ctx = mock.ANY
        pf_dict = mock.ANY
        port_dict = mock.ANY
        expected = [
            mock.call.exists_ofc_packet_filter(ctx, pf_id),
            mock.call.create_ofc_packet_filter(ctx, pf_id, pf_dict),
            mock.call.exists_ofc_port(ctx, in_port_id),
            mock.call.create_ofc_port(ctx, in_port_id, port_dict),

            mock.call.exists_ofc_port(ctx, in_port_id),
            mock.call.delete_ofc_port(ctx, in_port_id, port_dict),
            mock.call.exists_ofc_packet_filter(ctx, pf_id),
            mock.call.delete_ofc_packet_filter(ctx, pf_id),
        ]
        self.ofc.assert_has_calls(expected)
        self.assertEqual(2, self.ofc.create_ofc_packet_filter.call_count)
        self.assertEqual(1, self.ofc.delete_ofc_packet_filter.call_count)

    def test_activate_pf_while_exists_on_ofc(self):
        ctx = mock.ANY
        with self.packet_filter_on_network() as pf:
            pf_id = pf['packet_filter']['id']

            self.ofc.set_raise_exc('delete_ofc_packet_filter',
                                   nexc.OFCException(reason='hoge'))

            # This update request will make plugin reactivate pf.
            data = {'packet_filter': {'priority': 1000}}
            self._update('packet_filters', pf_id, data,
                         expected_code=webob.exc.HTTPInternalServerError.code)

            self.ofc.set_raise_exc('delete_ofc_packet_filter', None)

        ctx = mock.ANY
        pf_dict = mock.ANY
        expected = [
            mock.call.exists_ofc_packet_filter(ctx, pf_id),
            mock.call.create_ofc_packet_filter(ctx, pf_id, pf_dict),

            mock.call.exists_ofc_packet_filter(ctx, pf_id),
            mock.call.delete_ofc_packet_filter(ctx, pf_id),

            mock.call.exists_ofc_packet_filter(ctx, pf_id),
            mock.call.delete_ofc_packet_filter(ctx, pf_id),
        ]
        self.ofc.assert_has_calls(expected)
        self.assertEqual(self.ofc.delete_ofc_packet_filter.call_count, 2)

    def test_deactivate_pf_with_ofc_deletion_failure(self):
        ctx = mock.ANY
        with self.packet_filter_on_network() as pf:
            pf_id = pf['packet_filter']['id']

            self.ofc.set_raise_exc('delete_ofc_packet_filter',
                                   nexc.OFCException(reason='hoge'))

            data = {'packet_filter': {'admin_state_up': False}}
            self._update('packet_filters', pf_id, data,
                         expected_code=webob.exc.HTTPInternalServerError.code)

            pf_ref = self._show('packet_filters', pf_id)
            self.assertEqual(pf_ref['packet_filter']['status'], 'ERROR')

            self.ofc.set_raise_exc('delete_ofc_packet_filter', None)

            data = {'packet_filter': {'priority': 1000}}
            self._update('packet_filters', pf_id, data)

            pf_ref = self._show('packet_filters', pf_id)
            self.assertEqual(pf_ref['packet_filter']['status'], 'DOWN')

        ctx = mock.ANY
        pf_dict = mock.ANY
        expected = [
            mock.call.exists_ofc_packet_filter(ctx, pf_id),
            mock.call.create_ofc_packet_filter(ctx, pf_id, pf_dict),

            mock.call.exists_ofc_packet_filter(ctx, pf_id),
            mock.call.delete_ofc_packet_filter(ctx, pf_id),

            mock.call.exists_ofc_packet_filter(ctx, pf_id),
            mock.call.delete_ofc_packet_filter(ctx, pf_id),

            mock.call.exists_ofc_packet_filter(ctx, pf_id),
        ]
        self.ofc.assert_has_calls(expected)
        self.assertEqual(self.ofc.delete_ofc_packet_filter.call_count, 2)

    def test_delete_pf_with_ofc_deletion_failure(self):
        self.ofc.set_raise_exc('delete_ofc_packet_filter',
                               nexc.OFCException(reason='hoge'))

        with self.packet_filter_on_network() as pf:
            pf_id = pf['packet_filter']['id']

            self._delete('packet_filters', pf_id,
                         expected_code=webob.exc.HTTPInternalServerError.code)

            pf_ref = self._show('packet_filters', pf_id)
            self.assertEqual(pf_ref['packet_filter']['status'], 'ERROR')

            self.ofc.set_raise_exc('delete_ofc_packet_filter', None)
            # Then, self._delete('packet_filters', pf_id) will success.

        ctx = mock.ANY
        pf_dict = mock.ANY
        expected = [
            mock.call.exists_ofc_packet_filter(ctx, pf_id),
            mock.call.create_ofc_packet_filter(ctx, pf_id, pf_dict),

            mock.call.exists_ofc_packet_filter(ctx, pf_id),
            mock.call.delete_ofc_packet_filter(ctx, pf_id),

            mock.call.exists_ofc_packet_filter(ctx, pf_id),
            mock.call.delete_ofc_packet_filter(ctx, pf_id),
        ]
        self.ofc.assert_has_calls(expected)
        self.assertEqual(self.ofc.delete_ofc_packet_filter.call_count, 2)

    def test_auto_delete_pf_in_network_deletion(self):
        with self.packet_filter_on_network(admin_state_up=False) as pf:
            pf_id = pf['packet_filter']['id']

        self._show('packet_filters', pf_id,
                   expected_code=webob.exc.HTTPNotFound.code)

    def test_auto_delete_pf_in_port_deletion(self):
        with self.port() as port:
            network = self._show('networks', port['port']['network_id'])

            with self.packet_filter_on_network(network=network) as pfn:
                with self.packet_filter_on_port(port=port,
                                                set_portinfo=False) as pf:
                    pf_id = pf['packet_filter']['id']
                    in_port_id = pf['packet_filter']['in_port']

                    self._delete('ports', in_port_id)
                    # Check the packet filter on the port is deleted.
                    self._show('packet_filters', pf_id,
                               expected_code=webob.exc.HTTPNotFound.code)
                    # Check the packet filter on the network is not deleted.
                    self._show('packet_filters', pfn['packet_filter']['id'])

    def test_no_pf_activation_while_port_operations(self):
        with self.packet_filter_on_port() as pf:
            in_port_id = pf['packet_filter']['in_port']
            self.assertEqual(self.ofc.create_ofc_packet_filter.call_count, 1)
            self.assertEqual(self.ofc.delete_ofc_packet_filter.call_count, 0)

            data = {'port': {'admin_state_up': False}}
            self._update('ports', in_port_id, data)
            self.assertEqual(self.ofc.create_ofc_packet_filter.call_count, 1)
            self.assertEqual(self.ofc.delete_ofc_packet_filter.call_count, 0)

            data = {'port': {'admin_state_up': True}}
            self._update('ports', in_port_id, data)
            self.assertEqual(self.ofc.create_ofc_packet_filter.call_count, 1)
            self.assertEqual(self.ofc.delete_ofc_packet_filter.call_count, 0)


class TestNecPluginPacketFilterWithValidate(TestNecPluginPacketFilterBase):

    def setUp(self):
        super(TestNecPluginPacketFilterWithValidate, self).setUp()
        # Remove attributes explicitly from mock object to check
        # a case where there are no update_filter.
        del self.ofc.driver.update_filter
        self.validate_create = self.ofc.driver.validate_filter_create
        self.validate_update = self.ofc.driver.validate_filter_update

    def test_create_pf_on_network(self):
        with self.packet_filter_on_network() as pf:
            pf_id = pf['packet_filter']['id']
            self.assertEqual(pf['packet_filter']['status'], 'ACTIVE')

        ctx = mock.ANY
        pf_dict = mock.ANY
        expected = [
            mock.call.driver.validate_filter_create(ctx, pf_dict),
            mock.call.exists_ofc_packet_filter(ctx, pf_id),
            mock.call.create_ofc_packet_filter(ctx, pf_id, pf_dict),
            mock.call.exists_ofc_packet_filter(ctx, pf_id),
            mock.call.delete_ofc_packet_filter(ctx, pf_id),
        ]
        self.ofc.assert_has_calls(expected)
        self.assertEqual(self.ofc.create_ofc_packet_filter.call_count, 1)
        self.assertEqual(self.ofc.delete_ofc_packet_filter.call_count, 1)

    def test_update_pf_on_network(self):
        ctx = mock.ANY
        pf_dict = mock.ANY
        with self.packet_filter_on_network(admin_state_up=False) as pf:
            pf_id = pf['packet_filter']['id']

            self.assertFalse(self.ofc.create_ofc_packet_filter.called)
            data = {'packet_filter': {'admin_state_up': True}}
            self._update('packet_filters', pf_id, data)
            self.ofc.create_ofc_packet_filter.assert_called_once_with(
                ctx, pf_id, pf_dict)
            self.ofc.driver.validate_filter_update.assert_called_once_with(
                ctx, data['packet_filter'])

            self.assertFalse(self.ofc.delete_ofc_packet_filter.called)
            data = {'packet_filter': {'admin_state_up': False}}
            self._update('packet_filters', pf_id, data)
            self.ofc.delete_ofc_packet_filter.assert_called_once_with(
                ctx, pf_id)
            self.assertEqual(
                2, self.ofc.driver.validate_filter_update.call_count)

    def test_create_pf_on_network_with_validation_error(self):
        self.validate_create.side_effect = ext_pf.PacketFilterInvalidPriority(
            min=1, max=65535)
        with self.network() as net:
            net_id = net['network']['id']
            e = self.assertRaises(webob.exc.HTTPClientError,
                                  self._make_packet_filter,
                                  self.fmt, net_id, expected_res_status=400)
            self.assertEqual(400, e.status_int)

    def test_update_pf_on_network_with_validation_error(self):
        self.validate_update.side_effect = (
            ext_pf.PacketFilterUpdateNotSupported(field='priority'))
        with self.packet_filter_on_network() as pf:
            pf_id = pf['packet_filter']['id']
            pf_ref = self._show('packet_filters', pf_id)
            self.assertEqual(pf_ref['packet_filter']['status'], 'ACTIVE')
            data = {'packet_filter': {'priority': 1000}}
            self._update('packet_filters', pf_id, data,
                         expected_code=400)


class TestNecPluginPacketFilterWithFilterUpdate(TestNecPluginPacketFilterBase):

    def setUp(self):
        super(TestNecPluginPacketFilterWithFilterUpdate, self).setUp()
        # Remove attributes explicitly from mock object to check
        # a case where there are no update_filter and validate_*.
        del self.ofc.driver.validate_filter_create
        del self.ofc.driver.validate_filter_update

    def test_update_pf_toggle_admin_state(self):
        ctx = mock.ANY
        pf_dict = mock.ANY
        with self.packet_filter_on_network(admin_state_up=False) as pf:
            pf_id = pf['packet_filter']['id']

            self.assertFalse(self.ofc.create_ofc_packet_filter.called)
            data = {'packet_filter': {'admin_state_up': True}}
            self._update('packet_filters', pf_id, data)
            self.ofc.create_ofc_packet_filter.assert_called_once_with(
                ctx, pf_id, pf_dict)

            self.assertFalse(self.ofc.delete_ofc_packet_filter.called)
            data = {'packet_filter': {'admin_state_up': False}}
            self._update('packet_filters', pf_id, data)
            self.ofc.delete_ofc_packet_filter.assert_called_once_with(
                ctx, pf_id)

    def test_update_pf_change_field(self):
        ctx = mock.ANY
        with self.packet_filter_on_network(admin_state_up=True) as pf:
            pf_id = pf['packet_filter']['id']
            self.assertTrue(self.ofc.create_ofc_packet_filter.called)

            data = {'packet_filter': {'src_mac': '12:34:56:78:9a:bc'}}
            self._update('packet_filters', pf_id, data)
            self.ofc.update_ofc_packet_filter.assert_called_once_with(
                ctx, pf_id, data['packet_filter'])
            self.assertEqual(1, self.ofc.update_ofc_packet_filter.call_count)

            self.assertFalse(self.ofc.delete_ofc_packet_filter.called)
            data = {'packet_filter': {'admin_state_up': False}}
            self._update('packet_filters', pf_id, data)
            self.ofc.delete_ofc_packet_filter.assert_called_once_with(
                ctx, pf_id)

            data = {'packet_filter': {'src_mac': '11:22:33:44:55:66'}}
            self._update('packet_filters', pf_id, data)
            self.assertEqual(1, self.ofc.update_ofc_packet_filter.call_count)

            data = {'packet_filter': {'admin_state_up': True}}
            self._update('packet_filters', pf_id, data)

            data = {'packet_filter': {'src_mac': '66:55:44:33:22:11'}}
            self._update('packet_filters', pf_id, data)
            self.assertEqual(2, self.ofc.update_ofc_packet_filter.call_count)
