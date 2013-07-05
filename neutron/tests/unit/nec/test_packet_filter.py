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
from neutron.common.test_lib import test_config
from neutron import context
from neutron.plugins.nec.extensions import packetfilter
from neutron.tests.unit import test_db_plugin as test_plugin


PLUGIN_NAME = 'neutron.plugins.nec.nec_plugin.NECPluginV2'
OFC_MANAGER = 'neutron.plugins.nec.nec_plugin.ofc_manager.OFCManager'


class PacketfilterExtensionManager(packetfilter.Packetfilter):

    def get_resources(self):
        # Add the resources to the global attribute map
        # This is done here as the setup process won't
        # initialize the main API router which extends
        # the global attribute map
        attributes.RESOURCE_ATTRIBUTE_MAP.update(
            {'packet_filters': packetfilter.PACKET_FILTER_ATTR_MAP})
        return super(PacketfilterExtensionManager, self).get_resources()


class TestNecPluginPacketFilter(test_plugin.NeutronDbPluginV2TestCase):

    def setUp(self):
        self.addCleanup(mock.patch.stopall)
        ofc_manager_cls = mock.patch(OFC_MANAGER).start()
        ofc_driver = ofc_manager_cls.return_value.driver
        ofc_driver.filter_supported.return_value = True
        test_config['extension_manager'] = PacketfilterExtensionManager()
        super(TestNecPluginPacketFilter, self).setUp(PLUGIN_NAME)

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
    def packet_filter_on_network(self, network=None, fmt=None, do_delete=True,
                                 **kwargs):
        with test_plugin.optional_ctx(network, self.network) as network_to_use:
            net_id = network_to_use['network']['id']
            pf = self._make_packet_filter(fmt or self.fmt, net_id, **kwargs)
            try:
                yield pf
            finally:
                if do_delete:
                    self._delete('packet_filters', pf['packet_filter']['id'])

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
                           'src_port': 35001, 'dst_port': 22})

            self.assertEqual(pf_id, pf_ref['packet_filter']['id'])
            for key in kwargs:
                self.assertEqual(kwargs[key], pf_ref['packet_filter'][key])
