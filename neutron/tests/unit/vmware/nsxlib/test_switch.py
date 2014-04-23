# Copyright (c) 2014 VMware, Inc.
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

import hashlib
import mock

from neutron.common import constants
from neutron.common import exceptions
from neutron.plugins.vmware.common import utils
from neutron.plugins.vmware.nsxlib import switch as switchlib
from neutron.tests.unit import test_api_v2
from neutron.tests.unit.vmware.nsxlib import base

_uuid = test_api_v2._uuid


class LogicalSwitchesTestCase(base.NsxlibTestCase):

    def test_create_and_get_lswitches_single(self):
        tenant_id = 'pippo'
        transport_zones_config = [{'zone_uuid': _uuid(),
                                   'transport_type': 'stt'}]
        lswitch = switchlib.create_lswitch(self.fake_cluster,
                                           _uuid(),
                                           tenant_id,
                                           'fake-switch',
                                           transport_zones_config)
        res_lswitch = switchlib.get_lswitches(self.fake_cluster,
                                              lswitch['uuid'])
        self.assertEqual(len(res_lswitch), 1)
        self.assertEqual(res_lswitch[0]['uuid'],
                         lswitch['uuid'])

    def test_create_and_get_lswitches_single_name_exceeds_40_chars(self):
        tenant_id = 'pippo'
        transport_zones_config = [{'zone_uuid': _uuid(),
                                   'transport_type': 'stt'}]
        lswitch = switchlib.create_lswitch(self.fake_cluster,
                                           tenant_id,
                                           _uuid(),
                                           '*' * 50,
                                           transport_zones_config)
        res_lswitch = switchlib.get_lswitches(self.fake_cluster,
                                              lswitch['uuid'])
        self.assertEqual(len(res_lswitch), 1)
        self.assertEqual(res_lswitch[0]['uuid'], lswitch['uuid'])
        self.assertEqual(res_lswitch[0]['display_name'], '*' * 40)

    def test_create_and_get_lswitches_multiple(self):
        tenant_id = 'pippo'
        transport_zones_config = [{'zone_uuid': _uuid(),
                                   'transport_type': 'stt'}]
        network_id = _uuid()
        main_lswitch = switchlib.create_lswitch(
            self.fake_cluster, network_id,
            tenant_id, 'fake-switch', transport_zones_config,
            tags=[{'scope': 'multi_lswitch', 'tag': 'True'}])
        # Create secondary lswitch
        second_lswitch = switchlib.create_lswitch(
            self.fake_cluster, network_id,
            tenant_id, 'fake-switch-2', transport_zones_config)
        res_lswitch = switchlib.get_lswitches(self.fake_cluster,
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
        lswitch = switchlib.create_lswitch(self.fake_cluster,
                                           _uuid(),
                                           'pippo',
                                           'fake-switch',
                                           transport_zones_config)
        switchlib.update_lswitch(self.fake_cluster, lswitch['uuid'],
                                 new_name, tags=new_tags)
        res_lswitch = switchlib.get_lswitches(self.fake_cluster,
                                              lswitch['uuid'])
        self.assertEqual(len(res_lswitch), 1)
        self.assertEqual(res_lswitch[0]['display_name'], new_name)
        switch_tags = self._build_tag_dict(res_lswitch[0]['tags'])
        self.assertIn('new_tag', switch_tags)
        self.assertEqual(switch_tags['new_tag'], 'xxx')

    def test_update_non_existing_lswitch_raises(self):
        self.assertRaises(exceptions.NetworkNotFound,
                          switchlib.update_lswitch,
                          self.fake_cluster, 'whatever',
                          'foo', 'bar')

    def test_delete_networks(self):
        transport_zones_config = [{'zone_uuid': _uuid(),
                                   'transport_type': 'stt'}]
        lswitch = switchlib.create_lswitch(self.fake_cluster,
                                           _uuid(),
                                           'pippo',
                                           'fake-switch',
                                           transport_zones_config)
        switchlib.delete_networks(self.fake_cluster, lswitch['uuid'],
                                  [lswitch['uuid']])
        self.assertRaises(exceptions.NotFound,
                          switchlib.get_lswitches,
                          self.fake_cluster,
                          lswitch['uuid'])

    def test_delete_non_existing_lswitch_raises(self):
        self.assertRaises(exceptions.NetworkNotFound,
                          switchlib.delete_networks,
                          self.fake_cluster, 'whatever', ['whatever'])


class LogicalPortsTestCase(base.NsxlibTestCase):

    def _create_switch_and_port(self, tenant_id='pippo',
                                neutron_port_id='whatever',
                                name='name', device_id='device_id'):
        transport_zones_config = [{'zone_uuid': _uuid(),
                                   'transport_type': 'stt'}]
        lswitch = switchlib.create_lswitch(self.fake_cluster,
                                           _uuid(), tenant_id, 'fake-switch',
                                           transport_zones_config)
        lport = switchlib.create_lport(self.fake_cluster, lswitch['uuid'],
                                       tenant_id, neutron_port_id,
                                       name, device_id, True)
        return lswitch, lport

    def test_create_and_get_port(self):
        lswitch, lport = self._create_switch_and_port()
        lport_res = switchlib.get_port(self.fake_cluster,
                                       lswitch['uuid'], lport['uuid'])
        self.assertEqual(lport['uuid'], lport_res['uuid'])
        # Try again with relation
        lport_res = switchlib.get_port(self.fake_cluster,
                                       lswitch['uuid'], lport['uuid'],
                                       relations='LogicalPortStatus')
        self.assertEqual(lport['uuid'], lport_res['uuid'])

    def test_plug_interface(self):
        lswitch, lport = self._create_switch_and_port()
        switchlib.plug_vif_interface(self.fake_cluster, lswitch['uuid'],
                                     lport['uuid'], 'VifAttachment', 'fake')
        lport_res = switchlib.get_port(self.fake_cluster,
                                       lswitch['uuid'], lport['uuid'])
        self.assertEqual(lport['uuid'], lport_res['uuid'])

    def test_get_port_by_tag(self):
        lswitch, lport = self._create_switch_and_port()
        lport2 = switchlib.get_port_by_neutron_tag(self.fake_cluster,
                                                   lswitch['uuid'],
                                                   'whatever')
        self.assertIsNotNone(lport2)
        self.assertEqual(lport['uuid'], lport2['uuid'])

    def test_get_port_by_tag_not_found_with_switch_id_raises_not_found(self):
        tenant_id = 'pippo'
        neutron_port_id = 'whatever'
        transport_zones_config = [{'zone_uuid': _uuid(),
                                   'transport_type': 'stt'}]
        lswitch = switchlib.create_lswitch(
            self.fake_cluster, tenant_id, _uuid(),
            'fake-switch', transport_zones_config)
        self.assertRaises(exceptions.NotFound,
                          switchlib.get_port_by_neutron_tag,
                          self.fake_cluster, lswitch['uuid'],
                          neutron_port_id)

    def test_get_port_by_tag_not_find_wildcard_lswitch_returns_none(self):
        tenant_id = 'pippo'
        neutron_port_id = 'whatever'
        transport_zones_config = [{'zone_uuid': _uuid(),
                                   'transport_type': 'stt'}]
        switchlib.create_lswitch(
            self.fake_cluster, tenant_id, _uuid(),
            'fake-switch', transport_zones_config)
        lport = switchlib.get_port_by_neutron_tag(
            self.fake_cluster, '*', neutron_port_id)
        self.assertIsNone(lport)

    def test_get_port_status(self):
        lswitch, lport = self._create_switch_and_port()
        status = switchlib.get_port_status(
            self.fake_cluster, lswitch['uuid'], lport['uuid'])
        self.assertEqual(constants.PORT_STATUS_ACTIVE, status)

    def test_get_port_status_non_existent_raises(self):
        self.assertRaises(exceptions.PortNotFoundOnNetwork,
                          switchlib.get_port_status,
                          self.fake_cluster,
                          'boo', 'boo')

    def test_update_port(self):
        lswitch, lport = self._create_switch_and_port()
        switchlib.update_port(
            self.fake_cluster, lswitch['uuid'], lport['uuid'],
            'neutron_port_id', 'pippo2', 'new_name', 'device_id', False)
        lport_res = switchlib.get_port(self.fake_cluster,
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
        lport_res = switchlib.get_port(self.fake_cluster,
                                       lswitch['uuid'], lport['uuid'])
        port_tags = self._build_tag_dict(lport_res['tags'])
        self.assertEqual('device_id', port_tags['vm_id'])

    def test_create_port_device_id_more_than_40_chars(self):
        dev_id = "this_is_a_very_long_device_id_with_lots_of_characters"
        lswitch, lport = self._create_switch_and_port(device_id=dev_id)
        lport_res = switchlib.get_port(self.fake_cluster,
                                       lswitch['uuid'], lport['uuid'])
        port_tags = self._build_tag_dict(lport_res['tags'])
        self.assertNotEqual(len(dev_id), len(port_tags['vm_id']))

    def test_get_ports_with_obsolete_and_new_vm_id_tag(self):
        def obsolete(device_id, obfuscate=False):
            return hashlib.sha1(device_id).hexdigest()

        with mock.patch.object(utils, 'device_id_to_vm_id', new=obsolete):
            dev_id1 = "short-dev-id-1"
            _, lport1 = self._create_switch_and_port(device_id=dev_id1)
        dev_id2 = "short-dev-id-2"
        _, lport2 = self._create_switch_and_port(device_id=dev_id2)

        lports = switchlib.get_ports(self.fake_cluster, None, [dev_id1])
        port_tags = self._build_tag_dict(lports['whatever']['tags'])
        self.assertNotEqual(dev_id1, port_tags['vm_id'])

        lports = switchlib.get_ports(self.fake_cluster, None, [dev_id2])
        port_tags = self._build_tag_dict(lports['whatever']['tags'])
        self.assertEqual(dev_id2, port_tags['vm_id'])

    def test_update_non_existent_port_raises(self):
        self.assertRaises(exceptions.PortNotFoundOnNetwork,
                          switchlib.update_port, self.fake_cluster,
                          'boo', 'boo', 'boo', 'boo', 'boo', 'boo', False)

    def test_delete_port(self):
        lswitch, lport = self._create_switch_and_port()
        switchlib.delete_port(self.fake_cluster,
                              lswitch['uuid'], lport['uuid'])
        self.assertRaises(exceptions.PortNotFoundOnNetwork,
                          switchlib.get_port, self.fake_cluster,
                          lswitch['uuid'], lport['uuid'])

    def test_delete_non_existent_port_raises(self):
        lswitch = self._create_switch_and_port()[0]
        self.assertRaises(exceptions.PortNotFoundOnNetwork,
                          switchlib.delete_port, self.fake_cluster,
                          lswitch['uuid'], 'bad_port_uuid')

    def test_query_lswitch_ports(self):
        lswitch, lport = self._create_switch_and_port()
        switch_port_uuids = [
            switchlib.create_lport(
                self.fake_cluster, lswitch['uuid'], 'pippo', 'qportid-%s' % k,
                'port-%s' % k, 'deviceid-%s' % k, True)['uuid']
            for k in range(2)]
        switch_port_uuids.append(lport['uuid'])
        ports = switchlib.query_lswitch_lports(
            self.fake_cluster, lswitch['uuid'])
        self.assertEqual(len(ports), 3)
        for res_port in ports:
            self.assertIn(res_port['uuid'], switch_port_uuids)
