# Copyright (c) 2018 Red Hat, Inc.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.

import mock
from neutron_lib import constants

from neutron.agent.common import utils
from neutron.plugins.ml2.drivers.linuxbridge.agent import arp_protect
from neutron.tests import base


VIF = 'vif_tap0'
PORT_NO_SEC = {'port_security_enabled': False}
PORT_TRUSTED = {'device_owner': constants.DEVICE_OWNER_ROUTER_GW}
PORT = {'fixed_ips': [{'ip_address': '10.1.1.1'}],
        'device_owner': 'nobody',
        'mac_address': '00:11:22:33:44:55'}
PORT_ADDR_PAIR = {'fixed_ips': [{'ip_address': '10.1.1.1'}],
                  'device_owner': 'nobody',
                  'mac_address': '00:11:22:33:44:55',
                  'allowed_address_pairs': [
                      {'mac_address': '00:11:22:33:44:66',
                       'ip_address': '10.1.1.2'}]}


class TestLinuxBridgeARPSpoofing(base.BaseTestCase):

    def setUp(self):
        super(TestLinuxBridgeARPSpoofing, self).setUp()
        self.execute = mock.patch.object(utils, "execute").start()

    @mock.patch.object(arp_protect, "delete_arp_spoofing_protection")
    def test_port_no_security(self, dasp):
        arp_protect.setup_arp_spoofing_protection(VIF, PORT_NO_SEC)
        dasp.assert_called_with([VIF])

    @mock.patch.object(arp_protect, "delete_arp_spoofing_protection")
    def test_port_trusted(self, dasp):
        arp_protect.setup_arp_spoofing_protection(VIF, PORT_TRUSTED)
        dasp.assert_called_with([VIF])

    def _test_port_add_arp_spoofing(self, vif, port):
        mac_addresses = {port['mac_address']}
        ip_addresses = {p['ip_address'] for p in port['fixed_ips']}
        if port.get('allowed_address_pairs'):
            mac_addresses |= {p['mac_address']
                              for p in port['allowed_address_pairs']}
            ip_addresses |= {p['ip_address']
                             for p in port['allowed_address_pairs']}
        spoof_chain = arp_protect.SPOOF_CHAIN_PREFIX + vif
        mac_chain = arp_protect.MAC_CHAIN_PREFIX + vif

        expected = [
            mock.call(['ebtables', '-t', 'nat', '--concurrent', '-L'],
                      check_exit_code=True, extra_ok_codes=None,
                      log_fail_as_error=True, run_as_root=True),
            mock.ANY,
            mock.ANY,
            mock.call(['ebtables', '-t', 'nat', '--concurrent', '-N',
                       'neutronMAC-%s' % vif, '-P', 'DROP'],
                      check_exit_code=True, extra_ok_codes=None,
                      log_fail_as_error=True, run_as_root=True),
            mock.ANY,
            mock.call(['ebtables', '-t', 'nat', '--concurrent', '-A',
                       'PREROUTING', '-i', vif, '-j', mac_chain],
                      check_exit_code=True, extra_ok_codes=None,
                      log_fail_as_error=True, run_as_root=True),
            mock.call(['ebtables', '-t', 'nat', '--concurrent', '-A',
                       mac_chain, '-i', vif,
                       '--among-src', '%s' % ','.join(sorted(mac_addresses)),
                       '-j', 'RETURN'],
                      check_exit_code=True, extra_ok_codes=None,
                      log_fail_as_error=True, run_as_root=True),
            mock.ANY,
            mock.ANY,
            mock.call(['ebtables', '-t', 'nat', '--concurrent', '-N',
                       spoof_chain, '-P', 'DROP'],
                      check_exit_code=True, extra_ok_codes=None,
                      log_fail_as_error=True, run_as_root=True),
            mock.call(['ebtables', '-t', 'nat', '--concurrent', '-F',
                       spoof_chain],
                      check_exit_code=True, extra_ok_codes=None,
                      log_fail_as_error=True, run_as_root=True),
        ]
        for addr in sorted(ip_addresses):
            expected.extend([
                mock.call(['ebtables', '-t', 'nat', '--concurrent', '-A',
                           spoof_chain, '-p', 'ARP',
                           '--arp-ip-src', addr, '-j', 'ACCEPT'],
                          check_exit_code=True, extra_ok_codes=None,
                          log_fail_as_error=True, run_as_root=True),
            ])
        expected.extend([
            mock.ANY,
            mock.call(['ebtables', '-t', 'nat', '--concurrent', '-A',
                       'PREROUTING', '-i', vif, '-j',
                       spoof_chain, '-p', 'ARP'],
                      check_exit_code=True, extra_ok_codes=None,
                      log_fail_as_error=True, run_as_root=True),
        ])

        arp_protect.setup_arp_spoofing_protection(vif, port)
        self.execute.assert_has_calls(expected)

    def test_port_add_arp_spoofing(self):
        self._test_port_add_arp_spoofing(VIF, PORT)

    def test_port_add_arp_spoofing_addr_pair(self):
        self._test_port_add_arp_spoofing(VIF, PORT_ADDR_PAIR)

    @mock.patch.object(arp_protect, "chain_exists", return_value=True)
    @mock.patch.object(arp_protect, "vif_jump_present", return_value=True)
    def test_port_delete_arp_spoofing(self, ce, vjp):
        spoof_chain = arp_protect.SPOOF_CHAIN_PREFIX + VIF
        mac_chain = arp_protect.MAC_CHAIN_PREFIX + VIF
        expected = [
            mock.call(['ebtables', '-t', 'nat', '--concurrent', '-L'],
                      check_exit_code=True, extra_ok_codes=None,
                      log_fail_as_error=True, run_as_root=True),
            mock.ANY,
            mock.call(['ebtables', '-t', 'nat', '--concurrent', '-D',
                       'PREROUTING', '-i', VIF, '-j', spoof_chain,
                       '-p', 'ARP'],
                      check_exit_code=True, extra_ok_codes=None,
                      log_fail_as_error=True, run_as_root=True),
            mock.call(['ebtables', '-t', 'nat', '--concurrent', '-X',
                       spoof_chain],
                      check_exit_code=True, extra_ok_codes=None,
                      log_fail_as_error=True, run_as_root=True),
            mock.ANY,
            mock.call(['ebtables', '-t', 'nat', '--concurrent', '-X',
                       mac_chain],
                      check_exit_code=True, extra_ok_codes=None,
                      log_fail_as_error=True, run_as_root=True),
            mock.call(['ebtables', '-t', 'filter', '--concurrent', '-L'],
                      check_exit_code=True, extra_ok_codes=None,
                      log_fail_as_error=True, run_as_root=True),
            mock.ANY,
            mock.call(['ebtables', '-t', 'filter', '--concurrent', '-D',
                       'FORWARD', '-i', VIF, '-j', spoof_chain,
                       '-p', 'ARP'],
                      check_exit_code=True, extra_ok_codes=None,
                      log_fail_as_error=True, run_as_root=True),
            mock.call(['ebtables', '-t', 'filter', '--concurrent', '-X',
                       spoof_chain],
                      check_exit_code=True, extra_ok_codes=None,
                      log_fail_as_error=True, run_as_root=True),
            mock.ANY,
            mock.call(['ebtables', '-t', 'filter', '--concurrent', '-X',
                       mac_chain],
                      check_exit_code=True, extra_ok_codes=None,
                      log_fail_as_error=True, run_as_root=True),
        ]

        arp_protect.delete_arp_spoofing_protection([VIF])
        self.execute.assert_has_calls(expected)
