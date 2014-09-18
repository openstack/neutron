# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright (c) 2013 OpenStack Foundation.
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
#
# @author: Edouard Thuleau, Cloudwatt.
# based on
#   neutron/tests/unit/test_iptables_manager.py

import inspect
import os

import mock

from neutron.agent.linux import ebtables_manager
from neutron.tests import base


EBTABLES_ARG = {'pc': ebtables_manager.ChainName.binary_name()}

FILTER_DUMP1 = ('*filter\n'
                ':INPUT ACCEPT\n'
                ':FORWARD ACCEPT\n'
                ':OUTPUT ACCEPT\n'
                'COMMIT\n')

FILTER_DUMP2 = ('*filter\n'
                ':INPUT ACCEPT\n'
                ':FORWARD ACCEPT\n'
                ':OUTPUT ACCEPT\n'
                '[0:0] -A INPUT -j CONTINUE\n'
                'COMMIT\n')

FILTER_DUMP3 = ('*filter\n'
                ':INPUT ACCEPT\n'
                ':FORWARD ACCEPT\n'
                ':OUTPUT ACCEPT\n'
                ':%(pc)s-FORWARD ACCEPT\n'
                ':%(pc)s-INPUT ACCEPT\n'
                ':%(pc)s-OUTPUT ACCEPT\n'
                '[0:0] -A INPUT -j %(pc)s-INPUT\n'
                '[0:0] -A OUTPUT -j %(pc)s-OUTPUT\n'
                '[0:0] -A FORWARD -j %(pc)s-FORWARD\n'
                'COMMIT\n' % EBTABLES_ARG)

NAT_DUMP1 = ('*nat\n'
             ':PREROUTING ACCEPT\n'
             ':OUTPUT ACCEPT\n'
             ':POSTROUTING ACCEPT\n'
             'COMMIT\n')

NAT_DUMP2 = ('*nat\n'
             ':PREROUTING ACCEPT\n'
             ':OUTPUT ACCEPT\n'
             ':POSTROUTING ACCEPT\n'
             '[0:0] -A PREROUTING -j CONTINUE\n'
             'COMMIT\n')

NAT_DUMP3 = ('*nat\n'
             ':PREROUTING ACCEPT\n'
             ':OUTPUT ACCEPT\n'
             ':POSTROUTING ACCEPT\n'
             ':%(pc)s-OUTPUT ACCEPT\n'
             ':%(pc)s-PREROUTING ACCEPT\n'
             ':%(pc)s-POSTROUTING ACCEPT\n'
             '[0:0] -A PREROUTING -j %(pc)s-PREROUTING\n'
             '[0:0] -A OUTPUT -j %(pc)s-OUTPUT\n'
             '[0:0] -A POSTROUTING -j %(pc)s-POSTROUTING\n'
             'COMMIT\n' % EBTABLES_ARG)

BROUTE_DUMP1 = ('*broute\n'
                ':BROUTE ACCEPT\n'
                'COMMIT\n')

BROUTE_DUMP2 = ('*broute\n'
                ':BROUTE ACCEPT\n'
                '[0:0] -A BROUTING -j CONTINUE\n'
                'COMMIT\n')

BROUTE_DUMP3 = ('*broute\n'
                ':BROUTE ACCEPT\n'
                ':%(pc)s-BROUTING ACCEPT\n'
                '[0:0] -A BROUTING -j %(pc)s-BROUTING\n'
                'COMMIT\n' % EBTABLES_ARG)


class EbtablesTestCase(base.BaseTestCase):

    def setUp(self):
        super(EbtablesTestCase, self).setUp()
        self.root_helper = 'sudo'
        self.ebtables_path = '/tmp/ebtables-'
        self.execute_p = mock.patch('neutron.agent.linux.utils.execute')
        self.execute = self.execute_p.start()
        self.addCleanup(self.execute_p.stop)

    def test_ebtables_save_and_restore(self):
        dump_filter = ('Bridge table: filter\n'
                       '\n'
                       'Bridge chain: INPUT, entries: 1, policy: ACCEPT\n'
                       '-j CONTINUE , pcnt = 0 -- bcnt = 0\n'
                       '\n'
                       'Bridge chain: FORWARD, entries: 1, policy: ACCEPT\n'
                       '-j CONTINUE , pcnt = 0 -- bcnt = 1\n'
                       '\n'
                       'Bridge chain: OUTPUT, entries: 1, policy: ACCEPT\n'
                       '-j CONTINUE , pcnt = 1 -- bcnt = 1')

        dump_nat = ('Bridge table: nat\n'
                    '\n'
                    'Bridge chain: PREROUTING, entries: 1, policy: ACCEPT\n'
                    '-j CONTINUE , pcnt = 0 -- bcnt = 0\n'
                    '\n'
                    'Bridge chain: OUTPUT, entries: 1, policy: ACCEPT\n'
                    '-j CONTINUE , pcnt = 0 -- bcnt = 1\n'
                    '\n'
                    'Bridge chain: POSTROUTING, entries: 1, policy: ACCEPT\n'
                    '-j CONTINUE , pcnt = 1 -- bcnt = 1')

        dump_broute = ('Bridge table: broute\n'
                       '\n'
                       'Bridge chain: BROUTING, entries: 1, policy: ACCEPT\n'
                       '-j CONTINUE , pcnt = 0 -- bcnt = 0')

        dump_save = ('*filter\n'
                     ':INPUT ACCEPT\n'
                     ':FORWARD ACCEPT\n'
                     ':OUTPUT ACCEPT\n'
                     '[0:0] -A INPUT -j CONTINUE\n'
                     '[0:1] -A FORWARD -j CONTINUE\n'
                     '[1:1] -A OUTPUT -j CONTINUE\n'
                     'COMMIT\n'
                     '*nat\n'
                     ':PREROUTING ACCEPT\n'
                     ':OUTPUT ACCEPT\n'
                     ':POSTROUTING ACCEPT\n'
                     '[0:0] -A PREROUTING -j CONTINUE\n'
                     '[0:1] -A OUTPUT -j CONTINUE\n'
                     '[1:1] -A POSTROUTING -j CONTINUE\n'
                     'COMMIT\n'
                     '*broute\n'
                     ':BROUTING ACCEPT\n'
                     '[0:0] -A BROUTING -j CONTINUE\n'
                     'COMMIT')

        def fake_execute(*args, **kwargs):
            table = args[0][2]
            if table == 'filter':
                return dump_filter
            elif table == 'nat':
                return dump_nat
            elif table == 'broute':
                return dump_broute
            else:
                return ''

        self.execute.side_effect = fake_execute
        save = ebtables_manager.ebtables_save(self.execute,
                                              self.root_helper)
        self.assertEqual(dump_save, save)

        self.execute.reset_mock()
        self.execute.side_effect = None
        ebtables_manager.ebtables_restore(dump_save,
                                          self.ebtables_path,
                                          self.execute,
                                          self.root_helper)
        str_dump_filter = ['EBTABLES_ATOMIC_FILE=/tmp/ebtables-filter',
                           'ebtables', '-t', 'filter']
        str_dump_nat = ['EBTABLES_ATOMIC_FILE=/tmp/ebtables-nat', 'ebtables',
                        '-t', 'nat']
        str_dump_broute = ['EBTABLES_ATOMIC_FILE=/tmp/ebtables-broute',
                           'ebtables', '-t', 'broute']
        expected = [
            mock.call(str_dump_filter + ['--atomic-init'],
                      root_helper=self.root_helper),
            mock.call(str_dump_filter + ['-P', 'INPUT', 'ACCEPT'],
                      root_helper=self.root_helper),
            mock.call(str_dump_filter + ['-P', 'FORWARD', 'ACCEPT'],
                      root_helper=self.root_helper),
            mock.call(str_dump_filter + ['-P', 'OUTPUT', 'ACCEPT'],
                      root_helper=self.root_helper),
            mock.call(str_dump_filter + ['-A', 'INPUT', '-j', 'CONTINUE'],
                      root_helper=self.root_helper),
            mock.call(str_dump_filter + ['-A', 'FORWARD', '-j', 'CONTINUE'],
                      root_helper=self.root_helper),
            mock.call(str_dump_filter + ['-A', 'OUTPUT', '-j', 'CONTINUE'],
                      root_helper=self.root_helper),
            mock.call(str_dump_filter + ['-C', 'OUTPUT', '1', '1', '-j',
                                         'CONTINUE'],
                      root_helper=self.root_helper),
            mock.call(str_dump_filter + ['--atomic-commit'],
                      root_helper=self.root_helper),
            mock.call(str_dump_nat + ['--atomic-init'],
                      root_helper=self.root_helper),
            mock.call(str_dump_nat + ['-P', 'PREROUTING', 'ACCEPT'],
                      root_helper=self.root_helper),
            mock.call(str_dump_nat + ['-P', 'OUTPUT', 'ACCEPT'],
                      root_helper=self.root_helper),
            mock.call(str_dump_nat + ['-P', 'POSTROUTING', 'ACCEPT'],
                      root_helper=self.root_helper),
            mock.call(str_dump_nat + ['-A', 'PREROUTING', '-j', 'CONTINUE'],
                      root_helper=self.root_helper),
            mock.call(str_dump_nat + ['-A', 'OUTPUT', '-j', 'CONTINUE'],
                      root_helper=self.root_helper),
            mock.call(str_dump_nat + ['-A', 'POSTROUTING', '-j', 'CONTINUE'],
                      root_helper=self.root_helper),
            mock.call(str_dump_nat + ['-C', 'POSTROUTING', '1', '1', '-j',
                                      'CONTINUE'],
                      root_helper=self.root_helper),
            mock.call(str_dump_nat + ['--atomic-commit'],
                      root_helper=self.root_helper),
            mock.call(str_dump_broute + ['--atomic-init'],
                      root_helper=self.root_helper),
            mock.call(str_dump_broute + ['-P', 'BROUTING', 'ACCEPT'],
                      root_helper=self.root_helper),
            mock.call(str_dump_broute + ['-A', 'BROUTING', '-j', 'CONTINUE'],
                      root_helper=self.root_helper),
            mock.call(str_dump_broute + ['--atomic-commit'],
                      root_helper=self.root_helper)
        ]
        self.execute.assert_has_calls(expected)

    def test_ebtables_save_and_restore_for_only_one_table(self):
        dump_filter = ('Bridge table: filter\n'
                       '\n'
                       'Bridge chain: INPUT, entries: 1, policy: ACCEPT\n'
                       '-j CONTINUE , pcnt = 0 -- bcnt = 0\n'
                       '\n'
                       'Bridge chain: FORWARD, entries: 1, policy: ACCEPT\n'
                       '-j CONTINUE , pcnt = 0 -- bcnt = 1\n'
                       '\n'
                       'Bridge chain: OUTPUT, entries: 1, policy: ACCEPT\n'
                       '-j CONTINUE , pcnt = 1 -- bcnt = 1')

        dump_save = ('*filter\n'
                     ':INPUT ACCEPT\n'
                     ':FORWARD ACCEPT\n'
                     ':OUTPUT ACCEPT\n'
                     '[0:0] -A INPUT -j CONTINUE\n'
                     '[0:1] -A FORWARD -j CONTINUE\n'
                     '[1:1] -A OUTPUT -j CONTINUE\n'
                     'COMMIT')

        def fake_execute(*args, **kwargs):
            table = args[0][2]
            if table == 'filter':
                return dump_filter
            else:
                return ''

        self.execute.side_effect = fake_execute
        save = ebtables_manager.ebtables_save(self.execute,
                                              self.root_helper,
                                              tables=['filter'])
        self.assertEqual(dump_save, save)

        self.execute.reset_mock()
        self.execute.side_effect = None
        ebtables_manager.ebtables_restore(dump_save,
                                          self.ebtables_path,
                                          self.execute,
                                          self.root_helper)
        str_dump_filter = ['EBTABLES_ATOMIC_FILE=/tmp/ebtables-filter',
                           'ebtables', '-t', 'filter']
        expected = [
            mock.call(str_dump_filter + ['--atomic-init'],
                      root_helper=self.root_helper),
            mock.call(str_dump_filter + ['-P', 'INPUT', 'ACCEPT'],
                      root_helper=self.root_helper),
            mock.call(str_dump_filter + ['-P', 'FORWARD', 'ACCEPT'],
                      root_helper=self.root_helper),
            mock.call(str_dump_filter + ['-P', 'OUTPUT', 'ACCEPT'],
                      root_helper=self.root_helper),
            mock.call(str_dump_filter + ['-A', 'INPUT', '-j', 'CONTINUE'],
                      root_helper=self.root_helper),
            mock.call(str_dump_filter + ['-A', 'FORWARD', '-j', 'CONTINUE'],
                      root_helper=self.root_helper),
            mock.call(str_dump_filter + ['-A', 'OUTPUT', '-j', 'CONTINUE'],
                      root_helper=self.root_helper),
            mock.call(str_dump_filter + ['-C', 'OUTPUT', '1', '1', '-j',
                                         'CONTINUE'],
                      root_helper=self.root_helper),
            mock.call(str_dump_filter + ['--atomic-commit'],
                      root_helper=self.root_helper)
        ]
        self.execute.assert_has_calls(expected)


class EbtablesManagerTestCase(base.BaseTestCase):

    def setUp(self):
        super(EbtablesManagerTestCase, self).setUp()
        self.root_helper = 'sudo'
        self.ebtables = (ebtables_manager.
                         EbtablesManager(root_helper=self.root_helper))

        self.ebt_save_p = mock.patch.object(ebtables_manager, 'ebtables_save')
        self.ebt_save = self.ebt_save_p.start()
        self.addCleanup(self.ebt_save_p.stop)

        self.ebt_restore_p = mock.patch.object(ebtables_manager,
                                               'ebtables_restore')
        self.ebt_restore = self.ebt_restore_p.start()
        self.addCleanup(self.ebt_restore_p.stop)

    def test_binary_name(self):
        max = ebtables_manager.ChainName.MAX_LEN_PREFIX_CHAIN
        self.assertEqual(ebtables_manager.ChainName.binary_name(),
                         os.path.basename(inspect.stack()[-1][1])[:max])

    def test_prefix_chain(self):
        self.ebtables = (ebtables_manager.
                         EbtablesManager(root_helper=self.root_helper))
        bn = ebtables_manager.ChainName.binary_name()
        self.assertEqual(self.ebtables.prefix_chain,
                         bn[:ebtables_manager.ChainName.MAX_LEN_PREFIX_CHAIN])

        pc = ('0123456789' * 5)
        self.ebtables = (ebtables_manager.
                         EbtablesManager(root_helper=self.root_helper,
                                         prefix_chain=pc))
        self.assertEqual(self.ebtables.prefix_chain,
                         pc[:ebtables_manager.ChainName.MAX_LEN_PREFIX_CHAIN])
        pass

    def test_get_chain_name_all_possible_characters_prefix_chain(self):
        name = '0123456789' * 5
        self.ebtables = (ebtables_manager.
                         EbtablesManager(root_helper=self.root_helper,
                                         prefix_chain=name))
        pc = self.ebtables.prefix_chain
        name_nowrap = name[:ebtables_manager.ChainName.MAX_CHAIN_LEN_EBTABLES]
        name_wrap = name[:ebtables_manager.ChainName.MAX_CHAIN_LEN_EBTABLES -
                         (len(pc) + len('-'))]
        cn_nowrap = self.ebtables.get_chain_name(name,
                                                 wrap=False,
                                                 prefix_chain=pc)
        cn_wrap = self.ebtables.get_chain_name(name,
                                               wrap=True,
                                               prefix_chain=pc)
        self.assertEqual(cn_nowrap, name_nowrap)
        self.assertEqual(cn_wrap, name_wrap)

    def test_get_chain_name_one_character_prefix_chain(self):
        name = '0'
        self.ebtables = (ebtables_manager.
                         EbtablesManager(root_helper=self.root_helper,
                                         prefix_chain=name))
        pc = self.ebtables.prefix_chain
        name_nowrap = name[:ebtables_manager.ChainName.MAX_CHAIN_LEN_EBTABLES]
        name_wrap = name[:ebtables_manager.ChainName.MAX_CHAIN_LEN_EBTABLES -
                         (len(pc) + len('-'))]
        cn_nowrap = self.ebtables.get_chain_name(name,
                                                 wrap=False,
                                                 prefix_chain=pc)
        cn_wrap = self.ebtables.get_chain_name(name,
                                               wrap=True,
                                               prefix_chain=pc)
        self.assertEqual(cn_nowrap, name_nowrap)
        self.assertEqual(cn_wrap, name_wrap)

    def test_init_manager_and_rules_add_before_others(self):
        ebtables_dump = FILTER_DUMP2 + NAT_DUMP2 + BROUTE_DUMP2
        self.ebt_save.return_value = ebtables_dump
        self.ebtables.apply()
        filter_dump_mod = ('*filter\n'
                           ':INPUT ACCEPT\n'
                           ':FORWARD ACCEPT\n'
                           ':OUTPUT ACCEPT\n'
                           ':%(pc)s-FORWARD ACCEPT\n'
                           ':%(pc)s-INPUT ACCEPT\n'
                           ':%(pc)s-OUTPUT ACCEPT\n'
                           '[0:0] -A INPUT -j %(pc)s-INPUT\n'
                           '[0:0] -A OUTPUT -j %(pc)s-OUTPUT\n'
                           '[0:0] -A FORWARD -j %(pc)s-FORWARD\n'
                           '[0:0] -A INPUT -j CONTINUE\n'
                           'COMMIT\n' % EBTABLES_ARG)
        nat_dump_mod = ('*nat\n'
                        ':PREROUTING ACCEPT\n'
                        ':OUTPUT ACCEPT\n'
                        ':POSTROUTING ACCEPT\n'
                        ':%(pc)s-OUTPUT ACCEPT\n'
                        ':%(pc)s-PREROUTING ACCEPT\n'
                        ':%(pc)s-POSTROUTING ACCEPT\n'
                        '[0:0] -A PREROUTING -j %(pc)s-PREROUTING\n'
                        '[0:0] -A OUTPUT -j %(pc)s-OUTPUT\n'
                        '[0:0] -A POSTROUTING -j %(pc)s-POSTROUTING\n'
                        '[0:0] -A PREROUTING -j CONTINUE\n'
                        'COMMIT\n' % EBTABLES_ARG)
        broute_dump_mod = ('*broute\n'
                           ':BROUTE ACCEPT\n'
                           ':%(pc)s-BROUTING ACCEPT\n'
                           '[0:0] -A BROUTING -j %(pc)s-BROUTING\n'
                           '[0:0] -A BROUTING -j CONTINUE\n'
                           'COMMIT\n' % EBTABLES_ARG)

        ebtables_dump_mod = filter_dump_mod + nat_dump_mod + broute_dump_mod
        self.ebt_restore.assert_called_once_with(ebtables_dump_mod,
                                                 self.ebtables.ebtables_path,
                                                 self.ebtables.execute,
                                                 self.ebtables.root_helper,
                                                 namespace=None)

    def test_add_and_remove_chain_with_rule_and_custom_prefix_chain(self):
        pc = ("abcdef" * 5)[:ebtables_manager.ChainName.MAX_LEN_PREFIX_CHAIN]

        self.ebtables = (ebtables_manager.
                         EbtablesManager(root_helper=self.root_helper,
                                         prefix_chain=pc))
        ebtables_dump = FILTER_DUMP1 + NAT_DUMP1 + BROUTE_DUMP1
        ebtables_dump = ebtables_dump.replace(
            ebtables_manager.ChainName.binary_name(), pc)
        ebtables_args = {'pc': pc}

        self.ebt_save.return_value = ebtables_dump
        self.ebtables.tables['filter'].add_chain('filter')
        self.ebtables.tables['filter'].add_rule('filter',
                                                '-p ARP -i eth0 -j DROP')
        self.ebtables.apply()
        filter_dump_mod = ('*filter\n'
                           ':INPUT ACCEPT\n'
                           ':FORWARD ACCEPT\n'
                           ':OUTPUT ACCEPT\n'
                           ':%(pc)s-FORWARD ACCEPT\n'
                           ':%(pc)s-INPUT ACCEPT\n'
                           ':%(pc)s-filter ACCEPT\n'
                           ':%(pc)s-OUTPUT ACCEPT\n'
                           '[0:0] -A INPUT -j %(pc)s-INPUT\n'
                           '[0:0] -A OUTPUT -j %(pc)s-OUTPUT\n'
                           '[0:0] -A FORWARD -j %(pc)s-FORWARD\n'
                           '[0:0] -A %(pc)s-filter -p ARP -i eth0 -j DROP\n'
                           'COMMIT\n' % ebtables_args)
        ebtables_dump_mod = filter_dump_mod + NAT_DUMP3 + BROUTE_DUMP3
        ebtables_dump_mod = ebtables_dump_mod.replace(
            ebtables_manager.ChainName.binary_name(), pc)
        self.ebt_restore.assert_called_with(ebtables_dump_mod,
                                            self.ebtables.ebtables_path,
                                            self.ebtables.execute,
                                            self.ebtables.root_helper,
                                            namespace=None)

        self.ebt_save.return_value = ebtables_dump_mod
        self.ebtables.tables['filter'].remove_chain('filter')
        self.ebtables.apply()
        ebtables_dump_mod = FILTER_DUMP3 + NAT_DUMP3 + BROUTE_DUMP3
        ebtables_dump_mod = ebtables_dump_mod.replace(
            ebtables_manager.ChainName.binary_name(), pc)
        self.ebt_restore.assert_called_with(ebtables_dump_mod,
                                            self.ebtables.ebtables_path,
                                            self.ebtables.execute,
                                            self.ebtables.root_helper,
                                            namespace=None)

    def test_add_and_remove_filter_chain(self):
        self.ebt_save.return_value = FILTER_DUMP1 + NAT_DUMP1 + BROUTE_DUMP1
        self.ebtables.tables['filter'].add_chain('filter')
        self.ebtables.tables['filter'].add_rule('filter',
                                                '-p ARP -i eth0 -j DROP')
        self.ebtables.apply()
        filter_dump_mod = ('*filter\n'
                           ':INPUT ACCEPT\n'
                           ':FORWARD ACCEPT\n'
                           ':OUTPUT ACCEPT\n'
                           ':%(pc)s-FORWARD ACCEPT\n'
                           ':%(pc)s-INPUT ACCEPT\n'
                           ':%(pc)s-filter ACCEPT\n'
                           ':%(pc)s-OUTPUT ACCEPT\n'
                           '[0:0] -A INPUT -j %(pc)s-INPUT\n'
                           '[0:0] -A OUTPUT -j %(pc)s-OUTPUT\n'
                           '[0:0] -A FORWARD -j %(pc)s-FORWARD\n'
                           '[0:0] -A %(pc)s-filter -p ARP -i eth0 -j DROP\n'
                           'COMMIT\n' % EBTABLES_ARG)
        ebtables_dump_mod = filter_dump_mod + NAT_DUMP3 + BROUTE_DUMP3
        self.ebt_restore.assert_called_with(ebtables_dump_mod,
                                            self.ebtables.ebtables_path,
                                            self.ebtables.execute,
                                            self.ebtables.root_helper,
                                            namespace=None)

        self.ebt_save.return_value = ebtables_dump_mod
        self.ebtables.tables['filter'].remove_chain('filter')
        self.ebtables.apply()
        ebtables_dump_mod = FILTER_DUMP3 + NAT_DUMP3 + BROUTE_DUMP3
        self.ebt_restore.assert_called_with(ebtables_dump_mod,
                                            self.ebtables.ebtables_path,
                                            self.ebtables.execute,
                                            self.ebtables.root_helper,
                                            namespace=None)

    def test_add_and_remove_nat_chain(self):
        self.ebt_save.return_value = FILTER_DUMP1 + NAT_DUMP1 + BROUTE_DUMP1
        self.ebtables.tables['nat'].add_chain('nat')
        self.ebtables.tables['nat'].add_rule('nat',
                                             '-d 00:11:22:33:44:55 -i eth0 '
                                             '-j dnat --to-destination '
                                             '54:44:33:22:11:00')
        self.ebtables.apply()
        nat_dump_mod = ('*nat\n'
                        ':PREROUTING ACCEPT\n'
                        ':OUTPUT ACCEPT\n'
                        ':POSTROUTING ACCEPT\n'
                        ':%(pc)s-OUTPUT ACCEPT\n'
                        ':%(pc)s-PREROUTING ACCEPT\n'
                        ':%(pc)s-nat ACCEPT\n'
                        ':%(pc)s-POSTROUTING ACCEPT\n'
                        '[0:0] -A PREROUTING -j %(pc)s-PREROUTING\n'
                        '[0:0] -A OUTPUT -j %(pc)s-OUTPUT\n'
                        '[0:0] -A POSTROUTING -j %(pc)s-POSTROUTING\n'
                        '[0:0] -A %(pc)s-nat -d 00:11:22:33:44:55 -i eth0 '
                        '-j dnat --to-destination 54:44:33:22:11:00\n'
                        'COMMIT\n' % EBTABLES_ARG)
        ebtables_dump_mod = FILTER_DUMP3 + nat_dump_mod + BROUTE_DUMP3
        self.ebt_restore.assert_called_with(ebtables_dump_mod,
                                            self.ebtables.ebtables_path,
                                            self.ebtables.execute,
                                            self.ebtables.root_helper,
                                            namespace=None)

        self.ebt_save.return_value = ebtables_dump_mod
        self.ebtables.tables['nat'].remove_chain('nat')
        self.ebtables.apply()
        ebtables_dump_mod = FILTER_DUMP3 + NAT_DUMP3 + BROUTE_DUMP3
        self.ebt_restore.assert_called_with(ebtables_dump_mod,
                                            self.ebtables.ebtables_path,
                                            self.ebtables.execute,
                                            self.ebtables.root_helper,
                                            namespace=None)

    def test_add_and_remove_broute_chain(self):
        self.ebt_save.return_value = FILTER_DUMP1 + NAT_DUMP1 + BROUTE_DUMP1
        self.ebtables.tables['broute'].add_chain('broute')
        self.ebtables.tables['broute'].add_rule('broute',
                                                '-d 00:11:22:33:44:55 -p ipv4 '
                                                '-j redirect --redirect-target'
                                                ' DROP')
        self.ebtables.apply()
        broute_dump_mod = ('*broute\n'
                           ':BROUTE ACCEPT\n'
                           ':%(pc)s-BROUTING ACCEPT\n'
                           ':%(pc)s-broute ACCEPT\n'
                           '[0:0] -A BROUTING -j %(pc)s-BROUTING\n'
                           '[0:0] -A %(pc)s-broute -d 00:11:22:33:44:55 -p '
                           'ipv4 -j redirect --redirect-target DROP\n'
                           'COMMIT\n' % EBTABLES_ARG)
        ebtables_dump_mod = FILTER_DUMP3 + NAT_DUMP3 + broute_dump_mod
        self.ebt_restore.assert_called_with(ebtables_dump_mod,
                                            self.ebtables.ebtables_path,
                                            self.ebtables.execute,
                                            self.ebtables.root_helper,
                                            namespace=None)

        self.ebt_save.return_value = ebtables_dump_mod
        self.ebtables.tables['broute'].remove_chain('broute')
        self.ebtables.apply()
        ebtables_dump_mod = FILTER_DUMP3 + NAT_DUMP3 + BROUTE_DUMP3
        self.ebt_restore.assert_called_with(ebtables_dump_mod,
                                            self.ebtables.ebtables_path,
                                            self.ebtables.execute,
                                            self.ebtables.root_helper,
                                            namespace=None)

    def test_add_and_remove_filter_rule(self):
        self.ebt_save.return_value = FILTER_DUMP1 + NAT_DUMP1 + BROUTE_DUMP1
        self.ebtables.tables['filter'].add_chain('filter')
        self.ebtables.tables['filter'].add_rule('filter',
                                                '-p ARP -i eth0 -j DROP')
        self.ebtables.tables['filter'].add_rule('filter',
                                                '-p ARP -i eth1 -j DROP')
        self.ebtables.apply()
        filter_dump_mod = ('*filter\n'
                           ':INPUT ACCEPT\n'
                           ':FORWARD ACCEPT\n'
                           ':OUTPUT ACCEPT\n'
                           ':%(pc)s-FORWARD ACCEPT\n'
                           ':%(pc)s-INPUT ACCEPT\n'
                           ':%(pc)s-filter ACCEPT\n'
                           ':%(pc)s-OUTPUT ACCEPT\n'
                           '[0:0] -A INPUT -j %(pc)s-INPUT\n'
                           '[0:0] -A OUTPUT -j %(pc)s-OUTPUT\n'
                           '[0:0] -A FORWARD -j %(pc)s-FORWARD\n'
                           '[0:0] -A %(pc)s-filter -p ARP -i eth0 -j DROP\n'
                           '[0:0] -A %(pc)s-filter -p ARP -i eth1 -j DROP\n'
                           'COMMIT\n' % EBTABLES_ARG)
        ebtables_dump_mod = filter_dump_mod + NAT_DUMP3 + BROUTE_DUMP3
        self.ebt_restore.assert_called_with(ebtables_dump_mod,
                                            self.ebtables.ebtables_path,
                                            self.ebtables.execute,
                                            self.ebtables.root_helper,
                                            namespace=None)

        self.ebt_save.return_value = ebtables_dump_mod
        self.ebtables.tables['filter'].remove_rule('filter',
                                                   '-p ARP -i eth1 -j DROP')
        self.ebtables.apply()
        filter_dump_mod = ('*filter\n'
                           ':INPUT ACCEPT\n'
                           ':FORWARD ACCEPT\n'
                           ':OUTPUT ACCEPT\n'
                           ':%(pc)s-FORWARD ACCEPT\n'
                           ':%(pc)s-INPUT ACCEPT\n'
                           ':%(pc)s-filter ACCEPT\n'
                           ':%(pc)s-OUTPUT ACCEPT\n'
                           '[0:0] -A INPUT -j %(pc)s-INPUT\n'
                           '[0:0] -A OUTPUT -j %(pc)s-OUTPUT\n'
                           '[0:0] -A FORWARD -j %(pc)s-FORWARD\n'
                           '[0:0] -A %(pc)s-filter -p ARP -i eth0 -j DROP\n'
                           'COMMIT\n' % EBTABLES_ARG)
        ebtables_dump_mod = filter_dump_mod + NAT_DUMP3 + BROUTE_DUMP3
        self.ebt_restore.assert_called_with(ebtables_dump_mod,
                                            self.ebtables.ebtables_path,
                                            self.ebtables.execute,
                                            self.ebtables.root_helper,
                                            namespace=None)

    def test_add_and_remove_nat_rule(self):
        self.ebt_save.return_value = FILTER_DUMP1 + NAT_DUMP1 + BROUTE_DUMP1
        self.ebtables.tables['nat'].add_chain('nat')
        self.ebtables.tables['nat'].add_rule('nat',
                                             '-d 00:11:22:33:44:55 -i eth0 '
                                             '-j dnat --to-destination '
                                             '54:44:33:22:11:00')
        self.ebtables.tables['nat'].add_rule('nat',
                                             '-d 00:11:22:33:44:55 -i eth1 '
                                             '-j dnat --to-destination '
                                             '54:44:33:22:11:00')
        self.ebtables.apply()
        nat_dump_mod = ('*nat\n'
                        ':PREROUTING ACCEPT\n'
                        ':OUTPUT ACCEPT\n'
                        ':POSTROUTING ACCEPT\n'
                        ':%(pc)s-OUTPUT ACCEPT\n'
                        ':%(pc)s-PREROUTING ACCEPT\n'
                        ':%(pc)s-nat ACCEPT\n'
                        ':%(pc)s-POSTROUTING ACCEPT\n'
                        '[0:0] -A PREROUTING -j %(pc)s-PREROUTING\n'
                        '[0:0] -A OUTPUT -j %(pc)s-OUTPUT\n'
                        '[0:0] -A POSTROUTING -j %(pc)s-POSTROUTING\n'
                        '[0:0] -A %(pc)s-nat -d 00:11:22:33:44:55 -i eth0 '
                        '-j dnat --to-destination 54:44:33:22:11:00\n'
                        '[0:0] -A %(pc)s-nat -d 00:11:22:33:44:55 -i eth1 '
                        '-j dnat --to-destination 54:44:33:22:11:00\n'
                        'COMMIT\n' % EBTABLES_ARG)
        ebtables_dump_mod = FILTER_DUMP3 + nat_dump_mod + BROUTE_DUMP3
        self.ebt_restore.assert_called_with(ebtables_dump_mod,
                                            self.ebtables.ebtables_path,
                                            self.ebtables.execute,
                                            self.ebtables.root_helper,
                                            namespace=None)

        self.ebt_save.return_value = ebtables_dump_mod
        self.ebtables.tables['nat'].remove_rule('nat',
                                                '-d 00:11:22:33:44:55 -i eth1 '
                                                '-j dnat --to-destination '
                                                '54:44:33:22:11:00')
        self.ebtables.apply()
        nat_dump_mod = ('*nat\n'
                        ':PREROUTING ACCEPT\n'
                        ':OUTPUT ACCEPT\n'
                        ':POSTROUTING ACCEPT\n'
                        ':%(pc)s-OUTPUT ACCEPT\n'
                        ':%(pc)s-PREROUTING ACCEPT\n'
                        ':%(pc)s-nat ACCEPT\n'
                        ':%(pc)s-POSTROUTING ACCEPT\n'
                        '[0:0] -A PREROUTING -j %(pc)s-PREROUTING\n'
                        '[0:0] -A OUTPUT -j %(pc)s-OUTPUT\n'
                        '[0:0] -A POSTROUTING -j %(pc)s-POSTROUTING\n'
                        '[0:0] -A %(pc)s-nat -d 00:11:22:33:44:55 -i eth0 '
                        '-j dnat --to-destination 54:44:33:22:11:00\n'
                        'COMMIT\n' % EBTABLES_ARG)
        ebtables_dump_mod = FILTER_DUMP3 + nat_dump_mod + BROUTE_DUMP3
        self.ebt_restore.assert_called_with(ebtables_dump_mod,
                                            self.ebtables.ebtables_path,
                                            self.ebtables.execute,
                                            self.ebtables.root_helper,
                                            namespace=None)

    def test_add_and_remove_broute_rule(self):
        self.ebt_save.return_value = FILTER_DUMP1 + NAT_DUMP1 + BROUTE_DUMP1
        self.ebtables.tables['broute'].add_chain('broute')
        self.ebtables.tables['broute'].add_rule('broute',
                                                '-d 00:11:22:33:44:55 -p ipv4 '
                                                '-j redirect --redirect-target'
                                                ' DROP')
        self.ebtables.tables['broute'].add_rule('broute',
                                                '-d 00:11:22:33:44:55 -p ipv6 '
                                                '-j redirect --redirect-target'
                                                ' DROP')
        self.ebtables.apply()
        broute_dump_mod = ('*broute\n'
                           ':BROUTE ACCEPT\n'
                           ':%(pc)s-BROUTING ACCEPT\n'
                           ':%(pc)s-broute ACCEPT\n'
                           '[0:0] -A BROUTING -j %(pc)s-BROUTING\n'
                           '[0:0] -A %(pc)s-broute -d 00:11:22:33:44:55 -p '
                           'ipv4 -j redirect --redirect-target DROP\n'
                           '[0:0] -A %(pc)s-broute -d 00:11:22:33:44:55 -p '
                           'ipv6 -j redirect --redirect-target DROP\n'
                           'COMMIT\n' % EBTABLES_ARG)
        ebtables_dump_mod = FILTER_DUMP3 + NAT_DUMP3 + broute_dump_mod
        self.ebt_restore.assert_called_with(ebtables_dump_mod,
                                            self.ebtables.ebtables_path,
                                            self.ebtables.execute,
                                            self.ebtables.root_helper,
                                            namespace=None)

        self.ebt_save.return_value = ebtables_dump_mod
        self.ebtables.tables['broute'].remove_rule('broute',
                                                   '-d 00:11:22:33:44:55 -p '
                                                   'ipv6 -j redirect '
                                                   '--redirect-target DROP')
        self.ebtables.apply()
        broute_dump_mod = ('*broute\n'
                           ':BROUTE ACCEPT\n'
                           ':%(pc)s-BROUTING ACCEPT\n'
                           ':%(pc)s-broute ACCEPT\n'
                           '[0:0] -A BROUTING -j %(pc)s-BROUTING\n'
                           '[0:0] -A %(pc)s-broute -d 00:11:22:33:44:55 -p '
                           'ipv4 -j redirect --redirect-target DROP\n'
                           'COMMIT\n' % EBTABLES_ARG)
        ebtables_dump_mod = FILTER_DUMP3 + NAT_DUMP3 + broute_dump_mod
        self.ebt_restore.assert_called_with(ebtables_dump_mod,
                                            self.ebtables.ebtables_path,
                                            self.ebtables.execute,
                                            self.ebtables.root_helper,
                                            namespace=None)

    def test_empty_filter_chain(self):
        self.ebt_save.return_value = FILTER_DUMP1 + NAT_DUMP1 + BROUTE_DUMP1
        self.ebtables.tables['filter'].add_chain('filter')
        self.ebtables.tables['filter'].add_rule('filter',
                                                '-p ARP -i eth0 -j DROP')
        self.ebtables.apply()
        filter_dump_mod = ('*filter\n'
                           ':INPUT ACCEPT\n'
                           ':FORWARD ACCEPT\n'
                           ':OUTPUT ACCEPT\n'
                           ':%(pc)s-FORWARD ACCEPT\n'
                           ':%(pc)s-INPUT ACCEPT\n'
                           ':%(pc)s-filter ACCEPT\n'
                           ':%(pc)s-OUTPUT ACCEPT\n'
                           '[0:0] -A INPUT -j %(pc)s-INPUT\n'
                           '[0:0] -A OUTPUT -j %(pc)s-OUTPUT\n'
                           '[0:0] -A FORWARD -j %(pc)s-FORWARD\n'
                           '[0:0] -A %(pc)s-filter -p ARP -i eth0 -j DROP\n'
                           'COMMIT\n' % EBTABLES_ARG)
        ebtables_dump_mod = filter_dump_mod + NAT_DUMP3 + BROUTE_DUMP3
        self.ebt_restore.assert_called_with(ebtables_dump_mod,
                                            self.ebtables.ebtables_path,
                                            self.ebtables.execute,
                                            self.ebtables.root_helper,
                                            namespace=None)

        self.ebt_save.return_value = ebtables_dump_mod
        self.ebtables.tables['filter'].empty_chain('filter')
        self.ebtables.apply()
        filter_dump_mod = ('*filter\n'
                           ':INPUT ACCEPT\n'
                           ':FORWARD ACCEPT\n'
                           ':OUTPUT ACCEPT\n'
                           ':%(pc)s-FORWARD ACCEPT\n'
                           ':%(pc)s-INPUT ACCEPT\n'
                           ':%(pc)s-filter ACCEPT\n'
                           ':%(pc)s-OUTPUT ACCEPT\n'
                           '[0:0] -A INPUT -j %(pc)s-INPUT\n'
                           '[0:0] -A OUTPUT -j %(pc)s-OUTPUT\n'
                           '[0:0] -A FORWARD -j %(pc)s-FORWARD\n'
                           'COMMIT\n' % EBTABLES_ARG)
        ebtables_dump_mod = filter_dump_mod + NAT_DUMP3 + BROUTE_DUMP3
        self.ebt_restore.assert_called_with(ebtables_dump_mod,
                                            self.ebtables.ebtables_path,
                                            self.ebtables.execute,
                                            self.ebtables.root_helper,
                                            namespace=None)

    def test_empty_nat_chain(self):
        self.ebt_save.return_value = FILTER_DUMP1 + NAT_DUMP1 + BROUTE_DUMP1
        self.ebtables.tables['nat'].add_chain('nat')
        self.ebtables.tables['nat'].add_rule('nat',
                                             '-d 00:11:22:33:44:55 -i eth0 '
                                             '-j dnat --to-destination '
                                             '54:44:33:22:11:00')
        self.ebtables.apply()
        nat_dump_mod = ('*nat\n'
                        ':PREROUTING ACCEPT\n'
                        ':OUTPUT ACCEPT\n'
                        ':POSTROUTING ACCEPT\n'
                        ':%(pc)s-OUTPUT ACCEPT\n'
                        ':%(pc)s-PREROUTING ACCEPT\n'
                        ':%(pc)s-nat ACCEPT\n'
                        ':%(pc)s-POSTROUTING ACCEPT\n'
                        '[0:0] -A PREROUTING -j %(pc)s-PREROUTING\n'
                        '[0:0] -A OUTPUT -j %(pc)s-OUTPUT\n'
                        '[0:0] -A POSTROUTING -j %(pc)s-POSTROUTING\n'
                        '[0:0] -A %(pc)s-nat -d 00:11:22:33:44:55 -i eth0 '
                        '-j dnat --to-destination 54:44:33:22:11:00\n'
                        'COMMIT\n' % EBTABLES_ARG)
        ebtables_dump_mod = FILTER_DUMP3 + nat_dump_mod + BROUTE_DUMP3
        self.ebt_restore.assert_called_with(ebtables_dump_mod,
                                            self.ebtables.ebtables_path,
                                            self.ebtables.execute,
                                            self.ebtables.root_helper,
                                            namespace=None)

        self.ebt_save.return_value = ebtables_dump_mod
        self.ebtables.tables['nat'].empty_chain('nat')
        self.ebtables.apply()
        nat_dump_mod = ('*nat\n'
                        ':PREROUTING ACCEPT\n'
                        ':OUTPUT ACCEPT\n'
                        ':POSTROUTING ACCEPT\n'
                        ':%(pc)s-OUTPUT ACCEPT\n'
                        ':%(pc)s-PREROUTING ACCEPT\n'
                        ':%(pc)s-nat ACCEPT\n'
                        ':%(pc)s-POSTROUTING ACCEPT\n'
                        '[0:0] -A PREROUTING -j %(pc)s-PREROUTING\n'
                        '[0:0] -A OUTPUT -j %(pc)s-OUTPUT\n'
                        '[0:0] -A POSTROUTING -j %(pc)s-POSTROUTING\n'
                        'COMMIT\n' % EBTABLES_ARG)
        ebtables_dump_mod = FILTER_DUMP3 + nat_dump_mod + BROUTE_DUMP3
        self.ebt_restore.assert_called_with(ebtables_dump_mod,
                                            self.ebtables.ebtables_path,
                                            self.ebtables.execute,
                                            self.ebtables.root_helper,
                                            namespace=None)

    def test_empty_broute_chain(self):
        self.ebt_save.return_value = FILTER_DUMP1 + NAT_DUMP1 + BROUTE_DUMP1
        self.ebtables.tables['broute'].add_chain('broute')
        self.ebtables.tables['broute'].add_rule('broute',
                                                '-d 00:11:22:33:44:55 -p ipv4 '
                                                '-j redirect --redirect-target'
                                                ' DROP')
        self.ebtables.apply()
        broute_dump_mod = ('*broute\n'
                           ':BROUTE ACCEPT\n'
                           ':%(pc)s-BROUTING ACCEPT\n'
                           ':%(pc)s-broute ACCEPT\n'
                           '[0:0] -A BROUTING -j %(pc)s-BROUTING\n'
                           '[0:0] -A %(pc)s-broute -d 00:11:22:33:44:55 -p '
                           'ipv4 -j redirect --redirect-target DROP\n'
                           'COMMIT\n' % EBTABLES_ARG)
        ebtables_dump_mod = FILTER_DUMP3 + NAT_DUMP3 + broute_dump_mod
        self.ebt_restore.assert_called_with(ebtables_dump_mod,
                                            self.ebtables.ebtables_path,
                                            self.ebtables.execute,
                                            self.ebtables.root_helper,
                                            namespace=None)

        self.ebt_save.return_value = ebtables_dump_mod
        self.ebtables.tables['broute'].empty_chain('broute')
        self.ebtables.apply()
        broute_dump_mod = ('*broute\n'
                           ':BROUTE ACCEPT\n'
                           ':%(pc)s-BROUTING ACCEPT\n'
                           ':%(pc)s-broute ACCEPT\n'
                           '[0:0] -A BROUTING -j %(pc)s-BROUTING\n'
                           'COMMIT\n' % EBTABLES_ARG)
        ebtables_dump_mod = FILTER_DUMP3 + NAT_DUMP3 + broute_dump_mod
        self.ebt_restore.assert_called_with(ebtables_dump_mod,
                                            self.ebtables.ebtables_path,
                                            self.ebtables.execute,
                                            self.ebtables.root_helper,
                                            namespace=None)

    def test_add_rule_to_a_nonexistent_chain(self):
        self.assertRaises(LookupError, self.ebtables.tables['filter'].add_rule,
                          'nonexistent', '-j DROP')

    def test_remove_nonexistent_chain(self):
        with mock.patch.object(ebtables_manager, 'LOG') as log:
            self.ebtables.tables['filter'].remove_chain('nonexistent')
            msg = ('Attempted to remove chain %s which does not exist')
            log.warn.assert_called_with(msg, 'nonexistent')

    def test_remove_nonexistent_rule(self):
        with mock.patch.object(ebtables_manager, 'LOG') as log:
            self.ebtables.tables['filter'].remove_rule('nonexistent',
                                                       '-j DROP')
            msg = ('Tried to remove rule that was not there: '
                   '%(chain)r %(rule)r %(wrap)r %(top)r')
            log.warn.assert_called_with(msg, {'wrap': True, 'top': False,
                                              'rule': '-j DROP',
                                              'chain': 'nonexistent'})

    def test_get_traffic_counters(self):
        with mock.patch.object(self.ebtables, 'execute') as execute:
            execute.return_value = (
                'Bridge table: filter\n'
                '\n'
                'Bridge chain: INPUT, entries: 1, policy: ACCEPT\n'
                '-j tmp1-INPUT, pcnt = 1234 -- bcnt = 56789\n'
                '-j tmp2-INPUT, pcnt = 1234 -- bcnt = 56789\n')
            acc = self.ebtables.get_traffic_counters('INPUT')
            cmd = 'ebtables -t %(pc)sfilter -L INPUT --Lc' % EBTABLES_ARG
            execute.assert_call_with(cmd.split(' '),
                                     root_helper=self.root_helper)
            self.assertEqual(acc['pkts'], 2468)
            self.assertEqual(acc['bytes'], 113578)

    def test_get_traffic_counters_chain_not_exists(self):
        with mock.patch.object(self.ebtables, 'execute') as execute:
            execute.return_value = (
                'Bridge table: filter\n'
                '\n'
                'Bridge chain: INPUT, entries: 1, policy: ACCEPT\n'
                '-j tmp1-INPUT, pcnt = 1234 -- bcnt = 56789\n'
                '-j tmp2-INPUT, pcnt = 1234 -- bcnt = 56789\n')
            acc = self.ebtables.get_traffic_counters('tmp1-INPUT')
            cmd = 'ebtables -t %(pc)sfilter -L INPUT --Lc' % EBTABLES_ARG
            execute.assert_call_with(cmd.split(' '),
                                     root_helper=self.root_helper)
            self.assertIsNone(acc)

    def test_get_traffic_counters_with_zero(self):
        with mock.patch.object(self.ebtables, 'execute') as execute:
            execute.return_value = (
                'Bridge table: filter\n'
                '\n'
                'Bridge chain: INPUT, entries: 1, policy: ACCEPT\n'
                '-j tmp1-INPUT, pcnt = 1234 -- bcnt = 56789\n'
                '-j tmp2-INPUT, pcnt = 1234 -- bcnt = 56789\n')
            acc = self.ebtables.get_traffic_counters('INPUT', zero=True)
            cmd = 'ebtables -t %(pc)sfilter -L INPUT --Lc -Z' % EBTABLES_ARG
            execute.assert_call_with(cmd.split(' '),
                                     root_helper=self.root_helper)
            self.assertEqual(acc['pkts'], 2468)
            self.assertEqual(acc['bytes'], 113578)

    def test_restore_counters(self):
        filter_dump = ('*filter\n'
                       ':INPUT ACCEPT\n'
                       ':FORWARD ACCEPT\n'
                       ':OUTPUT ACCEPT\n'
                       ':%(pc)s-FORWARD ACCEPT\n'
                       ':%(pc)s-INPUT ACCEPT\n'
                       ':%(pc)s-OUTPUT ACCEPT\n'
                       '[0:1] -A INPUT -j %(pc)s-INPUT\n'
                       '[2:3] -A OUTPUT -j %(pc)s-OUTPUT\n'
                       '[4:5] -A FORWARD -j %(pc)s-FORWARD\n'
                       'COMMIT\n' % EBTABLES_ARG)
        nat_dump = ('*nat\n'
                    ':PREROUTING ACCEPT\n'
                    ':OUTPUT ACCEPT\n'
                    ':POSTROUTING ACCEPT\n'
                    ':%(pc)s-OUTPUT ACCEPT\n'
                    ':%(pc)s-PREROUTING ACCEPT\n'
                    ':%(pc)s-POSTROUTING ACCEPT\n'
                    '[0:1] -A PREROUTING -j %(pc)s-PREROUTING\n'
                    '[2:3] -A OUTPUT -j %(pc)s-OUTPUT\n'
                    '[4:5] -A POSTROUTING -j %(pc)s-POSTROUTING\n'
                    'COMMIT\n' % EBTABLES_ARG)
        broute_dump = ('*broute\n'
                       ':BROUTE ACCEPT\n'
                       ':%(pc)s-BROUTING ACCEPT\n'
                       '[0:1] -A BROUTING -j %(pc)s-BROUTING\n'
                       'COMMIT\n' % EBTABLES_ARG)
        self.ebt_save.return_value = filter_dump + nat_dump + broute_dump
        self.ebtables.tables['filter'].add_chain('filter')
        self.ebtables.tables['filter'].add_rule('filter',
                                                '-p ARP -i eth0 -j DROP')

        self.ebtables.tables['nat'].add_chain('nat')
        self.ebtables.tables['nat'].add_rule('nat',
                                             '-d 00:11:22:33:44:55 -i eth0 '
                                             '-j dnat --to-destination '
                                             '54:44:33:22:11:00')
        self.ebtables.tables['broute'].add_chain('broute')
        self.ebtables.tables['broute'].add_rule('broute',
                                                '-d 00:11:22:33:44:55 -p ipv4 '
                                                '-j redirect --redirect-target'
                                                ' DROP')
        self.ebtables.apply()
        filter_dump_mod = ('*filter\n'
                           ':INPUT ACCEPT\n'
                           ':FORWARD ACCEPT\n'
                           ':OUTPUT ACCEPT\n'
                           ':%(pc)s-FORWARD ACCEPT\n'
                           ':%(pc)s-INPUT ACCEPT\n'
                           ':%(pc)s-filter ACCEPT\n'
                           ':%(pc)s-OUTPUT ACCEPT\n'
                           '[0:1] -A INPUT -j %(pc)s-INPUT\n'
                           '[2:3] -A OUTPUT -j %(pc)s-OUTPUT\n'
                           '[4:5] -A FORWARD -j %(pc)s-FORWARD\n'
                           '[0:0] -A %(pc)s-filter -p ARP -i eth0 -j DROP\n'
                           'COMMIT\n' % EBTABLES_ARG)
        nat_dump_mod = ('*nat\n'
                        ':PREROUTING ACCEPT\n'
                        ':OUTPUT ACCEPT\n'
                        ':POSTROUTING ACCEPT\n'
                        ':%(pc)s-OUTPUT ACCEPT\n'
                        ':%(pc)s-PREROUTING ACCEPT\n'
                        ':%(pc)s-nat ACCEPT\n'
                        ':%(pc)s-POSTROUTING ACCEPT\n'
                        '[0:1] -A PREROUTING -j %(pc)s-PREROUTING\n'
                        '[2:3] -A OUTPUT -j %(pc)s-OUTPUT\n'
                        '[4:5] -A POSTROUTING -j %(pc)s-POSTROUTING\n'
                        '[0:0] -A %(pc)s-nat -d 00:11:22:33:44:55 -i eth0 '
                        '-j dnat --to-destination 54:44:33:22:11:00\n'
                        'COMMIT\n' % EBTABLES_ARG)
        broute_dump_mod = ('*broute\n'
                           ':BROUTE ACCEPT\n'
                           ':%(pc)s-BROUTING ACCEPT\n'
                           ':%(pc)s-broute ACCEPT\n'
                           '[0:1] -A BROUTING -j %(pc)s-BROUTING\n'
                           '[0:0] -A %(pc)s-broute -d 00:11:22:33:44:55 -p '
                           'ipv4 -j redirect --redirect-target DROP\n'
                           'COMMIT\n' % EBTABLES_ARG)
        ebtables_dump_mod = filter_dump_mod + nat_dump_mod + broute_dump_mod
        self.ebt_restore.assert_called_with(ebtables_dump_mod,
                                            self.ebtables.ebtables_path,
                                            self.ebtables.execute,
                                            self.ebtables.root_helper,
                                            namespace=None)

    def test_defer_apply(self):
        self.ebtables.tables['broute'].add_chain('broute')

        self.ebtables.defer_apply_on()
        self.ebtables.apply()
        self.assertFalse(self.ebt_save.called)
        self.assertFalse(self.ebt_restore.called)

        self.ebtables.defer_apply_off()
        self.assertTrue(self.ebt_save.called)
        self.assertTrue(self.ebt_restore.called)


class EbtablesManagerTransactionTestCase(base.BaseTestCase):

    def setUp(self):
        super(EbtablesManagerTransactionTestCase, self).setUp()
        self.root_helper = 'sudo'
        self.ebtables = (ebtables_manager.
                         EbtablesManager(root_helper=self.root_helper))

        self.ebt_save_p = mock.patch.object(ebtables_manager, 'ebtables_save')
        self.ebt_save = self.ebt_save_p.start()
        self.addCleanup(self.ebt_save_p.stop)

        self.ebt_restore_p = mock.patch.object(ebtables_manager,
                                               'ebtables_restore')
        self.ebt_restore = self.ebt_restore_p.start()
        self.addCleanup(self.ebt_restore_p.stop)

    def test_ebtables_manager_transaction(self):
        with ebtables_manager.EbtablesManagerTransaction(self.ebtables):
            self.ebtables.tables['broute'].add_chain('broute1')
            self.assertFalse(self.ebt_save.called)
            self.assertFalse(self.ebt_restore.called)
            with ebtables_manager.EbtablesManagerTransaction(self.ebtables):
                self.ebtables.tables['broute'].add_chain('broute2')
                self.assertFalse(self.ebt_save.called)
                self.assertFalse(self.ebt_restore.called)
            self.assertFalse(self.ebt_save.called)
            self.assertFalse(self.ebt_restore.called)
        self.assertEqual(self.ebt_save.call_count, 1)
        self.assertEqual(self.ebt_restore.call_count, 1)

        self.ebt_save.reset_mock()
        self.ebt_restore.reset_mock()
        with ebtables_manager.EbtablesManagerTransaction(self.ebtables):
            self.ebtables.tables['broute'].add_chain('broute1')
            self.assertFalse(self.ebt_save.called)
            self.assertFalse(self.ebt_restore.called)
        self.assertEqual(self.ebt_save.call_count, 1)
        self.assertEqual(self.ebt_restore.call_count, 1)
