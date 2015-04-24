# Copyright (c) 2015 OpenStack Foundation.
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

import mock

from oslo_config import cfg

from neutron.agent.linux import ebtables_driver as eb
from neutron.cmd.sanity.checks import ebtables_supported
from neutron.tests import base


TABLES_NAMES = ['filter', 'nat', 'broute']

CONF = cfg.CONF


class EbtablesDriverLowLevelInputTestCase(base.BaseTestCase):

    def test_match_rule_line(self):
        self.assertEqual((None, None), eb._match_rule_line(None, "foo"))

        rule_line = "[0:1] foobar blah bar"
        self.assertEqual(('mytab', [('mytab', ['foobar', 'blah', 'bar'])]),
                         eb._match_rule_line("mytab", rule_line))

        rule_line = "[2:3] foobar -A BAR -j BLAH"
        self.assertEqual(
            ('mytab',
            [('mytab', ['foobar', '-A', 'BAR', '-j', 'BLAH']),
             ('mytab', ['foobar', '-C', 'BAR', '2', '3', '-j', 'BLAH'])]),
            eb._match_rule_line("mytab", rule_line))

    def test_match_chain_name(self):
        self.assertEqual((None, None), eb._match_chain_name(None, None, "foo"))

        rule_line = ":neutron-nwfilter-OUTPUT ACCEPT"
        tables = {"mytab": []}
        self.assertEqual(
            ('mytab',
             ('mytab', ['-N', 'neutron-nwfilter-OUTPUT', '-P', 'ACCEPT'])),
            eb._match_chain_name("mytab", tables, rule_line))

        rule_line = ":neutron-nwfilter-OUTPUT ACCEPT"
        tables = {"mytab": ['neutron-nwfilter-OUTPUT']}
        self.assertEqual(
            ('mytab',
             ('mytab', ['-P', 'neutron-nwfilter-OUTPUT', 'ACCEPT'])),
            eb._match_chain_name("mytab", tables, rule_line))

    def test_match_table_name(self):
        self.assertEqual((None, None), eb._match_table_name(None, "foo"))

        rule_line = "*filter"
        self.assertEqual(('filter', ('filter', ['--atomic-init'])),
                         eb._match_table_name("mytab", rule_line))

    def test_commit_statement(self):
        self.assertEqual(None, eb._match_commit_statement(None, "foo"))

        rule_line = "COMMIT"
        self.assertEqual(('mytab', ['--atomic-commit']),
                         eb._match_commit_statement("mytab", rule_line))

    def test_ebtables_input_parse_comment(self):
        # Comments and empty lines are stripped, nothing should be left.
        test_input = ("# Here is a comment\n"
                      "\n"
                      "# We just had an empty line.\n")
        res = eb._process_ebtables_input(test_input)
        self.assertEqual(list(), res)

    def test_ebtables_input_parse_start(self):
        # Starting
        test_input = "*filter"
        res = eb._process_ebtables_input(test_input)
        self.assertEqual([('filter', ['--atomic-init'])], res)

    def test_ebtables_input_parse_commit(self):
        # COMMIT without first starting a table should result in nothing,
        test_input = "COMMIT"
        res = eb._process_ebtables_input(test_input)
        self.assertEqual(list(), res)

        test_input = "*filter\nCOMMIT"
        res = eb._process_ebtables_input(test_input)
        self.assertEqual([('filter', ['--atomic-init']),
                          ('filter', ['--atomic-commit'])],
                         res)

    def test_ebtables_input_parse_rule(self):
        test_input = "*filter\n[0:0] -A INPUT -j neutron-nwfilter-INPUT"
        res = eb._process_ebtables_input(test_input)
        self.assertEqual([('filter', ['--atomic-init']),
                          ('filter',
                           ['-A', 'INPUT', '-j', 'neutron-nwfilter-INPUT'])],
                         res)

    def test_ebtables_input_parse_chain(self):
        test_input = "*filter\n:foobar ACCEPT"
        res = eb._process_ebtables_input(test_input)
        self.assertEqual([('filter', ['--atomic-init']),
                          ('filter', ['-N', 'foobar', '-P', 'ACCEPT'])],
                         res)

    def test_ebtables_input_parse_all_together(self):
        test_input = \
            ("*filter\n"
             ":INPUT ACCEPT\n"
             ":FORWARD ACCEPT\n"
             ":OUTPUT ACCEPT\n"
             ":neutron-nwfilter-spoofing-fallb ACCEPT\n"
             ":neutron-nwfilter-OUTPUT ACCEPT\n"
             ":neutron-nwfilter-INPUT ACCEPT\n"
             ":neutron-nwfilter-FORWARD ACCEPT\n"
             "[0:0] -A INPUT -j neutron-nwfilter-INPUT\n"
             "[0:0] -A OUTPUT -j neutron-nwfilter-OUTPUT\n"
             "[0:0] -A FORWARD -j neutron-nwfilter-FORWARD\n"
             "[0:0] -A neutron-nwfilter-spoofing-fallb -j DROP\n"
             "COMMIT")
        observed_res = eb._process_ebtables_input(test_input)
        TNAME = 'filter'
        expected_res = [
            (TNAME, ['--atomic-init']),
            (TNAME, ['-P', 'INPUT', 'ACCEPT']),
            (TNAME, ['-P', 'FORWARD', 'ACCEPT']),
            (TNAME, ['-P', 'OUTPUT', 'ACCEPT']),
            (TNAME, ['-N', 'neutron-nwfilter-spoofing-fallb', '-P', 'ACCEPT']),
            (TNAME, ['-N', 'neutron-nwfilter-OUTPUT', '-P', 'ACCEPT']),
            (TNAME, ['-N', 'neutron-nwfilter-INPUT', '-P', 'ACCEPT']),
            (TNAME, ['-N', 'neutron-nwfilter-FORWARD', '-P', 'ACCEPT']),
            (TNAME, ['-A', 'INPUT', '-j', 'neutron-nwfilter-INPUT']),
            (TNAME, ['-A', 'OUTPUT', '-j', 'neutron-nwfilter-OUTPUT']),
            (TNAME, ['-A', 'FORWARD', '-j', 'neutron-nwfilter-FORWARD']),
            (TNAME, ['-A', 'neutron-nwfilter-spoofing-fallb', '-j', 'DROP']),
            (TNAME, ['--atomic-commit'])]

        self.assertEqual(expected_res, observed_res)


class EbtablesDriverLowLevelOutputTestCase(base.BaseTestCase):

    def test_ebtables_save_and_restore(self):
        test_output = ('Bridge table: filter\n'
                       'Bridge chain: INPUT, entries: 1, policy: ACCEPT\n'
                       '-j CONTINUE , pcnt = 0 -- bcnt = 0\n'
                       'Bridge chain: FORWARD, entries: 1, policy: ACCEPT\n'
                       '-j CONTINUE , pcnt = 0 -- bcnt = 1\n'
                       'Bridge chain: OUTPUT, entries: 1, policy: ACCEPT\n'
                       '-j CONTINUE , pcnt = 1 -- bcnt = 1').split('\n')

        observed_res = eb._process_ebtables_output(test_output)
        expected_res = ['*filter',
                        ':INPUT ACCEPT',
                        ':FORWARD ACCEPT',
                        ':OUTPUT ACCEPT',
                        '[0:0] -A INPUT -j CONTINUE',
                        '[0:1] -A FORWARD -j CONTINUE',
                        '[1:1] -A OUTPUT -j CONTINUE',
                        'COMMIT']
        self.assertEqual(expected_res, observed_res)


class EbtablesDriverTestCase(base.BaseTestCase):

    def setUp(self):
        super(EbtablesDriverTestCase, self).setUp()
        self.root_helper = 'sudo'
        self.ebtables_path = CONF.ebtables_path
        self.execute_p = mock.patch('neutron.agent.linux.utils.execute')
        self.execute = self.execute_p.start()

    def test_ebtables_sanity_check(self):
        self.assertTrue(ebtables_supported())
        self.execute.assert_has_calls([mock.call(['ebtables', '--version'])])

        self.execute.side_effect = RuntimeError
        self.assertFalse(ebtables_supported())
