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

from neutron.agent.linux import ebtables_manager as em

from neutron.tests import base

LONG_NAME = "1234567890" * 3


class EbtablesManagerBaseTestCase(base.BaseTestCase):
    def setUp(self):
        super(EbtablesManagerBaseTestCase, self).setUp()
        mock.patch.object(em, "binary_name", return_value="binary").start()


class EbtablesChainNameTestCase(EbtablesManagerBaseTestCase):

    def test_get_prefix_chain(self):
        # Fake the binary name to a known value for this test.
        # Testing prefix chain name
        self.assertEqual(em._get_prefix_chain(), "binary")
        self.assertEqual(em._get_prefix_chain("some-name"),
                         "some-name")
        self.assertEqual(em._get_prefix_chain(LONG_NAME),
                         LONG_NAME[:em.MAX_LEN_PREFIX_CHAIN])

    def test_get_chain_name(self):
        # Testing full chain name
        prefix_chain = "some-other-name"
        self.assertEqual(em.get_chain_name(chain_name="foobar",
                                           prefix_chain=prefix_chain),
                         "foobar")

        is_name = em.get_chain_name(chain_name=LONG_NAME,
                                    wrap=True,
                                    prefix_chain=prefix_chain)
        should_name = (LONG_NAME[:em.MAX_CHAIN_LEN_EBTABLES -
                                 len(prefix_chain) - 1])
        self.assertEqual(is_name, should_name)
        self.assertEqual(em.get_chain_name(chain_name=LONG_NAME,
                                           wrap=False,
                                           prefix_chain=prefix_chain),
                         LONG_NAME)
        should_name = LONG_NAME[:-len("bar")]
        self.assertEqual(em.get_chain_name(chain_name=LONG_NAME,
                                           wrap=True,
                                           prefix_chain="bar"),
                         should_name)
        self.assertEqual(em.get_chain_name(chain_name=LONG_NAME,
                                           wrap=False,
                                           prefix_chain="bar"),
                         LONG_NAME)


class EbtablesRuleTestCase(EbtablesManagerBaseTestCase):

    def test_basic_ops(self):
        r1 = em.EbtablesRule("chain-name", "some-rule", wrap=True, top=False,
                             prefix_chain="foobar")
        r2 = em.EbtablesRule("chain-name", "some-rule", wrap=True, top=False,
                             prefix_chain="foobar")
        r3 = em.EbtablesRule("chain-name", "some-rule", wrap=True, top=True,
                             prefix_chain="foobar")
        self.assertEqual(r1, r2)
        self.assertNotEqual(r1, r3)

        self.assertEqual("-A foobar-chain-name some-rule", str(r1))


class EbtablesTableTestCase(EbtablesManagerBaseTestCase):

    def setUp(self):
        super(EbtablesTableTestCase, self).setUp()
        self.et = em.EbtablesTable()

    def test_add_chain(self):
        # Wrapped and un-wrapped chains are maintained separately, thus same
        # name is possible.
        self.et.add_chain("bar" + LONG_NAME, wrap=False)
        self.et.add_chain("baz" + LONG_NAME, wrap=False)
        self.et.add_chain("baz" + LONG_NAME)
        self.et.add_chain("foo" + LONG_NAME)

        self.assertEqual(set(['baz123456789012345678901',
                              'foo123456789012345678901']),
                         self.et._select_chain_set(wrap=True))
        self.assertEqual(set(['bar1234567890123456789012345678',
                              'baz1234567890123456789012345678']),
                         self.et._select_chain_set(wrap=False))

    def test_add_remove_rule(self):
        # Adding some rules to a chain
        self.et.add_chain("foobar")
        self.et.add_rule("foobar", "some rule text")
        self.assertEqual("-A binary-foobar some rule text",
                         str(self.et.rules[0]))
        self.assertEqual(1, len(self.et.rules))

        self.et.add_rule("foobar", "another rule")
        self.assertEqual(2, len(self.et.rules))
        self.assertEqual("-A binary-foobar some rule text",
                         str(self.et.rules[0]))
        self.assertEqual("-A binary-foobar another rule",
                         str(self.et.rules[1]))

        # Removing one of the rules, testing the state of the remaining rule
        # list.
        self.et.remove_rule("foobar", "some rule text")
        self.assertEqual(1, len(self.et.rules))
        self.assertEqual("-A binary-foobar another rule",
                         str(self.et.rules[0]))

        # Testing emptying of a chain
        self.et.add_rule("foobar", "yet another rule")
        self.assertEqual(2, len(self.et.rules))
        self.et.empty_chain("foobar")
        self.assertEqual(0, len(self.et.rules))

    def test_remove_chain(self):
        self.et.add_chain("foobar")
        self.et.add_rule("foobar", "some rule text")
        self.et.add_rule("foobar", "yet another rule")
        self.et.ensure_remove_chain("foobar")
        self.assertEqual(0, len(self.et.rules))
        self.assertEqual(0, len(self.et.chains))

        # Testing the 'cascading' remove: If rules of chain A point to chain B
        # and chain B is removed then those rules of chain A also need to be
        # removed.
        self.et.add_chain("chain-A")
        self.et.add_rule("chain-A", "some rule text")
        self.et.add_chain("chain-B")
        self.et.add_rule("chain-B", "another rule")
        # Now add the rule to chain-A with chain-B as jump target
        self.et.add_rule("chain-A", "jumpyjump -j binary-chain-B")
        self.assertEqual(2, len(self.et.chains))
        self.assertEqual(3, len(self.et.rules))
        # Remove chain-B, making the jump rule in chain-A invalid. This should
        # trigger the cascading deletion of the rules.
        self.et.ensure_remove_chain("chain-B")
        self.assertEqual(1, len(self.et.chains))
        self.assertEqual(1, len(self.et.rules))
        self.assertEqual("-A binary-chain-A some rule text",
                         str(self.et.rules[0]))
