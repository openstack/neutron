# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2013 New Dream Network, LLC (DreamHost)
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

# @author Mark McClain (DreamHost)

import mock
from oslo.config import cfg

from neutron.common import legacy
from neutron.tests import base


class TestLegacyScrubPath(base.BaseTestCase):
    def test_neutron_path(self):
        self.assertEqual(
            'neutron.foo.NeutronPlugin',
            legacy.scrub_class_path('neutron.foo.NeutronPlugin')
        )

    def test_quantum_path(self):
        with mock.patch.object(legacy, 'LOG') as log:
            self.assertEqual(
                'neutron.foo.NeutronPlugin',
                legacy.scrub_class_path('quantum.foo.QuantumPlugin')
            )

            log.assert_has_calls([mock.call.warn(mock.ANY, mock.ANY)])

    def test_third_party_path(self):
        self.assertEqual(
            'third.party.quantum.QuantumPlugin',
            legacy.scrub_class_path('third.party.quantum.QuantumPlugin')
        )


class TestLegacyConfigOverride(base.BaseTestCase):
    def setUp(self):
        super(TestLegacyConfigOverride, self).setUp()
        self.cfg = cfg.ConfigOpts()
        self.cfg.register_cli_opts([cfg.StrOpt('foo'), cfg.ListOpt('thelist')])
        self.cfg.register_cli_opts([cfg.StrOpt('baz')], group='bar')

    def test_override_config_simple_key(self):
        self.cfg(args=['--foo=quantum'])
        legacy.override_config(self.cfg, ['foo'])
        self.assertEqual(self.cfg.foo, 'neutron')

    def test_override_config_simple_key_unchanged(self):
        self.cfg(args=['--foo=something.else'])
        legacy.override_config(self.cfg, ['foo'])
        self.assertEqual(self.cfg.foo, 'something.else')

    def test_override_config_missing_key(self):
        self.cfg(args=[])
        legacy.override_config(self.cfg, ['foo'])
        self.assertIsNone(self.cfg.foo)

    def test_override_config_group_key(self):
        self.cfg(args=['--bar-baz=quantum'])
        legacy.override_config(self.cfg, [('bar', 'baz', 'mod')])
        self.assertEqual(self.cfg.bar.baz, 'neutron')

    def test_override_config_list_value(self):
        self.cfg(args=['--thelist=quantum,neutron,quantum.Quantum'])
        legacy.override_config(self.cfg, ['thelist'])
        self.assertEqual(
            self.cfg.thelist,
            ['neutron', 'neutron', 'neutron.Neutron']
        )
