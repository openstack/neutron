# Copyright 2019 Red Hat, Inc.
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

import mock
from oslo_config import cfg

from neutron.tests import base
from neutron.tests.functional import base as functional_base


NEW_CONFIG_GROUP = cfg.OptGroup('testgroup',
                                title='Test wrapping cfg register')
SOME_OPTIONS = [
    cfg.StrOpt('str_opt', default='default_value'),
    cfg.StrOpt('int_opt', default=1),
    cfg.BoolOpt('bool_opt', default=True)
]


def register_some_options(cfg=cfg.CONF):
    cfg.register_opts(SOME_OPTIONS, 'testgroup')


class ConfigDecoratorTestCase(base.BaseTestCase):

    def setUp(self):
        super(ConfigDecoratorTestCase, self).setUp()
        cfg.CONF.register_group(NEW_CONFIG_GROUP)

    def test_no_config_decorator(self):
        register_some_options()
        self.assertEqual('default_value', cfg.CONF.testgroup.str_opt)
        self.assertEqual('1', cfg.CONF.testgroup.int_opt)
        self.assertTrue(cfg.CONF.testgroup.bool_opt)

    def test_override_variables(self):
        opts = [('str_opt', 'another_value', 'testgroup'),
                ('int_opt', 123, 'testgroup'),
                ('bool_opt', False, 'testgroup')]
        cfg_decorator = functional_base.config_decorator(register_some_options,
                                                         opts)
        mock.patch('neutron.tests.unit.tests.functional.test_base.'
                   'register_some_options', new=cfg_decorator).start()
        register_some_options()
        self.assertEqual('another_value', cfg.CONF.testgroup.str_opt)
        self.assertEqual('123', cfg.CONF.testgroup.int_opt)
        self.assertFalse(cfg.CONF.testgroup.bool_opt)
