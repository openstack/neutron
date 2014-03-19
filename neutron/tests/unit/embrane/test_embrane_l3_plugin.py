# vim:  tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 Embrane, Inc.
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
# @author:  Ivar Lazzaro, Embrane, Inc.

import sys

import mock
from oslo.config import cfg

from neutron.db import api as db
from neutron.plugins.embrane.common import config  # noqa
from neutron.tests.unit import test_extension_extraroute as extraroute_test
from neutron.tests.unit import test_l3_plugin as router_test

PLUGIN_NAME = ('neutron.plugins.embrane.plugins.embrane_fake_plugin.'
               'EmbraneFakePlugin')
sys.modules["heleosapi"] = mock.Mock()


class TestEmbraneL3NatDBTestCase(router_test.L3NatDBIntTestCase):
    _plugin_name = PLUGIN_NAME

    def setUp(self):
        cfg.CONF.set_override('admin_password', "admin123", 'heleos')
        self.addCleanup(db.clear_db)
        super(TestEmbraneL3NatDBTestCase, self).setUp()


class ExtraRouteDBTestCase(extraroute_test.ExtraRouteDBIntTestCase):
    _plugin_name = PLUGIN_NAME
