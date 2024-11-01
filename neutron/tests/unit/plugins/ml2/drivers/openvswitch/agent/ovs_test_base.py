# Copyright (C) 2014,2015 VA Linux Systems Japan K.K.
# Copyright (C) 2014 Fumihiko Kakuma <kakuma at valinux co jp>
# Copyright (C) 2014,2015 YAMAMOTO Takashi <yamamoto at valinux co jp>
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

import functools
from unittest import mock

from oslo_utils import importutils

from neutron.tests import base
from neutron.tests.unit.plugins.ml2.drivers.openvswitch.agent \
    import fake_oflib


_AGENT_PACKAGE = 'neutron.plugins.ml2.drivers.openvswitch.agent'
_AGENT_NAME = _AGENT_PACKAGE + '.ovs_neutron_agent'
_DVR_AGENT_NAME = ('neutron.plugins.ml2.drivers.openvswitch.agent.'
                   'ovs_dvr_neutron_agent')


class OVSAgentConfigTestBase(base.BaseTestCase):
    def setUp(self):
        super().setUp()
        self.mod_agent = importutils.import_module(_AGENT_NAME)
        self.mod_dvr_agent = importutils.import_module(_DVR_AGENT_NAME)


class OVSOSKenTestBase(OVSAgentConfigTestBase):

    _DRIVER_PACKAGE = _AGENT_PACKAGE + '.openflow.native'
    _BR_INT_CLASS = _DRIVER_PACKAGE + '.br_int.OVSIntegrationBridge'
    _BR_TUN_CLASS = _DRIVER_PACKAGE + '.br_tun.OVSTunnelBridge'
    _BR_PHYS_CLASS = _DRIVER_PACKAGE + '.br_phys.OVSPhysicalBridge'

    def setUp(self):
        self.fake_oflib_of = fake_oflib.patch_fake_oflib_of()
        self.fake_oflib_of.start()
        self.addCleanup(self.fake_oflib_of.stop)
        super().setUp()
        conn_patcher = mock.patch(
            'neutron.agent.ovsdb.impl_idl._connection')
        conn_patcher.start()
        self.addCleanup(conn_patcher.stop)
        self.br_int_cls = importutils.import_class(self._BR_INT_CLASS)
        self.br_phys_cls = importutils.import_class(self._BR_PHYS_CLASS)
        self.br_tun_cls = importutils.import_class(self._BR_TUN_CLASS)
        os_ken_app = mock.Mock()
        self.br_int_cls = functools.partial(self.br_int_cls,
                                            os_ken_app=os_ken_app)
        self.br_phys_cls = functools.partial(self.br_phys_cls,
                                             os_ken_app=os_ken_app)
        self.br_tun_cls = functools.partial(self.br_tun_cls,
                                            os_ken_app=os_ken_app)

    def _bridge_classes(self):
        return {
            'br_int': self.br_int_cls,
            'br_phys': self.br_phys_cls,
            'br_tun': self.br_tun_cls,
        }
