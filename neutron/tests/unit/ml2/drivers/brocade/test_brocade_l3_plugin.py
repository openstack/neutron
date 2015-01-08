# Copyright (c) 2014 OpenStack Foundation
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
#

import mock
from oslo_config import cfg
from oslo_context import context as oslo_context
from oslo_utils import importutils

from neutron.db import api as db
from neutron.openstack.common import log as logging
from neutron.tests.unit import test_l3_plugin

LOG = logging.getLogger(__name__)
L3_SVC_PLUGIN = ('neutron.services.l3_router.'
                 'brocade.l3_router_plugin.BrocadeSVIPlugin')


class BrocadeSVIPlugin_TestCases(test_l3_plugin.TestL3NatBasePlugin):

    def setUp(self):

        def mocked_brocade_init(self):
            LOG.debug("brocadeSVIPlugin::mocked_brocade_init()")

            self._switch = {'address': cfg.CONF.ml2_brocade.address,
                            'username': cfg.CONF.ml2_brocade.username,
                            'password': cfg.CONF.ml2_brocade.password,
                            'rbridge_id': cfg.CONF.ml2_brocade.rbridge_id
                            }
            LOG.info(_("rbridge id %s"), self._switch['rbridge_id'])
            self._driver = mock.MagicMock()

        self.l3_plugin = importutils.import_object(L3_SVC_PLUGIN)
        with mock.patch.object(self.l3_plugin,
                               'brocade_init', new=mocked_brocade_init):
            super(BrocadeSVIPlugin_TestCases, self).setUp()
        self.context = oslo_context.get_admin_context()
        self.context.session = db.get_session()


class TestBrocadeSVINatBase(test_l3_plugin.L3NatExtensionTestCase,
                            BrocadeSVIPlugin_TestCases):
    pass
