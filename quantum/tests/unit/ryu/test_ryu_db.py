# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2012 Isaku Yamahata <yamahata at private email ne jp>
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

import os
import unittest2

from quantum.db import api as db
from quantum.db import models_v2
from quantum.openstack.common import cfg
from quantum.plugins.ryu.common import config
from quantum.plugins.ryu.db import api_v2 as db_api_v2
from quantum.plugins.ryu.db import models_v2 as ryu_models_v2
from quantum.plugins.ryu import ofp_service_type


class RyuDBTest(unittest2.TestCase):
    def setUp(self):
        options = {"sql_connection": 'sqlite:///:memory:'}
        options.update({'base': models_v2.model_base.BASEV2})
        reconnect_interval = cfg.CONF.DATABASE.reconnect_interval
        options.update({"reconnect_interval": reconnect_interval})
        db.configure_db(options)

        self.hosts = [(cfg.CONF.OVS.openflow_controller,
                       ofp_service_type.CONTROLLER),
                      (cfg.CONF.OVS.openflow_rest_api,
                       ofp_service_type.REST_API)]
        db_api_v2.set_ofp_servers(self.hosts)

    def tearDown(self):
        db.clear_db()
        cfg.CONF.reset()

    def test_ofp_server(self):
        session = db.get_session()
        servers = session.query(ryu_models_v2.OFPServer).all()
        print servers
        self.assertEqual(len(servers), 2)
        for s in servers:
            self.assertTrue((s.address, s.host_type) in self.hosts)
