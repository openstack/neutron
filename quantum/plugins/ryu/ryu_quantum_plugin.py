# vim: tabstop=4 shiftwidth=4 softtabstop=4
# Copyright 2012 Isaku Yamahata <yamahata at private email ne jp>
#                               <yamahata at valinux co jp>
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
# @author: Isaku Yamahata

import logging
import os

from ryu.app import client
from ryu.app import rest_nw_id

from quantum.common import exceptions as q_exc
from quantum.common.utils import find_config_file
from quantum.db import api as db
from quantum.db import db_base_plugin_v2
from quantum.db import models_v2
from quantum.plugins.ryu.db import api as db_api
from quantum.plugins.ryu.db import api_v2 as db_api_v2
from quantum.plugins.ryu import ofp_service_type
from quantum.plugins.ryu import ovs_quantum_plugin_base
from quantum.plugins.ryu.common import config

LOG = logging.getLogger(__name__)


class OFPRyuDriver(ovs_quantum_plugin_base.OVSQuantumPluginDriverBase):
    def __init__(self, conf):
        super(OFPRyuDriver, self).__init__()
        ofp_con_host = conf.OVS.openflow_controller
        ofp_api_host = conf.OVS.openflow_rest_api

        if ofp_con_host is None or ofp_api_host is None:
            raise q_exc.Invalid("invalid configuration. check ryu.ini")

        hosts = [(ofp_con_host, ofp_service_type.CONTROLLER),
                 (ofp_api_host, ofp_service_type.REST_API)]
        db_api.set_ofp_servers(hosts)

        self.client = client.OFPClient(ofp_api_host)
        self.client.update_network(rest_nw_id.NW_ID_EXTERNAL)

        # register known all network list on startup
        self._create_all_tenant_network()

    def _create_all_tenant_network(self):
        networks = db.network_all_tenant_list()
        for net in networks:
            self.client.update_network(net.uuid)

    def create_network(self, net):
        self.client.create_network(net.uuid)

    def delete_network(self, net):
        self.client.delete_network(net.uuid)


class RyuQuantumPlugin(ovs_quantum_plugin_base.OVSQuantumPluginBase):
    def __init__(self, configfile=None):
        super(RyuQuantumPlugin, self).__init__(__file__, configfile)
        self.driver = OFPRyuDriver(self.conf)


class RyuQuantumPluginV2(db_base_plugin_v2.QuantumDbPluginV2):
    def __init__(self, configfile=None):
        options = {"sql_connection": cfg.CONF.DATABASE.sql_connection}
        options.update({'base': models_v2.model_base.BASEV2})
        reconnect_interval = cfg.CONF.DATABASE.reconnect_interval
        options.update({"reconnect_interval": reconnect_interval})
        db.configure_db(options)

        ofp_con_host = cfg.CONF.OVS.openflow_controller
        ofp_api_host = cfg.CONF.OVS.openflow_rest_api

        if ofp_con_host is None or ofp_api_host is None:
            raise q_exc.Invalid("invalid configuration. check ryu.ini")

        hosts = [(ofp_con_host, ofp_service_type.CONTROLLER),
                 (ofp_api_host, ofp_service_type.REST_API)]
        db_api_v2.set_ofp_servers(hosts)

        self.client = client.OFPClient(ofp_api_host)
        self.client.update_network(rest_nw_id.NW_ID_EXTERNAL)

        # register known all network list on startup
        self._create_all_tenant_network()

    def _create_all_tenant_network(self):
        networks = db_api_v2.network_all_tenant_list()
        for net in networks:
            self.client.update_network(net.id)

    def create_network(self, context, network):
        net = super(RyuQuantumPluginV2, self).create_network(context, network)
        self.client.create_network(net['id'])
        return net

    def delete_network(self, context, id):
        self.client.delete_network(id)
        return super(RyuQuantumPluginV2, self).delete_network(context, id)
