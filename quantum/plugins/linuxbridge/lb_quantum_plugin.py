# Copyright (c) 2012 OpenStack, LLC.
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

import logging

from quantum.db import db_base_plugin_v2
from quantum.db import models_v2
from quantum.plugins.linuxbridge.db import l2network_db as cdb

LOG = logging.getLogger(__name__)


class LinuxBridgePluginV2(db_base_plugin_v2.QuantumDbPluginV2):
    """
    LinuxBridgePlugin provides support for Quantum abstractions
    using LinuxBridge. A new VLAN is created for each network.
    It relies on an agent to perform the actual bridge configuration
    on each host.
    """

    def __init__(self):
        cdb.initialize(base=models_v2.model_base.BASEV2)
        LOG.debug("Linux Bridge Plugin initialization complete")

    def create_network(self, context, network):
        new_network = super(LinuxBridgePluginV2, self).create_network(context,
                                                                      network)
        try:
            vlan_id = cdb.reserve_vlanid()
            cdb.add_vlan_binding(vlan_id, new_network['id'])
        except:
            super(LinuxBridgePluginV2, self).delete_network(context,
                                                            new_network['id'])
            raise

        return new_network

    def delete_network(self, context, id):
        vlan_binding = cdb.get_vlan_binding(id)
        cdb.release_vlanid(vlan_binding['vlan_id'])
        cdb.remove_vlan_binding(id)
        return super(LinuxBridgePluginV2, self).delete_network(context, id)
