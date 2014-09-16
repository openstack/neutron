# Copyright 2014 Embrane, Inc.
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

from heleosapi import info as h_info

from neutron.common import constants
from neutron import manager
from neutron.plugins.embrane.l2base import support_base as base
from neutron.plugins.embrane.l2base import support_exceptions as exc


class Ml2Support(base.SupportBase):
    """Modular Layer 2 plugin support.

    Obtains the information needed to build the user security zones.

    """

    def __init__(self):
        super(Ml2Support, self).__init__()

    def retrieve_utif_info(self, context, neutron_port):
        plugin = manager.NeutronManager.get_plugin()
        network = plugin.get_network(
            context, neutron_port['network_id'])
        is_gw = (neutron_port["device_owner"] ==
                 constants.DEVICE_OWNER_ROUTER_GW)
        network_type = network.get('provider:network_type')
        if network_type != 'vlan':
            raise exc.UtifInfoError(
                err_msg=_("Network type %s not supported. Please be sure "
                          "that tenant_network_type is vlan") % network_type)
        result = h_info.UtifInfo(network.get('provider:segmentation_id'),
                                 network['name'],
                                 network['id'],
                                 is_gw,
                                 network['tenant_id'],
                                 neutron_port['id'],
                                 neutron_port['mac_address'])
        return result
