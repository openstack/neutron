# vim: tabstop=4 shiftwidth=4 softtabstop=4

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
# @author: Ivar Lazzaro, Embrane, Inc.

from heleosapi import info as h_info

from neutron.common import constants
from neutron import manager
from neutron.plugins.embrane.l2base import support_base as base
from neutron.plugins.embrane.l2base import support_exceptions as exc
from neutron.plugins.openvswitch import ovs_db_v2


class OpenvswitchSupport(base.SupportBase):
    """OpenVSwitch plugin support.

    Obtains the informations needed to build the user security zones

    """

    def __init__(self):
        super(OpenvswitchSupport, self).__init__()

    def retrieve_utif_info(self, context, neutron_port):
        plugin = manager.NeutronManager.get_plugin()
        session = context.session
        network_id = neutron_port["network_id"]
        network_binding = ovs_db_v2.get_network_binding(session, network_id)
        if not network_binding["segmentation_id"]:
            raise exc.UtifInfoError(
                err_msg=_("No segmentation_id found for the network, "
                          "please be sure that tenant_network_type is vlan"))
        network = plugin._get_network(context, network_id)
        is_gw = (neutron_port["device_owner"] ==
                 constants.DEVICE_OWNER_ROUTER_GW)
        result = h_info.UtifInfo(vlan=network_binding["segmentation_id"],
                                 network_name=network["name"],
                                 network_id=network["id"],
                                 is_gw=is_gw,
                                 owner_tenant=network["tenant_id"],
                                 port_id=neutron_port["id"],
                                 mac_address=neutron_port["mac_address"])
        return result
