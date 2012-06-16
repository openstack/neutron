# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2011 Cisco Systems, Inc.  All rights reserved.
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
# @author: Sumit Naiksatam, Cisco Systems, Inc.

import hashlib
import logging

from quantum.plugins.cisco.common import cisco_constants as const
from quantum.plugins.cisco.db import l2network_db as cdb


LOG = logging.getLogger(__name__)


def get16ByteUUID(uuid):
    """
    Return a 16 byte has of the UUID, used when smaller unique
    ID is required.
    """
    return hashlib.md5(uuid).hexdigest()[:16]


def make_net_dict(net_id, net_name, ports):
    """Helper funciton"""
    res = {const.NET_ID: net_id, const.NET_NAME: net_name}
    res[const.NET_PORTS] = ports
    return res


def make_port_dict(port_id, port_state, net_id, attachment):
    """Helper funciton"""
    res = {const.PORT_ID: port_id, const.PORT_STATE: port_state}
    res[const.NET_ID] = net_id
    res[const.ATTACHMENT] = attachment
    return res


def make_portprofile_dict(tenant_id, profile_id,
                          profile_name, qos):
    """Helper funciton"""
    profile_associations = make_portprofile_assc_list(tenant_id,
                                                      profile_id)
    res = {const.PROFILE_ID: str(profile_id),
           const.PROFILE_NAME: profile_name,
           const.PROFILE_ASSOCIATIONS: profile_associations,
           const.PROFILE_VLAN_ID: None,
           const.PROFILE_QOS: qos}
    return res


def make_portprofile_assc_list(tenant_id, profile_id):
    """Helper function to create port profile association list"""
    plist = cdb.get_pp_binding(tenant_id, profile_id)
    assc_list = []
    for port in plist:
        assc_list.append(port[const.PORTID])

    return assc_list
