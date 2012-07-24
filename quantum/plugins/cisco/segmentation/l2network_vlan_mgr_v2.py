# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2012 Cisco Systems, Inc.  All rights reserved.
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
#

import logging

from quantum.plugins.cisco.common import cisco_constants as const
from quantum.plugins.cisco.db import network_db_v2 as cdb
from quantum.plugins.cisco import l2network_plugin_configuration as conf
from quantum.plugins.cisco.l2network_segmentation_base import (
    L2NetworkSegmentationMgrBase,
)


LOG = logging.getLogger(__name__)


class L2NetworkVLANMgr(L2NetworkSegmentationMgrBase):
    """
    VLAN Manager which gets VLAN ID from DB
    """
    def __init__(self):
        cdb.create_vlanids()

    def reserve_segmentation_id(self, tenant_id, net_name, **kwargs):
        """Get an available VLAN ID"""
        return cdb.reserve_vlanid()

    def release_segmentation_id(self, tenant_id, net_id, **kwargs):
        """Release the ID"""
        vlan_binding = cdb.get_vlan_binding(net_id)
        return cdb.release_vlanid(vlan_binding[const.VLANID])

    def get_vlan_name(self, net_id, vlan):
        """Getting the vlan name from the tenant and vlan"""
        vlan_name = conf.VLAN_NAME_PREFIX + vlan
        return vlan_name
