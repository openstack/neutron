"""
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
"""

import logging

from quantum.api.api_common import OperationalStatus
from quantum.plugins.linuxbridge.common import constants as const

LOG = logging.getLogger(__name__)


def make_net_dict(net_id, net_name, ports, op_status):
    """Helper funciton"""
    res = {const.NET_ID: net_id, const.NET_NAME: net_name, const.NET_OP_STATUS:
          op_status}
    if ports:
        res[const.NET_PORTS] = ports
    return res


def make_port_dict(port):
    """Helper funciton"""
    if port[const.PORTSTATE] == const.PORT_UP:
        op_status = port[const.OPSTATUS]
    else:
        op_status = OperationalStatus.DOWN

    return {const.PORT_ID: str(port[const.UUID]),
            const.PORT_STATE: port[const.PORTSTATE],
            const.PORT_OP_STATUS: op_status,
            const.NET_ID: port[const.NETWORKID],
            const.ATTACHMENT: port[const.INTERFACEID]}
