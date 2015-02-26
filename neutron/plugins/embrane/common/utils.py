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

from heleosapi import info as h_info
from oslo_log import log as logging

from neutron.common import constants
from neutron.db import models_v2
from neutron.i18n import _LI

LOG = logging.getLogger(__name__)


def set_db_item_state(context, neutron_item, new_state):
    with context.session.begin(subtransactions=True):
        if neutron_item["status"] != new_state:
            neutron_item["status"] = new_state
            context.session.merge(neutron_item)


def retrieve_subnet(context, subnet_id):
    return (context.session.query(
        models_v2.Subnet).filter(models_v2.Subnet.id == subnet_id).one())


def retrieve_ip_allocation_info(context, neutron_port):
    """Retrieves ip allocation info for a specific port if any."""

    try:
        subnet_id = neutron_port["fixed_ips"][0]["subnet_id"]
    except (KeyError, IndexError):
        LOG.info(_LI("No ip allocation set"))
        return
    subnet = retrieve_subnet(context, subnet_id)
    allocated_ip = neutron_port["fixed_ips"][0]["ip_address"]
    is_gw_port = (neutron_port["device_owner"] ==
                  constants.DEVICE_OWNER_ROUTER_GW)
    gateway_ip = subnet["gateway_ip"]

    ip_allocation_info = h_info.IpAllocationInfo(
        is_gw=is_gw_port,
        ip_version=subnet["ip_version"],
        prefix=subnet["cidr"].split("/")[1],
        ip_address=allocated_ip,
        port_id=neutron_port["id"],
        gateway_ip=gateway_ip)

    return ip_allocation_info


def retrieve_nat_info(context, fip, fixed_prefix, floating_prefix, router):
    nat_info = h_info.NatInfo(source_address=fip["floating_ip_address"],
                              source_prefix=floating_prefix,
                              destination_address=fip["fixed_ip_address"],
                              destination_prefix=fixed_prefix,
                              floating_ip_id=fip["id"],
                              fixed_port_id=fip["port_id"])
    return nat_info
