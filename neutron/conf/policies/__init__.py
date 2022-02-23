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

import importlib
import inspect
import itertools

from neutron.conf.policies import address_group
from neutron.conf.policies import address_scope
from neutron.conf.policies import agent
from neutron.conf.policies import auto_allocated_topology
from neutron.conf.policies import availability_zone
from neutron.conf.policies import base
from neutron.conf.policies import flavor
from neutron.conf.policies import floatingip
from neutron.conf.policies import floatingip_pools
from neutron.conf.policies import floatingip_port_forwarding
from neutron.conf.policies import l3_conntrack_helper
from neutron.conf.policies import local_ip
from neutron.conf.policies import local_ip_association
from neutron.conf.policies import logging
from neutron.conf.policies import metering
from neutron.conf.policies import ndp_proxy
from neutron.conf.policies import network
from neutron.conf.policies import network_ip_availability
from neutron.conf.policies import network_segment_range
from neutron.conf.policies import port
from neutron.conf.policies import qos
from neutron.conf.policies import quotas
from neutron.conf.policies import rbac
from neutron.conf.policies import router
from neutron.conf.policies import security_group
from neutron.conf.policies import segment
from neutron.conf.policies import service_type
from neutron.conf.policies import subnet
from neutron.conf.policies import subnetpool
from neutron.conf.policies import trunk


def list_rules():
    return itertools.chain(
        base.list_rules(),
        address_group.list_rules(),
        address_scope.list_rules(),
        agent.list_rules(),
        auto_allocated_topology.list_rules(),
        availability_zone.list_rules(),
        flavor.list_rules(),
        floatingip.list_rules(),
        floatingip_pools.list_rules(),
        floatingip_port_forwarding.list_rules(),
        l3_conntrack_helper.list_rules(),
        local_ip.list_rules(),
        local_ip_association.list_rules(),
        logging.list_rules(),
        metering.list_rules(),
        ndp_proxy.list_rules(),
        network.list_rules(),
        network_ip_availability.list_rules(),
        network_segment_range.list_rules(),
        port.list_rules(),
        qos.list_rules(),
        quotas.list_rules(),
        rbac.list_rules(),
        router.list_rules(),
        security_group.list_rules(),
        segment.list_rules(),
        service_type.list_rules(),
        subnet.list_rules(),
        subnetpool.list_rules(),
        trunk.list_rules(),
    )


def reload_default_policies():
    for name, module in globals().items():
        if (inspect.ismodule(module) and
                module.__name__.startswith(__package__)):
            # NOTE: pylint checks function args wrongly.
            # pylint: disable=too-many-function-args
            importlib.reload(module)
