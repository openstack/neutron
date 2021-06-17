# (c) Copyright 2016 Hewlett Packard Enterprise Development LP
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from neutron_lib.api import extensions
from neutron_lib.plugins import directory
from neutron_lib.utils import runtime
from oslo_config import cfg


def get_agent_types_by_host(context, host):
    """Return the agent types registered on the host."""
    agent_types = []
    core_plugin = directory.get_plugin()
    if extensions.is_extension_supported(core_plugin, 'agent'):
        agents = core_plugin.get_agents(
            context.elevated(), filters={'host': [host]})
        agent_types = [a['agent_type'] for a in agents]
    return agent_types


def is_driver_compatible(context, driver, interface, host_agent_types):
    """True if the driver is compatible with interface and host_agent_types.

    There may be edge cases where a stale view or the deployment may make the
    following test fail to detect the right driver in charge of the bound port.
    """

    # NOTE(armax): this logic stems from the fact that the way Neutron is
    # architected we do not have a univocal mapping between VIF type and the
    # Driver serving it, in that the same vif type can be supported by
    # multiple drivers. A practical example of this is OVS and OVN in the
    # same deployment. In order to uniquely identify the driver, we cannot
    # simply look at the vif type, and we need to look at whether the host
    # to which the port is bound is actually managed by one driver or the
    # other.
    is_interface_compatible = driver.is_interface_compatible(interface)

    # For an agentless driver, only interface compatibility is required.
    if not driver.agent_type:
        return is_interface_compatible

    # For an agent-based driver, both interface and agent compat is required.
    return is_interface_compatible and driver.agent_type in host_agent_types


def is_trunk_service_loaded():
    for service_plugins in cfg.CONF.service_plugins:
        try:
            klass = runtime.load_class_by_alias_or_classname(
                'neutron.service_plugins', service_plugins)
            if klass.__name__ == 'TrunkPlugin':
                return True
        except ImportError:
            continue
    return False
