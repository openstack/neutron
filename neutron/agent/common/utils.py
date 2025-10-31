# Copyright 2015 Cloudbase Solutions.
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

import socket

from neutron_lib.utils import runtime
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import timeutils

from neutron.agent.linux import utils
from neutron.conf.agent import common as config
from neutron.conf.agent.database import agents_db


LOG = logging.getLogger(__name__)
config.register_root_helper(cfg.CONF)
agents_db.register_db_agents_opts()

INTERFACE_NAMESPACE = 'neutron.interface_drivers'


create_process = utils.create_process
kill_process = utils.kill_process
execute = utils.execute
get_root_helper_child_pid = utils.get_root_helper_child_pid
pid_invoked_with_cmdline = utils.pid_invoked_with_cmdline


def load_interface_driver(conf, get_networks_callback=None):
    """Load interface driver for agents like DHCP or L3 agent.

    :param conf: Driver configuration object
    :param get_networks_callback: A callback to get network information.
                                  This will be passed as additional keyword
                                  argument to the interface driver.
    :raises SystemExit of 1 if driver cannot be loaded
    """

    try:
        loaded_class = runtime.load_class_by_alias_or_classname(
            INTERFACE_NAMESPACE, conf.interface_driver)
        return loaded_class(conf, get_networks_callback=get_networks_callback)
    except ImportError:
        LOG.error("Error loading interface driver '%s'",
                  conf.interface_driver)
        raise SystemExit(1)


def is_agent_down(heart_beat_time):
    return timeutils.is_older_than(heart_beat_time,
                                   cfg.CONF.agent_down_time)


def get_hypervisor_hostname():
    """Get hypervisor hostname

    This logic is implemented following the logic of virGetHostnameImpl
    in libvirt.
    """
    hypervisor_hostname = socket.gethostname()
    if (hypervisor_hostname.startswith('localhost') or
            '.' in hypervisor_hostname):
        return hypervisor_hostname

    try:
        addrinfo = socket.getaddrinfo(host=hypervisor_hostname,
                                      port=None,
                                      family=socket.AF_UNSPEC,
                                      flags=socket.AI_CANONNAME)
        # getaddrinfo returns a list of 5-tuples with;
        #     (family, type, proto, canonname, sockaddr)
        if (addrinfo and addrinfo[0][3] and
                not addrinfo[0][3].startswith('localhost')):
            return addrinfo[0][3]
    except OSError as os_err:
        LOG.warning("Error: %s, occured while querying for fqdn. "
                    "get_hypervisor_hostname will just "
                    "return %s", os_err, hypervisor_hostname)

    return hypervisor_hostname


# TODO(bence romsics): rehome this to neutron_lib.placement.utils
def default_rp_hypervisors(hypervisors, device_mappings,
                           default_hypervisor=None,
                           tunnelled_network_rp_name=None):
    """Fill config option 'resource_provider_hypervisors' with defaults.

    :param hypervisors: Config option 'resource_provider_hypervisors'
        as parsed by oslo.config, that is a dict with keys of physical devices
        and values of hypervisor names.
    :param device_mappings: Device mappings standardized to the list-valued
        format.
    :param default_hypervisor: Default hypervisor hostname. If not set,
        it tries to default to fully qualified domain name (fqdn)
    :param tunnelled_network_rp_name: the resource provider name for tunnelled
        networks; if present, it will be added to the devices list.
    """
    _default_hypervisor = default_hypervisor or get_hypervisor_hostname()
    # device_mappings = {'physnet1': ['br-phy1'], 'physnet2': ['br-phy2'], ...}
    devices = {dev for devs in device_mappings.values() for dev in devs}
    if tunnelled_network_rp_name:
        devices.add(tunnelled_network_rp_name)
    return {device: hypervisors.get(device) or _default_hypervisor
            for device in devices}
