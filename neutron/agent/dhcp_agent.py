# Copyright 2015 OpenStack Foundation
#
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

import sys

from neutron_lib.agent import topics
from oslo_config import cfg
from oslo_service import service

from neutron.common import config as common_config
from neutron.conf.agent import common as config
from neutron.conf.agent import dhcp as dhcp_config
from neutron.conf.agent.metadata import config as meta_conf
from neutron.conf.plugins.ml2.drivers import ovs_conf
from neutron import service as neutron_service


def register_options(conf):
    config.register_interface_driver_opts_helper(conf)
    config.register_agent_state_opts_helper(conf)
    config.register_availability_zone_opts_helper(conf)
    dhcp_config.register_agent_dhcp_opts(conf)
    meta_conf.register_meta_conf_opts(meta_conf.SHARED_OPTS, conf)
    config.register_interface_opts(conf)
    config.register_root_helper(conf)
    ovs_conf.register_ovs_opts(conf)


def main():
    register_options(cfg.CONF)
    common_config.init(sys.argv[1:])
    config.setup_logging()
    config.setup_privsep()
    server = neutron_service.Service.create(
        binary='neutron-dhcp-agent',
        topic=topics.DHCP_AGENT,
        report_interval=cfg.CONF.AGENT.report_interval,
        manager='neutron.agent.dhcp.agent.DhcpAgentWithStateReport')
    service.launch(cfg.CONF, server, restart_method='mutate').wait()
