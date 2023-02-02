# Copyright (c) 2023 Red Hat, Inc.
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

from neutron.common import config
from neutron.common import utils
from oslo_config import cfg
from oslo_log import log as logging
from oslo_service import service

from neutron.agent.ovn.agent import ovn_neutron_agent
from neutron.conf.agent.ovn.ovn_neutron_agent import config as config_ovn_agent


LOG = logging.getLogger(__name__)


def main():
    config.register_common_config_options()
    config_ovn_agent.register_opts()
    config.init(sys.argv[1:])
    config.setup_logging()
    utils.log_opt_values(LOG)
    config_ovn_agent.setup_privsep()

    ovn_agent = ovn_neutron_agent.OVNNeutronAgent(cfg.CONF)

    LOG.info('OVN Neutron Agent initialized successfully, now running... ')
    launcher = service.launch(cfg.CONF, ovn_agent, restart_method='mutate')
    launcher.wait()
