# Copyright 2013 Cloudbase Solutions SRL
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

from oslo_config import cfg
from oslo_log import log as logging

from neutron.agent.common import config
from neutron.common import config as common_config
from neutron.i18n import _LI
from neutron.plugins.hyperv.agent import config as hyperv_config
from neutron.plugins.hyperv.agent import l2_agent

LOG = logging.getLogger(__name__)


def register_options():
    config.register_agent_state_opts_helper(cfg.CONF)
    cfg.CONF.register_opts(hyperv_config.HYPERV_AGENT_OPTS, "AGENT")


def main():
    register_options()
    common_config.init(sys.argv[1:])
    config.setup_logging()

    hyperv_agent = l2_agent.HyperVNeutronAgent()

    # Start everything.
    LOG.info(_LI("Agent initialized successfully, now running... "))
    hyperv_agent.daemon_loop()
