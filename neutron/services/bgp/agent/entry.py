# Copyright 2016 Huawei Technologies India Pvt. Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import sys

from oslo_config import cfg
from oslo_service import service

from neutron.agent.common import config
from neutron.agent.linux import external_process
from neutron.common import config as common_config
from neutron import service as neutron_service
from neutron.services.bgp.agent import config as bgp_dragent_config
from neutron.services.bgp.common import constants as bgp_consts


def register_options():
    config.register_agent_state_opts_helper(cfg.CONF)
    config.register_root_helper(cfg.CONF)
    cfg.CONF.register_opts(bgp_dragent_config.BGP_DRIVER_OPTS, 'BGP')
    cfg.CONF.register_opts(bgp_dragent_config.BGP_PROTO_CONFIG_OPTS, 'BGP')
    cfg.CONF.register_opts(external_process.OPTS)


def main():
    register_options()
    common_config.init(sys.argv[1:])
    config.setup_logging()
    server = neutron_service.Service.create(
        binary='neutron-bgp-dragent',
        topic=bgp_consts.BGP_DRAGENT,
        report_interval=cfg.CONF.AGENT.report_interval,
        manager='neutron.services.bgp.agent.bgp_dragent.'
                'BgpDrAgentWithStateReport')
    service.launch(cfg.CONF, server).wait()
