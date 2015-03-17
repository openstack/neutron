# Copyright 2015 OpenStack Foundation.
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

from neutron.agent.common import config as agent_conf
from neutron.agent.metadata import agent
from neutron.agent.metadata import config as metadata_conf
from neutron.common import config
from neutron.common import utils
from neutron.openstack.common.cache import cache

LOG = logging.getLogger(__name__)


def main():
    cfg.CONF.register_opts(metadata_conf.SHARED_OPTS)
    cfg.CONF.register_opts(metadata_conf.UNIX_DOMAIN_METADATA_PROXY_OPTS)
    cfg.CONF.register_opts(metadata_conf.METADATA_PROXY_HANDLER_OPTS)
    cache.register_oslo_configs(cfg.CONF)
    cfg.CONF.set_default(name='cache_url', default='memory://?default_ttl=5')
    agent_conf.register_agent_state_opts_helper(cfg.CONF)
    config.init(sys.argv[1:])
    config.setup_logging()
    utils.log_opt_values(LOG)
    # metadata agent need not connect DB
    cfg.CONF.set_override("connection", "", "database")
    proxy = agent.UnixDomainMetadataProxy(cfg.CONF)
    proxy.run()
