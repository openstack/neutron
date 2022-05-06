# Copyright 2017 OpenStack Foundation.
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

from neutron.agent.ovn.metadata import agent
from neutron.conf.agent.metadata import config as meta
from neutron.conf.agent.ovn.metadata import config as ovn_meta
from neutron.conf.plugins.ml2.drivers.ovn import ovn_conf

LOG = logging.getLogger(__name__)


def main():
    config.register_common_config_options()
    ovn_conf.register_opts()
    ovn_meta.register_meta_conf_opts(meta.SHARED_OPTS)
    ovn_meta.register_meta_conf_opts(meta.UNIX_DOMAIN_METADATA_PROXY_OPTS)
    ovn_meta.register_meta_conf_opts(meta.METADATA_PROXY_HANDLER_OPTS)
    ovn_meta.register_meta_conf_opts(ovn_meta.OVS_OPTS, group='ovs')
    config.init(sys.argv[1:])
    config.setup_logging()
    ovn_meta.setup_privsep()
    utils.log_opt_values(LOG)

    agt = agent.MetadataAgent(cfg.CONF)
    agt.start()
