# Copyright (C) 2014,2015 VA Linux Systems Japan K.K.
# Copyright (C) 2014 Fumihiko Kakuma <kakuma at valinux co jp>
# Copyright (C) 2014,2015 YAMAMOTO Takashi <yamamoto at valinux co jp>
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

from neutron.common import config as common_config
from neutron.common import profiler
from neutron.plugins.ml2.drivers.openvswitch.agent.openflow.native import \
        main as of_main


cfg.CONF.import_group('OVS', 'neutron.plugins.ml2.drivers.openvswitch.agent.'
                      'common.config')


def main():
    common_config.register_common_config_options()
    common_config.init(sys.argv[1:])
    of_main.init_config()
    common_config.setup_logging()
    common_config.setup_gmr()
    profiler.setup("neutron-ovs-agent", cfg.CONF.host)
    of_main.main()
