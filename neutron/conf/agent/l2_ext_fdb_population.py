# Copyright (c) 2016 Mellanox Technologies, Ltd
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

from oslo_config import cfg

from neutron._i18n import _

# if shared_physical_device_mappings is not configured KeyError will be thrown
fdb_population_opt = [
    cfg.ListOpt('shared_physical_device_mappings', default=[],
                help=_("Comma-separated list of "
                       "<physical_network>:<network_device> tuples mapping "
                       "physical network names to the agent's node-specific "
                       "shared physical network device between "
                       "SR-IOV and OVS or SR-IOV and linux bridge"))
]


def register_fdb_population_opts(cfg=cfg.CONF):
    cfg.register_opts(fdb_population_opt, 'FDB')
