# Copyright (c) 2015 Red Hat, Inc.
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

import functools

from oslo_config import cfg

from neutron.conf.agent import ovs_conf as agent_ovs_conf
from neutron.conf.plugins.ml2.drivers import ovs_conf as ml2_ovs_conf
from neutron.privileged.agent.ovsdb.native import helpers as priv_helpers


agent_ovs_conf.register_ovs_agent_opts(cfg.CONF)
ml2_ovs_conf.register_ovs_opts(cfg=cfg.CONF)

enable_connection_uri = functools.partial(
    priv_helpers.enable_connection_uri,
    log_fail_as_error=False, check_exit_code=False,
    timeout=cfg.CONF.OVS.ovsdb_timeout,
    inactivity_probe=cfg.CONF.OVS.of_inactivity_probe * 1000)
