# Copyright (C) 2015 VA Linux Systems Japan K.K.
# Copyright (C) 2015 YAMAMOTO Takashi <yamamoto at valinux co jp>
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
from ryu.base import app_manager
from ryu import cfg as ryu_cfg


cfg.CONF.import_group(
    'OVS',
    'neutron.plugins.ml2.drivers.openvswitch.agent.common.config')


def init_config():
    ryu_cfg.CONF(project='ryu', args=[])
    ryu_cfg.CONF.ofp_listen_host = cfg.CONF.OVS.of_listen_address
    ryu_cfg.CONF.ofp_tcp_listen_port = cfg.CONF.OVS.of_listen_port


def main():
    app_manager.AppManager.run_apps([
        'neutron.plugins.ml2.drivers.openvswitch.agent.'
        'openflow.native.ovs_ryuapp',
    ])
