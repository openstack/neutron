#!/usr/bin/env python
# Copyright 2016 OVH SAS
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

import copy
import os
import sys

from oslo_config import cfg
from oslo_utils import uuidutils

from neutron.agent.linux import dhcp as linux_dhcp
from neutron.cmd.eventlet.agents import dhcp as dhcp_agent


OPTS = [
    cfg.StrOpt('test_namespace_suffix', default='testprefix',
               help="Suffix to append to all DHCP namespace names."),
]


def _get_namespace_name(id_, suffix=None):
    suffix = suffix or cfg.CONF.test_namespace_suffix
    return "%s%s%s" % (linux_dhcp.NS_PREFIX, id_, suffix)


def NetModel_init(self, d):
    super(linux_dhcp.NetModel, self).__init__(d)
    self._ns_name = _get_namespace_name(self.id)


@classmethod
def existing_dhcp_networks(cls, conf):
    """Return a list of existing networks ids that we have configs for."""
    confs_dir = cls.get_confs_dir(conf)
    networks = []
    try:
        for c in os.listdir(confs_dir):
            c = c.replace(cfg.CONF.test_namespace_suffix, "")
            if uuidutils.is_uuid_like(c):
                networks.append(c)
    except OSError:
        pass
    return networks


def monkeypatch_dhcplocalprocess_init():
    original_init = linux_dhcp.DhcpLocalProcess.__init__

    def new_init(self, conf, network, process_monitor, version=None,
                 plugin=None):
        network_copy = copy.deepcopy(network)
        network_copy.id = "%s%s" % (network.id, cfg.CONF.test_namespace_suffix)
        original_init(
            self, conf, network_copy, process_monitor, version, plugin)
        self.network = network

    linux_dhcp.DhcpLocalProcess.__init__ = new_init


def monkeypatch_linux_dhcp():
    linux_dhcp.NetModel.__init__ = NetModel_init
    linux_dhcp.Dnsmasq.existing_dhcp_networks = existing_dhcp_networks
    monkeypatch_dhcplocalprocess_init()


def main():
    cfg.CONF.register_opts(OPTS)
    monkeypatch_linux_dhcp()
    dhcp_agent.main()


if __name__ == "__main__":
    sys.exit(main())
