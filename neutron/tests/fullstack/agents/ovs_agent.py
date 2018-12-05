#!/usr/bin/env python
# Copyright 2017 OVH SAS
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

from neutron.services.trunk.drivers.openvswitch.agent \
    import driver as trunk_driver
from neutron.tests.common.agents import ovs_agent


def monkeypatch_init_handler():
    original_handler = trunk_driver.init_handler

    def new_init_handler(resource, event, trigger, payload=None):
        # NOTE(slaweq): make this setup conditional based on server-side
        # capabilities for fullstack tests we can assume that server-side
        # and agent-side conf are in sync
        if "trunk" not in cfg.CONF.service_plugins:
            return
        original_handler(resource, event, trigger, payload)

    trunk_driver.init_handler = new_init_handler


def main():
    # TODO(slaweq): this monkepatch will not be necessary when
    # https://review.openstack.org/#/c/506722/ will be merged and ovsdb-server
    # ovs-vswitchd processes for each test will be isolated in separate
    # namespace
    monkeypatch_init_handler()
    ovs_agent.main()


if __name__ == "__main__":
    sys.exit(main())
