#!/usr/bin/env python3
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
import types
from unittest import mock

from neutron_lib import constants
from oslo_config import cfg

from neutron.agent.l3 import agent
from neutron.agent.l3 import namespaces
from neutron.agent import l3_agent


class L3NATAgentForTest(agent.L3NATAgentWithStateReport):
    def __init__(self, host, conf=None):
        ns_suffix = '@%s' % cfg.CONF.test_namespace_suffix

        # Mock out building of namespace names
        orig_build_ns_name = namespaces.build_ns_name

        def build_ns_name(prefix, identifier):
            return "%s%s" % (orig_build_ns_name(prefix, identifier), ns_suffix)

        build_ns = mock.patch.object(namespaces, 'build_ns_name').start()
        build_ns.side_effect = build_ns_name

        # Mock the parsing prefix from namespace names
        orig_get_prefix = namespaces.get_prefix_from_ns_name

        def get_prefix_from_ns_name(ns_name):
            if ns_name.endswith(ns_suffix):
                return orig_get_prefix(ns_name[:-len(ns_suffix)])

        parse_prefix = mock.patch.object(namespaces,
                                         'get_prefix_from_ns_name').start()
        parse_prefix.side_effect = get_prefix_from_ns_name

        # Mock the parsing id from namespace names
        orig_get_id = namespaces.get_id_from_ns_name

        def get_id_from_ns_name(ns_name):
            if ns_name.endswith(ns_suffix):
                return orig_get_id(ns_name[:-len(ns_suffix)])

        parse_id = mock.patch.object(namespaces, 'get_id_from_ns_name').start()
        parse_id.side_effect = get_id_from_ns_name

        super(L3NATAgentForTest, self).__init__(host, conf)

    def _create_router(self, router_id, router):
        """Create a router with suffix added to the router namespace name.

        This is needed to be able to run two agents serving the same router
        on the same node.
        """
        router = (
            super(L3NATAgentForTest, self)._create_router(router_id, router))

        router.get_internal_device_name = types.MethodType(
            get_internal_device_name, router)
        router.get_external_device_name = types.MethodType(
            get_external_device_name, router)

        return router


def _append_suffix(dev_name):
    # If dev_name = 'xyz123' and the suffix is 'hostB' then the result
    # will be 'xy_stB'
    return '%s_%s' % (dev_name[:-4], cfg.CONF.test_namespace_suffix[-3:])


def get_internal_device_name(ri, port_id):
    return _append_suffix(
        (namespaces.INTERNAL_DEV_PREFIX + port_id)
        [:constants.LINUX_DEV_LEN])


def get_external_device_name(ri, port_id):
    return _append_suffix(
        (namespaces.EXTERNAL_DEV_PREFIX + port_id)
        [:constants.LINUX_DEV_LEN])


OPTS = [
    cfg.StrOpt('test_namespace_suffix', default='testprefix',
               help="Suffix to append to all namespace names."),
]


def register_opts(conf):
    conf.register_opts(OPTS)


def main(manager='neutron.tests.common.agents.l3_agent.L3NATAgentForTest'):
    register_opts(cfg.CONF)
    l3_agent.main(manager=manager)


if __name__ == "__main__":
    sys.exit(main())
