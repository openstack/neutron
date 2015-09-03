# Copyright 2015 Red Hat, Inc.
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

import datetime
import os

from oslo_utils import timeutils

import neutron
from neutron.common import constants
from neutron.common import topics
from neutron import context
from neutron.db import agents_db
from neutron.db import common_db_mixin

HOST = 'localhost'


def find_file(filename, path):
    """Find a file with name 'filename' located in 'path'."""
    for root, _, files in os.walk(path):
        if filename in files:
            return os.path.abspath(os.path.join(root, filename))


def find_sample_file(filename):
    """Find a file with name 'filename' located in the sample directory."""
    return find_file(
        filename,
        path=os.path.join(neutron.__path__[0], '..', 'etc'))


class FakePlugin(common_db_mixin.CommonDbMixin,
                 agents_db.AgentDbMixin):
    pass


def _get_l3_agent_dict(host, agent_mode, internal_only=True,
                       ext_net_id='', ext_bridge='', router_id=None):
    return {
        'agent_type': constants.AGENT_TYPE_L3,
        'binary': 'neutron-l3-agent',
        'host': host,
        'topic': topics.L3_AGENT,
        'configurations': {'agent_mode': agent_mode,
                           'handle_internal_only_routers': internal_only,
                           'external_network_bridge': ext_bridge,
                           'gateway_external_network_id': ext_net_id,
                           'router_id': router_id,
                           'use_namespaces': router_id is None}}


def _register_agent(agent):
    plugin = FakePlugin()
    admin_context = context.get_admin_context()
    plugin.create_or_update_agent(admin_context, agent)
    return plugin._get_agent_by_type_and_host(
        admin_context, agent['agent_type'], agent['host'])


def register_l3_agent(host=HOST, agent_mode=constants.L3_AGENT_MODE_LEGACY,
                      internal_only=True, ext_net_id='', ext_bridge='',
                      router_id=None):
    agent = _get_l3_agent_dict(host, agent_mode, internal_only, ext_net_id,
                               ext_bridge, router_id)
    return _register_agent(agent)


def _get_dhcp_agent_dict(host, networks=0):
    agent = {
        'binary': 'neutron-dhcp-agent',
        'host': host,
        'topic': topics.DHCP_AGENT,
        'agent_type': constants.AGENT_TYPE_DHCP,
        'configurations': {'dhcp_driver': 'dhcp_driver',
                           'use_namespaces': True,
                           'networks': networks}}
    return agent


def register_dhcp_agent(host=HOST, networks=0, admin_state_up=True,
                        alive=True):
    agent = _register_agent(
        _get_dhcp_agent_dict(host, networks))

    if not admin_state_up:
        set_agent_admin_state(agent['id'])
    if not alive:
        kill_agent(agent['id'])

    return FakePlugin()._get_agent_by_type_and_host(
        context.get_admin_context(), agent['agent_type'], agent['host'])


def kill_agent(agent_id):
    hour_ago = timeutils.utcnow() - datetime.timedelta(hours=1)
    FakePlugin().update_agent(
        context.get_admin_context(),
        agent_id,
        {'agent': {
            'started_at': hour_ago,
            'heartbeat_timestamp': hour_ago}})


def set_agent_admin_state(agent_id, admin_state_up=False):
    FakePlugin().update_agent(
        context.get_admin_context(),
        agent_id,
        {'agent': {'admin_state_up': admin_state_up}})


def _get_ovs_agent_dict(host, agent_type, binary, tunnel_types,
                        tunneling_ip='20.0.0.1', interface_mappings=None,
                        l2pop_network_types=None):
    agent = {
        'binary': binary,
        'host': host,
        'topic': constants.L2_AGENT_TOPIC,
        'configurations': {'tunneling_ip': tunneling_ip,
                           'tunnel_types': tunnel_types},
        'agent_type': agent_type,
        'tunnel_type': [],
        'start_flag': True}

    if interface_mappings is not None:
        agent['configurations']['interface_mappings'] = interface_mappings
    if l2pop_network_types is not None:
        agent['configurations']['l2pop_network_types'] = l2pop_network_types
    return agent


def register_ovs_agent(host=HOST, agent_type=constants.AGENT_TYPE_OVS,
                       binary='neutron-openvswitch-agent',
                       tunnel_types=['vxlan'], tunneling_ip='20.0.0.1',
                       interface_mappings=None,
                       l2pop_network_types=None):
    agent = _get_ovs_agent_dict(host, agent_type, binary, tunnel_types,
                                tunneling_ip, interface_mappings,
                                l2pop_network_types)
    return _register_agent(agent)
