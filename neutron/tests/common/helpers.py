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

import os

import neutron
from neutron.common import constants
from neutron.common import topics
from neutron import context
from neutron import manager

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
    core_plugin = manager.NeutronManager.get_plugin()
    admin_context = context.get_admin_context()
    core_plugin.create_or_update_agent(admin_context, agent)
    return core_plugin.get_agents_db(
        admin_context,
        filters={'host': [agent['host']],
                 'agent_type': [agent['agent_type']]})[0]


def register_l3_agent(host=HOST, agent_mode=constants.L3_AGENT_MODE_LEGACY,
                      internal_only=True, ext_net_id='', ext_bridge='',
                      router_id=None):
    agent = _get_l3_agent_dict(host, agent_mode, internal_only, ext_net_id,
                               ext_bridge, router_id)
    return _register_agent(agent)
