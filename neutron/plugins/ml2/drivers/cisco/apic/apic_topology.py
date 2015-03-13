# Copyright (c) 2014 Cisco Systems Inc.
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

import re
import sys

import eventlet
eventlet.monkey_patch()

from oslo_concurrency import lockutils
from oslo_config import cfg
from oslo_log import log as logging
import oslo_messaging

from neutron.agent.common import config
from neutron.agent.linux import ip_lib
from neutron.agent.linux import utils
from neutron.common import config as common_cfg
from neutron.common import rpc
from neutron.common import utils as neutron_utils
from neutron.db import agents_db
from neutron.i18n import _LE, _LI
from neutron import manager
from neutron.openstack.common import periodic_task
from neutron.openstack.common import service as svc
from neutron.plugins.ml2.drivers.cisco.apic import mechanism_apic as ma
from neutron.plugins.ml2.drivers import type_vlan  # noqa

from neutron import service

ACI_PORT_DESCR_FORMATS = [
    r'topology/pod-1/node-(\d+)/sys/conng/path-\[eth(\d+)/(\d+)\]',
    r'topology/pod-1/paths-(\d+)/pathep-\[eth(\d+)/(\d+)\]',
]
AGENT_FORCE_UPDATE_COUNT = 100
BINARY_APIC_SERVICE_AGENT = 'neutron-cisco-apic-service-agent'
BINARY_APIC_HOST_AGENT = 'neutron-cisco-apic-host-agent'
TOPIC_APIC_SERVICE = 'apic-service'
TYPE_APIC_SERVICE_AGENT = 'cisco-apic-service-agent'
TYPE_APIC_HOST_AGENT = 'cisco-apic-host-agent'


LOG = logging.getLogger(__name__)


class ApicTopologyService(manager.Manager):

    target = oslo_messaging.Target(version='1.1')

    def __init__(self, host=None):
        if host is None:
            host = neutron_utils.get_hostname()
        super(ApicTopologyService, self).__init__(host=host)

        self.conf = cfg.CONF.ml2_cisco_apic
        self.conn = None
        self.peers = {}
        self.invalid_peers = []
        self.dispatcher = None
        self.state = None
        self.state_agent = None
        self.topic = TOPIC_APIC_SERVICE
        self.apic_manager = ma.APICMechanismDriver.get_apic_manager(False)

    def init_host(self):
        LOG.info(_LI("APIC service agent starting ..."))
        self.state = {
            'binary': BINARY_APIC_SERVICE_AGENT,
            'host': self.host,
            'topic': self.topic,
            'configurations': {},
            'start_flag': True,
            'agent_type': TYPE_APIC_SERVICE_AGENT,
        }

        self.conn = rpc.create_connection(new=True)
        self.dispatcher = [self, agents_db.AgentExtRpcCallback()]
        self.conn.create_consumer(
            self.topic, self.dispatcher, fanout=True)
        self.conn.consume_in_threads()

    def after_start(self):
        LOG.info(_LI("APIC service agent started"))

    def report_send(self, context):
        if not self.state_agent:
            return
        LOG.debug("APIC service agent: sending report state")

        try:
            self.state_agent.report_state(context, self.state)
            self.state.pop('start_flag', None)
        except AttributeError:
            # This means the server does not support report_state
            # ignore it
            return
        except Exception:
            LOG.exception(_LE("APIC service agent: failed in reporting state"))

    @lockutils.synchronized('apic_service')
    def update_link(self, context,
                    host, interface, mac,
                    switch, module, port):
        LOG.debug("APIC service agent: received update_link: %s",
                  ", ".join(map(str,
                                [host, interface, mac, switch, module, port])))

        nlink = (host, interface, mac, switch, module, port)
        clink = self.peers.get((host, interface), None)

        if switch == 0:
            # this is a link delete, remove it
            if clink is not None:
                self.apic_manager.remove_hostlink(*clink)
                self.peers.pop((host, interface))
        else:
            if clink is None:
                # add new link to database
                self.apic_manager.add_hostlink(*nlink)
                self.peers[(host, interface)] = nlink
            elif clink != nlink:
                # delete old link and add new one (don't update in place)
                self.apic_manager.remove_hostlink(*clink)
                self.peers.pop((host, interface))
                self.apic_manager.add_hostlink(*nlink)
                self.peers[(host, interface)] = nlink


class ApicTopologyServiceNotifierApi(object):

    def __init__(self):
        target = oslo_messaging.Target(topic=TOPIC_APIC_SERVICE, version='1.0')
        self.client = rpc.get_client(target)

    def update_link(self, context, host, interface, mac, switch, module, port):
        cctxt = self.client.prepare(version='1.1', fanout=True)
        cctxt.cast(context, 'update_link', host=host, interface=interface,
                   mac=mac, switch=switch, module=module, port=port)

    def delete_link(self, context, host, interface):
        cctxt = self.client.prepare(version='1.1', fanout=True)
        cctxt.cast(context, 'delete_link', host=host, interface=interface,
                   mac=None, switch=0, module=0, port=0)


class ApicTopologyAgent(manager.Manager):
    def __init__(self, host=None):
        if host is None:
            host = neutron_utils.get_hostname()
        super(ApicTopologyAgent, self).__init__(host=host)

        self.conf = cfg.CONF.ml2_cisco_apic
        self.count_current = 0
        self.count_force_send = AGENT_FORCE_UPDATE_COUNT
        self.interfaces = {}
        self.lldpcmd = None
        self.peers = {}
        self.port_desc_re = map(re.compile, ACI_PORT_DESCR_FORMATS)
        self.service_agent = ApicTopologyServiceNotifierApi()
        self.state = None
        self.state_agent = None
        self.topic = TOPIC_APIC_SERVICE
        self.uplink_ports = []
        self.invalid_peers = []

    def init_host(self):
        LOG.info(_LI("APIC host agent: agent starting on %s"), self.host)
        self.state = {
            'binary': BINARY_APIC_HOST_AGENT,
            'host': self.host,
            'topic': self.topic,
            'configurations': {},
            'start_flag': True,
            'agent_type': TYPE_APIC_HOST_AGENT,
        }

        self.uplink_ports = []
        for inf in self.conf.apic_host_uplink_ports:
            if ip_lib.device_exists(inf):
                self.uplink_ports.append(inf)
            else:
                # ignore unknown interfaces
                LOG.error(_LE("No such interface (ignored): %s"), inf)
        self.lldpcmd = ['lldpctl', '-f', 'keyvalue'] + self.uplink_ports

    def after_start(self):
        LOG.info(_LI("APIC host agent: started on %s"), self.host)

    @periodic_task.periodic_task
    def _check_for_new_peers(self, context):
        LOG.debug("APIC host agent: _check_for_new_peers")

        if not self.lldpcmd:
            return
        try:
            # Check if we must send update even if there is no change
            force_send = False
            self.count_current += 1
            if self.count_current >= self.count_force_send:
                force_send = True
                self.count_current = 0

            # Check for new peers
            new_peers = self._get_peers()
            new_peers = self._valid_peers(new_peers)

            # Make a copy of current interfaces
            curr_peers = {}
            for interface in self.peers:
                curr_peers[interface] = self.peers[interface]
            # Based curr -> new updates, add the new interfaces
            self.peers = {}
            for interface in new_peers:
                peer = new_peers[interface]
                self.peers[interface] = peer
                if (interface in curr_peers and
                        curr_peers[interface] != peer):
                    self.service_agent.update_link(
                        context, peer[0], peer[1], None, 0, 0, 0)
                if (interface not in curr_peers or
                        curr_peers[interface] != peer or
                        force_send):
                    self.service_agent.update_link(context, *peer)
                if interface in curr_peers:
                    curr_peers.pop(interface)

            # Any interface still in curr_peers need to be deleted
            for peer in curr_peers.values():
                self.service_agent.update_link(
                    context, peer[0], peer[1], None, 0, 0, 0)

        except Exception:
            LOG.exception(_LE("APIC service agent: exception in LLDP parsing"))

    def _get_peers(self):
        peers = {}
        lldpkeys = utils.execute(self.lldpcmd, run_as_root=True)
        for line in lldpkeys.splitlines():
            if '=' not in line:
                continue
            fqkey, value = line.split('=', 1)
            lldp, interface, key = fqkey.split('.', 2)
            if key == 'port.descr':
                for regexp in self.port_desc_re:
                    match = regexp.match(value)
                    if match:
                        mac = self._get_mac(interface)
                        switch, module, port = match.group(1, 2, 3)
                        peer = (self.host, interface, mac,
                                switch, module, port)
                        if interface not in peers:
                            peers[interface] = []
                        peers[interface].append(peer)
        return peers

    def _valid_peers(self, peers):
        # Reduce the peers array to one valid peer per interface
        # NOTE:
        # There is a bug in lldpd daemon that it keeps reporting
        # old peers even after their updates have stopped
        # we keep track of that report remove them from peers

        valid_peers = {}
        invalid_peers = []
        for interface in peers:
            curr_peer = None
            for peer in peers[interface]:
                if peer in self.invalid_peers or curr_peer:
                    invalid_peers.append(peer)
                else:
                    curr_peer = peer
            if curr_peer is not None:
                valid_peers[interface] = curr_peer

        self.invalid_peers = invalid_peers
        return valid_peers

    def _get_mac(self, interface):
        if interface in self.interfaces:
            return self.interfaces[interface]
        try:
            mac = ip_lib.IPDevice(interface).link.address
            self.interfaces[interface] = mac
            return mac
        except Exception:
            # we can safely ignore it, it is only needed for debugging
            LOG.exception(
                _LE("APIC service agent: can not get MACaddr for %s"),
                interface)

    def report_send(self, context):
        if not self.state_agent:
            return
        LOG.debug("APIC host agent: sending report state")

        try:
            self.state_agent.report_state(context, self.state)
            self.state.pop('start_flag', None)
        except AttributeError:
            # This means the server does not support report_state
            # ignore it
            return
        except Exception:
            LOG.exception(_LE("APIC host agent: failed in reporting state"))


def launch(binary, manager, topic=None):
    cfg.CONF(project='neutron')
    common_cfg.init(sys.argv[1:])
    config.setup_logging()
    report_period = cfg.CONF.ml2_cisco_apic.apic_agent_report_interval
    poll_period = cfg.CONF.ml2_cisco_apic.apic_agent_poll_interval
    server = service.Service.create(
        binary=binary, manager=manager, topic=topic,
        report_interval=report_period, periodic_interval=poll_period)
    svc.launch(server).wait()


def service_main():
    launch(
        BINARY_APIC_SERVICE_AGENT,
        'neutron.plugins.ml2.drivers.' +
        'cisco.apic.apic_topology.ApicTopologyService',
        TOPIC_APIC_SERVICE)


def agent_main():
    launch(
        BINARY_APIC_HOST_AGENT,
        'neutron.plugins.ml2.drivers.' +
        'cisco.apic.apic_topology.ApicTopologyAgent')
