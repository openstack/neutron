# Copyright 2014 IBM Corp.
#
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


import socket
import sys
import time

import eventlet
eventlet.monkey_patch()

from oslo_config import cfg
from oslo_log import log as logging
import oslo_messaging

from neutron.agent.common import ovs_lib
from neutron.agent.linux import ip_lib
from neutron.agent import rpc as agent_rpc
from neutron.common import config as common_config
from neutron.common import constants as n_const
from neutron.common import topics
from neutron.common import utils as n_utils
from neutron.i18n import _LE, _LI
from neutron import context
from neutron.openstack.common import loopingcall
from neutron.plugins.ibm.common import constants


LOG = logging.getLogger(__name__)
cfg.CONF.import_group('SDNVE', 'neutron.plugins.ibm.common.config')
cfg.CONF.import_group('SDNVE_AGENT', 'neutron.plugins.ibm.common.config')


class SdnvePluginApi(agent_rpc.PluginApi):

    def sdnve_info(self, context, info):
        cctxt = self.client.prepare()
        return cctxt.call(context, 'sdnve_info', info=info)


class SdnveNeutronAgent(object):

    target = oslo_messaging.Target(version='1.1')

    def __init__(self, integ_br, interface_mappings,
                 info, polling_interval,
                 controller_ip, reset_br, out_of_band):
        '''The agent initialization.

        Sets the following parameters and sets up the integration
        bridge and physical interfaces if need be.
        :param integ_br: name of the integration bridge.
        :param interface_mappings: interfaces to physical networks.
        :param info: local IP address of this hypervisor.
        :param polling_interval: interval (secs) to poll DB.
        :param controller_ip: Ip address of SDN-VE controller.
        '''

        super(SdnveNeutronAgent, self).__init__()
        self.int_bridge_name = integ_br
        self.controller_ip = controller_ip
        self.interface_mappings = interface_mappings
        self.polling_interval = polling_interval
        self.info = info
        self.reset_br = reset_br
        self.out_of_band = out_of_band

        self.agent_state = {
            'binary': 'neutron-sdnve-agent',
            'host': cfg.CONF.host,
            'topic': n_const.L2_AGENT_TOPIC,
            'configurations': {'interface_mappings': interface_mappings,
                               'reset_br': self.reset_br,
                               'out_of_band': self.out_of_band,
                               'controller_ip': self.controller_ip},
            'agent_type': n_const.AGENT_TYPE_SDNVE,
            'start_flag': True}

        if self.int_bridge_name:
            self.int_br = self.setup_integration_br(integ_br, reset_br,
                                                    out_of_band,
                                                    self.controller_ip)
            self.setup_physical_interfaces(self.interface_mappings)
        else:
            self.int_br = None

        self.setup_rpc()

    def _report_state(self):
        try:
            self.state_rpc.report_state(self.context,
                                        self.agent_state)
            self.agent_state.pop('start_flag', None)
        except Exception:
            LOG.exception(_LE("Failed reporting state!"))

    def setup_rpc(self):
        if self.int_br:
            mac = self.int_br.get_local_port_mac()
            self.agent_id = '%s%s' % ('sdnve', (mac.replace(":", "")))
        else:
            nameaddr = socket.gethostbyname(socket.gethostname())
            self.agent_id = '%s%s' % ('sdnve_', (nameaddr.replace(".", "_")))

        self.topic = topics.AGENT
        self.plugin_rpc = SdnvePluginApi(topics.PLUGIN)
        self.state_rpc = agent_rpc.PluginReportStateAPI(topics.PLUGIN)

        self.context = context.get_admin_context_without_session()
        self.endpoints = [self]
        consumers = [[constants.INFO, topics.UPDATE]]

        self.connection = agent_rpc.create_consumers(self.endpoints,
                                                     self.topic,
                                                     consumers)
        if self.polling_interval:
            heartbeat = loopingcall.FixedIntervalLoopingCall(
                self._report_state)
            heartbeat.start(interval=self.polling_interval)

    # Plugin calls the agents through the following
    def info_update(self, context, **kwargs):
        LOG.debug("info_update received")
        info = kwargs.get('info', {})
        new_controller = info.get('new_controller')
        out_of_band = info.get('out_of_band')
        if self.int_br and new_controller:
            LOG.debug("info_update received. New controller "
                      "is to be set to: %s", new_controller)
            self.int_br.set_controller(["tcp:" + new_controller])
            if out_of_band:
                LOG.debug("info_update received. New controller "
                          "is set to be out of band")
                self.int_br.set_db_attribute("Controller",
                                             self.int_bridge_name,
                                             "connection-mode",
                                             "out-of-band")

    def setup_integration_br(self, bridge_name, reset_br, out_of_band,
                             controller_ip=None):
        '''Sets up the integration bridge.

        Create the bridge and remove all existing flows if reset_br is True.
        Otherwise, creates the bridge if not already existing.
        :param bridge_name: the name of the integration bridge.
        :param reset_br: A boolean to rest the bridge if True.
        :param out_of_band: A boolean indicating controller is out of band.
        :param controller_ip: IP address to use as the bridge controller.
        :returns: the integration bridge
        '''

        int_br = ovs_lib.OVSBridge(bridge_name)
        if reset_br:
            int_br.reset_bridge()
            int_br.remove_all_flows()
        else:
            int_br.create()

        # set the controller
        if controller_ip:
            int_br.set_controller(["tcp:" + controller_ip])
        if out_of_band:
            int_br.set_db_attribute("Controller", bridge_name,
                                    "connection-mode", "out-of-band")

        return int_br

    def setup_physical_interfaces(self, interface_mappings):
        '''Sets up the physical network interfaces.

        Link physical interfaces to the integration bridge.
        :param interface_mappings: map physical net names to interface names.
        '''

        for physical_network, interface in interface_mappings.iteritems():
            LOG.info(_LI("Mapping physical network %(physical_network)s to "
                         "interface %(interface)s"),
                     {'physical_network': physical_network,
                      'interface': interface})
            # Connect the physical interface to the bridge
            if not ip_lib.device_exists(interface):
                LOG.error(_LE("Interface %(interface)s for physical network "
                              "%(physical_network)s does not exist. Agent "
                              "terminated!"),
                          {'physical_network': physical_network,
                           'interface': interface})
                raise SystemExit(1)
            self.int_br.add_port(interface)

    def sdnve_info(self):
        details = self.plugin_rpc.sdnve_info(
            self.context,
            {'info': self.info})
        return details

    def rpc_loop(self):

        while True:
            start = time.time()
            LOG.debug("Agent in the rpc loop.")

            # sleep till end of polling interval
            elapsed = (time.time() - start)
            if (elapsed < self.polling_interval):
                time.sleep(self.polling_interval - elapsed)
            else:
                LOG.info(_LI("Loop iteration exceeded interval "
                             "(%(polling_interval)s vs. %(elapsed)s)!"),
                         {'polling_interval': self.polling_interval,
                          'elapsed': elapsed})

    def daemon_loop(self):
        self.rpc_loop()


def create_agent_config_map(config):
    interface_mappings = n_utils.parse_mappings(
        config.SDNVE.interface_mappings)

    controller_ips = config.SDNVE.controller_ips
    LOG.info(_LI("Controller IPs: %s"), controller_ips)
    controller_ip = controller_ips[0]

    return {
        'integ_br': config.SDNVE.integration_bridge,
        'interface_mappings': interface_mappings,
        'controller_ip': controller_ip,
        'info': config.SDNVE.info,
        'polling_interval': config.SDNVE_AGENT.polling_interval,
        'reset_br': config.SDNVE.reset_bridge,
        'out_of_band': config.SDNVE.out_of_band}


def main():
    cfg.CONF.register_opts(ip_lib.OPTS)
    common_config.init(sys.argv[1:])
    common_config.setup_logging()

    try:
        agent_config = create_agent_config_map(cfg.CONF)
    except ValueError as e:
        LOG.exception(_LE("%s Agent terminated!"), e)
        raise SystemExit(1)

    plugin = SdnveNeutronAgent(**agent_config)

    # Start everything.
    LOG.info(_LI("Agent initialized successfully, now running... "))
    plugin.daemon_loop()
