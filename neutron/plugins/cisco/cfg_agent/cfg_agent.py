# Copyright 2014 Cisco Systems, Inc.  All rights reserved.
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

import eventlet
eventlet.monkey_patch()
import pprint
import sys
import time

from oslo.config import cfg

from neutron.agent.common import config
from neutron.agent.linux import external_process
from neutron.agent.linux import interface
from neutron.agent import rpc as agent_rpc
from neutron.common import config as common_config
from neutron.common import rpc as n_rpc
from neutron.common import topics
from neutron import context as n_context
from neutron import manager
from neutron.openstack.common import importutils
from neutron.openstack.common import lockutils
from neutron.openstack.common import log as logging
from neutron.openstack.common import loopingcall
from neutron.openstack.common import periodic_task
from neutron.openstack.common import service
from neutron.openstack.common import timeutils
from neutron.plugins.cisco.cfg_agent import device_status
from neutron.plugins.cisco.common import cisco_constants as c_constants
from neutron import service as neutron_service

LOG = logging.getLogger(__name__)

# Constants for agent registration.
REGISTRATION_RETRY_DELAY = 2
MAX_REGISTRATION_ATTEMPTS = 30


class CiscoDeviceManagementApi(n_rpc.RpcProxy):
    """Agent side of the device manager RPC API."""

    BASE_RPC_API_VERSION = '1.0'

    def __init__(self, topic, host):
        super(CiscoDeviceManagementApi, self).__init__(
            topic=topic, default_version=self.BASE_RPC_API_VERSION)
        self.host = host

    def report_dead_hosting_devices(self, context, hd_ids=None):
        """Report that a hosting device cannot be contacted (presumed dead).

        :param: context: session context
        :param: hosting_device_ids: list of non-responding hosting devices
        :return: None
        """
        # Cast since we don't expect a return value.
        self.cast(context,
                  self.make_msg('report_non_responding_hosting_devices',
                                host=self.host,
                                hosting_device_ids=hd_ids),
                  topic=self.topic)

    def register_for_duty(self, context):
        """Report that a config agent is ready for duty."""
        return self.call(context,
                         self.make_msg('register_for_duty',
                                       host=self.host),
                         topic=self.topic)


class CiscoCfgAgent(manager.Manager):
    """Cisco Cfg Agent.

    This class defines a generic configuration agent for cisco devices which
    implement network services in the cloud backend. It is based on the
    (reference) l3-agent, but has been enhanced to support multiple services
     in addition to routing.

    The agent acts like as a container for services and does not do any
    service specific processing or configuration itself.
    All service specific processing is delegated to service helpers which
    the agent loads. Thus routing specific updates are processed by the
    routing service helper, firewall by firewall helper etc.
    A further layer of abstraction is implemented by using device drivers for
    encapsulating all configuration operations of a service on a device.
    Device drivers are specific to a particular device/service VM eg: CSR1kv.

    The main entry points in this class are the `process_services()` and
    `_backlog_task()` .
    """
    RPC_API_VERSION = '1.1'

    OPTS = [
        cfg.IntOpt('rpc_loop_interval', default=10,
                   help=_("Interval when the process_services() loop "
                          "executes in seconds. This is when the config agent "
                          "lets each service helper to process its neutron "
                          "resources.")),
        cfg.StrOpt('routing_svc_helper_class',
                   default='neutron.plugins.cisco.cfg_agent.service_helpers'
                           '.routing_svc_helper.RoutingServiceHelper',
                   help=_("Path of the routing service helper class.")),
    ]

    def __init__(self, host, conf=None):
        self.conf = conf or cfg.CONF
        self._dev_status = device_status.DeviceStatus()
        self.context = n_context.get_admin_context_without_session()

        self._initialize_rpc(host)
        self._initialize_service_helpers(host)
        self._start_periodic_tasks()
        super(CiscoCfgAgent, self).__init__(host=self.conf.host)

    def _initialize_rpc(self, host):
        self.devmgr_rpc = CiscoDeviceManagementApi(topics.L3PLUGIN, host)

    def _initialize_service_helpers(self, host):
        svc_helper_class = self.conf.cfg_agent.routing_svc_helper_class
        try:
            self.routing_service_helper = importutils.import_object(
                svc_helper_class, host, self.conf, self)
        except ImportError as e:
            LOG.warn(_("Error in loading routing service helper. Class "
                       "specified is %(class)s. Reason:%(reason)s"),
                     {'class': self.conf.cfg_agent.routing_svc_helper_class,
                      'reason': e})
            self.routing_service_helper = None

    def _start_periodic_tasks(self):
        self.loop = loopingcall.FixedIntervalLoopingCall(self.process_services)
        self.loop.start(interval=self.conf.cfg_agent.rpc_loop_interval)

    def after_start(self):
        LOG.info(_("Cisco cfg agent started"))

    def get_routing_service_helper(self):
        return self.routing_service_helper

    ## Periodic tasks ##
    @periodic_task.periodic_task
    def _backlog_task(self, context):
        """Process backlogged devices."""
        LOG.debug("Processing backlog.")
        self._process_backlogged_hosting_devices(context)

    ## Main orchestrator ##
    @lockutils.synchronized('cisco-cfg-agent', 'neutron-')
    def process_services(self, device_ids=None, removed_devices_info=None):
        """Process services managed by this config agent.

        This method is invoked by any of three scenarios.

        1. Invoked by a periodic task running every `RPC_LOOP_INTERVAL`
        seconds. This is the most common scenario.
        In this mode, the method is called without any arguments.

        2. Called by the `_process_backlogged_hosting_devices()` as part of
        the backlog processing task. In this mode, a list of device_ids
        are passed as arguments. These are the list of backlogged
        hosting devices that are now reachable and we want to sync services
        on them.

        3. Called by the `hosting_devices_removed()` method. This is when
        the config agent has received a notification from the plugin that
        some hosting devices are going to be removed. The payload contains
        the details of the hosting devices and the associated neutron
        resources on them which should be processed and removed.

        To avoid race conditions with these scenarios, this function is
        protected by a lock.

        This method goes on to invoke `process_service()` on the
        different service helpers.

        :param device_ids : List of devices that are now available and needs
         to be processed
        :param removed_devices_info: Info about the hosting devices which
        are going to be removed and details of the resources hosted on them.
        Expected Format:
                {
                 'hosting_data': {'hd_id1': {'routers': [id1, id2, ...]},
                                  'hd_id2': {'routers': [id3, id4, ...]}, ...},
                 'deconfigure': True/False
                }
        :return: None
        """
        LOG.debug("Processing services started")
        # Now we process only routing service, additional services will be
        # added in future
        if self.routing_service_helper:
            self.routing_service_helper.process_service(device_ids,
                                                        removed_devices_info)
        else:
            LOG.warn(_("No routing service helper loaded"))
        LOG.debug("Processing services completed")

    def _process_backlogged_hosting_devices(self, context):
        """Process currently backlogged devices.

        Go through the currently backlogged devices and process them.
        For devices which are now reachable (compared to last time), we call
        `process_services()` passing the now reachable device's id.
        For devices which have passed the `hosting_device_dead_timeout` and
        hence presumed dead, execute a RPC to the plugin informing that.
        :param context: RPC context
        :return: None
        """
        res = self._dev_status.check_backlogged_hosting_devices()
        if res['reachable']:
            self.process_services(device_ids=res['reachable'])
        if res['dead']:
            LOG.debug("Reporting dead hosting devices: %s", res['dead'])
            self.devmgr_rpc.report_dead_hosting_devices(context,
                                                        hd_ids=res['dead'])

    def hosting_devices_removed(self, context, payload):
        """Deal with hosting device removed RPC message."""
        try:
            if payload['hosting_data']:
                if payload['hosting_data'].keys():
                    self.process_services(removed_devices_info=payload)
        except KeyError as e:
            LOG.error(_("Invalid payload format for received RPC message "
                        "`hosting_devices_removed`. Error is %{error}s. "
                        "Payload is %(payload)s"),
                      {'error': e, 'payload': payload})


class CiscoCfgAgentWithStateReport(CiscoCfgAgent):

    def __init__(self, host, conf=None):
        self.state_rpc = agent_rpc.PluginReportStateAPI(topics.PLUGIN)
        self.agent_state = {
            'binary': 'neutron-cisco-cfg-agent',
            'host': host,
            'topic': c_constants.CFG_AGENT,
            'configurations': {},
            'start_flag': True,
            'agent_type': c_constants.AGENT_TYPE_CFG}
        report_interval = cfg.CONF.AGENT.report_interval
        self.use_call = True
        self._initialize_rpc(host)
        self._agent_registration()
        super(CiscoCfgAgentWithStateReport, self).__init__(host=host,
                                                           conf=conf)
        if report_interval:
            self.heartbeat = loopingcall.FixedIntervalLoopingCall(
                self._report_state)
            self.heartbeat.start(interval=report_interval)

    def _agent_registration(self):
        """Register this agent with the server.

        This method registers the cfg agent with the neutron server so hosting
        devices can be assigned to it. In case the server is not ready to
        accept registration (it sends a False) then we retry registration
        for `MAX_REGISTRATION_ATTEMPTS` with a delay of
        `REGISTRATION_RETRY_DELAY`. If there is no server response or a
        failure to register after the required number of attempts,
        the agent stops itself.
        """
        for attempts in xrange(MAX_REGISTRATION_ATTEMPTS):
            context = n_context.get_admin_context_without_session()
            self.send_agent_report(self.agent_state, context)
            res = self.devmgr_rpc.register_for_duty(context)
            if res is True:
                LOG.info(_("[Agent registration] Agent successfully "
                           "registered"))
                return
            elif res is False:
                LOG.warn(_("[Agent registration] Neutron server said that "
                           "device manager was not ready. Retrying in %0.2f "
                           "seconds "), REGISTRATION_RETRY_DELAY)
                time.sleep(REGISTRATION_RETRY_DELAY)
            elif res is None:
                LOG.error(_("[Agent registration] Neutron server said that no "
                            "device manager was found. Cannot "
                            "continue. Exiting!"))
                raise SystemExit("Cfg Agent exiting")
        LOG.error(_("[Agent registration] %d unsuccessful registration "
                    "attempts. Exiting!"), MAX_REGISTRATION_ATTEMPTS)
        raise SystemExit("Cfg Agent exiting")

    def _report_state(self):
        """Report state to the plugin.

        This task run every `report_interval` period.
        Collects, creates and sends a summary of the services currently
        managed by this agent. Data is collected from the service helper(s).
        Refer the `configurations` dict for the parameters reported.
        :return: None
        """
        LOG.debug("Report state task started")
        configurations = {}
        if self.routing_service_helper:
            configurations = self.routing_service_helper.collect_state(
                self.agent_state['configurations'])
        non_responding = self._dev_status.get_backlogged_hosting_devices_info()
        configurations['non_responding_hosting_devices'] = non_responding
        self.agent_state['configurations'] = configurations
        self.agent_state['local_time'] = str(timeutils.utcnow())
        LOG.debug("State report data: %s", pprint.pformat(self.agent_state))
        self.send_agent_report(self.agent_state, self.context)

    def send_agent_report(self, report, context):
        """Send the agent report via RPC."""
        try:
            self.state_rpc.report_state(context, report, self.use_call)
            report.pop('start_flag', None)
            self.use_call = False
            LOG.debug("Send agent report successfully completed")
        except AttributeError:
            # This means the server does not support report_state
            LOG.warn(_("Neutron server does not support state report. "
                       "State report for this agent will be disabled."))
            self.heartbeat.stop()
            return
        except Exception:
            LOG.exception(_("Failed sending agent report!"))


def main(manager='neutron.plugins.cisco.cfg_agent.'
                 'cfg_agent.CiscoCfgAgentWithStateReport'):
    conf = cfg.CONF
    conf.register_opts(CiscoCfgAgent.OPTS, "cfg_agent")
    config.register_agent_state_opts_helper(conf)
    config.register_root_helper(conf)
    conf.register_opts(interface.OPTS)
    conf.register_opts(external_process.OPTS)
    common_config.init(sys.argv[1:])
    conf(project='neutron')
    config.setup_logging()
    server = neutron_service.Service.create(
        binary='neutron-cisco-cfg-agent',
        topic=c_constants.CFG_AGENT,
        report_interval=cfg.CONF.AGENT.report_interval,
        manager=manager)
    service.launch(server).wait()
