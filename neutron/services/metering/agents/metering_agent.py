# Copyright (C) 2013 eNovance SAS <licensing@enovance.com>
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import sys

from neutron_lib.agent import topics
from neutron_lib import constants
from neutron_lib import context
from neutron_lib import rpc as n_rpc
from neutron_lib.utils import runtime
from oslo_config import cfg
from oslo_log import log as logging
import oslo_messaging
from oslo_service import loopingcall
from oslo_service import periodic_task
from oslo_service import service
from oslo_utils import timeutils

from neutron._i18n import _
from neutron.agent import rpc as agent_rpc
from neutron.common import config as common_config
from neutron.conf.agent import common as config
from neutron.conf.services import metering_agent
from neutron import manager
from neutron import service as neutron_service

from neutron.services.metering.drivers import abstract_driver as driver
from neutron.services.metering.drivers import utils as driverutils

LOG = logging.getLogger(__name__)


class MeteringPluginRpc:

    def __init__(self, host):
        # NOTE(yamamoto): super.__init__() call here is not only for
        # aesthetics.  Because of multiple inheritances in MeteringAgent,
        # it's actually necessary to initialize parent classes of
        # manager.Manager correctly.
        super().__init__(host)
        target = oslo_messaging.Target(topic=topics.METERING_PLUGIN,
                                       version='1.0')
        self.client = n_rpc.get_client(target)

    def _get_sync_data_metering(self, context):
        try:
            cctxt = self.client.prepare()
            return cctxt.call(context, 'get_sync_data_metering',
                              host=self.host)
        except Exception:
            LOG.exception("Failed synchronizing routers")


class MeteringAgent(MeteringPluginRpc, manager.Manager):

    def __init__(self, host, conf=None):
        self.conf = conf or cfg.CONF
        self._load_drivers()
        self.host = host
        self.label_project_id = {}
        self.routers = {}
        self.metering_infos = {}
        self.metering_labels = {}
        self.last_report = 0
        self.context = context.get_admin_context_without_session()
        self.metering_loop = None
        super().__init__(host=host)

    def init_host(self):
        super().init_host()
        self.metering_loop = loopingcall.FixedIntervalLoopingCall(
            f=self._metering_loop
        )
        self.metering_loop.start(interval=self.conf.measure_interval)

    def _load_drivers(self):
        """Loads plugin-driver from configuration."""
        LOG.info("Loading Metering driver %s", self.conf.driver)
        if not self.conf.driver:
            raise SystemExit(_('A metering driver must be specified'))
        self.metering_driver = driverutils.load_metering_driver(self,
                                                                self.conf)

    def _metering_notification(self):
        for key, info in self.metering_infos.items():
            data = self.create_notification_message_data(info, key)

            traffic_meter_event = 'l3.meter'

            granularity = info.get('traffic-counter-granularity')
            if granularity:
                traffic_meter_event = 'l3.meter.%s' % granularity

            LOG.debug("Send metering report [%s] via event [%s].",
                      data, traffic_meter_event)

            notifier = n_rpc.get_notifier('metering')
            notifier.info(self.context, traffic_meter_event, data)

            info['pkts'] = 0
            info['bytes'] = 0
            info['time'] = 0

    def create_notification_message_data(self, info, key):
        data = {'pkts': info['pkts'],
                'bytes': info['bytes'],
                'time': info['time'],
                'first_update': info['first_update'],
                'last_update': info['last_update'],
                'host': self.host}

        if self.conf.granular_traffic_data:
            data['resource_id'] = key
            self.set_project_id_for_granular_traffic_data(data, key)
        else:
            data['label_id'] = key
            data['project_id'] = self.label_project_id.get(key)

        LOG.debug("Metering notification created [%s] with info data [%s], "
                  "key[%s], and metering_labels configured [%s]. ", data, info,
                  key, self.metering_labels)
        return data

    def set_project_id_for_granular_traffic_data(self, data, key):
        if driver.BASE_LABEL_TRAFFIC_COUNTER_KEY in key:
            other_ids, actual_label_id = key.split(
                driver.BASE_LABEL_TRAFFIC_COUNTER_KEY)

            is_label_shared = None
            label_name = actual_label_id

            metering_label = self.metering_labels.get(actual_label_id)
            if metering_label:
                is_label_shared = metering_label['shared']
                label_name = metering_label['name']

            data['label_id'] = actual_label_id
            data['label_name'] = label_name
            data['label_shared'] = is_label_shared

            if is_label_shared:
                self.configure_project_id_shared_labels(data, other_ids[:-1])
            else:
                data['project_id'] = self.label_project_id.get(actual_label_id)
        elif driver.BASE_PROJECT_TRAFFIC_COUNTER_KEY in key:
            data['project_id'] = key.split(
                driver.BASE_PROJECT_TRAFFIC_COUNTER_KEY)[1]
        elif driver.BASE_ROUTER_TRAFFIC_COUNTER_KEY in key:
            router_id = key.split(driver.BASE_ROUTER_TRAFFIC_COUNTER_KEY)[1]
            data['router_id'] = router_id
            self.configure_project_id_based_on_router(data, router_id)
        else:
            raise Exception(_("Unexpected key [%s] format.") % key)

    def configure_project_id_shared_labels(self, data, key):
        if driver.BASE_PROJECT_TRAFFIC_COUNTER_KEY in key:
            project_id = key.split(driver.BASE_PROJECT_TRAFFIC_COUNTER_KEY)[1]

            data['project_id'] = project_id
        elif driver.BASE_ROUTER_TRAFFIC_COUNTER_KEY in key:
            router_id = key.split(driver.BASE_ROUTER_TRAFFIC_COUNTER_KEY)[1]

            data['router_id'] = router_id
            self.configure_project_id_based_on_router(data, router_id)
        else:
            data['project_id'] = 'all'

    def configure_project_id_based_on_router(self, data, router_id):
        if router_id in self.routers:
            router = self.routers[router_id]
            data['project_id'] = router['project_id']
        else:
            LOG.warning("Could not find router with ID [%s].", router_id)

    def _purge_metering_info(self):
        deadline_timestamp = timeutils.utcnow_ts() - self.conf.report_interval
        expired_metering_info_key = [
            key for key, info in self.metering_infos.items()
            if info['last_update'] < deadline_timestamp]

        for key in expired_metering_info_key:
            del self.metering_infos[key]

    def _add_metering_info(self, key, traffic_counter):
        granularity = traffic_counter.get('traffic-counter-granularity')

        ts = timeutils.utcnow_ts()
        info = self.metering_infos.get(
            key, {'bytes': 0, 'traffic-counter-granularity': granularity,
                  'pkts': 0, 'time': 0, 'first_update': ts, 'last_update': ts})

        info['bytes'] += traffic_counter['bytes']
        info['pkts'] += traffic_counter['pkts']
        info['time'] += ts - info['last_update']
        info['last_update'] = ts

        self.metering_infos[key] = info

        return info

    def _add_metering_infos(self):
        self.label_project_id = {}
        for router in self.routers.values():
            project_id = router['project_id']
            labels = router.get(constants.METERING_LABEL_KEY, [])
            for label in labels:
                label_id = label['id']
                self.label_project_id[label_id] = project_id

        LOG.debug("Retrieving traffic counters for routers [%s].",
                  self.routers)
        traffic_counters = self._get_traffic_counters(self.context,
                                                      self.routers.values())
        LOG.debug("Traffic counters [%s] retrieved for routers [%s].",
                  traffic_counters, self.routers)
        if not traffic_counters:
            return

        for key, traffic_counter in traffic_counters.items():
            self._add_metering_info(key, traffic_counter)

    def _metering_loop(self):
        self._sync_router_namespaces(self.context, self.routers.values())
        self._add_metering_infos()

        ts = timeutils.utcnow_ts()
        delta = ts - self.last_report

        report_interval = self.conf.report_interval
        if delta >= report_interval:
            self._metering_notification()
            self._purge_metering_info()
            self.last_report = ts

    @runtime.synchronized('metering-agent')
    def _invoke_driver(self, context, meterings, func_name):
        try:
            return getattr(self.metering_driver, func_name)(context, meterings)
        except AttributeError:
            LOG.exception("Driver %(driver)s does not implement %(func)s",
                          {'driver': self.conf.driver,
                           'func': func_name})
        except RuntimeError:
            LOG.exception("Driver %(driver)s:%(func)s runtime error",
                          {'driver': self.conf.driver,
                           'func': func_name})

    @periodic_task.periodic_task(run_immediately=True)
    def _sync_routers_task(self, context):
        routers = self._get_sync_data_metering(self.context)

        routers_on_agent = set(self.routers.keys())
        routers_on_server = set(
            [router['id'] for router in routers] if routers else [])
        for router_id in routers_on_agent - routers_on_server:
            del self.routers[router_id]
            self._invoke_driver(context, router_id, 'remove_router')

        if not routers:
            return
        self._update_routers(context, routers)

    def router_deleted(self, context, router_id):
        self._add_metering_infos()

        if router_id in self.routers:
            del self.routers[router_id]

        return self._invoke_driver(context, router_id,
                                   'remove_router')

    def routers_updated(self, context, routers=None):
        if not routers:
            routers = self._get_sync_data_metering(self.context)
        if not routers:
            return
        self._update_routers(context, routers)

    def _update_routers(self, context, routers):
        for router in routers:
            self.routers[router['id']] = router

            self.store_metering_labels(router)

        return self._invoke_driver(context, routers,
                                   'update_routers')

    def _get_traffic_counters(self, context, routers):
        LOG.debug("Get router traffic counters")
        return self._invoke_driver(context, routers, 'get_traffic_counters')

    def _sync_router_namespaces(self, context, routers):
        LOG.debug("Sync router namespaces")
        return self._invoke_driver(context, routers, 'sync_router_namespaces')

    def add_metering_label_rule(self, context, routers):
        return self._invoke_driver(context, routers,
                                   'add_metering_label_rule')

    def remove_metering_label_rule(self, context, routers):
        return self._invoke_driver(context, routers,
                                   'remove_metering_label_rule')

    def update_metering_label_rules(self, context, routers):
        LOG.debug("Update metering rules from agent")
        return self._invoke_driver(context, routers,
                                   'update_metering_label_rules')

    def add_metering_label(self, context, routers):
        LOG.debug("Creating a metering label from agent with parameters ["
                  "%s].", routers)
        for router in routers:
            self.store_metering_labels(router)

        return self._invoke_driver(context, routers,
                                   'add_metering_label')

    def store_metering_labels(self, router):
        labels = router[constants.METERING_LABEL_KEY]
        for label in labels:
            self.metering_labels[label['id']] = label

    def remove_metering_label(self, context, routers):
        self._add_metering_infos()
        LOG.debug("Delete a metering label from agent with parameters ["
                  "%s].", routers)

        for router in routers:
            labels = router[constants.METERING_LABEL_KEY]
            for label in labels:
                if label['id'] in self.metering_labels.keys():
                    del self.metering_labels[label['id']]

        return self._invoke_driver(context, routers,
                                   'remove_metering_label')


class MeteringAgentWithStateReport(MeteringAgent):

    def __init__(self, host, conf=None):
        super().__init__(host=host, conf=conf)
        self.use_call = True
        self.failed_report_state = False
        self.state_rpc = None
        self.agent_state = {
            'binary': constants.AGENT_PROCESS_METERING,
            'host': self.host,
            'topic': topics.METERING_AGENT,
            'configurations': {
                'metering_driver': self.conf.driver,
                'measure_interval':
                self.conf.measure_interval,
                'report_interval': self.conf.report_interval
            },
            'start_flag': True,
            'agent_type': constants.AGENT_TYPE_METERING}

    def init_host(self):
        self.state_rpc = agent_rpc.PluginReportStateAPI(topics.REPORTS)
        report_interval = cfg.CONF.AGENT.report_interval
        if report_interval:
            self.heartbeat = loopingcall.FixedIntervalLoopingCall(
                f=self._report_state)
            self.heartbeat.start(interval=report_interval)

    def _report_state(self):
        try:
            self.state_rpc.report_state(self.context, self.agent_state,
                                        self.use_call)
            self.agent_state.pop('start_flag', None)
            self.use_call = False
        except AttributeError:
            # This means the server does not support report_state
            LOG.warning("Neutron server does not support state report. "
                        "State report for this agent will be disabled.")
            self.heartbeat.stop()
        except Exception:
            self.failed_report_state = True
            LOG.exception("Failed reporting state!")
            return
        if self.failed_report_state:
            self.failed_report_state = False
            LOG.info("Successfully reported state after a previous failure.")

    def agent_updated(self, context, payload):
        LOG.info("agent_updated by server side %s!", payload)


def main():
    conf = cfg.CONF
    common_config.register_common_config_options()
    metering_agent.register_metering_agent_opts()
    config.register_agent_state_opts_helper(conf)
    common_config.init(sys.argv[1:])
    config.setup_logging()
    common_config.setup_gmr()
    config.setup_privsep()
    server = neutron_service.Service.create(
        binary=constants.AGENT_PROCESS_METERING,
        topic=topics.METERING_AGENT,
        report_interval=cfg.CONF.AGENT.report_interval,
        manager='neutron.services.metering.agents.'
                'metering_agent.MeteringAgentWithStateReport')
    service.launch(cfg.CONF, server, restart_method='mutate').wait()
