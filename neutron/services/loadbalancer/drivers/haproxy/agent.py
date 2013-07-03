# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2013 New Dream Network, LLC (DreamHost)
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
#
# @author: Mark McClain, DreamHost

import eventlet
from oslo.config import cfg

from neutron.agent.common import config
from neutron.agent.linux import interface
from neutron.common import legacy
from neutron.openstack.common.rpc import service as rpc_service
from neutron.openstack.common import service
from neutron.services.loadbalancer.drivers.haproxy import (
    agent_manager as manager,
    plugin_driver
)

OPTS = [
    cfg.IntOpt(
        'periodic_interval',
        default=10,
        help=_('Seconds between periodic task runs')
    )
]


class LbaasAgentService(rpc_service.Service):
    def start(self):
        super(LbaasAgentService, self).start()
        self.tg.add_timer(
            cfg.CONF.periodic_interval,
            self.manager.run_periodic_tasks,
            None,
            None
        )


def main():
    eventlet.monkey_patch()
    cfg.CONF.register_opts(OPTS)
    cfg.CONF.register_opts(manager.OPTS)
    # import interface options just in case the driver uses namespaces
    cfg.CONF.register_opts(interface.OPTS)
    config.register_root_helper(cfg.CONF)

    cfg.CONF(project='neutron')
    legacy.modernize_quantum_config(cfg.CONF)
    config.setup_logging(cfg.CONF)

    mgr = manager.LbaasAgentManager(cfg.CONF)
    svc = LbaasAgentService(
        host=cfg.CONF.host,
        topic=plugin_driver.TOPIC_LOADBALANCER_AGENT,
        manager=mgr
    )
    service.launch(svc).wait()
