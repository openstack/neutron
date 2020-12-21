# Copyright (C) 2015 VA Linux Systems Japan K.K.
# Copyright (C) 2015 YAMAMOTO Takashi <yamamoto at valinux co jp>
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

import functools

import os_ken.app.ofctl.api  # noqa
from os_ken.base import app_manager
from os_ken.lib import hub
from oslo_log import log as logging
from oslo_utils import excutils

from neutron.plugins.ml2.drivers.openvswitch.agent.openflow.native \
    import base_oskenapp
from neutron.plugins.ml2.drivers.openvswitch.agent.openflow.native \
    import br_int
from neutron.plugins.ml2.drivers.openvswitch.agent.openflow.native \
    import br_phys
from neutron.plugins.ml2.drivers.openvswitch.agent.openflow.native \
    import br_tun
from neutron.plugins.ml2.drivers.openvswitch.agent \
    import ovs_neutron_agent as ovs_agent

LOG = logging.getLogger(__name__)


def agent_main_wrapper(bridge_classes):
    try:
        ovs_agent.main(bridge_classes)
    except Exception:
        with excutils.save_and_reraise_exception():
            LOG.exception("Agent main thread died of an exception")
    finally:
        # The following call terminates os-ken's AppManager.run_apps(),
        # which is needed for clean shutdown of an agent process.
        # The close() call must be called in another thread, otherwise
        # it suicides and ends prematurely.
        hub.spawn(app_manager.AppManager.get_instance().close)


class OVSNeutronAgentOSKenApp(base_oskenapp.BaseNeutronAgentOSKenApp):
    def start(self):
        # Start os-ken event loop thread
        super(OVSNeutronAgentOSKenApp, self).start()

        def _make_br_cls(br_cls):
            return functools.partial(br_cls, os_ken_app=self)

        # Start agent main loop thread
        bridge_classes = {
            'br_int': _make_br_cls(br_int.OVSIntegrationBridge),
            'br_phys': _make_br_cls(br_phys.OVSPhysicalBridge),
            'br_tun': _make_br_cls(br_tun.OVSTunnelBridge),
        }
        return hub.spawn(agent_main_wrapper, bridge_classes, raise_error=True)
