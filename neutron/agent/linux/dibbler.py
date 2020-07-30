# Copyright 2015 Cisco Systems
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

import io
import os
import shutil

import jinja2
from neutron_lib import constants as lib_const
from neutron_lib.utils import file as file_utils
from oslo_config import cfg
from oslo_log import log as logging

from neutron.agent.linux import external_process
from neutron.agent.linux import pd
from neutron.agent.linux import pd_driver
from neutron.agent.linux import utils

LOG = logging.getLogger(__name__)

PD_SERVICE_NAME = 'dibbler'
CONFIG_TEMPLATE = jinja2.Template("""
# Config for dibbler-client.

# Use enterprise number based duid
duid-type duid-en {{ enterprise_number }} {{ va_id }}

# 8 (Debug) is most verbose. 7 (Info) is usually the best option
log-level 8

# No automatic downlink address assignment
downlink-prefix-ifaces "none"

# Use script to notify l3_agent of assigned prefix
script {{ script_path }}

# Ask for prefix over the external gateway interface
iface {{ interface_name }} {
# Bind to generated LLA
bind-to-address {{ bind_address }}
# ask for address
   {% if hint_prefix != None %}
    pd 1 {
        prefix {{ hint_prefix }}
    }
   {% else %}
    pd 1
   {% endif %}
}
""")

# The first line must be #!/usr/bin/env bash
SCRIPT_TEMPLATE = jinja2.Template("""#!/usr/bin/env bash

exec neutron-pd-notify $1 {{ prefix_path }} {{ l3_agent_pid }}
""")


class PDDibbler(pd_driver.PDDriverBase):
    def __init__(self, router_id, subnet_id, ri_ifname):
        super(PDDibbler, self).__init__(router_id, subnet_id, ri_ifname)
        self.requestor_id = "%s:%s:%s" % (self.router_id,
                                          self.subnet_id,
                                          self.ri_ifname)
        self.dibbler_client_working_area = "%s/%s" % (cfg.CONF.pd_confs,
                                                      self.requestor_id)
        self.prefix_path = "%s/prefix" % self.dibbler_client_working_area
        self.pid_path = "%s/client.pid" % self.dibbler_client_working_area
        self.converted_subnet_id = self.subnet_id.replace('-', '')

    def _is_dibbler_client_running(self):
        return utils.get_value_from_file(self.pid_path)

    def _generate_dibbler_conf(self, ex_gw_ifname, lla, hint_prefix):
        dcwa = self.dibbler_client_working_area
        script_path = utils.get_conf_file_name(dcwa, 'notify', 'sh', True)
        buf = io.StringIO()
        buf.write('%s' % SCRIPT_TEMPLATE.render(
                             prefix_path=self.prefix_path,
                             l3_agent_pid=os.getpid()))
        file_utils.replace_file(script_path, buf.getvalue())
        os.chmod(script_path, 0o744)

        dibbler_conf = utils.get_conf_file_name(dcwa, 'client', 'conf', False)
        buf = io.StringIO()
        buf.write('%s' % CONFIG_TEMPLATE.render(
                             enterprise_number=cfg.CONF.vendor_pen,
                             va_id='0x%s' % self.converted_subnet_id,
                             script_path='"%s/notify.sh"' % dcwa,
                             interface_name='"%s"' % ex_gw_ifname,
                             bind_address='%s' % lla,
                             hint_prefix=hint_prefix))

        file_utils.replace_file(dibbler_conf, buf.getvalue())
        return dcwa

    def _spawn_dibbler(self, pmon, router_ns, dibbler_conf):
        def callback(pid_file):
            dibbler_cmd = ['dibbler-client',
                           'start',
                           '-w', '%s' % dibbler_conf]
            return dibbler_cmd

        pm = external_process.ProcessManager(
            uuid=self.requestor_id,
            default_cmd_callback=callback,
            namespace=router_ns,
            service=PD_SERVICE_NAME,
            conf=cfg.CONF,
            pid_file=self.pid_path)
        pm.enable(reload_cfg=False)
        pmon.register(uuid=self.requestor_id,
                      service_name=PD_SERVICE_NAME,
                      monitored_process=pm)

    def enable(self, pmon, router_ns, ex_gw_ifname, lla, prefix=None):
        LOG.debug("Enable IPv6 PD for router %s subnet %s ri_ifname %s",
                  self.router_id, self.subnet_id, self.ri_ifname)
        if not self._is_dibbler_client_running():
            dibbler_conf = self._generate_dibbler_conf(ex_gw_ifname,
                                                       lla, prefix)
            self._spawn_dibbler(pmon, router_ns, dibbler_conf)
            LOG.debug("dibbler client enabled for router %s subnet %s"
                      " ri_ifname %s",
                      self.router_id, self.subnet_id, self.ri_ifname)

    def disable(self, pmon, router_ns, switch_over=False):
        LOG.debug("Disable IPv6 PD for router %s subnet %s ri_ifname %s",
                  self.router_id, self.subnet_id, self.ri_ifname)
        dcwa = self.dibbler_client_working_area

        def callback(pid_file):
            dibbler_cmd = ['dibbler-client',
                           'stop',
                           '-w', '%s' % dcwa]
            return dibbler_cmd

        pmon.unregister(uuid=self.requestor_id,
                        service_name=PD_SERVICE_NAME)
        pm = external_process.ProcessManager(
                uuid=self.requestor_id,
                namespace=router_ns,
                service=PD_SERVICE_NAME,
                conf=cfg.CONF,
                pid_file=self.pid_path)
        if switch_over:
            pm.disable()
        else:
            pm.disable(get_stop_command=callback)
        shutil.rmtree(dcwa, ignore_errors=True)
        LOG.debug("dibbler client disabled for router %s subnet %s "
                  "ri_ifname %s",
                  self.router_id, self.subnet_id, self.ri_ifname)

    def get_prefix(self):
        prefix = utils.get_value_from_file(self.prefix_path)
        if not prefix:
            prefix = lib_const.PROVISIONAL_IPV6_PD_PREFIX
        return prefix

    @staticmethod
    def get_sync_data():
        try:
            requestor_ids = os.listdir(cfg.CONF.pd_confs)
        except OSError:
            return []

        sync_data = []
        requestors = (r.split(':') for r in requestor_ids if r.count(':') == 2)
        for router_id, subnet_id, ri_ifname in requestors:
            pd_info = pd.PDInfo()
            pd_info.router_id = router_id
            pd_info.subnet_id = subnet_id
            pd_info.ri_ifname = ri_ifname
            pd_info.driver = PDDibbler(router_id, subnet_id, ri_ifname)
            pd_info.client_started = (
                pd_info.driver._is_dibbler_client_running())
            pd_info.prefix = pd_info.driver.get_prefix()
            sync_data.append(pd_info)

        return sync_data
