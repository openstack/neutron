# Copyright 2014 OpenStack Foundation
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

import jinja2
import netaddr
from oslo_config import cfg
import six

from neutron.agent.linux import external_process
from neutron.agent.linux import utils
from neutron.common import constants
from neutron.openstack.common import log as logging


RADVD_SERVICE_NAME = 'radvd'
RADVD_SERVICE_CMD = 'radvd'

LOG = logging.getLogger(__name__)

OPTS = [
    cfg.StrOpt('ra_confs',
               default='$state_path/ra',
               help=_('Location to store IPv6 RA config files')),
]

cfg.CONF.register_opts(OPTS)

CONFIG_TEMPLATE = jinja2.Template("""interface {{ interface_name }}
{
   AdvSendAdvert on;
   MinRtrAdvInterval 3;
   MaxRtrAdvInterval 10;

   {% if ra_mode == constants.DHCPV6_STATELESS %}
   AdvOtherConfigFlag on;
   {% endif %}

   {% if ra_mode == constants.DHCPV6_STATEFUL %}
   AdvManagedFlag on;
   {% endif %}

   {% if ra_mode in (constants.IPV6_SLAAC, constants.DHCPV6_STATELESS) %}
   prefix {{ prefix }}
   {
        AdvOnLink on;
        AdvAutonomous on;
   };
   {% endif %}
};
""")


class DaemonMonitor(object):
    """Manage the data and state of an radvd process."""

    def __init__(self, router_id, router_ns, process_monitor, dev_name_helper):
        self._router_id = router_id
        self._router_ns = router_ns
        self._process_monitor = process_monitor
        self._dev_name_helper = dev_name_helper

    def _generate_radvd_conf(self, router_ports):
        radvd_conf = utils.get_conf_file_name(cfg.CONF.ra_confs,
                                              self._router_id,
                                              'radvd.conf',
                                              True)
        buf = six.StringIO()
        for p in router_ports:
            prefix = p['subnet']['cidr']
            if netaddr.IPNetwork(prefix).version == 6:
                interface_name = self._dev_name_helper(p['id'])
                ra_mode = p['subnet']['ipv6_ra_mode']
                buf.write('%s' % CONFIG_TEMPLATE.render(
                    ra_mode=ra_mode,
                    interface_name=interface_name,
                    prefix=prefix,
                    constants=constants))

        utils.replace_file(radvd_conf, buf.getvalue())
        return radvd_conf

    def _get_radvd_process_manager(self, callback=None):
        return external_process.ProcessManager(
            uuid=self._router_id,
            default_cmd_callback=callback,
            namespace=self._router_ns,
            service=RADVD_SERVICE_NAME,
            conf=cfg.CONF)

    def _spawn_radvd(self, radvd_conf):
        def callback(pid_file):
            # we need to use -m syslog and f.e. not -m stderr (the default)
            # or -m stderr_syslog so that radvd 2.0+ will close stderr and
            # exit after daemonization; otherwise, the current thread will
            # be locked waiting for result from radvd that won't ever come
            # until the process dies
            radvd_cmd = [RADVD_SERVICE_CMD,
                         '-C', '%s' % radvd_conf,
                         '-p', '%s' % pid_file,
                         '-m', 'syslog']
            return radvd_cmd

        pm = self._get_radvd_process_manager(callback)
        pm.enable(reload_cfg=True)
        self._process_monitor.register(uuid=self._router_id,
                                       service_name=RADVD_SERVICE_NAME,
                                       monitored_process=pm)
        LOG.debug("radvd enabled for router %s", self._router_id)

    def enable(self, router_ports):
        for p in router_ports:
            if netaddr.IPNetwork(p['subnet']['cidr']).version == 6:
                break
        else:
            # Kill the daemon if it's running
            self.disable()
            return

        LOG.debug("Enable IPv6 RA for router %s", self._router_id)
        radvd_conf = self._generate_radvd_conf(router_ports)
        self._spawn_radvd(radvd_conf)

    def disable(self):
        self._process_monitor.unregister(uuid=self._router_id,
                                         service_name=RADVD_SERVICE_NAME)
        pm = self._get_radvd_process_manager()
        pm.disable()
        utils.remove_conf_files(cfg.CONF.ra_confs, self._router_id)
        LOG.debug("radvd disabled for router %s", self._router_id)

    @property
    def enabled(self):
        return self._get_radvd_process_manager().active
