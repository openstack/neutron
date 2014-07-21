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

import netaddr
from oslo.config import cfg
import six

from neutron.agent.linux import external_process
from neutron.agent.linux import utils
from neutron.common import constants
from neutron.openstack.common import log as logging


LOG = logging.getLogger(__name__)

OPTS = [
    cfg.StrOpt('ra_confs',
               default='$state_path/ra',
               help=_('Location to store IPv6 RA config files')),
]

cfg.CONF.register_opts(OPTS)

prefix_fmt = """interface %s
{
   AdvSendAdvert on;
   MinRtrAdvInterval 3;
   MaxRtrAdvInterval 10;
   prefix %s
   {
        AdvOnLink on;
        AdvAutonomous on;
   };
};
"""

default_fmt = """interface %s
{
   AdvSendAdvert on;
   MinRtrAdvInterval 3;
   MaxRtrAdvInterval 10;
};
"""


def _is_slaac(ra_mode):
    return (ra_mode == constants.IPV6_SLAAC or
            ra_mode == constants.DHCPV6_STATELESS)


def _generate_radvd_conf(router_id, router_ports, dev_name_helper):
    radvd_conf = utils.get_conf_file_name(cfg.CONF.ra_confs,
                                          router_id,
                                          'radvd.conf',
                                          True)
    buf = six.StringIO()
    for p in router_ports:
        if netaddr.IPNetwork(p['subnet']['cidr']).version == 6:
            interface_name = dev_name_helper(p['id'])
            if _is_slaac(p['subnet']['ipv6_ra_mode']):
                conf_str = prefix_fmt % (interface_name,
                                         p['subnet']['cidr'])
            else:
                conf_str = default_fmt % interface_name
            buf.write('%s' % conf_str)

    utils.replace_file(radvd_conf, buf.getvalue())
    return radvd_conf


def _spawn_radvd(router_id, radvd_conf, router_ns, root_helper):
    def callback(pid_file):
        radvd_cmd = ['radvd',
                     '-C', '%s' % radvd_conf,
                     '-p', '%s' % pid_file]
        return radvd_cmd

    radvd = external_process.ProcessManager(cfg.CONF,
                                            router_id,
                                            root_helper,
                                            router_ns,
                                            'radvd')
    radvd.enable(callback, True)
    LOG.debug("radvd enabled for router %s", router_id)


def enable_ipv6_ra(router_id, router_ns, router_ports,
                   dev_name_helper, root_helper):
    for p in router_ports:
        if netaddr.IPNetwork(p['subnet']['cidr']).version == 6:
            break
    else:
        # Kill the daemon if it's running
        disable_ipv6_ra(router_id, router_ns, root_helper)
        return

    LOG.debug("Enable IPv6 RA for router %s", router_id)
    radvd_conf = _generate_radvd_conf(router_id, router_ports, dev_name_helper)
    _spawn_radvd(router_id, radvd_conf, router_ns, root_helper)


def disable_ipv6_ra(router_id, router_ns, root_helper):
    radvd = external_process.ProcessManager(cfg.CONF,
                                            router_id,
                                            root_helper,
                                            router_ns,
                                            'radvd')
    radvd.disable()
    utils.remove_conf_files(cfg.CONF.ra_confs, router_id)
    LOG.debug("radvd disabled for router %s", router_id)
