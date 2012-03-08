# vim: tabstop=4 shiftwidth=4 softtabstop=4
# Copyright 2012 Isaku Yamahata <yamahata at private email ne jp>
#                               <yamahata at valinux co jp>
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

from nova import flags
from nova import log as logging
from nova import utils
from nova.network import linux_net
from nova.openstack.common import cfg
from ryu.app.client import OFPClient

LOG = logging.getLogger(__name__)

ryu_linux_net_opt = cfg.StrOpt('linuxnet_ovs_ryu_api_host',
                               default='127.0.0.1:8080',
                               help='Openflow Ryu REST API host:port')

FLAGS = flags.FLAGS
FLAGS.register_opt(ryu_linux_net_opt)


def _get_datapath_id(bridge_name):
    out, _err = utils.execute('ovs-vsctl', 'get', 'Bridge',
                              bridge_name, 'datapath_id', run_as_root=True)
    return out.strip().strip('"')


def _get_port_no(dev):
    out, _err = utils.execute('ovs-vsctl', 'get', 'Interface', dev,
                              'ofport', run_as_root=True)
    return int(out.strip())


class LinuxOVSRyuInterfaceDriver(linux_net.LinuxOVSInterfaceDriver):
    def __init__(self):
        super(LinuxOVSRyuInterfaceDriver, self).__init__()

        LOG.debug('ryu rest host %s', FLAGS.linuxnet_ovs_ryu_api_host)
        self.ryu_client = OFPClient(FLAGS.linuxnet_ovs_ryu_api_host)
        self.datapath_id = _get_datapath_id(
            FLAGS.linuxnet_ovs_integration_bridge)

        if linux_net.binary_name == 'nova-network':
            for tables in [linux_net.iptables_manager.ipv4,
                           linux_net.iptables_manager.ipv6]:
                tables['filter'].add_rule('FORWARD',
                        '--in-interface gw-+ --out-interface gw-+ -j DROP')
            linux_net.iptables_manager.apply()

    def plug(self, network, mac_address, gateway=True):
        LOG.debug("network %s mac_adress %s gateway %s",
                  network, mac_address, gateway)
        ret = super(LinuxOVSRyuInterfaceDriver, self).plug(
            network, mac_address, gateway)

        port_no = _get_port_no(self.get_dev(network))
        self.ryu_client.create_port(network['uuid'], self.datapath_id, port_no)
        return ret
