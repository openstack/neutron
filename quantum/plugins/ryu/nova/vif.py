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

import httplib

from ryu.app.client import OFPClient

from nova import flags
from nova.openstack.common import cfg
from nova.openstack.common import log as logging
from nova import utils
from nova.virt.libvirt import vif as libvirt_vif


LOG = logging.getLogger(__name__)

ryu_libvirt_ovs_driver_opt = cfg.StrOpt('libvirt_ovs_ryu_api_host',
                                        default='127.0.0.1:8080',
                                        help='Openflow Ryu REST API host:port')

FLAGS = flags.FLAGS
FLAGS.register_opt(ryu_libvirt_ovs_driver_opt)


def _get_datapath_id(bridge_name):
    out, _err = utils.execute('ovs-vsctl', 'get', 'Bridge',
                              bridge_name, 'datapath_id', run_as_root=True)
    return out.strip().strip('"')


def _get_port_no(dev):
    out, _err = utils.execute('ovs-vsctl', 'get', 'Interface', dev,
                              'ofport', run_as_root=True)
    return int(out.strip())


class LibvirtOpenVswitchOFPRyuDriver(libvirt_vif.LibvirtHybridOVSBridgeDriver):
    def __init__(self, **kwargs):
        super(LibvirtOpenVswitchOFPRyuDriver, self).__init__()
        LOG.debug('ryu rest host %s', FLAGS.libvirt_ovs_bridge)
        self.ryu_client = OFPClient(FLAGS.libvirt_ovs_ryu_api_host)
        self.datapath_id = _get_datapath_id(FLAGS.libvirt_ovs_bridge)

    def _get_port_no(self, mapping):
        iface_id = mapping['vif_uuid']
        _v1_name, v2_name = self.get_veth_pair_names(iface_id)
        return _get_port_no(v2_name)

    def plug(self, instance, vif):
        result = super(LibvirtOpenVswitchOFPRyuDriver, self).plug(
            instance, vif)
        network, mapping = vif
        port_no = self._get_port_no(mapping)
        try:
            self.ryu_client.create_port(network['id'], self.datapath_id,
                                        port_no)
        except httplib.HTTPException as e:
            res = e.args[0]
            if res.status != httplib.CONFLICT:
                raise
        return result

    def unplug(self, instance, vif):
        network, mapping = vif
        port_no = self._get_port_no(mapping)
        try:
            self.ryu_client.delete_port(network['id'],
                                        self.datapath_id, port_no)
        except httplib.HTTPException as e:
            res = e.args[0]
            if res.status != httplib.NOT_FOUND:
                raise
        super(LibvirtOpenVswitchOFPRyuDriver, self).unplug(instance, vif)
