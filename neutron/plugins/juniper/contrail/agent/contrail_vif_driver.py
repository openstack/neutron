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

from neutron.agent.linux import interface
from neutron.agent.linux import ip_lib
from neutron.openstack.common import log as logging
from oslo.config import cfg

from contrail_lib import rpc_client_instance
from contrail_lib import uuid_from_string
from vnc_api.vnc_api import *

LOG = logging.getLogger(__name__)


class ContrailInterfaceDriver(interface.LinuxInterfaceDriver):
    """ Opencontrail VIF driver for neutron."""
    def __init__(self, conf):
        super(ContrailInterfaceDriver, self).__init__(conf)
        self._port_dict = {}
        self._client = VncApi(api_server_host='127.0.0.1',
                              api_server_port=8082)

    def _add_port(self, data):
        rpc = rpc_client_instance()
        if not rpc:
            return False
        try:
            rpc.AddPort([data])
        except socket.error:
            LOG.error('RPC failure')
            return False

        return True

    def _delete_port(self, port_id):
        rpc = rpc_client_instance()
        if not rpc:
            return False
        try:
            rpc.DeletePort(port_id)
        except socket.error:
            LOG.error('RPC failure')
            return False

        return True

    def _instance_locate(self, instance_name):
        """ locates the instance."""
        fq_name = instance_name.split(':')
        try:
            vm_instance = self._client.virtual_machine_read(fq_name=fq_name)
            return vm_instance
        except NoIdError:
            pass

    def _add_port_to_agent(self, port_id, net_id, iface_name, mac_address):
        port_obj = self._client.virtual_machine_interface_read(id=port_id)
        if port_obj is None:
            LOG.debug(_("Invalid port_id : %s"), port_id)
            return

        ips = port_obj.get_instance_ip_back_refs()
        ip_addr = '0.0.0.0'
        # get the ip address of the port if associated
        if ips and len(ips):
            ip_uuid = ips[0]['uuid']
            ip = self._client.instance_ip_read(id=ip_uuid)
            ip_addr = ip.get_instance_ip_address()

        net_obj = self._client.virtual_network_read(id=net_id)
        if net_obj is None:
            LOG.debug(_("Invalid net_id : %s"), net_id)
            return

        # get the instance object the port is attached to
        instance_obj = self._instance_locate(port_obj.parent_name)

        if instance_obj is None:
            return

        from nova_contrail_vif.gen_py.instance_service import ttypes
        data = ttypes.Port(uuid_from_string(port_id),
                           uuid_from_string(instance_obj.uuid),
                           iface_name,
                           ip_addr,
                           uuid_from_string(net_id),
                           mac_address,
                           None,
                           None,
                           None,
                           uuid_from_string(net_obj.parent_uuid))

        if self._add_port(data):
            return data

    def plug(self, network_id, port_id, device_name, mac_address,
             bridge=None, namespace=None, prefix=None):
        if not ip_lib.device_exists(device_name, self.root_helper, namespace):
            ip = ip_lib.IPWrapper(self.root_helper)
            tap_name = device_name.replace(prefix or 'veth', 'veth')

            # Create ns_dev in a namespace if one is configured.
            root_dev, ns_dev = ip.add_veth(tap_name,
                                           device_name,
                                           namespace2=namespace)
            ns_dev.link.set_address(mac_address)
            namespace_obj = ip.ensure_namespace(namespace)
            namespace_obj.add_device_to_namespace(ns_dev)
            ns_dev.link.set_up()
            root_dev.link.set_up()

            port_data = self._add_port_to_agent(port_id, network_id,
                                                tap_name, mac_address)
            if port_data is None:
                LOG.warn(_("Failed adding %s to the interface"), device_name)
                return

            self._port_dict[tap_name] = port_data
        else:
            LOG.warn(_("Device %s already exists"), device_name)

    def unplug(self, device_name, bridge=None, namespace=None, prefix=None):
        tap_name = device_name.replace(prefix or 'veth', 'veth')
        if tap_name in self._port_dict:
            self._delete_port(self._port_dict[tap_name].port_id)
            del self._port_dict[tap_name]

        device = ip_lib.IPDevice(device_name, self.root_helper, namespace)
        device.link.delete()
        LOG.debug(_("Unplugged interface '%s'"), device_name)
        ip_lib.IPWrapper(
            self.root_helper, namespace).garbage_collect_namespace()
