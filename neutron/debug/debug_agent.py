# Copyright 2012,  Nachi Ueno,  NTT MCL,  Inc.
# All Rights Reserved.
#
#    Licensed under the Apache License,  Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing,  software
#    distributed under the License is distributed on an "AS IS" BASIS,  WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND,  either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import shlex
import socket

import netaddr
from neutron_lib.api.definitions import portbindings
from neutron_lib import constants
from oslo_log import log as logging

from neutron.agent.linux import dhcp
from neutron.agent.linux import ip_lib

LOG = logging.getLogger(__name__)

DEVICE_OWNER_NETWORK_PROBE = constants.DEVICE_OWNER_NETWORK_PREFIX + 'probe'

DEVICE_OWNER_COMPUTE_PROBE = constants.DEVICE_OWNER_COMPUTE_PREFIX + 'probe'


class NeutronDebugAgent(object):

    def __init__(self, conf, client, driver):
        self.conf = conf
        self.client = client
        self.driver = driver

    def _get_namespace(self, port):
        return "qprobe-%s" % port.id

    def create_probe(self, network_id, device_owner='network'):
        network = self._get_network(network_id)

        port = self._create_port(network, device_owner)
        interface_name = self.driver.get_device_name(port)
        namespace = self._get_namespace(port)

        if ip_lib.device_exists(interface_name, namespace=namespace):
            LOG.debug('Reusing existing device: %s.', interface_name)
        else:
            self.driver.plug(network.id,
                             port.id,
                             interface_name,
                             port.mac_address,
                             namespace=namespace)
        ip_cidrs = []
        for fixed_ip in port.fixed_ips:
            subnet = fixed_ip.subnet
            net = netaddr.IPNetwork(subnet.cidr)
            ip_cidr = '%s/%s' % (fixed_ip.ip_address, net.prefixlen)
            ip_cidrs.append(ip_cidr)
        self.driver.init_l3(interface_name, ip_cidrs, namespace=namespace)
        return port

    def _get_subnet(self, subnet_id):
        subnet_dict = self.client.show_subnet(subnet_id)['subnet']
        return dhcp.DictModel(subnet_dict)

    def _get_network(self, network_id):
        network_dict = self.client.show_network(network_id)['network']
        network = dhcp.DictModel(network_dict)
        # pylint: disable=assigning-non-slot
        network.external = network_dict.get('router:external')
        obj_subnet = [self._get_subnet(s_id) for s_id in network.subnets]
        network.subnets = obj_subnet
        return network

    def clear_probes(self):
        """Returns number of deleted probes"""
        ports = self.client.list_ports(
            device_id=socket.gethostname(),
            device_owner=[DEVICE_OWNER_NETWORK_PROBE,
                          DEVICE_OWNER_COMPUTE_PROBE])
        info = ports['ports']
        for port in info:
            self.delete_probe(port['id'])
        return len(info)

    def delete_probe(self, port_id):
        port = dhcp.DictModel(self.client.show_port(port_id)['port'])
        namespace = self._get_namespace(port)
        if ip_lib.network_namespace_exists(namespace):
            self.driver.unplug(self.driver.get_device_name(port),
                               namespace=namespace)
            try:
                ip_lib.delete_network_namespace(namespace)
            except Exception:
                LOG.warning('Failed to delete namespace %s', namespace)
        else:
            self.driver.unplug(self.driver.get_device_name(port))
        self.client.delete_port(port.id)

    def list_probes(self):
        ports = self.client.list_ports(
            device_owner=[DEVICE_OWNER_NETWORK_PROBE,
                          DEVICE_OWNER_COMPUTE_PROBE])
        info = ports['ports']
        for port in info:
            port['device_name'] = self.driver.get_device_name(
                dhcp.DictModel(port))
        return info

    def exec_command(self, port_id, command=None):
        port = dhcp.DictModel(self.client.show_port(port_id)['port'])
        ip = ip_lib.IPWrapper()
        namespace = self._get_namespace(port)
        if not command:
            return "sudo ip netns exec %s" % self._get_namespace(port)
        namespace = ip.ensure_namespace(namespace)
        return namespace.netns.execute(shlex.split(command))

    def ensure_probe(self, network_id):
        ports = self.client.list_ports(network_id=network_id,
                                       device_id=socket.gethostname(),
                                       device_owner=DEVICE_OWNER_NETWORK_PROBE)
        info = ports.get('ports', [])
        if info:
            return dhcp.DictModel(info[0])
        else:
            return self.create_probe(network_id)

    def ping_all(self, network_id=None, timeout=1):
        if network_id:
            ports = self.client.list_ports(network_id=network_id)['ports']
        else:
            ports = self.client.list_ports()['ports']
        result = ""
        for port in ports:
            probe = self.ensure_probe(port['network_id'])
            if port['device_owner'] == DEVICE_OWNER_NETWORK_PROBE:
                continue
            for fixed_ip in port['fixed_ips']:
                address = fixed_ip['ip_address']
                subnet = self._get_subnet(fixed_ip['subnet_id'])
                if subnet.ip_version == 4:
                    ping_command = 'ping'
                else:
                    ping_command = 'ping6'
                result += self.exec_command(probe.id,
                                            '%s -c 1 -w %s %s' % (ping_command,
                                                                  timeout,
                                                                  address))
        return result

    def _create_port(self, network, device_owner):
        host = self.conf.host
        body = {'port': {'admin_state_up': True,
                         'network_id': network.id,
                         'device_id': '%s' % socket.gethostname(),
                         'device_owner': '%s:probe' % device_owner,
                         'tenant_id': network.tenant_id,
                         portbindings.HOST_ID: host,
                         'fixed_ips': [dict(subnet_id=s.id)
                                       for s in network.subnets]}}
        port_dict = self.client.create_port(body)['port']
        port = dhcp.DictModel(port_dict)
        # pylint: disable=assigning-non-slot
        port.network = network
        for fixed_ip in port.fixed_ips:
            fixed_ip.subnet = self._get_subnet(fixed_ip.subnet_id)
        return port
