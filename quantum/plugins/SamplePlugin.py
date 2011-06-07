# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2011, Nicira Networks, Inc.
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
# @author: Somik Behera, Nicira Networks, Inc.

from quantum.common import exceptions as exc


class QuantumEchoPlugin(object):

    """
    QuantumEchoPlugin is a demo plugin that doesn't
    do anything but demonstrated the concept of a
    concrete Quantum Plugin. Any call to this plugin
    will result in just a "print" to std. out with
    the name of the method that was called.
    """

    def get_all_networks(self, tenant_id):
        """
        Returns a dictionary containing all
        <network_uuid, network_name> for
        the specified tenant.
        """
        print("get_all_networks() called\n")

    def create_network(self, tenant_id, net_name):
        """
        Creates a new Virtual Network, and assigns it
        a symbolic name.
        """
        print("create_network() called\n")

    def delete_network(self, tenant_id, net_id):
        """
        Deletes the network with the specified network identifier
        belonging to the specified tenant.
        """
        print("delete_network() called\n")

    def get_network_details(self, tenant_id, net_id):
        """
        Deletes the Virtual Network belonging to a the
        spec
        """
        print("get_network_details() called\n")

    def rename_network(self, tenant_id, net_id, new_name):
        """
        Updates the symbolic name belonging to a particular
        Virtual Network.
        """
        print("rename_network() called\n")

    def get_all_ports(self, tenant_id, net_id):
        """
        Retrieves all port identifiers belonging to the
        specified Virtual Network.
        """
        print("get_all_ports() called\n")

    def create_port(self, tenant_id, net_id):
        """
        Creates a port on the specified Virtual Network.
        """
        print("create_port() called\n")

    def delete_port(self, tenant_id, net_id, port_id):
        """
        Deletes a port on a specified Virtual Network,
        if the port contains a remote interface attachment,
        the remote interface is first un-plugged and then the port
        is deleted.
        """
        print("delete_port() called\n")

    def get_port_details(self, tenant_id, net_id, port_id):
        """
        This method allows the user to retrieve a remote interface
        that is attached to this particular port.
        """
        print("get_port_details() called\n")

    def plug_interface(self, tenant_id, net_id, port_id, remote_interface_id):
        """
        Attaches a remote interface to the specified port on the
        specified Virtual Network.
        """
        print("plug_interface() called\n")

    def unplug_interface(self, tenant_id, net_id, port_id):
        """
        Detaches a remote interface from the specified port on the
        specified Virtual Network.
        """
        print("unplug_interface() called\n")

    def get_interface_details(self, tenant_id, net_id, port_id):
        """
        Retrieves the remote interface that is attached at this
        particular port.
        """
        print("get_interface_details() called\n")

    def get_all_attached_interfaces(self, tenant_id, net_id):
        """
        Retrieves all remote interfaces that are attached to
        a particular Virtual Network.
        """
        print("get_all_attached_interfaces() called\n")


class DummyDataPlugin(object):

    """
    DummyDataPlugin is a demo plugin that provides
    hard-coded data structures to aid in quantum
    client/cli development
    """

    def get_all_networks(self, tenant_id):
        """
        Returns a dictionary containing all
        <network_uuid, network_name> for
        the specified tenant.
        """
        nets = {"001": "lNet1", "002": "lNet2", "003": "lNet3"}
        print("get_all_networks() called\n")
        return nets

    def create_network(self, tenant_id, net_name):
        """
        Creates a new Virtual Network, and assigns it
        a symbolic name.
        """
        print("create_network() called\n")
        # return network_id of the created network
        return 101

    def delete_network(self, tenant_id, net_id):
        """
        Deletes the network with the specified network identifier
        belonging to the specified tenant.
        """
        print("delete_network() called\n")

    def get_network_details(self, tenant_id, net_id):
        """
        retrieved a list of all the remote vifs that
        are attached to the network
        """
        print("get_network_details() called\n")
        vifs_on_net = ["/tenant1/networks/net_id/portid/vif2.0",
                       "/tenant1/networks/10/121/vif1.1"]
        return vifs_on_net

    def rename_network(self, tenant_id, net_id, new_name):
        """
        Updates the symbolic name belonging to a particular
        Virtual Network.
        """
        print("rename_network() called\n")

    def get_all_ports(self, tenant_id, net_id):
        """
        Retrieves all port identifiers belonging to the
        specified Virtual Network.
        """
        print("get_all_ports() called\n")
        port_ids_on_net = ["2", "3", "4"]
        return port_ids_on_net

    def create_port(self, tenant_id, net_id):
        """
        Creates a port on the specified Virtual Network.
        """
        print("create_port() called\n")
        #return the port id
        return 201

    def delete_port(self, tenant_id, net_id, port_id):
        """
        Deletes a port on a specified Virtual Network,
        if the port contains a remote interface attachment,
        the remote interface is first un-plugged and then the port
        is deleted.
        """
        print("delete_port() called\n")

    def get_port_details(self, tenant_id, net_id, port_id):
        """
        This method allows the user to retrieve a remote interface
        that is attached to this particular port.
        """
        print("get_port_details() called\n")
        #returns the remote interface UUID
        return "/tenant1/networks/net_id/portid/vif2.1"

    def plug_interface(self, tenant_id, net_id, port_id, remote_interface_id):
        """
        Attaches a remote interface to the specified port on the
        specified Virtual Network.
        """
        print("plug_interface() called\n")

    def unplug_interface(self, tenant_id, net_id, port_id):
        """
        Detaches a remote interface from the specified port on the
        specified Virtual Network.
        """
        print("unplug_interface() called\n")

    def get_interface_details(self, tenant_id, net_id, port_id):
        """
        Retrieves the remote interface that is attached at this
        particular port.
        """
        print("get_interface_details() called\n")
        #returns the remote interface UUID
        return "/tenant1/networks/net_id/portid/vif2.0"

    def get_all_attached_interfaces(self, tenant_id, net_id):
        """
        Retrieves all remote interfaces that are attached to
        a particular Virtual Network.
        """
        print("get_all_attached_interfaces() called\n")
        # returns a list of all attached remote interfaces
        vifs_on_net = ["/tenant1/networks/net_id/portid/vif2.0",
                       "/tenant1/networks/10/121/vif1.1"]
        return vifs_on_net


class FakePlugin(object):
    """
    FakePlugin is a demo plugin that provides
    in-memory data structures to aid in quantum
    client/cli/api development
    """

    #static data for networks and ports
    _port_dict_1 = {
                   1: {'port-id': 1,
                       'port-state': 'DOWN',
                       'attachment': None},
                   2: {'port-id': 2,
                       'port-state': 'UP',
                       'attachment': None}
                   }
    _port_dict_2 = {
                   1: {'port-id': 1,
                       'port-state': 'UP',
                       'attachment': 'SomeFormOfVIFID'},
                   2: {'port-id': 2,
                       'port-state': 'DOWN',
                       'attachment': None}
                   }
    _networks = {'001':
                    {
                    'net-id': '001',
                    'net-name': 'pippotest',
                    'net-ports': _port_dict_1
                    },
                    '002':
                    {
                    'net-id': '002',
                    'net-name': 'cicciotest',
                    'net-ports': _port_dict_2
                    }}

    def __init__(self):
        FakePlugin._net_counter = len(FakePlugin._networks)

    def _get_network(self, tenant_id, network_id):
        network = FakePlugin._networks.get(network_id)
        if not network:
            raise exc.NetworkNotFound(net_id=network_id)
        return network

    def _get_port(self, tenant_id, network_id, port_id):
        net = self._get_network(tenant_id, network_id)
        port = net['net-ports'].get(int(port_id))
        if not port:
            raise exc.PortNotFound(net_id=network_id, port_id=port_id)
        return port

    def _validate_port_state(self, port_state):
        if port_state.upper() not in ('UP', 'DOWN'):
            raise exc.StateInvalid(port_state=port_state)
        return True

    def _validate_attachment(self, tenant_id, network_id, port_id,
                             remote_interface_id):
        network = self._get_network(tenant_id, network_id)
        for port in network['net-ports'].values():
            if port['attachment'] == remote_interface_id:
                raise exc.AlreadyAttached(net_id=network_id,
                                          port_id=port_id,
                                          att_id=port['attachment'],
                                          att_port_id=port['port-id'])

    def get_all_networks(self, tenant_id):
        """
        Returns a dictionary containing all
        <network_uuid, network_name> for
        the specified tenant.
        """
        print("get_all_networks() called\n")
        return FakePlugin._networks.values()

    def get_network_details(self, tenant_id, net_id):
        """
        retrieved a list of all the remote vifs that
        are attached to the network
        """
        print("get_network_details() called\n")
        return self._get_network(tenant_id, net_id)

    def create_network(self, tenant_id, net_name):
        """
        Creates a new Virtual Network, and assigns it
        a symbolic name.
        """
        print("create_network() called\n")
        FakePlugin._net_counter += 1
        new_net_id = ("0" * (3 - len(str(FakePlugin._net_counter)))) + \
                    str(FakePlugin._net_counter)
        print new_net_id
        new_net_dict = {'net-id': new_net_id,
                        'net-name': net_name,
                        'net-ports': {}}
        FakePlugin._networks[new_net_id] = new_net_dict
        # return network_id of the created network
        return new_net_dict

    def delete_network(self, tenant_id, net_id):
        """
        Deletes the network with the specified network identifier
        belonging to the specified tenant.
        """
        print("delete_network() called\n")
        net = FakePlugin._networks.get(net_id)
        # Verify that no attachments are plugged into the network
        if net:
            if net['net-ports']:
                for port in net['net-ports'].values():
                    if port['attachment']:
                        raise exc.NetworkInUse(net_id=net_id)
            FakePlugin._networks.pop(net_id)
            return net
        # Network not found
        raise exc.NetworkNotFound(net_id=net_id)

    def rename_network(self, tenant_id, net_id, new_name):
        """
        Updates the symbolic name belonging to a particular
        Virtual Network.
        """
        print("rename_network() called\n")
        net = self._get_network(tenant_id, net_id)
        net['net-name'] = new_name
        return net

    def get_all_ports(self, tenant_id, net_id):
        """
        Retrieves all port identifiers belonging to the
        specified Virtual Network.
        """
        print("get_all_ports() called\n")
        network = self._get_network(tenant_id, net_id)
        ports_on_net = network['net-ports'].values()
        return ports_on_net

    def get_port_details(self, tenant_id, net_id, port_id):
        """
        This method allows the user to retrieve a remote interface
        that is attached to this particular port.
        """
        print("get_port_details() called\n")
        return self._get_port(tenant_id, net_id, port_id)

    def create_port(self, tenant_id, net_id, port_state=None):
        """
        Creates a port on the specified Virtual Network.
        """
        print("create_port() called\n")
        net = self._get_network(tenant_id, net_id)
        # check port state
        # TODO(salvatore-orlando): Validate port state in API?
        self._validate_port_state(port_state)
        ports = net['net-ports']
        new_port_id = max(ports.keys()) + 1
        new_port_dict = {'port-id': new_port_id,
                         'port-state': port_state,
                         'attachment': None}
        ports[new_port_id] = new_port_dict
        return new_port_dict

    def update_port(self, tenant_id, net_id, port_id, port_state):
        """
        Updates the state of a port on the specified Virtual Network.
        """
        print("create_port() called\n")
        port = self._get_port(tenant_id, net_id, port_id)
        self._validate_port_state(port_state)
        port['port-state'] = port_state
        return port

    def delete_port(self, tenant_id, net_id, port_id):
        """
        Deletes a port on a specified Virtual Network,
        if the port contains a remote interface attachment,
        the remote interface is first un-plugged and then the port
        is deleted.
        """
        print("delete_port() called\n")
        net = self._get_network(tenant_id, net_id)
        port = self._get_port(tenant_id, net_id, port_id)
        if port['attachment']:
            raise exc.PortInUse(net_id=net_id, port_id=port_id,
                                att_id=port['attachment'])
        try:
            net['net-ports'].pop(int(port_id))
        except KeyError:
            raise exc.PortNotFound(net_id=net_id, port_id=port_id)

    def get_interface_details(self, tenant_id, net_id, port_id):
        """
        Retrieves the remote interface that is attached at this
        particular port.
        """
        print("get_interface_details() called\n")
        port = self._get_port(tenant_id, net_id, port_id)
        return port['attachment']

    def plug_interface(self, tenant_id, net_id, port_id, remote_interface_id):
        """
        Attaches a remote interface to the specified port on the
        specified Virtual Network.
        """
        print("plug_interface() called\n")
        # Validate attachment
        self._validate_attachment(tenant_id, net_id, port_id,
                                  remote_interface_id)
        port = self._get_port(tenant_id, net_id, port_id)
        if port['attachment']:
            raise exc.PortInUse(net_id=net_id, port_id=port_id,
                                att_id=port['attachment'])
        port['attachment'] = remote_interface_id

    def unplug_interface(self, tenant_id, net_id, port_id):
        """
        Detaches a remote interface from the specified port on the
        specified Virtual Network.
        """
        print("unplug_interface() called\n")
        port = self._get_port(tenant_id, net_id, port_id)
        # TODO(salvatore-orlando):
        # Should unplug on port without attachment raise an Error?
        port['attachment'] = None

    # TODO - neeed to update methods from this point onwards
    def get_all_attached_interfaces(self, tenant_id, net_id):
        """
        Retrieves all remote interfaces that are attached to
        a particular Virtual Network.
        """
        print("get_all_attached_interfaces() called\n")
        # returns a list of all attached remote interfaces
        vifs_on_net = ["/tenant1/networks/net_id/portid/vif2.0",
                       "/tenant1/networks/10/121/vif1.1"]
        return vifs_on_net
