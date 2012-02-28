# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2012 Isaku Yamahata
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
# @author: Isaku Yamahata
import ConfigParser
import logging as LOG
import os
from abc import ABCMeta, abstractmethod

import quantum.db.api as db
from quantum.api.api_common import OperationalStatus
from quantum.common import exceptions as q_exc
from quantum.manager import find_config
from quantum.quantum_plugin_base import QuantumPluginBase


LOG.getLogger(__name__)


class OVSQuantumPluginDriverBase(object):
    """
    Base class for OVS quantum plugin driver
    """
    __metaclass__ = ABCMeta

    @abstractmethod
    def create_network(self, net):
        pass

    @abstractmethod
    def delete_network(self, net):
        pass


class OVSQuantumPluginBase(QuantumPluginBase):
    """
    Base class for OVS-based plugin which referes to a subclass of
    OVSQuantumPluginDriverBase which is defined above.
    Subclass of OVSQuantumPluginBase must set self.driver to a subclass of
    OVSQuantumPluginDriverBase.
    """
    def __init__(self, conf_file, mod_file, configfile=None):
        super(OVSQuantumPluginBase, self).__init__()
        config = ConfigParser.ConfigParser()
        if configfile is None:
            if conf_file and os.path.exists(conf_file):
                configfile = conf_file
            else:
                configfile = find_config(os.path.abspath(
                        os.path.dirname(mod_file)))
        if configfile is None:
            raise Exception("Configuration file \"%s\" doesn't exist" %
              (configfile))
        LOG.debug("Using configuration file: %s", configfile)
        config.read(configfile)
        LOG.debug("Config: %s", config)

        options = {"sql_connection": config.get("DATABASE", "sql_connection")}
        db.configure_db(options)

        self.config = config
        # Subclass must set self.driver to its own OVSQuantumPluginDriverBase
        self.driver = None

    def get_all_networks(self, tenant_id, **kwargs):
        nets = []
        for net in db.network_list(tenant_id):
            LOG.debug("Adding network: %s", net.uuid)
            nets.append(self._make_net_dict(str(net.uuid), net.name,
                                            None, net.op_status))
        return nets

    def _make_net_dict(self, net_id, net_name, ports, op_status):
        res = {'net-id': net_id,
               'net-name': net_name,
               'net-op-status': op_status}
        if ports:
            res['net-ports'] = ports
        return res

    def create_network(self, tenant_id, net_name, **kwargs):
        net = db.network_create(tenant_id, net_name,
                                op_status=OperationalStatus.UP)
        LOG.debug("Created network: %s", net)
        self.driver.create_network(net)
        return self._make_net_dict(str(net.uuid), net.name, [], net.op_status)

    def delete_network(self, tenant_id, net_id):
        db.validate_network_ownership(tenant_id, net_id)
        net = db.network_get(net_id)

        # Verify that no attachments are plugged into the network
        for port in db.port_list(net_id):
            if port.interface_id:
                raise q_exc.NetworkInUse(net_id=net_id)
        net = db.network_destroy(net_id)
        self.driver.delete_network(net)
        return self._make_net_dict(str(net.uuid), net.name, [], net.op_status)

    def get_network_details(self, tenant_id, net_id):
        db.validate_network_ownership(tenant_id, net_id)
        net = db.network_get(net_id)
        ports = self.get_all_ports(tenant_id, net_id)
        return self._make_net_dict(str(net.uuid), net.name,
                                   ports, net.op_status)

    def update_network(self, tenant_id, net_id, **kwargs):
        db.validate_network_ownership(tenant_id, net_id)
        net = db.network_update(net_id, tenant_id, **kwargs)
        return self._make_net_dict(str(net.uuid), net.name,
                                   None, net.op_status)

    def _make_port_dict(self, port):
        if port.state == "ACTIVE":
            op_status = port.op_status
        else:
            op_status = OperationalStatus.DOWN

        return {'port-id': str(port.uuid),
                'port-state': port.state,
                'port-op-status': op_status,
                'net-id': port.network_id,
                'attachment': port.interface_id}

    def get_all_ports(self, tenant_id, net_id, **kwargs):
        db.validate_network_ownership(tenant_id, net_id)
        ports = db.port_list(net_id)
        # This plugin does not perform filtering at the moment
        return [{'port-id': str(port.uuid)} for port in ports]

    def create_port(self, tenant_id, net_id, port_state=None, **kwargs):
        LOG.debug("Creating port with network_id: %s", net_id)
        port = db.port_create(net_id, port_state,
                              op_status=OperationalStatus.DOWN)
        return self._make_port_dict(port)

    def delete_port(self, tenant_id, net_id, port_id):
        db.validate_port_ownership(tenant_id, net_id, port_id)
        port = db.port_destroy(port_id, net_id)
        return self._make_port_dict(port)

    def update_port(self, tenant_id, net_id, port_id, **kwargs):
        """
        Updates the state of a port on the specified Virtual Network.
        """
        LOG.debug("update_port() called\n")
        db.validate_port_ownership(tenant_id, net_id, port_id)
        port = db.port_get(port_id, net_id)
        db.port_update(port_id, net_id, **kwargs)
        return self._make_port_dict(port)

    def get_port_details(self, tenant_id, net_id, port_id):
        db.validate_port_ownership(tenant_id, net_id, port_id)
        port = db.port_get(port_id, net_id)
        return self._make_port_dict(port)

    def plug_interface(self, tenant_id, net_id, port_id, remote_iface_id):
        db.validate_port_ownership(tenant_id, net_id, port_id)
        db.port_set_attachment(port_id, net_id, remote_iface_id)

    def unplug_interface(self, tenant_id, net_id, port_id):
        db.validate_port_ownership(tenant_id, net_id, port_id)
        db.port_set_attachment(port_id, net_id, "")
        db.port_update(port_id, net_id, op_status=OperationalStatus.DOWN)

    def get_interface_details(self, tenant_id, net_id, port_id):
        db.validate_port_ownership(tenant_id, net_id, port_id)
        res = db.port_get(port_id, net_id)
        return res.interface_id
