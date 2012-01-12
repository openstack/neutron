# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2011, Cisco Systems, Inc.
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
# @author: Rohit Agarwalla, Cisco Systems, Inc.

"""
test_database.py is an independent test suite
that tests the database api method calls
"""
import logging as LOG
import unittest

from quantum.plugins.cisco.common import cisco_constants as const

import quantum.plugins.cisco.db.api as db
import quantum.plugins.cisco.db.l2network_db as l2network_db
import quantum.plugins.cisco.db.nexus_db as nexus_db
import quantum.plugins.cisco.db.services_db as services_db
import quantum.plugins.cisco.db.ucs_db as ucs_db


LOG.getLogger(const.LOGGER_COMPONENT_NAME)


class UcsDB(object):
    """Class consisting of methods to call ucs db methods"""
    def get_all_port_bindings(self):
        """get all port binding"""
        port_bindings = []
        try:
            for bind in ucs_db.get_all_portbindings():
                LOG.debug("Getting port binding for port: %s" % bind.port_id)
                port_bind_dict = {}
                port_bind_dict["port-id"] = bind.port_id
                port_bind_dict["blade-intf-dn"] = str(bind.blade_intf_dn)
                port_bind_dict["portprofile-name"] = bind.portprofile_name
                port_bind_dict["vlan-name"] = bind.vlan_name
                port_bind_dict["vlan-id"] = str(bind.vlan_id)
                port_bind_dict["qos"] = bind.qos
                port_bindings.append(port_bind_dict)
        except Exception, exc:
            LOG.error("Failed to get all port bindings: %s" % str(exc))
        return port_bindings

    def get_port_binding(self, port_id):
        """get port binding"""
        port_binding = []
        try:
            for bind in ucs_db.get_portbinding(port_id):
                LOG.debug("Getting port binding for port: %s" % bind.port_id)
                port_bind_dict = {}
                port_bind_dict["port-id"] = bind.port_id
                port_bind_dict["blade-intf-dn"] = str(bind.blade_intf_dn)
                port_bind_dict["portprofile-name"] = bind.portprofile_name
                port_bind_dict["vlan-name"] = bind.vlan_name
                port_bind_dict["vlan-id"] = str(bind.vlan_id)
                port_bind_dict["qos"] = bind.qos
                port_binding.append(port_bind_dict)
        except Exception, exc:
            LOG.error("Failed to get port binding: %s" % str(exc))
        return port_binding

    def create_port_binding(self, port_id, blade_intf_dn, portprofile_name, \
                            vlan_name, vlan_id, qos):
        """create port binding"""
        port_bind_dict = {}
        try:
            res = ucs_db.add_portbinding(port_id, blade_intf_dn, \
                                  portprofile_name, vlan_name, vlan_id, qos)
            LOG.debug("Created port binding: %s" % res.port_id)
            port_bind_dict["port-id"] = res.port_id
            port_bind_dict["blade-intf-dn"] = str(res.blade_intf_dn)
            port_bind_dict["portprofile-name"] = res.portprofile_name
            port_bind_dict["vlan-name"] = res.vlan_name
            port_bind_dict["vlan-id"] = str(res.vlan_id)
            port_bind_dict["qos"] = res.qos
            return port_bind_dict
        except Exception, exc:
            LOG.error("Failed to create port binding: %s" % str(exc))

    def delete_port_binding(self, port_id):
        """delete port binding"""
        try:
            res = ucs_db.remove_portbinding(port_id)
            LOG.debug("Deleted port binding : %s" % res.port_id)
            port_bind_dict = {}
            port_bind_dict["port-id"] = res.port_id
            return port_bind_dict
        except Exception, exc:
            raise Exception("Failed to delete port profile: %s" % str(exc))

    def update_port_binding(self, port_id, blade_intf_dn, \
                         portprofile_name, vlan_name, vlan_id, qos):
        """update port binding"""
        try:
            res = ucs_db.update_portbinding(port_id, blade_intf_dn, \
                               portprofile_name, vlan_name, vlan_id, qos)
            LOG.debug("Updating port binding: %s" % res.port_id)
            port_bind_dict = {}
            port_bind_dict["port-id"] = res.port_id
            port_bind_dict["dynamic-vnic-id"] = str(res.blade_intf_dn)
            port_bind_dict["portprofile-name"] = res.portprofile_name
            port_bind_dict["vlan-name"] = res.vlan_name
            port_bind_dict["vlan-id"] = str(res.vlan_id)
            port_bind_dict["qos"] = res.qos
            return port_bind_dict
        except Exception, exc:
            raise Exception("Failed to update portprofile binding:%s"
                            % str(exc))


class NexusDB(object):
    """Class consisting of methods to call nexus db methods"""
    def get_all_nexusportbindings(self):
        """get all nexus port bindings"""
        bindings = []
        try:
            for bind in nexus_db.get_all_nexusport_bindings():
                LOG.debug("Getting nexus port binding : %s" % bind.port_id)
                bind_dict = {}
                bind_dict["port-id"] = str(bind.port_id)
                bind_dict["vlan-id"] = str(bind.vlan_id)
                bindings.append(bind_dict)
        except Exception, exc:
            LOG.error("Failed to get all bindings: %s" % str(exc))
        return bindings

    def get_nexusportbinding(self, vlan_id):
        """get nexus port binding"""
        binding = []
        try:
            for bind in nexus_db.get_nexusport_binding(vlan_id):
                LOG.debug("Getting nexus port binding : %s" % bind.port_id)
                bind_dict = {}
                bind_dict["port-id"] = str(bind.port_id)
                bind_dict["vlan-id"] = str(bind.vlan_id)
                binding.append(bind_dict)
        except Exception, exc:
            LOG.error("Failed to get all bindings: %s" % str(exc))
        return binding

    def create_nexusportbinding(self, port_id, vlan_id):
        """create nexus port binding"""
        bind_dict = {}
        try:
            res = nexus_db.add_nexusport_binding(port_id, vlan_id)
            LOG.debug("Created nexus port binding : %s" % res.port_id)
            bind_dict["port-id"] = str(res.port_id)
            bind_dict["vlan-id"] = str(res.vlan_id)
            return bind_dict
        except Exception, exc:
            LOG.error("Failed to create nexus binding: %s" % str(exc))

    def delete_nexusportbinding(self, vlan_id):
        """delete nexus port binding"""
        bindings = []
        try:
            bind = nexus_db.remove_nexusport_binding(vlan_id)
            for res in bind:
                LOG.debug("Deleted nexus port binding: %s" % res.vlan_id)
                bind_dict = {}
                bind_dict["port-id"] = res.port_id
                bindings.append(bind_dict)
            return bindings
        except Exception, exc:
            raise Exception("Failed to delete nexus port binding: %s"
                             % str(exc))

    def update_nexusport_binding(self, port_id, new_vlan_id):
        """update nexus port binding"""
        try:
            res = nexus_db.update_nexusport_binding(port_id, new_vlan_id)
            LOG.debug("Updating nexus port binding : %s" % res.port_id)
            bind_dict = {}
            bind_dict["port-id"] = str(res.port_id)
            bind_dict["vlan-id"] = str(res.vlan_id)
            return bind_dict
        except Exception, exc:
            raise Exception("Failed to update nexus port binding vnic: %s"
                            % str(exc))


class ServicesDB(object):
    """Class consisting of methods to call services db methods"""
    def get_all_servicesbindings(self):
        """get all services port bindings"""
        bindings = []
        try:
            for bind in services_db.get_all_services_bindings():
                LOG.debug("Getting services bindings : %s" % bind.service_id)
                bind_dict = {}
                bind_dict["service_id"] = str(bind.service_id)
                bind_dict["mngnet_id"] = str(bind.mngnet_id)
                bind_dict["nbnet_id"] = str(bind.nbnet_id)
                bind_dict["sbnet_id"] = str(bind.sbnet_id)
                bindings.append(bind_dict)
        except Exception, exc:
            LOG.error("Failed to get all bindings: %s" % str(exc))
        return bindings

    def get_servicebindings(self, service_id):
        """get service binding"""
        try:
            bind = services_db.get_service_bindings(service_id)
            LOG.debug("Getting service binding : %s" % bind.service_id)
            return bind
        except Exception, exc:
            LOG.error("Failed to get service binding: %s" % str(exc))

    def create_servicebinding(self, service_id, mngnet_id, nbnet_id, sbnet_id):
        """create service binding"""
        bind_dict = {}
        try:
            res = services_db.add_services_binding(service_id, mngnet_id, \
                                                   nbnet_id, sbnet_id)
            LOG.debug("Created service binding : %s" % res.service_id)
            bind_dict["service_id"] = str(res.service_id)
            bind_dict["mngnet_id"] = str(res.mngnet_id)
            bind_dict["nbnet_id"] = str(res.nbnet_id)
            bind_dict["sbnet_id"] = str(res.sbnet_id)
            return bind_dict
        except Exception, exc:
            LOG.error("Failed to create service binding: %s" % str(exc))

    def delete_servicebinding(self, service_id):
        """delete service binding"""
        try:
            bind = services_db.remove_services_binding(service_id)
            for res in bind:
                LOG.debug("Deleted service binding: %s" % res.service_id)
        except Exception, exc:
            raise Exception("Failed to delete service binding: %s"
                             % str(exc))


class L2networkDB(object):
    """Class conisting of methods to call L2network db methods"""
    def get_all_vlan_bindings(self):
        """Get all vlan binding into a list of dict"""
        vlans = []
        try:
            for vlan_bind in l2network_db.get_all_vlan_bindings():
                LOG.debug("Getting vlan bindings for vlan: %s" %
                            vlan_bind.vlan_id)
                vlan_dict = {}
                vlan_dict["vlan-id"] = str(vlan_bind.vlan_id)
                vlan_dict["vlan-name"] = vlan_bind.vlan_name
                vlan_dict["net-id"] = str(vlan_bind.network_id)
                vlans.append(vlan_dict)
        except Exception, exc:
            LOG.error("Failed to get all vlan bindings: %s" % str(exc))
        return vlans

    def get_vlan_binding(self, network_id):
        """Get a vlan binding"""
        vlan = []
        try:
            for vlan_bind in l2network_db.get_vlan_binding(network_id):
                LOG.debug("Getting vlan binding for vlan: %s"
                           % vlan_bind.vlan_id)
                vlan_dict = {}
                vlan_dict["vlan-id"] = str(vlan_bind.vlan_id)
                vlan_dict["vlan-name"] = vlan_bind.vlan_name
                vlan_dict["net-id"] = str(vlan_bind.network_id)
                vlan.append(vlan_dict)
        except Exception, exc:
            LOG.error("Failed to get vlan binding: %s" % str(exc))
        return vlan

    def create_vlan_binding(self, vlan_id, vlan_name, network_id):
        """Create a vlan binding"""
        vlan_dict = {}
        try:
            res = l2network_db.add_vlan_binding(vlan_id, vlan_name, network_id)
            LOG.debug("Created vlan binding for vlan: %s" % res.vlan_id)
            vlan_dict["vlan-id"] = str(res.vlan_id)
            vlan_dict["vlan-name"] = res.vlan_name
            vlan_dict["net-id"] = str(res.network_id)
            return vlan_dict
        except Exception, exc:
            LOG.error("Failed to create vlan binding: %s" % str(exc))

    def delete_vlan_binding(self, network_id):
        """Delete a vlan binding"""
        try:
            res = l2network_db.remove_vlan_binding(network_id)
            LOG.debug("Deleted vlan binding for vlan: %s" % res.vlan_id)
            vlan_dict = {}
            vlan_dict["vlan-id"] = str(res.vlan_id)
            return vlan_dict
        except Exception, exc:
            raise Exception("Failed to delete vlan binding: %s" % str(exc))

    def update_vlan_binding(self, network_id, vlan_id, vlan_name):
        """Update a vlan binding"""
        try:
            res = l2network_db.update_vlan_binding(network_id, vlan_id,
                                                            vlan_name)
            LOG.debug("Updating vlan binding for vlan: %s" % res.vlan_id)
            vlan_dict = {}
            vlan_dict["vlan-id"] = str(res.vlan_id)
            vlan_dict["vlan-name"] = res.vlan_name
            vlan_dict["net-id"] = str(res.network_id)
            return vlan_dict
        except Exception, exc:
            raise Exception("Failed to update vlan binding: %s" % str(exc))

    def get_all_portprofiles(self):
        """Get all portprofiles"""
        pps = []
        try:
            for portprof in l2network_db.get_all_portprofiles():
                LOG.debug("Getting port profile : %s" % portprof.uuid)
                pp_dict = {}
                pp_dict["portprofile-id"] = str(portprof.uuid)
                pp_dict["portprofile-name"] = portprof.name
                pp_dict["vlan-id"] = str(portprof.vlan_id)
                pp_dict["qos"] = portprof.qos
                pps.append(pp_dict)
        except Exception, exc:
            LOG.error("Failed to get all port profiles: %s" % str(exc))
        return pps

    def get_portprofile(self, tenant_id, pp_id):
        """Get a portprofile"""
        pp_list = []
        try:
            for portprof in l2network_db.get_portprofile(tenant_id, pp_id):
                LOG.debug("Getting port profile : %s" % portprof.uuid)
                pp_dict = {}
                pp_dict["portprofile-id"] = str(portprof.uuid)
                pp_dict["portprofile-name"] = portprof.name
                pp_dict["vlan-id"] = str(portprof.vlan_id)
                pp_dict["qos"] = portprof.qos
                pp_list.append(pp_dict)
        except Exception, exc:
            LOG.error("Failed to get port profile: %s" % str(exc))
        return pp_list

    def create_portprofile(self, tenant_id, name, vlan_id, qos):
        """Create a portprofile"""
        pp_dict = {}
        try:
            res = l2network_db.add_portprofile(tenant_id, name, vlan_id, qos)
            LOG.debug("Created port profile: %s" % res.uuid)
            pp_dict["portprofile-id"] = str(res.uuid)
            pp_dict["portprofile-name"] = res.name
            pp_dict["vlan-id"] = str(res.vlan_id)
            pp_dict["qos"] = res.qos
            return pp_dict
        except Exception, exc:
            LOG.error("Failed to create port profile: %s" % str(exc))

    def delete_portprofile(self, tenant_id, pp_id):
        """Delete a portprofile"""
        try:
            res = l2network_db.remove_portprofile(tenant_id, pp_id)
            LOG.debug("Deleted port profile : %s" % res.uuid)
            pp_dict = {}
            pp_dict["pp-id"] = str(res.uuid)
            return pp_dict
        except Exception, exc:
            raise Exception("Failed to delete port profile: %s" % str(exc))

    def update_portprofile(self, tenant_id, pp_id, name, vlan_id, qos):
        """Update a portprofile"""
        try:
            res = l2network_db.update_portprofile(tenant_id, pp_id, name,
                                                  vlan_id, qos)
            LOG.debug("Updating port profile : %s" % res.uuid)
            pp_dict = {}
            pp_dict["portprofile-id"] = str(res.uuid)
            pp_dict["portprofile-name"] = res.name
            pp_dict["vlan-id"] = str(res.vlan_id)
            pp_dict["qos"] = res.qos
            return pp_dict
        except Exception, exc:
            raise Exception("Failed to update port profile: %s" % str(exc))

    def get_all_pp_bindings(self):
        """Get all portprofile bindings"""
        pp_bindings = []
        try:
            for pp_bind in l2network_db.get_all_pp_bindings():
                LOG.debug("Getting port profile binding: %s" %
                                               pp_bind.portprofile_id)
                ppbinding_dict = {}
                ppbinding_dict["portprofile-id"] = str(pp_bind.portprofile_id)
                ppbinding_dict["port-id"] = str(pp_bind.port_id)
                ppbinding_dict["tenant-id"] = pp_bind.tenant_id
                ppbinding_dict["default"] = pp_bind.default
                pp_bindings.append(ppbinding_dict)
        except Exception, exc:
            LOG.error("Failed to get all port profiles: %s" % str(exc))
        return pp_bindings

    def get_pp_binding(self, tenant_id, pp_id):
        """Get a portprofile binding"""
        pp_binding = []
        try:
            for pp_bind in l2network_db.get_pp_binding(tenant_id, pp_id):
                LOG.debug("Getting port profile binding: %s" %
                                                 pp_bind.portprofile_id)
                ppbinding_dict = {}
                ppbinding_dict["portprofile-id"] = str(pp_bind.portprofile_id)
                ppbinding_dict["port-id"] = str(pp_bind.port_id)
                ppbinding_dict["tenant-id"] = pp_bind.tenant_id
                ppbinding_dict["default"] = pp_bind.default
                pp_binding.append(ppbinding_dict)
        except Exception, exc:
            LOG.error("Failed to get port profile binding: %s" % str(exc))
        return pp_binding

    def create_pp_binding(self, tenant_id, port_id, pp_id, default):
        """Add a portprofile binding"""
        ppbinding_dict = {}
        try:
            res = l2network_db.add_pp_binding(tenant_id, port_id, pp_id,
                                                                default)
            LOG.debug("Created port profile binding: %s" % res.portprofile_id)
            ppbinding_dict["portprofile-id"] = str(res.portprofile_id)
            ppbinding_dict["port-id"] = str(res.port_id)
            ppbinding_dict["tenant-id"] = res.tenant_id
            ppbinding_dict["default"] = res.default
            return ppbinding_dict
        except Exception, exc:
            LOG.error("Failed to create port profile binding: %s" % str(exc))

    def delete_pp_binding(self, tenant_id, port_id, pp_id):
        """Delete a portprofile binding"""
        try:
            res = l2network_db.remove_pp_binding(tenant_id, port_id, pp_id)
            LOG.debug("Deleted port profile binding : %s" % res.portprofile_id)
            ppbinding_dict = {}
            ppbinding_dict["portprofile-id"] = str(res.portprofile_id)
            return ppbinding_dict
        except Exception, exc:
            raise Exception("Failed to delete port profile: %s" % str(exc))

    def update_pp_binding(self, tenant_id, pp_id, newtenant_id,
                          port_id, default):
        """Update portprofile binding"""
        try:
            res = l2network_db.update_pp_binding(tenant_id, pp_id,
                                            newtenant_id, port_id, default)
            LOG.debug("Updating port profile binding: %s" % res.portprofile_id)
            ppbinding_dict = {}
            ppbinding_dict["portprofile-id"] = str(res.portprofile_id)
            ppbinding_dict["port-id"] = str(res.port_id)
            ppbinding_dict["tenant-id"] = res.tenant_id
            ppbinding_dict["default"] = res.default
            return ppbinding_dict
        except Exception, exc:
            raise Exception("Failed to update portprofile binding:%s"
                            % str(exc))


class QuantumDB(object):
    """Class conisting of methods to call Quantum db methods"""
    def get_all_networks(self, tenant_id):
        """Get all networks"""
        nets = []
        try:
            for net in db.network_list(tenant_id):
                LOG.debug("Getting network: %s" % net.uuid)
                net_dict = {}
                net_dict["tenant-id"] = net.tenant_id
                net_dict["net-id"] = str(net.uuid)
                net_dict["net-name"] = net.name
                nets.append(net_dict)
        except Exception, exc:
            LOG.error("Failed to get all networks: %s" % str(exc))
        return nets

    def get_network(self, network_id):
        """Get a network"""
        net = []
        try:
            for net in db.network_get(network_id):
                LOG.debug("Getting network: %s" % net.uuid)
                net_dict = {}
                net_dict["tenant-id"] = net.tenant_id
                net_dict["net-id"] = str(net.uuid)
                net_dict["net-name"] = net.name
                net.append(net_dict)
        except Exception, exc:
            LOG.error("Failed to get network: %s" % str(exc))
        return net

    def create_network(self, tenant_id, net_name):
        """Create a network"""
        net_dict = {}
        try:
            res = db.network_create(tenant_id, net_name)
            LOG.debug("Created network: %s" % res.uuid)
            net_dict["tenant-id"] = res.tenant_id
            net_dict["net-id"] = str(res.uuid)
            net_dict["net-name"] = res.name
            return net_dict
        except Exception, exc:
            LOG.error("Failed to create network: %s" % str(exc))

    def delete_network(self, net_id):
        """Delete a network"""
        try:
            net = db.network_destroy(net_id)
            LOG.debug("Deleted network: %s" % net.uuid)
            net_dict = {}
            net_dict["net-id"] = str(net.uuid)
            return net_dict
        except Exception, exc:
            raise Exception("Failed to delete port: %s" % str(exc))

    def update_network(self, tenant_id, net_id, **kwargs):
        """Update a network"""
        try:
            net = db.network_update(net_id, tenant_id, **kwargs)
            LOG.debug("Updated network: %s" % net.uuid)
            net_dict = {}
            net_dict["net-id"] = str(net.uuid)
            net_dict["net-name"] = net.name
            return net_dict
        except Exception, exc:
            raise Exception("Failed to update network: %s" % str(exc))

    def get_all_ports(self, net_id):
        """Get all ports"""
        ports = []
        try:
            for port in db.port_list(net_id):
                LOG.debug("Getting port: %s" % port.uuid)
                port_dict = {}
                port_dict["port-id"] = str(port.uuid)
                port_dict["net-id"] = str(port.network_id)
                port_dict["int-id"] = port.interface_id
                port_dict["state"] = port.state
                port_dict["net"] = port.network
                ports.append(port_dict)
            return ports
        except Exception, exc:
            LOG.error("Failed to get all ports: %s" % str(exc))

    def get_port(self, net_id, port_id):
        """Get a port"""
        port_list = []
        port = db.port_get(net_id, port_id)
        try:
            LOG.debug("Getting port: %s" % port.uuid)
            port_dict = {}
            port_dict["port-id"] = str(port.uuid)
            port_dict["net-id"] = str(port.network_id)
            port_dict["int-id"] = port.interface_id
            port_dict["state"] = port.state
            port_list.append(port_dict)
            return port_list
        except Exception, exc:
            LOG.error("Failed to get port: %s" % str(exc))

    def create_port(self, net_id):
        """Add a port"""
        port_dict = {}
        try:
            port = db.port_create(net_id)
            LOG.debug("Creating port %s" % port.uuid)
            port_dict["port-id"] = str(port.uuid)
            port_dict["net-id"] = str(port.network_id)
            port_dict["int-id"] = port.interface_id
            port_dict["state"] = port.state
            return port_dict
        except Exception, exc:
            LOG.error("Failed to create port: %s" % str(exc))

    def delete_port(self, net_id, port_id):
        """Delete a port"""
        try:
            port = db.port_destroy(net_id, port_id)
            LOG.debug("Deleted port %s" % port.uuid)
            port_dict = {}
            port_dict["port-id"] = str(port.uuid)
            return port_dict
        except Exception, exc:
            raise Exception("Failed to delete port: %s" % str(exc))

    def update_port(self, net_id, port_id, port_state):
        """Update a port"""
        try:
            port = db.port_set_state(net_id, port_id, port_state)
            LOG.debug("Updated port %s" % port.uuid)
            port_dict = {}
            port_dict["port-id"] = str(port.uuid)
            port_dict["net-id"] = str(port.network_id)
            port_dict["int-id"] = port.interface_id
            port_dict["state"] = port.state
            return port_dict
        except Exception, exc:
            raise Exception("Failed to update port state: %s" % str(exc))

    def plug_interface(self, net_id, port_id, int_id):
        """Plug interface to a port"""
        try:
            port = db.port_set_attachment(net_id, port_id, int_id)
            LOG.debug("Attached interface to port %s" % port.uuid)
            port_dict = {}
            port_dict["port-id"] = str(port.uuid)
            port_dict["net-id"] = str(port.network_id)
            port_dict["int-id"] = port.interface_id
            port_dict["state"] = port.state
            return port_dict
        except Exception, exc:
            raise Exception("Failed to plug interface: %s" % str(exc))

    def unplug_interface(self, net_id, port_id):
        """Unplug interface to a port"""
        try:
            port = db.port_unset_attachment(net_id, port_id)
            LOG.debug("Detached interface from port %s" % port.uuid)
            port_dict = {}
            port_dict["port-id"] = str(port.uuid)
            port_dict["net-id"] = str(port.network_id)
            port_dict["int-id"] = port.interface_id
            port_dict["state"] = port.state
            return port_dict
        except Exception, exc:
            raise Exception("Failed to unplug interface: %s" % str(exc))


class UcsDBTest(unittest.TestCase):
    """Class conisting of ucs DB unit tests"""
    def setUp(self):
        """Setup for ucs db tests"""
        l2network_db.initialize()
        self.quantum = QuantumDB()
        self.dbtest = UcsDB()
        LOG.debug("Setup")

    def tearDown(self):
        """Tear Down"""
        db.clear_db()

    def testm_create_portbinding(self):
        """create port binding"""
        net1 = self.quantum.create_network("t1", "netid1")
        port1 = self.quantum.create_port(net1["net-id"])
        port_bind1 = self.dbtest.create_port_binding(port1["port-id"],
                                "vnic1", "pp1", "vlan1", 10, "qos1")
        self.assertTrue(port_bind1["port-id"] == port1["port-id"])
        self.teardown_portbinding()
        self.teardown_network_port()

    def testn_getall_portbindings(self):
        """get all port binding"""
        net1 = self.quantum.create_network("t1", "netid1")
        port1 = self.quantum.create_port(net1["net-id"])
        port2 = self.quantum.create_port(net1["net-id"])
        port_bind1 = self.dbtest.create_port_binding(port1["port-id"],
                                "vnic1", "pp1", "vlan1", 10, "qos1")
        port_bind2 = self.dbtest.create_port_binding(port2["port-id"],
                                "vnic2", "pp2", "vlan2", 20, "qos2")
        port_bindings = self.dbtest.get_all_port_bindings()
        count = 0
        for pbind in port_bindings:
            if "vlan" in pbind["vlan-name"]:
                count += 1
        self.assertTrue(count == 2)
        self.teardown_portbinding()
        self.teardown_network_port()

    def testo_delete_portbinding(self):
        """delete port binding"""
        net1 = self.quantum.create_network("t1", "netid1")
        port1 = self.quantum.create_port(net1["net-id"])
        port_bind1 = self.dbtest.create_port_binding(port1["port-id"],
                                "vnic1", "pp1", "vlan1", 10, "qos1")
        self.dbtest.delete_port_binding(port1["port-id"])
        port_bindings = self.dbtest.get_all_port_bindings()
        count = 0
        for pbind in port_bindings:
            if "vlan " in pbind["vlan-name"]:
                count += 1
        self.assertTrue(count == 0)
        self.teardown_portbinding()
        self.teardown_network_port()

    def testp_update_portbinding(self):
        """update port binding"""
        net1 = self.quantum.create_network("t1", "netid1")
        port1 = self.quantum.create_port(net1["net-id"])
        port_bind1 = self.dbtest.create_port_binding(port1["port-id"],
                                "vnic1", "pp1", "vlan1", 10, "qos1")
        port_bind1 = self.dbtest.update_port_binding(port1["port-id"],
                        "vnic1", "newpp1", "newvlan1", 11, "newqos1")
        port_bindings = self.dbtest.get_all_port_bindings()
        count = 0
        for pbind in port_bindings:
            if "new" in pbind["vlan-name"]:
                count += 1
        self.assertTrue(count == 1)
        self.teardown_portbinding()
        self.teardown_network_port()

    def teardown_portbinding(self):
        """tear down port binding"""
        LOG.debug("Tearing Down Port Binding")
        port_bindings = self.dbtest.get_all_port_bindings()
        for port_binding in port_bindings:
            portid = port_binding["port-id"]
            self.dbtest.delete_port_binding(portid)

    def teardown_network_port(self):
        """tearDown for Network and Port table"""
        networks = self.quantum.get_all_networks("t1")
        for net in networks:
            netid = net["net-id"]
            name = net["net-name"]
            if "net" in name:
                ports = self.quantum.get_all_ports(netid)
                for por in ports:
                    self.quantum.delete_port(netid, por["port-id"])
                self.quantum.delete_network(netid)


class NexusDBTest(unittest.TestCase):
    """Class conisting of nexus DB unit tests"""
    def setUp(self):
        """Setup for nexus db tests"""
        l2network_db.initialize()
        self.dbtest = NexusDB()
        LOG.debug("Setup")

    def tearDown(self):
        """Tear Down"""
        db.clear_db()

    def testa_create_nexusportbinding(self):
        """create nexus port binding"""
        binding1 = self.dbtest.create_nexusportbinding("port1", 10)
        self.assertTrue(binding1["port-id"] == "port1")
        self.tearDown_nexusportbinding()

    def testb_getall_nexusportbindings(self):
        """get all nexus port binding"""
        binding1 = self.dbtest.create_nexusportbinding("port1", 10)
        binding2 = self.dbtest.create_nexusportbinding("port2", 10)
        bindings = self.dbtest.get_all_nexusportbindings()
        count = 0
        for bind in bindings:
            if "port" in bind["port-id"]:
                count += 1
        self.assertTrue(count == 2)
        self.tearDown_nexusportbinding()

    def testc_delete_nexusportbinding(self):
        """delete nexus port binding"""
        binding1 = self.dbtest.create_nexusportbinding("port1", 10)
        self.dbtest.delete_nexusportbinding(10)
        bindings = self.dbtest.get_all_nexusportbindings()
        count = 0
        for bind in bindings:
            if "port " in bind["port-id"]:
                count += 1
        self.assertTrue(count == 0)
        self.tearDown_nexusportbinding()

    def testd_update_nexusportbinding(self):
        """update nexus port binding"""
        binding1 = self.dbtest.create_nexusportbinding("port1", 10)
        binding1 = self.dbtest.update_nexusport_binding(binding1["port-id"], \
                                                             20)
        bindings = self.dbtest.get_all_nexusportbindings()
        count = 0
        for bind in bindings:
            if "20" in str(bind["vlan-id"]):
                count += 1
        self.assertTrue(count == 1)
        self.tearDown_nexusportbinding()

    def tearDown_nexusportbinding(self):
        """tear down nexusport binding table"""
        LOG.debug("Tearing Down Nexus port Bindings")
        binds = self.dbtest.get_all_nexusportbindings()
        for bind in binds:
            vlan_id = bind["vlan-id"]
            self.dbtest.delete_nexusportbinding(vlan_id)


class ServicesDBTest(unittest.TestCase):
    """Class conisting of services DB unit tests"""
    def setUp(self):
        """Setup for services db tests"""
        l2network_db.initialize()
        self.dbtest = ServicesDB()
        LOG.debug("Setup")

    def tearDown(self):
        """Tear Down"""
        db.clear_db()

    def testa_create_servicebinding(self):
        """create service binding"""
        service_id = self.dbtest.create_servicebinding("i-00001", \
                                    "mng_net", "northb_net", "northb_net")
        self.assertTrue(service_id["service_id"] == "i-00001")
        self.tearDown_servicebinding()

    def testb_get_servicesbindings(self):
        """get all services binding"""
        service_id = self.dbtest.create_servicebinding("i-00001", \
                                    "mng_net", "northb_net", "northb_net")
        bindings = self.dbtest.get_servicebindings("i-00001")
        count = 0
        if bindings:
            count += 1
        self.assertTrue(count == 1)
        self.tearDown_servicebinding()

    def testb_getall_servicesbindings(self):
        """get all services binding"""
        service_id = self.dbtest.create_servicebinding("i-00001", \
                                    "mng_net", "northb_net", "northb_net")
        service_id = self.dbtest.create_servicebinding("i-00002", \
                                    "mng_net", "northb_net", "northb_net")
        bindings = self.dbtest.get_all_servicesbindings()
        count = 0
        for bind in bindings:
            if "mng_net" in bind["mngnet_id"]:
                count += 1
        self.assertTrue(count == 2)
        self.tearDown_servicebinding()

    def testc_delete_servicesbinding(self):
        """delete services binding"""
        binding_serv = self.dbtest.create_servicebinding("i-00001", \
                                    "mng_net", "northb_net", "northb_net")
        self.dbtest.delete_servicebinding("i-00001")
        bindings = self.dbtest.get_all_servicesbindings()
        count = 0
        for bind in bindings:
            if "mng_net" in bind["mngnet_id"]:
                count += 1
        self.assertTrue(count == 0)
        self.tearDown_servicebinding()

    def tearDown_servicebinding(self):
        """tear down nexusport binding table"""
        LOG.debug("Tearing Down Nexus port Bindings")
        binds = self.dbtest.get_all_servicesbindings()
        for bind in binds:
            service_id = bind["service_id"]
            self.dbtest.delete_servicebinding(service_id)


class L2networkDBTest(unittest.TestCase):
    """Class conisting of L2network DB unit tests"""
    def setUp(self):
        """Setup for tests"""
        l2network_db.initialize()
        self.dbtest = L2networkDB()
        self.quantum = QuantumDB()
        LOG.debug("Setup")

    def tearDown(self):
        """Tear Down"""
        db.clear_db()

    def testa_create_vlanbinding(self):
        """test add vlan binding"""
        net1 = self.quantum.create_network("t1", "netid1")
        vlan1 = self.dbtest.create_vlan_binding(10, "vlan1", net1["net-id"])
        self.assertTrue(vlan1["vlan-id"] == "10")
        self.teardown_vlanbinding()
        self.teardown_network()

    def testb_getall_vlanbindings(self):
        """test get all vlan binding"""
        net1 = self.quantum.create_network("t1", "netid1")
        net2 = self.quantum.create_network("t1", "netid2")
        vlan1 = self.dbtest.create_vlan_binding(10, "vlan1", net1["net-id"])
        self.assertTrue(vlan1["vlan-id"] == "10")
        vlan2 = self.dbtest.create_vlan_binding(20, "vlan2", net2["net-id"])
        self.assertTrue(vlan2["vlan-id"] == "20")
        vlans = self.dbtest.get_all_vlan_bindings()
        count = 0
        for vlan in vlans:
            if "vlan" in vlan["vlan-name"]:
                count += 1
        self.assertTrue(count == 2)
        self.teardown_vlanbinding()
        self.teardown_network()

    def testc_delete_vlanbinding(self):
        """test delete vlan binding"""
        net1 = self.quantum.create_network("t1", "netid1")
        vlan1 = self.dbtest.create_vlan_binding(10, "vlan1", net1["net-id"])
        self.assertTrue(vlan1["vlan-id"] == "10")
        self.dbtest.delete_vlan_binding(net1["net-id"])
        vlans = self.dbtest.get_all_vlan_bindings()
        count = 0
        for vlan in vlans:
            if "vlan " in vlan["vlan-name"]:
                count += 1
        self.assertTrue(count == 0)
        self.teardown_vlanbinding()
        self.teardown_network()

    def testd_update_vlanbinding(self):
        """test update vlan binding"""
        net1 = self.quantum.create_network("t1", "netid1")
        vlan1 = self.dbtest.create_vlan_binding(10, "vlan1", net1["net-id"])
        self.assertTrue(vlan1["vlan-id"] == "10")
        vlan1 = self.dbtest.update_vlan_binding(net1["net-id"], 11, "newvlan1")
        vlans = self.dbtest.get_all_vlan_bindings()
        count = 0
        for vlan in vlans:
            if "new" in vlan["vlan-name"]:
                count += 1
        self.assertTrue(count == 1)
        self.teardown_vlanbinding()
        self.teardown_network()

    def teste_create_portprofile(self):
        """test add port profile"""
        pp1 = self.dbtest.create_portprofile("t1", "portprofile1", 10, "qos1")
        self.assertTrue(pp1["portprofile-name"] == "portprofile1")
        self.teardown_portprofile()
        self.teardown_network()

    def testf_getall_portprofile(self):
        """test get all portprofiles"""
        pp1 = self.dbtest.create_portprofile("t1", "portprofile1", 10, "qos1")
        self.assertTrue(pp1["portprofile-name"] == "portprofile1")
        pp2 = self.dbtest.create_portprofile("t1", "portprofile2", 20, "qos2")
        self.assertTrue(pp2["portprofile-name"] == "portprofile2")
        pps = self.dbtest.get_all_portprofiles()
        count = 0
        for pprofile in pps:
            if "portprofile" in pprofile["portprofile-name"]:
                count += 1
        self.assertTrue(count == 2)
        self.teardown_portprofile()

    def testg_delete_portprofile(self):
        """test delete portprofile"""
        pp1 = self.dbtest.create_portprofile("t1", "portprofile1", 10, "qos1")
        self.assertTrue(pp1["portprofile-name"] == "portprofile1")
        self.dbtest.delete_portprofile("t1", pp1["portprofile-id"])
        pps = self.dbtest.get_all_portprofiles()
        count = 0
        for pprofile in pps:
            if "portprofile " in pprofile["portprofile-name"]:
                count += 1
        self.assertTrue(count == 0)
        self.teardown_portprofile()

    def testh_update_portprofile(self):
        """test update portprofile"""
        pp1 = self.dbtest.create_portprofile("t1", "portprofile1", 10, "qos1")
        self.assertTrue(pp1["portprofile-name"] == "portprofile1")
        pp1 = self.dbtest.update_portprofile("t1", pp1["portprofile-id"], \
                                          "newportprofile1", 20, "qos2")
        pps = self.dbtest.get_all_portprofiles()
        count = 0
        for pprofile in pps:
            if "new" in pprofile["portprofile-name"]:
                count += 1
        self.assertTrue(count == 1)
        self.teardown_portprofile()

    def testi_create_portprofilebinding(self):
        """test create portprofile binding"""
        net1 = self.quantum.create_network("t1", "netid1")
        port1 = self.quantum.create_port(net1["net-id"])
        pp1 = self.dbtest.create_portprofile("t1", "portprofile1", 10, "qos1")
        pp_binding1 = self.dbtest.create_pp_binding("t1", port1["port-id"], \
                                              pp1["portprofile-id"], "0")
        self.assertTrue(pp_binding1["tenant-id"] == "t1")
        self.teardown_portprofilebinding()
        self.teardown_port()
        self.teardown_network()
        self.teardown_portprofile()

    def testj_getall_portprofilebinding(self):
        """test get all portprofile binding"""
        net1 = self.quantum.create_network("t1", "netid1")
        port1 = self.quantum.create_port(net1["net-id"])
        port2 = self.quantum.create_port(net1["net-id"])
        pp1 = self.dbtest.create_portprofile("t1", "portprofile1", 10, "qos1")
        pp2 = self.dbtest.create_portprofile("t1", "portprofile2", 20, "qos2")
        pp_binding1 = self.dbtest.create_pp_binding("t1", port1["port-id"], \
                                               pp1["portprofile-id"], "0")
        self.assertTrue(pp_binding1["tenant-id"] == "t1")
        pp_binding2 = self.dbtest.create_pp_binding("t1", port2["port-id"], \
                                               pp2["portprofile-id"], "0")
        self.assertTrue(pp_binding2["tenant-id"] == "t1")
        pp_bindings = self.dbtest.get_all_pp_bindings()
        count = 0
        for pp_bind in pp_bindings:
            if "t1" in pp_bind["tenant-id"]:
                count += 1
        self.assertTrue(count == 2)
        self.teardown_portprofilebinding()
        self.teardown_port()
        self.teardown_network()
        self.teardown_portprofile()

    def testk_delete_portprofilebinding(self):
        """test delete portprofile binding"""
        net1 = self.quantum.create_network("t1", "netid1")
        port1 = self.quantum.create_port(net1["net-id"])
        pp1 = self.dbtest.create_portprofile("t1", "portprofile1", 10, "qos1")
        pp_binding1 = self.dbtest.create_pp_binding("t1", port1["port-id"], \
                                                pp1["portprofile-id"], "0")
        self.assertTrue(pp_binding1["tenant-id"] == "t1")
        self.dbtest.delete_pp_binding("t1", port1["port-id"], \
                                      pp_binding1["portprofile-id"])
        pp_bindings = self.dbtest.get_all_pp_bindings()
        count = 0
        for pp_bind in pp_bindings:
            if "t1 " in pp_bind["tenant-id"]:
                count += 1
        self.assertTrue(count == 0)
        self.teardown_portprofilebinding()
        self.teardown_port()
        self.teardown_network()
        self.teardown_portprofile()

    def testl_update_portprofilebinding(self):
        """test update portprofile binding"""
        net1 = self.quantum.create_network("t1", "netid1")
        port1 = self.quantum.create_port(net1["net-id"])
        pp1 = self.dbtest.create_portprofile("t1", "portprofile1", 10, "qos1")
        pp_binding1 = self.dbtest.create_pp_binding("t1", port1["port-id"], \
                                                pp1["portprofile-id"], "0")
        self.assertTrue(pp_binding1["tenant-id"] == "t1")
        pp_binding1 = self.dbtest.update_pp_binding("t1", \
                      pp1["portprofile-id"], "newt1", port1["port-id"], "1")
        pp_bindings = self.dbtest.get_all_pp_bindings()
        count = 0
        for pp_bind in pp_bindings:
            if "new" in pp_bind["tenant-id"]:
                count += 1
        self.assertTrue(count == 1)
        self.teardown_portprofilebinding()
        self.teardown_port()
        self.teardown_network()
        self.teardown_portprofile()

    def testm_test_vlanids(self):
        """test vlanid methods"""
        l2network_db.create_vlanids()
        vlanids = l2network_db.get_all_vlanids()
        self.assertTrue(len(vlanids) > 0)
        vlanid = l2network_db.reserve_vlanid()
        used = l2network_db.is_vlanid_used(vlanid)
        self.assertTrue(used)
        used = l2network_db.release_vlanid(vlanid)
        self.assertFalse(used)
        #counting on default teardown here to clear db

    def teardown_network(self):
        """tearDown Network table"""
        LOG.debug("Tearing Down Network")
        nets = self.quantum.get_all_networks("t1")
        for net in nets:
            netid = net["net-id"]
            self.quantum.delete_network(netid)

    def teardown_port(self):
        """tearDown Port table"""
        LOG.debug("Tearing Down Port")
        nets = self.quantum.get_all_networks("t1")
        for net in nets:
            netid = net["net-id"]
            ports = self.quantum.get_all_ports(netid)
            for port in ports:
                portid = port["port-id"]
                self.quantum.delete_port(netid, portid)

    def teardown_vlanbinding(self):
        """tearDown VlanBinding table"""
        LOG.debug("Tearing Down Vlan Binding")
        vlans = self.dbtest.get_all_vlan_bindings()
        for vlan in vlans:
            netid = vlan["net-id"]
            self.dbtest.delete_vlan_binding(netid)

    def teardown_portprofile(self):
        """tearDown PortProfile table"""
        LOG.debug("Tearing Down Port Profile")
        pps = self.dbtest.get_all_portprofiles()
        for pprofile in pps:
            ppid = pprofile["portprofile-id"]
            self.dbtest.delete_portprofile("t1", ppid)

    def teardown_portprofilebinding(self):
        """tearDown PortProfileBinding table"""
        LOG.debug("Tearing Down Port Profile Binding")
        pp_bindings = self.dbtest.get_all_pp_bindings()
        for pp_binding in pp_bindings:
            ppid = pp_binding["portprofile-id"]
            portid = pp_binding["port-id"]
            self.dbtest.delete_pp_binding("t1", portid, ppid)


class QuantumDBTest(unittest.TestCase):
    """Class conisting of Quantum DB unit tests"""
    def setUp(self):
        """Setup for tests"""
        l2network_db.initialize()
        self.dbtest = QuantumDB()
        self.tenant_id = "t1"
        LOG.debug("Setup")

    def tearDown(self):
        """Tear Down"""
        db.clear_db()

    def testa_create_network(self):
        """test to create network"""
        net1 = self.dbtest.create_network(self.tenant_id, "plugin_test1")
        self.assertTrue(net1["net-name"] == "plugin_test1")
        self.teardown_network_port()

    def testb_get_networks(self):
        """test to get all networks"""
        net1 = self.dbtest.create_network(self.tenant_id, "plugin_test1")
        self.assertTrue(net1["net-name"] == "plugin_test1")
        net2 = self.dbtest.create_network(self.tenant_id, "plugin_test2")
        self.assertTrue(net2["net-name"] == "plugin_test2")
        nets = self.dbtest.get_all_networks(self.tenant_id)
        count = 0
        for net in nets:
            if "plugin_test" in net["net-name"]:
                count += 1
        self.assertTrue(count == 2)
        self.teardown_network_port()

    def testc_delete_network(self):
        """test to delete network"""
        net1 = self.dbtest.create_network(self.tenant_id, "plugin_test1")
        self.assertTrue(net1["net-name"] == "plugin_test1")
        self.dbtest.delete_network(net1["net-id"])
        nets = self.dbtest.get_all_networks(self.tenant_id)
        count = 0
        for net in nets:
            if "plugin_test1" in net["net-name"]:
                count += 1
        self.assertTrue(count == 0)
        self.teardown_network_port()

    def testd_update_network(self):
        """test to update (rename) network"""
        net1 = self.dbtest.create_network(self.tenant_id, "plugin_test1")
        self.assertTrue(net1["net-name"] == "plugin_test1")
        net = self.dbtest.update_network(self.tenant_id, net1["net-id"],
          name="plugin_test1_renamed")
        self.assertTrue(net["net-name"] == "plugin_test1_renamed")
        self.teardown_network_port()

    def teste_create_port(self):
        """test to create port"""
        net1 = self.dbtest.create_network(self.tenant_id, "plugin_test1")
        port = self.dbtest.create_port(net1["net-id"])
        self.assertTrue(port["net-id"] == net1["net-id"])
        ports = self.dbtest.get_all_ports(net1["net-id"])
        count = 0
        for por in ports:
            count += 1
        self.assertTrue(count == 1)
        self.teardown_network_port()

    def testf_delete_port(self):
        """test to delete port"""
        net1 = self.dbtest.create_network(self.tenant_id, "plugin_test1")
        port = self.dbtest.create_port(net1["net-id"])
        self.assertTrue(port["net-id"] == net1["net-id"])
        ports = self.dbtest.get_all_ports(net1["net-id"])
        count = 0
        for por in ports:
            count += 1
        self.assertTrue(count == 1)
        for por in ports:
            self.dbtest.delete_port(net1["net-id"], por["port-id"])
        ports = self.dbtest.get_all_ports(net1["net-id"])
        count = 0
        for por in ports:
            count += 1
        self.assertTrue(count == 0)
        self.teardown_network_port()

    def testg_plug_unplug_interface(self):
        """test to plug/unplug interface"""
        net1 = self.dbtest.create_network(self.tenant_id, "plugin_test1")
        port1 = self.dbtest.create_port(net1["net-id"])
        self.dbtest.plug_interface(net1["net-id"], port1["port-id"], "vif1.1")
        port = self.dbtest.get_port(net1["net-id"], port1["port-id"])
        self.assertTrue(port[0]["int-id"] == "vif1.1")
        self.dbtest.unplug_interface(net1["net-id"], port1["port-id"])
        port = self.dbtest.get_port(net1["net-id"], port1["port-id"])
        self.assertTrue(port[0]["int-id"] is None)
        self.teardown_network_port()

    def testh_joined_test(self):
        """test to get network and port"""
        net1 = self.dbtest.create_network("t1", "net1")
        port1 = self.dbtest.create_port(net1["net-id"])
        self.assertTrue(port1["net-id"] == net1["net-id"])
        port2 = self.dbtest.create_port(net1["net-id"])
        self.assertTrue(port2["net-id"] == net1["net-id"])
        ports = self.dbtest.get_all_ports(net1["net-id"])
        for port in ports:
            net = port["net"]
            LOG.debug("Port id %s Net id %s" % (port["port-id"], net.uuid))
        self.teardown_joined_test()

    def teardown_network_port(self):
        """tearDown for Network and Port table"""
        networks = self.dbtest.get_all_networks(self.tenant_id)
        for net in networks:
            netid = net["net-id"]
            name = net["net-name"]
            if "plugin_test" in name:
                ports = self.dbtest.get_all_ports(netid)
                for por in ports:
                    self.dbtest.delete_port(netid, por["port-id"])
                self.dbtest.delete_network(netid)

    def teardown_joined_test(self):
        """tearDown for joined Network and Port test"""
        LOG.debug("Tearing Down Network and Ports")
        nets = self.dbtest.get_all_networks("t1")
        for net in nets:
            netid = net["net-id"]
            ports = self.dbtest.get_all_ports(netid)
            for port in ports:
                self.dbtest.delete_port(port["net-id"], port["port-id"])
            self.dbtest.delete_network(netid)

"""
if __name__ == "__main__":
    usagestr = "Usage: %prog [OPTIONS] <command> [args]"
    parser = OptionParser(usage=usagestr)
    parser.add_option("-v", "--verbose", dest="verbose",
      action="store_true", default=False, help="turn on verbose logging")

    options, args = parser.parse_args()

    if options.verbose:
        LOG.basicConfig(level=LOG.DEBUG)
    else:
        LOG.basicConfig(level=LOG.WARN)

    l2network_db.initialize()

    # Run the tests
    suite = unittest.TestLoader().loadTestsFromTestCase(QuantumDBTest)
    unittest.TextTestRunner(verbosity=2).run(suite)
    suite = unittest.TestLoader().loadTestsFromTestCase(L2networkDBTest)
    unittest.TextTestRunner(verbosity=2).run(suite)
"""
