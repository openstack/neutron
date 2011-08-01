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

import ConfigParser
import os
import logging as LOG
import unittest

from optparse import OptionParser
from quantum.plugins.cisco.common import cisco_constants as const

import quantum.db.api as db
import quantum.db.models
import quantum.plugins.cisco.db.l2network_db as l2network_db
import quantum.plugins.cisco.db.l2network_models

CONF_FILE = "db_conn.ini"
LOG.getLogger(const.LOGGER_COMPONENT_NAME)


def find_config(basepath):
    for root, dirs, files in os.walk(basepath):
        if CONF_FILE in files:
            return os.path.join(root, CONF_FILE)
    return None


def db_conf(configfile=None):
    config = ConfigParser.ConfigParser()
    if configfile == None:
        if os.path.exists(CONF_FILE):
            configfile = CONF_FILE
        else:
            configfile = \
           find_config(os.path.abspath(os.path.dirname(__file__)))
    if configfile == None:
        raise Exception("Configuration file \"%s\" doesn't exist" %
              (configfile))
    LOG.debug("Using configuration file: %s" % configfile)
    config.read(configfile)

    DB_NAME = config.get("DATABASE", "name")
    DB_USER = config.get("DATABASE", "user")
    DB_PASS = config.get("DATABASE", "pass")
    DB_HOST = config.get("DATABASE", "host")
    options = {"sql_connection": "mysql://%s:%s@%s/%s" % (DB_USER,
    DB_PASS, DB_HOST, DB_NAME)}
    db.configure_db(options)


class UcsDB(object):
    def get_all_ucsmbindings(self):
        bindings = []
        try:
            for x in ucs_db.get_all_ucsmbinding():
                LOG.debug("Getting ucsm binding : %s" % x.ucsm_ip)
                bind_dict = {}
                bind_dict["ucsm-ip"] = str(x.ucsm_ip)
                bind_dict["network-id"] = str(x.network_id)
                bindings.append(bind_dict)
        except Exception, e:
            LOG.error("Failed to get all bindings: %s" % str(e))
        return bindings

    def get_ucsmbinding(self, ucsm_ip):
        binding = []
        try:
            for x in ucs_db.get_ucsmbinding(ucsm_ip):
                LOG.debug("Getting ucsm binding : %s" % x.ucsm_ip)
                bind_dict = {}
                bind_dict["ucsm-ip"] = str(res.ucsm_ip)
                bind_dict["network-id"] = str(res.network_id)
                binding.append(bind_dict)
        except Exception, e:
            LOG.error("Failed to get binding: %s" % str(e))
        return binding

    def create_ucsmbinding(self, ucsm_ip, networ_id):
        bind_dict = {}
        try:
            res = ucs_db.add_ucsmbinding(ucsm_ip, networ_id)
            LOG.debug("Created ucsm binding: %s" % res.ucsm_ip)
            bind_dict["ucsm-ip"] = str(res.ucsm_ip)
            bind_dict["network-id"] = str(res.network_id)
            return bind_dict
        except Exception, e:
            LOG.error("Failed to create ucsm binding: %s" % str(e))

    def delete_ucsmbinding(self, ucsm_ip):
        try:
            res = ucs_db.remove_ucsmbinding(ucsm_ip)
            LOG.debug("Deleted ucsm binding : %s" % res.ucsm_ip)
            bind_dict = {}
            bind_dict["ucsm-ip"] = str(res.ucsm_ip)
            return bind_dict
        except Exception, e:
            raise Exception("Failed to delete dynamic vnic: %s" % str(e))

    def update_ucsmbinding(self, ucsm_ip, network_id):
        try:
            res = ucs_db.update_ucsmbinding(ucsm_ip, network_id)
            LOG.debug("Updating ucsm binding : %s" % res.ucsm_ip)
            bind_dict = {}
            bind_dict["ucsm-ip"] = str(res.ucsm_ip)
            bind_dict["network-id"] = str(res.network_id)
            return bind_dict
        except Exception, e:
            raise Exception("Failed to update dynamic vnic: %s" % str(e))

    def get_all_dynamicvnics(self):
        vnics = []
        try:
            for x in ucs_db.get_all_dynamicvnics():
                LOG.debug("Getting dynamic vnic : %s" % x.uuid)
                vnic_dict = {}
                vnic_dict["vnic-id"] = str(x.uuid)
                vnic_dict["device-name"] = x.device_name
                vnic_dict["blade-id"] = str(x.blade_id)
                vnics.append(vnic_dict)
        except Exception, e:
            LOG.error("Failed to get all dynamic vnics: %s" % str(e))
        return vnics

    def get_dynamicvnic(self, vnic_id):
        vnic = []
        try:
            for x in ucs_db.get_dynamicvnic(vnic_id):
                LOG.debug("Getting dynamic vnic : %s" % x.uuid)
                vnic_dict = {}
                vnic_dict["vnic-id"] = str(x.uuid)
                vnic_dict["device-name"] = x.device_name
                vnic_dict["blade-id"] = str(x.blade_id)
                vnic.append(vnic_dict)
        except Exception, e:
            LOG.error("Failed to get dynamic vnic: %s" % str(e))
        return vnic

    def create_dynamicvnic(self, device_name, blade_id):
        vnic_dict = {}
        try:
            res = ucs_db.add_dynamicvnic(device_name, blade_id)
            LOG.debug("Created dynamic vnic: %s" % res.uuid)
            vnic_dict["vnic-id"] = str(res.uuid)
            vnic_dict["device-name"] = res.device_name
            vnic_dict["blade-id"] = str(res.blade_id)
            return vnic_dict
        except Exception, e:
            LOG.error("Failed to create dynamic vnic: %s" % str(e))

    def delete_dynamicvnic(self, vnic_id):
        try:
            res = ucs_db.remove_dynamicvnic(vnic_id)
            LOG.debug("Deleted dynamic vnic : %s" % res.uuid)
            vnic_dict = {}
            vnic_dict["vnic-id"] = str(res.uuid)
            return vnic_dict
        except Exception, e:
            raise Exception("Failed to delete dynamic vnic: %s" % str(e))

    def update_dynamicvnic(self, vnic_id, device_name=None, blade_id=None):
        try:
            res = ucs_db.update_dynamicvnic(vnic_id, device_name, blade_id)
            LOG.debug("Updating dynamic vnic : %s" % res.uuid)
            vnic_dict = {}
            vnic_dict["vnic-id"] = str(res.uuid)
            vnic_dict["device-name"] = res.device_name
            vnic_dict["blade-id"] = str(res.blade_id)
            return vnic_dict
        except Exception, e:
            raise Exception("Failed to update dynamic vnic: %s" % str(e))

    def get_all_blades(self):
        blades = []
        try:
            for x in ucs_db.get_all_blades():
                LOG.debug("Getting blade : %s" % x.uuid)
                blade_dict = {}
                blade_dict["blade-id"] = str(x.uuid)
                blade_dict["mgmt-ip"] = str(x.mgmt_ip)
                blade_dict["mac-addr"] = str(x.mac_addr)
                blade_dict["chassis-id"] = str(x.chassis_id)
                blade_dict["ucsm-ip"] = str(x.ucsm_ip)
                blades.append(blade_dict)
        except Exception, e:
            LOG.error("Failed to get all blades: %s" % str(e))
        return blades

    def get_blade(self, blade_id):
        blade = []
        try:
            for x in ucs_db.get_blade(blade_id):
                LOG.debug("Getting blade : %s" % x.uuid)
                blade_dict = {}
                blade_dict["blade-id"] = str(x.uuid)
                blade_dict["mgmt-ip"] = str(x.mgmt_ip)
                blade_dict["mac-addr"] = str(x.mac_addr)
                blade_dict["chassis-id"] = str(x.chassis_id)
                blade_dict["ucsm-ip"] = str(x.ucsm_ip)
                blade.append(blade_dict)
        except Exception, e:
            LOG.error("Failed to get all blades: %s" % str(e))
        return blade

    def create_blade(self, mgmt_ip, mac_addr, chassis_id, ucsm_ip):
        blade_dict = {}
        try:
            res = ucs_db.add_blade(mgmt_ip, mac_addr, chassis_id, ucsm_ip)
            LOG.debug("Created blade: %s" % res.uuid)
            blade_dict["blade-id"] = str(res.uuid)
            blade_dict["mgmt-ip"] = str(res.mgmt_ip)
            blade_dict["mac-addr"] = str(res.mac_addr)
            blade_dict["chassis-id"] = str(res.chassis_id)
            blade_dict["ucsm-ip"] = str(res.ucsm_ip)
            return blade_dict
        except Exception, e:
            LOG.error("Failed to create blade: %s" % str(e))

    def delete_blade(self, blade_id):
        try:
            res = ucs_db.remove_blade(blade_id)
            LOG.debug("Deleted blade : %s" % res.uuid)
            blade_dict = {}
            blade_dict["blade-id"] = str(res.uuid)
            return blade_dict
        except Exception, e:
            raise Exception("Failed to delete blade: %s" % str(e))

    def update_blade(self, blade_id, mgmt_ip=None, mac_addr=None,\
                     chassis_id=None, ucsm_ip=None):
        try:
            res = ucs_db.update_blade(blade_id, mgmt_ip, mac_addr, \
                                      chassis_id, ucsm_ip)
            LOG.debug("Updating blade : %s" % res.uuid)
            blade_dict = {}
            blade_dict["blade-id"] = str(res.uuid)
            blade_dict["mgmt-ip"] = str(res.mgmt_ip)
            blade_dict["mac-addr"] = str(res.mac_addr)
            blade_dict["chassis-id"] = str(res.chassis_id)
            blade_dict["ucsm-ip"] = str(res.ucsm_ip)
            return blade_dict
        except Exception, e:
            raise Exception("Failed to update blade: %s" % str(e))

    def get_all_port_bindings(self):
        port_bindings = []
        try:
            for x in ucs_db.get_all_portbindings():
                LOG.debug("Getting port binding for port: %s" % x.port_id)
                port_bind_dict = {}
                port_bind_dict["port-id"] = x.port_id
                port_bind_dict["dynamic-vnic-id"] = str(x.dynamic_vnic_id)
                port_bind_dict["portprofile-name"] = x.portprofile_name
                port_bind_dict["vlan-name"] = x.vlan_name
                port_bind_dict["vlan-id"] = str(x.vlan_id)
                port_bind_dict["qos"] = x.qos
                port_bindings.append(port_bind_dict)
        except Exception, e:
            LOG.error("Failed to get all port bindings: %s" % str(e))
        return port_bindings

    def get_port_binding(self):
        port_binding = []
        try:
            for x in ucs_db.get_portbinding(port_id):
                LOG.debug("Getting port binding for port: %s" % x.port_id)
                port_bind_dict = {}
                port_bind_dict["port-id"] = x.port_id
                port_bind_dict["dynamic-vnic-id"] = str(x.dynamic_vnic_id)
                port_bind_dict["portprofile-name"] = x.portprofile_name
                port_bind_dict["vlan-name"] = x.vlan_name
                port_bind_dict["vlan-id"] = str(x.vlan_id)
                port_bind_dict["qos"] = x.qos
                port_bindings.append(port_bind_dict)
        except Exception, e:
            LOG.error("Failed to get port binding: %s" % str(e))
        return port_binding

    def create_port_binding(self, port_id, dynamic_vnic_id, portprofile_name, \
                            vlan_name, vlan_id, qos):
        port_bind_dict = {}
        try:
            res = ucs_db.add_portbinding(port_id, dynamic_vnic_id, \
                                  portprofile_name, vlan_name, vlan_id, qos)
            LOG.debug("Created port binding: %s" % res.port_id)
            port_bind_dict["port-id"] = res.port_id
            port_bind_dict["dynamic-vnic-id"] = str(res.dynamic_vnic_id)
            port_bind_dict["portprofile-name"] = res.portprofile_name
            port_bind_dict["vlan-name"] = res.vlan_name
            port_bind_dict["vlan-id"] = str(res.vlan_id)
            port_bind_dict["qos"] = res.qos
            return port_bind_dict
        except Exception, e:
            LOG.error("Failed to create port binding: %s" % str(e))

    def delete_port_binding(self, port_id):
        try:
            res = ucs_db.remove_portbinding(port_id)
            LOG.debug("Deleted port binding : %s" % res.port_id)
            port_bind_dict = {}
            port_bind_dict["port-id"] = res.port_id
            return port_bind_dict
        except Exception, e:
            raise Exception("Failed to delete port profile: %s" % str(e))

    def update_port_binding(self, port_id, dynamic_vnic_id, \
                         portprofile_name, vlan_name, vlan_id, qos):
        try:
            res = ucs_db.update_portbinding(port_id, dynamic_vnic_id, \
                               portprofile_name, vlan_name, vlan_id, qos)
            LOG.debug("Updating port binding: %s" % res.port_id)
            port_bind_dict = {}
            port_bind_dict["port-id"] = res.port_id
            port_bind_dict["dynamic-vnic-id"] = str(res.dynamic_vnic_id)
            port_bind_dict["portprofile-name"] = res.portprofile_name
            port_bind_dict["vlan-name"] = res.vlan_name
            port_bind_dict["vlan-id"] = str(res.vlan_id)
            port_bind_dict["qos"] = res.qos
            return port_bind_dict
        except Exception, e:
            raise Exception("Failed to update portprofile binding:%s" % str(e))


class QuantumDB(object):
    def get_all_networks(self, tenant_id):
        nets = []
        try:
            for x in db.network_list(tenant_id):
                LOG.debug("Getting network: %s" % x.uuid)
                net_dict = {}
                net_dict["tenant-id"] = x.tenant_id
                net_dict["net-id"] = str(x.uuid)
                net_dict["net-name"] = x.name
                nets.append(net_dict)
        except Exception, e:
            LOG.error("Failed to get all networks: %s" % str(e))
        return nets

    def get_network(self, network_id):
        net = []
        try:
            for x in db.network_get(network_id):
                LOG.debug("Getting network: %s" % x.uuid)
                net_dict = {}
                net_dict["tenant-id"] = x.tenant_id
                net_dict["net-id"] = str(x.uuid)
                net_dict["net-name"] = x.name
                nets.append(net_dict)
        except Exception, e:
            LOG.error("Failed to get network: %s" % str(e))
        return net

    def create_network(self, tenant_id, net_name):
        net_dict = {}
        try:
            res = db.network_create(tenant_id, net_name)
            LOG.debug("Created network: %s" % res.uuid)
            net_dict["tenant-id"] = res.tenant_id
            net_dict["net-id"] = str(res.uuid)
            net_dict["net-name"] = res.name
            return net_dict
        except Exception, e:
            LOG.error("Failed to create network: %s" % str(e))

    def delete_network(self, net_id):
        try:
            net = db.network_destroy(net_id)
            LOG.debug("Deleted network: %s" % net.uuid)
            net_dict = {}
            net_dict["net-id"] = str(net.uuid)
            return net_dict
        except Exception, e:
            raise Exception("Failed to delete port: %s" % str(e))

    def rename_network(self, tenant_id, net_id, new_name):
        try:
            net = db.network_rename(net_id, tenant_id, new_name)
            LOG.debug("Renamed network: %s" % net.uuid)
            net_dict = {}
            net_dict["net-id"] = str(net.uuid)
            net_dict["net-name"] = net.name
            return net_dict
        except Exception, e:
            raise Exception("Failed to rename network: %s" % str(e))

    def get_all_ports(self, net_id):
        ports = []
        try:
            for x in db.port_list(net_id):
                LOG.debug("Getting port: %s" % x.uuid)
                port_dict = {}
                port_dict["port-id"] = str(x.uuid)
                port_dict["net-id"] = str(x.network_id)
                port_dict["int-id"] = x.interface_id
                port_dict["state"] = x.state
                ports.append(port_dict)
            return ports
        except Exception, e:
            LOG.error("Failed to get all ports: %s" % str(e))

    def get_port(self, port_id):
        port = []
        try:
            for x in db.port_get(port_id):
                LOG.debug("Getting port: %s" % x.uuid)
                port_dict = {}
                port_dict["port-id"] = str(x.uuid)
                port_dict["net-id"] = str(x.network_id)
                port_dict["int-id"] = x.interface_id
                port_dict["state"] = x.state
                port.append(port_dict)
            return port
        except Exception, e:
            LOG.error("Failed to get port: %s" % str(e))

    def create_port(self, net_id):
        port_dict = {}
        try:
            port = db.port_create(net_id)
            LOG.debug("Creating port %s" % port.uuid)
            port_dict["port-id"] = str(port.uuid)
            port_dict["net-id"] = str(port.network_id)
            port_dict["int-id"] = port.interface_id
            port_dict["state"] = port.state
            return port_dict
        except Exception, e:
            LOG.error("Failed to create port: %s" % str(e))

    def delete_port(self, port_id):
        try:
            port = db.port_destroy(port_id)
            LOG.debug("Deleted port %s" % port.uuid)
            port_dict = {}
            port_dict["port-id"] = str(port.uuid)
            return port_dict
        except Exception, e:
            raise Exception("Failed to delete port: %s" % str(e))

    def update_port(self, port_id, port_state):
        try:
            port = db.port_set_state(port_id, port_state)
            LOG.debug("Updated port %s" % port.uuid)
            port_dict = {}
            port_dict["port-id"] = str(port.uuid)
            port_dict["net-id"] = str(port.network_id)
            port_dict["int-id"] = port.interface_id
            port_dict["state"] = port.state
            return port_dict
        except Exception, e:
            raise Exception("Failed to update port state: %s" % str(e))


class L2networkDB(object):
    def get_all_vlan_bindings(self):
        vlans = []
        try:
            for x in l2network_db.get_all_vlan_bindings():
                LOG.debug("Getting vlan bindings for vlan: %s" % x.vlan_id)
                vlan_dict = {}
                vlan_dict["vlan-id"] = str(x.vlan_id)
                vlan_dict["vlan-name"] = x.vlan_name
                vlan_dict["net-id"] = str(x.network_id)
                vlans.append(vlan_dict)
        except Exception, e:
            LOG.error("Failed to get all vlan bindings: %s" % str(e))
        return vlans

    def get_vlan_binding(self, network_id):
        vlan = []
        try:
            for x in l2network_db.get_vlan_binding(network_id):
                LOG.debug("Getting vlan binding for vlan: %s" % x.vlan_id)
                vlan_dict = {}
                vlan_dict["vlan-id"] = str(x.vlan_id)
                vlan_dict["vlan-name"] = x.vlan_name
                vlan_dict["net-id"] = str(x.network_id)
                vlan.append(vlan_dict)
        except Exception, e:
            LOG.error("Failed to get vlan binding: %s" % str(e))
        return vlan

    def create_vlan_binding(self, vlan_id, vlan_name, network_id):
        vlan_dict = {}
        try:
            res = l2network_db.add_vlan_binding(vlan_id, vlan_name, network_id)
            LOG.debug("Created vlan binding for vlan: %s" % res.vlan_id)
            vlan_dict["vlan-id"] = str(res.vlan_id)
            vlan_dict["vlan-name"] = res.vlan_name
            vlan_dict["net-id"] = str(res.network_id)
            return vlan_dict
        except Exception, e:
            LOG.error("Failed to create vlan binding: %s" % str(e))

    def delete_vlan_binding(self, network_id):
        try:
            res = l2network_db.remove_vlan_binding(network_id)
            LOG.debug("Deleted vlan binding for vlan: %s" % res.vlan_id)
            vlan_dict = {}
            vlan_dict["vlan-id"] = str(res.vlan_id)
            return vlan_dict
        except Exception, e:
            raise Exception("Failed to delete vlan binding: %s" % str(e))

    def update_vlan_binding(self, network_id, vlan_id, vlan_name):
        try:
            res = l2network_db.update_vlan_binding(network_id, vlan_id, \
                                                            vlan_name)
            LOG.debug("Updating vlan binding for vlan: %s" % res.vlan_id)
            vlan_dict = {}
            vlan_dict["vlan-id"] = str(res.vlan_id)
            vlan_dict["vlan-name"] = res.vlan_name
            vlan_dict["net-id"] = str(res.network_id)
            return vlan_dict
        except Exception, e:
            raise Exception("Failed to update vlan binding: %s" % str(e))

    def get_all_portprofiles(self):
        pps = []
        try:
            for x in l2network_db.get_all_portprofiles():
                LOG.debug("Getting port profile : %s" % x.uuid)
                pp_dict = {}
                pp_dict["portprofile-id"] = str(x.uuid)
                pp_dict["portprofile-name"] = x.name
                pp_dict["vlan-id"] = str(x.vlan_id)
                pp_dict["qos"] = x.qos
                pps.append(pp_dict)
        except Exception, e:
            LOG.error("Failed to get all port profiles: %s" % str(e))
        return pps

    def get_portprofile(self, port_id):
        pp = []
        try:
            for x in l2network_db.get_portprofile(port_id):
                LOG.debug("Getting port profile : %s" % x.uuid)
                pp_dict = {}
                pp_dict["portprofile-id"] = str(x.uuid)
                pp_dict["portprofile-name"] = x.name
                pp_dict["vlan-id"] = str(x.vlan_id)
                pp_dict["qos"] = x.qos
                pp.append(pp_dict)
        except Exception, e:
            LOG.error("Failed to get port profile: %s" % str(e))
        return pp

    def create_portprofile(self, name, vlan_id, qos):
        pp_dict = {}
        try:
            res = l2network_db.add_portprofile(name, vlan_id, qos)
            LOG.debug("Created port profile: %s" % res.uuid)
            pp_dict["portprofile-id"] = str(res.uuid)
            pp_dict["portprofile-name"] = res.name
            pp_dict["vlan-id"] = str(res.vlan_id)
            pp_dict["qos"] = res.qos
            return pp_dict
        except Exception, e:
            LOG.error("Failed to create port profile: %s" % str(e))

    def delete_portprofile(self, pp_id):
        try:
            res = l2network_db.remove_portprofile(pp_id)
            LOG.debug("Deleted port profile : %s" % res.uuid)
            pp_dict = {}
            pp_dict["pp-id"] = str(res.uuid)
            return pp_dict
        except Exception, e:
            raise Exception("Failed to delete port profile: %s" % str(e))

    def update_portprofile(self, pp_id, name, vlan_id, qos):
        try:
            res = l2network_db.update_portprofile(pp_id, name, vlan_id, qos)
            LOG.debug("Updating port profile : %s" % res.uuid)
            pp_dict = {}
            pp_dict["portprofile-id"] = str(res.uuid)
            pp_dict["portprofile-name"] = res.name
            pp_dict["vlan-id"] = str(res.vlan_id)
            pp_dict["qos"] = res.qos
            return pp_dict
        except Exception, e:
            raise Exception("Failed to update port profile: %s" % str(e))

    def get_all_pp_bindings(self):
        pp_bindings = []
        try:
            for x in l2network_db.get_all_pp_bindings():
                LOG.debug("Getting port profile binding: %s" % \
                                               x.portprofile_id)
                ppbinding_dict = {}
                ppbinding_dict["portprofile-id"] = str(x.portprofile_id)
                ppbinding_dict["net-id"] = str(x.network_id)
                ppbinding_dict["tenant-id"] = x.tenant_id
                ppbinding_dict["default"] = x.default
                pp_bindings.append(ppbinding_dict)
        except Exception, e:
            LOG.error("Failed to get all port profiles: %s" % str(e))
        return pp_bindings

    def get_pp_binding(self, pp_id):
        pp_binding = []
        try:
            for x in l2network_db.get_pp_binding(pp_id):
                LOG.debug("Getting port profile binding: %s" % \
                                                 x.portprofile_id)
                ppbinding_dict = {}
                ppbinding_dict["portprofile-id"] = str(x.portprofile_id)
                ppbinding_dict["net-id"] = str(x.network_id)
                ppbinding_dict["tenant-id"] = x.tenant_id
                ppbinding_dict["default"] = x.default
                pp_bindings.append(ppbinding_dict)
        except Exception, e:
            LOG.error("Failed to get port profile binding: %s" % str(e))
        return pp_binding

    def create_pp_binding(self, tenant_id, net_id, pp_id, default):
        ppbinding_dict = {}
        try:
            res = l2network_db.add_pp_binding(tenant_id, net_id, pp_id, \
                                                                default)
            LOG.debug("Created port profile binding: %s" % res.portprofile_id)
            ppbinding_dict["portprofile-id"] = str(res.portprofile_id)
            ppbinding_dict["net-id"] = str(res.network_id)
            ppbinding_dict["tenant-id"] = res.tenant_id
            ppbinding_dict["default"] = res.default
            return ppbinding_dict
        except Exception, e:
            LOG.error("Failed to create port profile binding: %s" % str(e))

    def delete_pp_binding(self, pp_id):
        try:
            res = l2network_db.remove_pp_binding(pp_id)
            LOG.debug("Deleted port profile binding : %s" % res.portprofile_id)
            ppbinding_dict = {}
            ppbinding_dict["portprofile-id"] = str(res.portprofile_id)
            return ppbinding_dict
        except Exception, e:
            raise Exception("Failed to delete port profile: %s" % str(e))

    def update_pp_binding(self, pp_id, tenant_id, net_id, default):
        try:
            res = l2network_db.update_pp_binding(pp_id, tenant_id, net_id,\
                                                                   default)
            LOG.debug("Updating port profile binding: %s" % res.portprofile_id)
            ppbinding_dict = {}
            ppbinding_dict["portprofile-id"] = str(res.portprofile_id)
            ppbinding_dict["net-id"] = str(res.network_id)
            ppbinding_dict["tenant-id"] = res.tenant_id
            ppbinding_dict["default"] = res.default
            return ppbinding_dict
        except Exception, e:
            raise Exception("Failed to update portprofile binding:%s" % str(e))


class UcsDBTest(unittest.TestCase):
    def setUp(self):
        self.dbtest = UcsDB()
        LOG.debug("Setup")

    def testACreateUcsmBinding(self):
        binding1 = self.dbtest.create_ucsmbinding("1.2.3.4", "net1")
        self.assertTrue(binding1["ucsm-ip"] == "1.2.3.4")
        self.tearDownUcsmBinding()

    def testBGetAllUcsmBindings(self):
        binding1 = self.dbtest.create_ucsmbinding("1.2.3.4", "net1")
        binding2 = self.dbtest.create_ucsmbinding("2.3.4.5", "net1")
        bindings = self.dbtest.get_all_ucsmbindings()
        count = 0
        for x in bindings:
            if "net" in x["network-id"]:
                count += 1
        self.assertTrue(count == 2)
        self.tearDownUcsmBinding()

    def testCDeleteUcsmBinding(self):
        binding1 = self.dbtest.create_ucsmbinding("1.2.3.4", "net1")
        self.dbtest.delete_ucsmbinding(binding1["ucsm-ip"])
        bindings = self.dbtest.get_all_ucsmbindings()
        count = 0
        for x in bindings:
            if "net " in x["network-id"]:
                count += 1
        self.assertTrue(count == 0)
        self.tearDownUcsmBinding()

    def testDUpdateUcsmBinding(self):
        binding1 = self.dbtest.create_ucsmbinding("1.2.3.4", "net1")
        binding1 = self.dbtest.update_ucsmbinding(binding1["ucsm-ip"], \
                                                             "newnet1")
        bindings = self.dbtest.get_all_ucsmbindings()
        count = 0
        for x in bindings:
            if "new" in x["network-id"]:
                count += 1
        self.assertTrue(count == 1)
        self.tearDownUcsmBinding()

    def testECreateDynamicVnic(self):
        blade1 = self.dbtest.create_blade("1.2.3.4", "abcd", "chassis1", \
                                                               "9.8.7.6")
        vnic1 = self.dbtest.create_dynamicvnic("eth1", blade1["blade-id"])
        self.assertTrue(vnic1["device-name"] == "eth1")
        self.tearDownDyanmicVnic()

    def testFGetAllDyanmicVnics(self):
        blade1 = self.dbtest.create_blade("1.2.3.4", "abcd", "chassis1", \
                                                                "9.8.7.6")
        vnic1 = self.dbtest.create_dynamicvnic("eth1", blade1["blade-id"])
        vnic2 = self.dbtest.create_dynamicvnic("eth2", blade1["blade-id"])
        vnics = self.dbtest.get_all_dynamicvnics()
        count = 0
        for x in vnics:
            if "eth" in x["device-name"]:
                count += 1
        self.assertTrue(count == 2)
        self.tearDownDyanmicVnic()

    def testGDeleteDyanmicVnic(self):
        blade1 = self.dbtest.create_blade("1.2.3.4", "abcd", "chassis1", \
                                                               "9.8.7.6")
        vnic1 = self.dbtest.create_dynamicvnic("eth1", blade1["blade-id"])
        self.dbtest.delete_dynamicvnic(vnic1["vnic-id"])
        vnics = self.dbtest.get_all_dynamicvnics()
        count = 0
        for x in vnics:
            if "eth " in x["device-name"]:
                count += 1
        self.assertTrue(count == 0)
        self.tearDownDyanmicVnic()

    def testHUpdateDynamicVnic(self):
        blade1 = self.dbtest.create_blade("1.2.3.4", "abcd", "chassis1", \
                                                                "9.8.7.6")
        vnic1 = self.dbtest.create_dynamicvnic("eth1", blade1["blade-id"])
        vnic1 = self.dbtest.update_dynamicvnic(vnic1["vnic-id"], "neweth1", \
                                                              "newblade2")
        vnics = self.dbtest.get_all_dynamicvnics()
        count = 0
        for x in vnics:
            if "new" in x["device-name"]:
                count += 1
        self.assertTrue(count == 1)
        self.tearDownDyanmicVnic()

    def testICreateUcsBlade(self):
        blade1 = self.dbtest.create_blade("1.2.3.4", "abcd", "chassis1", \
                                                              "9.8.7.6")
        self.assertTrue(blade1["mgmt-ip"] == "1.2.3.4")
        self.tearDownUcsBlade()

    def testJGetAllUcsBlade(self):
        blade1 = self.dbtest.create_blade("1.2.3.4", "abcd", "chassis1", \
                                                                 "9.8.7.6")
        blade2 = self.dbtest.create_blade("2.3.4.5", "efgh", "chassis1", \
                                                                 "9.8.7.6")
        blades = self.dbtest.get_all_blades()
        count = 0
        for x in blades:
            if "chassis" in x["chassis-id"]:
                count += 1
        self.assertTrue(count == 2)
        self.tearDownUcsBlade()

    def testKDeleteUcsBlade(self):
        blade1 = self.dbtest.create_blade("1.2.3.4", "abcd", "chassis1", \
                                                                 "9.8.7.6")
        self.dbtest.delete_blade(blade1["blade-id"])
        blades = self.dbtest.get_all_blades()
        count = 0
        for x in blades:
            if "chassis " in x["chassis-id"]:
                count += 1
        self.assertTrue(count == 0)
        self.tearDownUcsBlade()

    def testLUpdateUcsBlade(self):
        blade1 = self.dbtest.create_blade("1.2.3.4", "abcd", "chassis1", \
                                                                "9.8.7.6")
        blade2 = self.dbtest.update_blade(blade1["blade-id"], "2.3.4.5", \
                                          "newabcd", "chassis1", "9.8.7.6")
        blades = self.dbtest.get_all_blades()
        count = 0
        for x in blades:
            if "new" in x["mac-addr"]:
                count += 1
        self.assertTrue(count == 1)
        self.tearDownUcsBlade()

    def testMCreatePortBinding(self):
        port_bind1 = self.dbtest.create_port_binding("port1", "dv1", "pp1", \
                                                        "vlan1", 10, "qos1")
        self.assertTrue(port_bind1["port-id"] == "port1")
        self.tearDownPortBinding()

    def testNGetAllPortBinding(self):
        port_bind1 = self.dbtest.create_port_binding("port1", "dv1", "pp1", \
                                                         "vlan1", 10, "qos1")
        port_bind2 = self.dbtest.create_port_binding("port2", "dv2", "pp2", \
                                                         "vlan2", 20, "qos2")
        port_bindings = self.dbtest.get_all_port_bindings()
        count = 0
        for x in port_bindings:
            if "port" in x["port-id"]:
                count += 1
        self.assertTrue(count == 2)
        self.tearDownPortBinding()

    def testODeletePortBinding(self):
        port_bind1 = self.dbtest.create_port_binding("port1", "dv1", "pp1", \
                                                     "vlan1", 10, "qos1")
        self.dbtest.delete_port_binding("port1")
        port_bindings = self.dbtest.get_all_port_bindings()
        count = 0
        for x in port_bindings:
            if "port " in x["port-id"]:
                count += 1
        self.assertTrue(count == 0)
        self.tearDownPortBinding()

    def testPUpdatePortBinding(self):
        port_bind1 = self.dbtest.create_port_binding("port1", "dv1", "pp1", \
                                                     "vlan1", 10, "qos1")
        port_bind1 = self.dbtest.update_port_binding("port1", "newdv1", \
                                         "newpp1", "newvlan1", 11, "newqos1")
        port_bindings = self.dbtest.get_all_port_bindings()
        count = 0
        for x in port_bindings:
            if "new" in x["dynamic-vnic-id"]:
                count += 1
        self.assertTrue(count == 1)
        self.tearDownPortBinding()

    def tearDownUcsmBinding(self):
        print "Tearing Down Ucsm Bindings"
        binds = self.dbtest.get_all_ucsmbindings()
        for bind in binds:
            ip = bind["ucsm-ip"]
            self.dbtest.delete_ucsmbinding(ip)

    def tearDownDyanmicVnic(self):
        print "Tearing Down Dynamic Vnics"
        vnics = self.dbtest.get_all_dynamicvnics()
        for vnic in vnics:
            id = vnic["vnic-id"]
            self.dbtest.delete_dynamicvnic(id)
        self.tearDownUcsBlade()

    def tearDownUcsBlade(self):
        print "Tearing Down Blades"
        blades = self.dbtest.get_all_blades()
        for blade in blades:
            id = blade["blade-id"]
            self.dbtest.delete_blade(id)

    def tearDownPortBinding(self):
        print "Tearing Down Port Binding"
        port_bindings = self.dbtest.get_all_port_bindings()
        for port_binding in port_bindings:
            id = port_binding["port-id"]
            self.dbtest.delete_port_binding(id)


class L2networkDBTest(unittest.TestCase):
    def setUp(self):
        self.dbtest = L2networkDB()
        LOG.debug("Setup")

    def testACreateVlanBinding(self):
        vlan1 = self.dbtest.create_vlan_binding(10, "vlan1", "netid1")
        self.assertTrue(vlan1["vlan-id"] == "10")
        self.tearDownVlanBinding()

    def testBGetAllVlanBindings(self):
        vlan1 = self.dbtest.create_vlan_binding(10, "vlan1", "netid1")
        vlan2 = self.dbtest.create_vlan_binding(20, "vlan2", "netid2")
        vlans = self.dbtest.get_all_vlan_bindings()
        count = 0
        for x in vlans:
            if "netid" in x["net-id"]:
                count += 1
        self.assertTrue(count == 2)
        self.tearDownVlanBinding()

    def testCDeleteVlanBinding(self):
        vlan1 = self.dbtest.create_vlan_binding(10, "vlan1", "netid1")
        self.dbtest.delete_vlan_binding("netid1")
        vlans = self.dbtest.get_all_vlan_bindings()
        count = 0
        for x in vlans:
            if "netid " in x["net-id"]:
                count += 1
        self.assertTrue(count == 0)
        self.tearDownVlanBinding()

    def testDUpdateVlanBinding(self):
        vlan1 = self.dbtest.create_vlan_binding(10, "vlan1", "netid1")
        vlan1 = self.dbtest.update_vlan_binding("netid1", 11, "newvlan1")
        vlans = self.dbtest.get_all_vlan_bindings()
        count = 0
        for x in vlans:
            if "new" in x["vlan-name"]:
                count += 1
        self.assertTrue(count == 1)
        self.tearDownVlanBinding()

    def testICreatePortProfile(self):
        pp1 = self.dbtest.create_portprofile("portprofile1", 10, "qos1")
        self.assertTrue(pp1["portprofile-name"] == "portprofile1")
        self.tearDownPortProfile()

    def testJGetAllPortProfile(self):
        pp1 = self.dbtest.create_portprofile("portprofile1", 10, "qos1")
        pp2 = self.dbtest.create_portprofile("portprofile2", 20, "qos2")
        pps = self.dbtest.get_all_portprofiles()
        count = 0
        for x in pps:
            if "portprofile" in x["portprofile-name"]:
                count += 1
        self.assertTrue(count == 2)
        self.tearDownPortProfile()

    def testKDeletePortProfile(self):
        pp1 = self.dbtest.create_portprofile("portprofile1", 10, "qos1")
        self.dbtest.delete_portprofile(pp1["portprofile-id"])
        pps = self.dbtest.get_all_portprofiles()
        count = 0
        for x in pps:
            if "portprofile " in x["portprofile-name"]:
                count += 1
        self.assertTrue(count == 0)
        self.tearDownPortProfile()

    def testLUpdatePortProfile(self):
        pp1 = self.dbtest.create_portprofile("portprofile1", 10, "qos1")
        pp1 = self.dbtest.update_portprofile(pp1["portprofile-id"], \
                                          "newportprofile1", 20, "qos2")
        pps = self.dbtest.get_all_portprofiles()
        count = 0
        for x in pps:
            if "new" in x["portprofile-name"]:
                count += 1
        self.assertTrue(count == 1)
        self.tearDownPortProfile()

    def testMCreatePortProfileBinding(self):
        pp_binding1 = self.dbtest.create_pp_binding("t1", "net1", \
                                                    "portprofile1", "0")
        self.assertTrue(pp_binding1["portprofile-id"] == "portprofile1")
        self.tearDownPortProfileBinding()

    def testNGetAllPortProfileBinding(self):
        pp_binding1 = self.dbtest.create_pp_binding("t1", "net1", \
                                                     "portprofile1", "0")
        pp_binding2 = self.dbtest.create_pp_binding("t2", "net2", \
                                                     "portprofile2", "0")
        pp_bindings = self.dbtest.get_all_pp_bindings()
        count = 0
        for x in pp_bindings:
            if "portprofile" in x["portprofile-id"]:
                count += 1
        self.assertTrue(count == 2)
        self.tearDownPortProfileBinding()

    def testODeletePortProfileBinding(self):
        pp_binding1 = self.dbtest.create_pp_binding("t1", "net1", \
                                                     "portprofile1", "0")
        self.dbtest.delete_pp_binding(pp_binding1["portprofile-id"])
        pp_bindings = self.dbtest.get_all_pp_bindings()
        count = 0
        for x in pp_bindings:
            if "portprofile " in x["portprofile-id"]:
                count += 1
        self.assertTrue(count == 0)
        self.tearDownPortProfileBinding()

    def testPUpdatePortProfileBinding(self):
        pp_binding1 = self.dbtest.create_pp_binding("t1", "net1", \
                                                      "portprofile1", "0")
        pp_binding1 = self.dbtest.update_pp_binding("portprofile1", \
                                                  "newt1", "newnet1", "1")
        pp_bindings = self.dbtest.get_all_pp_bindings()
        count = 0
        for x in pp_bindings:
            if "new" in x["net-id"]:
                count += 1
        self.assertTrue(count == 1)
        self.tearDownPortProfileBinding()

    def tearDownVlanBinding(self):
        print "Tearing Down Vlan Binding"
        vlans = self.dbtest.get_all_vlan_bindings()
        for vlan in vlans:
            id = vlan["net-id"]
            self.dbtest.delete_vlan_binding(id)

    def tearDownPortProfile(self):
        print "Tearing Down Port Profile"
        pps = self.dbtest.get_all_portprofiles()
        for pp in pps:
            id = pp["portprofile-id"]
            self.dbtest.delete_portprofile(id)

    def tearDownPortProfileBinding(self):
        print "Tearing Down Port Profile Binding"
        pp_bindings = self.dbtest.get_all_pp_bindings()
        for pp_binding in pp_bindings:
            id = pp_binding["portprofile-id"]
            self.dbtest.delete_pp_binding(id)

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

    #load the models and db based on the 2nd level plugin argument
    if args[0] == "ucs":
        ucs_db = __import__("quantum.plugins.cisco.db.ucs_db", \
                fromlist=["ucs_db"])
        ucs_model = __import__("quantum.plugins.cisco.db.ucs_models", \
                fromlist=["ucs_models"])

    db_conf()

    # Run the tests
    suite = unittest.TestLoader().loadTestsFromTestCase(L2networkDBTest)
    unittest.TextTestRunner(verbosity=2).run(suite)
    suite = unittest.TestLoader().loadTestsFromTestCase(UcsDBTest)
    unittest.TextTestRunner(verbosity=2).run(suite)
