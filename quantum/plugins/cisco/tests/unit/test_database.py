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
import quantum.plugins.cisco.db.ucs_db as ucs_db


LOG.getLogger(const.LOGGER_COMPONENT_NAME)


class UcsDB(object):
    """Class consisting of methods to call ucs db methods"""
    def get_all_ucsmbindings(self):
        """get all ucsm bindings"""
        bindings = []
        try:
            for res in ucs_db.get_all_ucsmbinding():
                LOG.debug("Getting ucsm binding : %s" % res.ucsm_ip)
                bind_dict = {}
                bind_dict["ucsm-ip"] = str(res.ucsm_ip)
                bind_dict["network-id"] = str(res.network_id)
                bindings.append(bind_dict)
        except Exception, exc:
            LOG.error("Failed to get all bindings: %s" % str(exc))
        return bindings

    def get_ucsmbinding(self, ucsm_ip):
        """get ucsm binding"""
        binding = []
        try:
            for res in ucs_db.get_ucsmbinding(ucsm_ip):
                LOG.debug("Getting ucsm binding : %s" % res.ucsm_ip)
                bind_dict = {}
                bind_dict["ucsm-ip"] = str(res.ucsm_ip)
                bind_dict["network-id"] = str(res.network_id)
                binding.append(bind_dict)
        except Exception, exc:
            LOG.error("Failed to get binding: %s" % str(exc))
        return binding

    def create_ucsmbinding(self, ucsm_ip, network_id):
        """create ucsm binding"""
        bind_dict = {}
        try:
            res = ucs_db.add_ucsmbinding(ucsm_ip, network_id)
            LOG.debug("Created ucsm binding: %s" % res.ucsm_ip)
            bind_dict["ucsm-ip"] = str(res.ucsm_ip)
            bind_dict["network-id"] = str(res.network_id)
            return bind_dict
        except Exception, exc:
            LOG.error("Failed to create ucsm binding: %s" % str(exc))

    def delete_ucsmbinding(self, ucsm_ip):
        """delete ucsm binding"""
        try:
            res = ucs_db.remove_ucsmbinding(ucsm_ip)
            LOG.debug("Deleted ucsm binding : %s" % res.ucsm_ip)
            bind_dict = {}
            bind_dict["ucsm-ip"] = str(res.ucsm_ip)
            return bind_dict
        except Exception, exc:
            raise Exception("Failed to delete dynamic vnic: %s" % str(exc))

    def update_ucsmbinding(self, ucsm_ip, network_id):
        """update ucsm binding"""
        try:
            res = ucs_db.update_ucsmbinding(ucsm_ip, network_id)
            LOG.debug("Updating ucsm binding : %s" % res.ucsm_ip)
            bind_dict = {}
            bind_dict["ucsm-ip"] = str(res.ucsm_ip)
            bind_dict["network-id"] = str(res.network_id)
            return bind_dict
        except Exception, exc:
            raise Exception("Failed to update dynamic vnic: %s" % str(exc))

    def get_all_dynamicvnics(self):
        """get all dynamic vnics"""
        vnics = []
        try:
            for res in ucs_db.get_all_dynamicvnics():
                LOG.debug("Getting dynamic vnic : %s" % res.uuid)
                vnic_dict = {}
                vnic_dict["vnic-id"] = str(res.uuid)
                vnic_dict["device-name"] = res.device_name
                vnic_dict["blade-id"] = str(res.blade_id)
                vnic_dict["vnic_state"] = res.vnic_state
                vnics.append(vnic_dict)
        except Exception, exc:
            LOG.error("Failed to get all dynamic vnics: %s" % str(exc))
        return vnics

    def get_dynamicvnic(self, vnic_id):
        """get dynamic vnic"""
        vnic = []
        try:
            for res in ucs_db.get_dynamicvnic(vnic_id):
                LOG.debug("Getting dynamic vnic : %s" % res.uuid)
                vnic_dict = {}
                vnic_dict["vnic-id"] = str(res.uuid)
                vnic_dict["device-name"] = res.device_name
                vnic_dict["blade-id"] = str(res.blade_id)
                vnic_dict["vnic_state"] = res.vnic_state
                vnic.append(vnic_dict)
        except Exception, exc:
            LOG.error("Failed to get dynamic vnic: %s" % str(exc))
        return vnic

    def create_dynamicvnic(self, device_name, blade_id, vnic_state):
        """create dynamic vnic"""
        vnic_dict = {}
        try:
            res = ucs_db.add_dynamicvnic(device_name, blade_id, vnic_state)
            LOG.debug("Created dynamic vnic: %s" % res.uuid)
            vnic_dict["vnic-id"] = str(res.uuid)
            vnic_dict["device-name"] = res.device_name
            vnic_dict["blade-id"] = str(res.blade_id)
            vnic_dict["vnic_state"] = res.vnic_state
            return vnic_dict
        except Exception, exc:
            LOG.error("Failed to create dynamic vnic: %s" % str(exc))

    def delete_dynamicvnic(self, vnic_id):
        """delete dynamic vnic"""
        try:
            res = ucs_db.remove_dynamicvnic(vnic_id)
            LOG.debug("Deleted dynamic vnic : %s" % res.uuid)
            vnic_dict = {}
            vnic_dict["vnic-id"] = str(res.uuid)
            return vnic_dict
        except Exception, exc:
            raise Exception("Failed to delete dynamic vnic: %s" % str(exc))

    def update_dynamicvnic(self, vnic_id, device_name=None, blade_id=None,
                           vnic_state=None):
        """update dynamic vnic"""
        try:
            res = ucs_db.update_dynamicvnic(vnic_id, device_name, blade_id,
                                            vnic_state)
            LOG.debug("Updating dynamic vnic : %s" % res.uuid)
            vnic_dict = {}
            vnic_dict["vnic-id"] = str(res.uuid)
            vnic_dict["device-name"] = res.device_name
            vnic_dict["blade-id"] = str(res.blade_id)
            vnic_dict["vnic_state"] = res.vnic_state
            return vnic_dict
        except Exception, exc:
            raise Exception("Failed to update dynamic vnic: %s" % str(exc))

    def get_all_blades(self):
        """get all blades"""
        blades = []
        try:
            for res in ucs_db.get_all_blades():
                LOG.debug("Getting blade : %s" % res.uuid)
                blade_dict = {}
                blade_dict["blade-id"] = str(res.uuid)
                blade_dict["mgmt-ip"] = str(res.mgmt_ip)
                blade_dict["mac-addr"] = str(res.mac_addr)
                blade_dict["chassis-id"] = str(res.chassis_id)
                blade_dict["ucsm-ip"] = str(res.ucsm_ip)
                blade_dict["blade_state"] = str(res.blade_state)
                blade_dict["vnics_used"] = str(res.vnics_used)
                blade_dict["hostname"] = str(res.hostname)
                blades.append(blade_dict)
        except Exception, exc:
            LOG.error("Failed to get all blades: %s" % str(exc))
        return blades

    def get_blade(self, blade_id):
        """get blade"""
        blade = []
        try:
            for res in ucs_db.get_blade(blade_id):
                LOG.debug("Getting blade : %s" % res.uuid)
                blade_dict = {}
                blade_dict["blade-id"] = str(res.uuid)
                blade_dict["mgmt-ip"] = str(res.mgmt_ip)
                blade_dict["mac-addr"] = str(res.mac_addr)
                blade_dict["chassis-id"] = str(res.chassis_id)
                blade_dict["ucsm-ip"] = str(res.ucsm_ip)
                blade_dict["blade_state"] = str(res.blade_state)
                blade_dict["vnics_used"] = str(res.vnics_used)
                blade_dict["hostname"] = str(res.hostname)
                blade.append(blade_dict)
        except Exception, exc:
            LOG.error("Failed to get all blades: %s" % str(exc))
        return blade

    def create_blade(self, mgmt_ip, mac_addr, chassis_id, ucsm_ip,
                     blade_state, vnics_used, hostname):
        """create blade"""
        blade_dict = {}
        try:
            res = ucs_db.add_blade(mgmt_ip, mac_addr, chassis_id, ucsm_ip,
                                   blade_state, vnics_used, hostname)
            LOG.debug("Created blade: %s" % res.uuid)
            blade_dict["blade-id"] = str(res.uuid)
            blade_dict["mgmt-ip"] = str(res.mgmt_ip)
            blade_dict["mac-addr"] = str(res.mac_addr)
            blade_dict["chassis-id"] = str(res.chassis_id)
            blade_dict["ucsm-ip"] = str(res.ucsm_ip)
            blade_dict["blade_state"] = str(res.blade_state)
            blade_dict["vnics_used"] = str(res.vnics_used)
            blade_dict["hostname"] = str(res.hostname)
            return blade_dict
        except Exception, exc:
            LOG.error("Failed to create blade: %s" % str(exc))

    def delete_blade(self, blade_id):
        """delete blade"""
        try:
            res = ucs_db.remove_blade(blade_id)
            LOG.debug("Deleted blade : %s" % res.uuid)
            blade_dict = {}
            blade_dict["blade-id"] = str(res.uuid)
            return blade_dict
        except Exception, exc:
            raise Exception("Failed to delete blade: %s" % str(exc))

    def update_blade(self, blade_id, mgmt_ip=None, mac_addr=None,
                     chassis_id=None, ucsm_ip=None, blade_state=None,
                     vnics_used=None, hostname=None):
        """update blade"""
        try:
            res = ucs_db.update_blade(blade_id, mgmt_ip, mac_addr,
                                      chassis_id, ucsm_ip, blade_state,
                                      vnics_used, hostname)
            LOG.debug("Updating blade : %s" % res.uuid)
            blade_dict = {}
            blade_dict["blade-id"] = str(res.uuid)
            blade_dict["mgmt-ip"] = str(res.mgmt_ip)
            blade_dict["mac-addr"] = str(res.mac_addr)
            blade_dict["chassis-id"] = str(res.chassis_id)
            blade_dict["ucsm-ip"] = str(res.ucsm_ip)
            blade_dict["blade_state"] = str(res.blade_state)
            blade_dict["vnics_used"] = str(res.vnics_used)
            blade_dict["hostname"] = str(res.hostname)
            return blade_dict
        except Exception, exc:
            raise Exception("Failed to update blade: %s" % str(exc))

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

    def rename_network(self, tenant_id, net_id, new_name):
        """Rename a network"""
        try:
            net = db.network_rename(tenant_id, net_id, new_name)
            LOG.debug("Renamed network: %s" % net.uuid)
            net_dict = {}
            net_dict["net-id"] = str(net.uuid)
            net_dict["net-name"] = net.name
            return net_dict
        except Exception, exc:
            raise Exception("Failed to rename network: %s" % str(exc))

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

    def testa_create_ucsmbinding(self):
        """create ucsm binding"""
        net1 = self.quantum.create_network("t1", "netid1")
        binding1 = self.dbtest.create_ucsmbinding("1.2.3.4", net1["net-id"])
        self.assertTrue(binding1["ucsm-ip"] == "1.2.3.4")
        self.teardown_ucsmbinding()
        self.teardown_network()

    def testb_getall_ucsmbindings(self):
        """get all ucsm bindings"""
        net1 = self.quantum.create_network("t1", "netid1")
        binding1 = self.dbtest.create_ucsmbinding("1.2.3.4", net1["net-id"])
        binding2 = self.dbtest.create_ucsmbinding("2.3.4.5", net1["net-id"])
        bindings = self.dbtest.get_all_ucsmbindings()
        count = 0
        for bind in bindings:
            if net1["net-id"] == bind["network-id"]:
                count += 1
        self.assertTrue(count == 2)
        self.teardown_ucsmbinding()
        self.teardown_network()

    def testc_delete_ucsmbinding(self):
        """delete ucsm binding"""
        net1 = self.quantum.create_network("t1", "netid1")
        binding1 = self.dbtest.create_ucsmbinding("1.2.3.4", net1["net-id"])
        self.dbtest.delete_ucsmbinding(binding1["ucsm-ip"])
        bindings = self.dbtest.get_all_ucsmbindings()
        count = 0
        for bind in bindings:
            if "net " in bind["network-id"]:
                count += 1
        self.assertTrue(count == 0)
        self.teardown_ucsmbinding()
        self.teardown_network()

    def testd_update_ucsmbinding(self):
        """update ucsm binding"""
        net1 = self.quantum.create_network("t1", "netid1")
        net2 = self.quantum.create_network("t1", "netid2")
        binding1 = self.dbtest.create_ucsmbinding("1.2.3.4", net1["net-id"])
        binding1 = self.dbtest.update_ucsmbinding(binding1["ucsm-ip"],
                                                             net2["net-id"])
        bindings = self.dbtest.get_all_ucsmbindings()
        count = 0
        for bind in bindings:
            if net2["net-id"] == bind["network-id"]:
                count += 1
        self.assertTrue(count == 1)
        self.teardown_ucsmbinding()
        self.teardown_network()

    def teste_create_dynamicvnic(self):
        """create dynamic vnic"""
        blade1 = self.dbtest.create_blade("1.2.3.4", "abcd", "chassis1",
                                          "9.8.7.6", "UP", 2, "blade1")
        vnic1 = self.dbtest.create_dynamicvnic("eth1", blade1["blade-id"],
                                               "UP")
        self.assertTrue(vnic1["device-name"] == "eth1")
        self.teardown_dyanmicvnic()

    def testf_getall_dyanmicvnics(self):
        """get all dynamic vnics"""
        blade1 = self.dbtest.create_blade("1.2.3.4", "abcd", "chassis1",
                                          "9.8.7.6", "UP", 2, "blade1")
        vnic1 = self.dbtest.create_dynamicvnic("eth1", blade1["blade-id"],
                                               "UP")
        vnic2 = self.dbtest.create_dynamicvnic("eth2", blade1["blade-id"],
                                               "UP")
        vnics = self.dbtest.get_all_dynamicvnics()
        count = 0
        for vnic in vnics:
            if "eth" in vnic["device-name"]:
                count += 1
        self.assertTrue(count == 2)
        self.teardown_dyanmicvnic()

    def testg_delete_dyanmicvnic(self):
        """delete dynamic vnic"""
        blade1 = self.dbtest.create_blade("1.2.3.4", "abcd", "chassis1",
                                          "9.8.7.6", "UP", 2, "blade1")
        vnic1 = self.dbtest.create_dynamicvnic("eth1", blade1["blade-id"],
                                               "UP")
        self.dbtest.delete_dynamicvnic(vnic1["vnic-id"])
        vnics = self.dbtest.get_all_dynamicvnics()
        count = 0
        for vnic in vnics:
            if "eth " in vnic["device-name"]:
                count += 1
        self.assertTrue(count == 0)
        self.teardown_dyanmicvnic()

    def testh_updatedynamicvnic(self):
        """update dynamic vnic"""
        blade1 = self.dbtest.create_blade("1.2.3.4", "abcd", "chassis1",
                                          "9.8.7.6", "UP", 2, "blade1")
        vnic1 = self.dbtest.create_dynamicvnic("eth1", blade1["blade-id"],
                                               "UP")
        vnic1 = self.dbtest.update_dynamicvnic(vnic1["vnic-id"], "neweth1",
                                            blade1["blade-id"], "DOWN")
        vnics = self.dbtest.get_all_dynamicvnics()
        count = 0
        for vnic in vnics:
            if "new" in vnic["device-name"]:
                count += 1
        self.assertTrue(count == 1)
        self.teardown_dyanmicvnic()

    def testi_create_ucsblade(self):
        """create ucs blade"""
        blade1 = self.dbtest.create_blade("1.2.3.4", "abcd", "chassis1",
                                          "9.8.7.6", "UP", 2, "blade1")
        self.assertTrue(blade1["mgmt-ip"] == "1.2.3.4")
        self.teardown_ucsblade()

    def testj_getall_ucsblade(self):
        """get all ucs blades"""
        blade1 = self.dbtest.create_blade("1.2.3.4", "abcd", "chassis1",
                                          "9.8.7.6", "UP", 2, "blade1")
        blade2 = self.dbtest.create_blade("2.3.4.5", "efgh", "chassis1",
                                          "9.8.7.6", "UP", 3, "blade2")
        blades = self.dbtest.get_all_blades()
        count = 0
        for blade in blades:
            if "chassis" in blade["chassis-id"]:
                count += 1
        self.assertTrue(count == 2)
        self.teardown_ucsblade()

    def testk_delete_ucsblade(self):
        """delete ucs blades"""
        blade1 = self.dbtest.create_blade("1.2.3.4", "abcd", "chassis1",
                                          "9.8.7.6", "UP", 2, "blade1")
        self.dbtest.delete_blade(blade1["blade-id"])
        blades = self.dbtest.get_all_blades()
        count = 0
        for blade in blades:
            if "chassis " in blade["chassis-id"]:
                count += 1
        self.assertTrue(count == 0)
        self.teardown_ucsblade()

    def testl_update_ucsblade(self):
        """update ucs blade"""
        blade1 = self.dbtest.create_blade("1.2.3.4", "abcd", "chassis1",
                                          "9.8.7.6", "UP", 2, "blade1")
        blade2 = self.dbtest.update_blade(blade1["blade-id"], "2.3.4.5",
                                          "newabcd", "chassis1", "9.8.7.6",
                                          "UP", 3, "blade1")
        blades = self.dbtest.get_all_blades()
        count = 0
        for blade in blades:
            if "new" in blade["mac-addr"]:
                count += 1
        self.assertTrue(count == 1)
        self.teardown_ucsblade()

    def testm_create_portbinding(self):
        """create port binding"""
        net1 = self.quantum.create_network("t1", "netid1")
        port1 = self.quantum.create_port(net1["net-id"])
        blade1 = self.dbtest.create_blade("1.2.3.4", "abcd", "chassis1",
                                          "9.8.7.6", "UP", 2, "blade1")
        vnic1 = self.dbtest.create_dynamicvnic("eth1", blade1["blade-id"],
                                               "UP")
        port_bind1 = self.dbtest.create_port_binding(port1["port-id"],
                                vnic1["vnic-id"], "pp1", "vlan1", 10, "qos1")
        self.assertTrue(port_bind1["port-id"] == port1["port-id"])
        self.teardown_portbinding()
        self.teardown_dyanmicvnic()
        self.teardown_ucsblade()
        self.teardown_network_port()

    def testn_getall_portbindings(self):
        """get all port binding"""
        net1 = self.quantum.create_network("t1", "netid1")
        port1 = self.quantum.create_port(net1["net-id"])
        port2 = self.quantum.create_port(net1["net-id"])
        blade1 = self.dbtest.create_blade("1.2.3.4", "abcd", "chassis1",
                                          "9.8.7.6", "UP", 2, "blade1")
        vnic1 = self.dbtest.create_dynamicvnic("eth1", blade1["blade-id"],
                                               "UP")
        vnic2 = self.dbtest.create_dynamicvnic("eth2", blade1["blade-id"],
                                               "UP")
        port_bind1 = self.dbtest.create_port_binding(port1["port-id"],
                                vnic1["vnic-id"], "pp1", "vlan1", 10, "qos1")
        port_bind2 = self.dbtest.create_port_binding(port2["port-id"],
                                vnic2["vnic-id"], "pp2", "vlan2", 20, "qos2")
        port_bindings = self.dbtest.get_all_port_bindings()
        count = 0
        for pbind in port_bindings:
            if "vlan" in pbind["vlan-name"]:
                count += 1
        self.assertTrue(count == 2)
        self.teardown_portbinding()
        self.teardown_dyanmicvnic()
        self.teardown_ucsblade()
        self.teardown_network_port()

    def testo_delete_portbinding(self):
        """delete port binding"""
        net1 = self.quantum.create_network("t1", "netid1")
        port1 = self.quantum.create_port(net1["net-id"])
        blade1 = self.dbtest.create_blade("1.2.3.4", "abcd", "chassis1",
                                          "9.8.7.6", "UP", 2, "blade1")
        vnic1 = self.dbtest.create_dynamicvnic("eth1", blade1["blade-id"],
                                               "UP")
        port_bind1 = self.dbtest.create_port_binding(port1["port-id"],
                                vnic1["vnic-id"], "pp1", "vlan1", 10, "qos1")
        self.dbtest.delete_port_binding(port1["port-id"])
        port_bindings = self.dbtest.get_all_port_bindings()
        count = 0
        for pbind in port_bindings:
            if "vlan " in pbind["vlan-name"]:
                count += 1
        self.assertTrue(count == 0)
        self.teardown_portbinding()
        self.teardown_dyanmicvnic()
        self.teardown_ucsblade()
        self.teardown_network_port()

    def testp_update_portbinding(self):
        """update port binding"""
        net1 = self.quantum.create_network("t1", "netid1")
        port1 = self.quantum.create_port(net1["net-id"])
        blade1 = self.dbtest.create_blade("1.2.3.4", "abcd", "chassis1",
                                          "9.8.7.6", "UP", 2, "blade1")
        vnic1 = self.dbtest.create_dynamicvnic("eth1", blade1["blade-id"],
                                               "UP")
        port_bind1 = self.dbtest.create_port_binding(port1["port-id"],
                                vnic1["vnic-id"], "pp1", "vlan1", 10, "qos1")
        port_bind1 = self.dbtest.update_port_binding(port1["port-id"],
                        vnic1["vnic-id"], "newpp1", "newvlan1", 11, "newqos1")
        port_bindings = self.dbtest.get_all_port_bindings()
        count = 0
        for pbind in port_bindings:
            if "new" in pbind["vlan-name"]:
                count += 1
        self.assertTrue(count == 1)
        self.teardown_portbinding()
        self.teardown_dyanmicvnic()
        self.teardown_ucsblade()
        self.teardown_network_port()

    def teardown_ucsmbinding(self):
        """tear down ucsm binding"""
        LOG.debug("Tearing Down Ucsm Bindings")
        binds = self.dbtest.get_all_ucsmbindings()
        for bind in binds:
            ucsmip = bind["ucsm-ip"]
            self.dbtest.delete_ucsmbinding(ucsmip)

    def teardown_dyanmicvnic(self):
        """tear down dynamic vnics"""
        LOG.debug("Tearing Down Dynamic Vnics")
        vnics = self.dbtest.get_all_dynamicvnics()
        for vnic in vnics:
            vnicid = vnic["vnic-id"]
            self.dbtest.delete_dynamicvnic(vnicid)
        self.teardown_ucsblade()

    def teardown_ucsblade(self):
        """tear down ucs blades"""
        LOG.debug("Tearing Down Blades")
        blades = self.dbtest.get_all_blades()
        for blade in blades:
            bladeid = blade["blade-id"]
            self.dbtest.delete_blade(bladeid)

    def teardown_portbinding(self):
        """tear down port binding"""
        LOG.debug("Tearing Down Port Binding")
        port_bindings = self.dbtest.get_all_port_bindings()
        for port_binding in port_bindings:
            portid = port_binding["port-id"]
            self.dbtest.delete_port_binding(portid)

    def teardown_network(self):
        """tearDown Network table"""
        LOG.debug("Tearing Down Network")
        nets = self.quantum.get_all_networks("t1")
        for net in nets:
            netid = net["net-id"]
            self.quantum.delete_network(netid)

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
        self.assertTrue(used == True)
        used = l2network_db.release_vlanid(vlanid)
        self.assertTrue(used == False)
        self.teardown_vlanid()

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

    def teardown_vlanid(self):
        """tearDown VlanID table"""
        LOG.debug("Tearing Down Vlan IDs")
        vlanids = l2network_db.get_all_vlanids()
        for vlanid in vlanids:
            vlan_id = vlanid["vlan_id"]
            l2network_db.delete_vlanid(vlan_id)


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

    def testd_rename_network(self):
        """test to rename network"""
        net1 = self.dbtest.create_network(self.tenant_id, "plugin_test1")
        self.assertTrue(net1["net-name"] == "plugin_test1")
        net = self.dbtest.rename_network(self.tenant_id, net1["net-id"],
          "plugin_test1_renamed")
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
        self.assertTrue(port[0]["int-id"] == None)
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
