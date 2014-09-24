# Copyright 2014 Cisco Systems, Inc.  All rights reserved.
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

import logging
import netaddr
import re
import time
import xml.etree.ElementTree as ET

import ciscoconfparse
from ncclient import manager

from oslo.config import cfg

from neutron.plugins.cisco.cfg_agent import cfg_exceptions as cfg_exc
from neutron.plugins.cisco.cfg_agent.device_drivers.csr1kv import (
    cisco_csr1kv_snippets as snippets)
from neutron.plugins.cisco.cfg_agent.device_drivers import devicedriver_api

LOG = logging.getLogger(__name__)


# N1kv constants
T1_PORT_NAME_PREFIX = 't1_p:'  # T1 port/network is for VXLAN
T2_PORT_NAME_PREFIX = 't2_p:'  # T2 port/network is for VLAN


class CSR1kvRoutingDriver(devicedriver_api.RoutingDriverBase):
    """CSR1kv Routing Driver.

    This driver encapsulates the configuration logic via NETCONF protocol to
    configure a CSR1kv Virtual Router (IOS-XE based) for implementing
    Neutron L3 services. These services include routing, NAT and floating
    IPs (as per Neutron terminology).
    """

    DEV_NAME_LEN = 14

    def __init__(self, **device_params):
        try:
            self._csr_host = device_params['management_ip_address']
            self._csr_ssh_port = device_params['protocol_port']
            credentials = device_params['credentials']
            if credentials:
                self._csr_user = credentials['username']
                self._csr_password = credentials['password']
            self._timeout = cfg.CONF.cfg_agent.device_connection_timeout
            self._csr_conn = None
            self._intfs_enabled = False
        except KeyError as e:
            LOG.error(_("Missing device parameter:%s. Aborting "
                        "CSR1kvRoutingDriver initialization"), e)
            raise cfg_exc.CSR1kvInitializationException()

    ###### Public Functions ########
    def router_added(self, ri):
        self._csr_create_vrf(ri)

    def router_removed(self, ri):
        self._csr_remove_vrf(ri)

    def internal_network_added(self, ri, port):
        self._csr_create_subinterface(ri, port)
        if port.get('ha_info') is not None and ri.ha_info['ha:enabled']:
            self._csr_add_ha(ri, port)

    def internal_network_removed(self, ri, port):
        self._csr_remove_subinterface(port)

    def external_gateway_added(self, ri, ex_gw_port):
        self._csr_create_subinterface(ri, ex_gw_port)
        ex_gw_ip = ex_gw_port['subnet']['gateway_ip']
        if ex_gw_ip:
            #Set default route via this network's gateway ip
            self._csr_add_default_route(ri, ex_gw_ip)

    def external_gateway_removed(self, ri, ex_gw_port):
        ex_gw_ip = ex_gw_port['subnet']['gateway_ip']
        if ex_gw_ip:
            #Remove default route via this network's gateway ip
            self._csr_remove_default_route(ri, ex_gw_ip)
        #Finally, remove external network subinterface
        self._csr_remove_subinterface(ex_gw_port)

    def enable_internal_network_NAT(self, ri, port, ex_gw_port):
        self._csr_add_internalnw_nat_rules(ri, port, ex_gw_port)

    def disable_internal_network_NAT(self, ri, port, ex_gw_port):
        self._csr_remove_internalnw_nat_rules(ri, [port], ex_gw_port)

    def floating_ip_added(self, ri, ex_gw_port, floating_ip, fixed_ip):
        self._csr_add_floating_ip(ri, floating_ip, fixed_ip)

    def floating_ip_removed(self, ri, ex_gw_port, floating_ip, fixed_ip):
        self._csr_remove_floating_ip(ri, ex_gw_port, floating_ip, fixed_ip)

    def routes_updated(self, ri, action, route):
        self._csr_update_routing_table(ri, action, route)

    def clear_connection(self):
        self._csr_conn = None

    ##### Internal Functions  ####

    def _csr_create_subinterface(self, ri, port):
        vrf_name = self._csr_get_vrf_name(ri)
        ip_cidr = port['ip_cidr']
        netmask = netaddr.IPNetwork(ip_cidr).netmask
        gateway_ip = ip_cidr.split('/')[0]
        subinterface = self._get_interface_name_from_hosting_port(port)
        vlan = self._get_interface_vlan_from_hosting_port(port)
        self._create_subinterface(subinterface, vlan, vrf_name,
                                  gateway_ip, netmask)

    def _csr_remove_subinterface(self, port):
        subinterface = self._get_interface_name_from_hosting_port(port)
        self._remove_subinterface(subinterface)

    def _csr_add_ha(self, ri, port):
        func_dict = {
            'HSRP': CSR1kvRoutingDriver._csr_add_ha_HSRP,
            'VRRP': CSR1kvRoutingDriver._csr_add_ha_VRRP,
            'GBLP': CSR1kvRoutingDriver._csr_add_ha_GBLP
        }
        #Invoke the right function for the ha type
        func_dict[ri.ha_info['ha:type']](self, ri, port)

    def _csr_add_ha_HSRP(self, ri, port):
        priority = ri.ha_info['priority']
        port_ha_info = port['ha_info']
        group = port_ha_info['group']
        ip = port_ha_info['virtual_port']['fixed_ips'][0]['ip_address']
        if ip and group and priority:
            vrf_name = self._csr_get_vrf_name(ri)
            subinterface = self._get_interface_name_from_hosting_port(port)
            self._set_ha_HSRP(subinterface, vrf_name, priority, group, ip)

    def _csr_add_ha_VRRP(self, ri, port):
        raise NotImplementedError()

    def _csr_add_ha_GBLP(self, ri, port):
        raise NotImplementedError()

    def _csr_remove_ha(self, ri, port):
        pass

    def _csr_add_internalnw_nat_rules(self, ri, port, ex_port):
        vrf_name = self._csr_get_vrf_name(ri)
        in_vlan = self._get_interface_vlan_from_hosting_port(port)
        acl_no = 'acl_' + str(in_vlan)
        internal_cidr = port['ip_cidr']
        internal_net = netaddr.IPNetwork(internal_cidr).network
        netmask = netaddr.IPNetwork(internal_cidr).hostmask
        inner_intfc = self._get_interface_name_from_hosting_port(port)
        outer_intfc = self._get_interface_name_from_hosting_port(ex_port)
        self._nat_rules_for_internet_access(acl_no, internal_net,
                                            netmask, inner_intfc,
                                            outer_intfc, vrf_name)

    def _csr_remove_internalnw_nat_rules(self, ri, ports, ex_port):
        acls = []
        #First disable nat in all inner ports
        for port in ports:
            in_intfc_name = self._get_interface_name_from_hosting_port(port)
            inner_vlan = self._get_interface_vlan_from_hosting_port(port)
            acls.append("acl_" + str(inner_vlan))
            self._remove_interface_nat(in_intfc_name, 'inside')

        #Wait for two second
        LOG.debug("Sleep for 2 seconds before clearing NAT rules")
        time.sleep(2)

        #Clear the NAT translation table
        self._remove_dyn_nat_translations()

        # Remove dynamic NAT rules and ACLs
        vrf_name = self._csr_get_vrf_name(ri)
        ext_intfc_name = self._get_interface_name_from_hosting_port(ex_port)
        for acl in acls:
            self._remove_dyn_nat_rule(acl, ext_intfc_name, vrf_name)

    def _csr_add_default_route(self, ri, gw_ip):
        vrf_name = self._csr_get_vrf_name(ri)
        self._add_default_static_route(gw_ip, vrf_name)

    def _csr_remove_default_route(self, ri, gw_ip):
        vrf_name = self._csr_get_vrf_name(ri)
        self._remove_default_static_route(gw_ip, vrf_name)

    def _csr_add_floating_ip(self, ri, floating_ip, fixed_ip):
        vrf_name = self._csr_get_vrf_name(ri)
        self._add_floating_ip(floating_ip, fixed_ip, vrf_name)

    def _csr_remove_floating_ip(self, ri, ex_gw_port, floating_ip, fixed_ip):
        vrf_name = self._csr_get_vrf_name(ri)
        out_intfc_name = self._get_interface_name_from_hosting_port(ex_gw_port)
        # First remove NAT from outer interface
        self._remove_interface_nat(out_intfc_name, 'outside')
        #Clear the NAT translation table
        self._remove_dyn_nat_translations()
        #Remove the floating ip
        self._remove_floating_ip(floating_ip, fixed_ip, vrf_name)
        #Enable NAT on outer interface
        self._add_interface_nat(out_intfc_name, 'outside')

    def _csr_update_routing_table(self, ri, action, route):
        vrf_name = self._csr_get_vrf_name(ri)
        destination_net = netaddr.IPNetwork(route['destination'])
        dest = destination_net.network
        dest_mask = destination_net.netmask
        next_hop = route['nexthop']
        if action is 'replace':
            self._add_static_route(dest, dest_mask, next_hop, vrf_name)
        elif action is 'delete':
            self._remove_static_route(dest, dest_mask, next_hop, vrf_name)
        else:
            LOG.error(_('Unknown route command %s'), action)

    def _csr_create_vrf(self, ri):
        vrf_name = self._csr_get_vrf_name(ri)
        self._create_vrf(vrf_name)

    def _csr_remove_vrf(self, ri):
        vrf_name = self._csr_get_vrf_name(ri)
        self._remove_vrf(vrf_name)

    def _csr_get_vrf_name(self, ri):
        return ri.router_name()[:self.DEV_NAME_LEN]

    def _get_connection(self):
        """Make SSH connection to the CSR.

        The external ncclient library is used for creating this connection.
        This method keeps state of any existing connections and reuses them if
        already connected. Also CSR1kv's interfaces (except management) are
        disabled by default when it is booted. So if connecting for the first
        time, driver will enable all other interfaces and keep that status in
        the `_intfs_enabled` flag.
        """
        try:
            if self._csr_conn and self._csr_conn.connected:
                return self._csr_conn
            else:
                self._csr_conn = manager.connect(host=self._csr_host,
                                                 port=self._csr_ssh_port,
                                                 username=self._csr_user,
                                                 password=self._csr_password,
                                                 device_params={'name': "csr"},
                                                 timeout=self._timeout)
                if not self._intfs_enabled:
                    self._intfs_enabled = self._enable_intfs(self._csr_conn)
            return self._csr_conn
        except Exception as e:
            conn_params = {'host': self._csr_host, 'port': self._csr_ssh_port,
                           'user': self._csr_user,
                           'timeout': self._timeout, 'reason': e.message}
            raise cfg_exc.CSR1kvConnectionException(**conn_params)

    def _get_interface_name_from_hosting_port(self, port):
        vlan = self._get_interface_vlan_from_hosting_port(port)
        int_no = self._get_interface_no_from_hosting_port(port)
        intfc_name = 'GigabitEthernet%s.%s' % (int_no, vlan)
        return intfc_name

    @staticmethod
    def _get_interface_vlan_from_hosting_port(port):
        return port['hosting_info']['segmentation_id']

    @staticmethod
    def _get_interface_no_from_hosting_port(port):
        """Calculate interface number from the hosting port's name.

         Interfaces in the CSR1kv are created in pairs (T1 and T2) where
         T1 interface is used for VLAN and T2 interface for VXLAN traffic
         respectively. On the neutron side these are named T1 and T2 ports and
         follows the naming convention: <Tx_PORT_NAME_PREFIX>:<PAIR_INDEX>
         where the `PORT_NAME_PREFIX` indicates either VLAN or VXLAN and
         `PAIR_INDEX` is the pair number. `PAIR_INDEX` starts at 1.

         In CSR1kv, GigabitEthernet 0 is not present and GigabitEthernet 1
         is used as a management interface (Note: this might change in
         future). So the first (T1,T2) pair corresponds to
         (GigabitEthernet 2, GigabitEthernet 3) and so forth. This function
         extracts the `PAIR_INDEX` and calculates the corresponding interface
         number.

        :param port: neutron port corresponding to the interface.
        :return: number of the interface (eg: 1 in case of GigabitEthernet1)
        """
        _name = port['hosting_info']['hosting_port_name']
        if_type = _name.split(':')[0] + ':'
        if if_type == T1_PORT_NAME_PREFIX:
            return str(int(_name.split(':')[1]) * 2)
        elif if_type == T2_PORT_NAME_PREFIX:
            return str(int(_name.split(':')[1]) * 2 + 1)
        else:
            params = {'attribute': 'hosting_port_name', 'value': _name}
            raise cfg_exc.CSR1kvUnknownValueException(**params)

    def _get_interfaces(self):
        """Get a list of interfaces on this hosting device.

        :return: List of the interfaces
        """
        ioscfg = self._get_running_config()
        parse = ciscoconfparse.CiscoConfParse(ioscfg)
        intfs_raw = parse.find_lines("^interface GigabitEthernet")
        intfs = [raw_if.strip().split(' ')[1] for raw_if in intfs_raw]
        LOG.info(_("Interfaces:%s"), intfs)
        return intfs

    def _get_interface_ip(self, interface_name):
        """Get the ip address for an interface.

        :param interface_name: interface_name as a string
        :return: ip address of interface as a string
        """
        ioscfg = self._get_running_config()
        parse = ciscoconfparse.CiscoConfParse(ioscfg)
        children = parse.find_children("^interface %s" % interface_name)
        for line in children:
            if 'ip address' in line:
                ip_address = line.strip().split(' ')[2]
                LOG.info(_("IP Address:%s"), ip_address)
                return ip_address
        LOG.warn(_("Cannot find interface: %s"), interface_name)
        return None

    def _interface_exists(self, interface):
        """Check whether interface exists."""
        ioscfg = self._get_running_config()
        parse = ciscoconfparse.CiscoConfParse(ioscfg)
        intfs_raw = parse.find_lines("^interface " + interface)
        return len(intfs_raw) > 0

    def _enable_intfs(self, conn):
        """Enable the interfaces of a CSR1kv Virtual Router.

        When the virtual router first boots up, all interfaces except
        management are down. This method will enable all data interfaces.

        Note: In CSR1kv, GigabitEthernet 0 is not present. GigabitEthernet 1
        is used as management and GigabitEthernet 2 and up are used for data.
        This might change in future releases.

        Currently only the second and third Gig interfaces corresponding to a
        single (T1,T2) pair and configured as trunk for VLAN and VXLAN
        is enabled.

        :param conn: Connection object
        :return: True or False
        """

        #ToDo(Hareesh): Interfaces are hard coded for now. Make it dynamic.
        interfaces = ['GigabitEthernet 2', 'GigabitEthernet 3']
        try:
            for i in interfaces:
                confstr = snippets.ENABLE_INTF % i
                rpc_obj = conn.edit_config(target='running', config=confstr)
                if self._check_response(rpc_obj, 'ENABLE_INTF'):
                    LOG.info(_("Enabled interface %s "), i)
                    time.sleep(1)
        except Exception:
            return False
        return True

    def _get_vrfs(self):
        """Get the current VRFs configured in the device.

        :return: A list of vrf names as string
        """
        vrfs = []
        ioscfg = self._get_running_config()
        parse = ciscoconfparse.CiscoConfParse(ioscfg)
        vrfs_raw = parse.find_lines("^ip vrf")
        for line in vrfs_raw:
            #  raw format ['ip vrf <vrf-name>',....]
            vrf_name = line.strip().split(' ')[2]
            vrfs.append(vrf_name)
        LOG.info(_("VRFs:%s"), vrfs)
        return vrfs

    def _get_capabilities(self):
        """Get the servers NETCONF capabilities.

        :return: List of server capabilities.
        """
        conn = self._get_connection()
        capabilities = []
        for c in conn.server_capabilities:
            capabilities.append(c)
        LOG.debug("Server capabilities: %s", capabilities)
        return capabilities

    def _get_running_config(self):
        """Get the CSR's current running config.

        :return: Current IOS running config as multiline string
        """
        conn = self._get_connection()
        config = conn.get_config(source="running")
        if config:
            root = ET.fromstring(config._raw)
            running_config = root[0][0]
            rgx = re.compile("\r*\n+")
            ioscfg = rgx.split(running_config.text)
            return ioscfg

    def _check_acl(self, acl_no, network, netmask):
        """Check a ACL config exists in the running config.

        :param acl_no: access control list (ACL) number
        :param network: network which this ACL permits
        :param netmask: netmask of the network
        :return:
        """
        exp_cfg_lines = ['ip access-list standard ' + str(acl_no),
                         ' permit ' + str(network) + ' ' + str(netmask)]
        ioscfg = self._get_running_config()
        parse = ciscoconfparse.CiscoConfParse(ioscfg)
        acls_raw = parse.find_children(exp_cfg_lines[0])
        if acls_raw:
            if exp_cfg_lines[1] in acls_raw:
                return True
            LOG.error(_("Mismatch in ACL configuration for %s"), acl_no)
            return False
        LOG.debug("%s is not present in config", acl_no)
        return False

    def _cfg_exists(self, cfg_str):
        """Check a partial config string exists in the running config.

        :param cfg_str: config string to check
        :return : True or False
        """
        ioscfg = self._get_running_config()
        parse = ciscoconfparse.CiscoConfParse(ioscfg)
        cfg_raw = parse.find_lines("^" + cfg_str)
        LOG.debug("_cfg_exists(): Found lines %s", cfg_raw)
        return len(cfg_raw) > 0

    def _set_interface(self, name, ip_address, mask):
        conn = self._get_connection()
        confstr = snippets.SET_INTC % (name, ip_address, mask)
        rpc_obj = conn.edit_config(target='running', config=confstr)
        self._check_response(rpc_obj, 'SET_INTC')

    def _create_vrf(self, vrf_name):
        try:
            conn = self._get_connection()
            confstr = snippets.CREATE_VRF % vrf_name
            rpc_obj = conn.edit_config(target='running', config=confstr)
            if self._check_response(rpc_obj, 'CREATE_VRF'):
                LOG.info(_("VRF %s successfully created"), vrf_name)
        except Exception:
            LOG.exception(_("Failed creating VRF %s"), vrf_name)

    def _remove_vrf(self, vrf_name):
        if vrf_name in self._get_vrfs():
            conn = self._get_connection()
            confstr = snippets.REMOVE_VRF % vrf_name
            rpc_obj = conn.edit_config(target='running', config=confstr)
            if self._check_response(rpc_obj, 'REMOVE_VRF'):
                LOG.info(_("VRF %s removed"), vrf_name)
        else:
            LOG.warning(_("VRF %s not present"), vrf_name)

    def _create_subinterface(self, subinterface, vlan_id, vrf_name, ip, mask):
        if vrf_name not in self._get_vrfs():
            LOG.error(_("VRF %s not present"), vrf_name)
        confstr = snippets.CREATE_SUBINTERFACE % (subinterface, vlan_id,
                                                  vrf_name, ip, mask)
        self._edit_running_config(confstr, 'CREATE_SUBINTERFACE')

    def _remove_subinterface(self, subinterface):
        #Optional : verify this is the correct subinterface
        if self._interface_exists(subinterface):
            confstr = snippets.REMOVE_SUBINTERFACE % subinterface
            self._edit_running_config(confstr, 'REMOVE_SUBINTERFACE')

    def _set_ha_HSRP(self, subinterface, vrf_name, priority, group, ip):
        if vrf_name not in self._get_vrfs():
            LOG.error(_("VRF %s not present"), vrf_name)
        confstr = snippets.SET_INTC_HSRP % (subinterface, vrf_name, group,
                                            priority, group, ip)
        action = "SET_INTC_HSRP (Group: %s, Priority: % s)" % (group, priority)
        self._edit_running_config(confstr, action)

    def _remove_ha_HSRP(self, subinterface, group):
        confstr = snippets.REMOVE_INTC_HSRP % (subinterface, group)
        action = ("REMOVE_INTC_HSRP (subinterface:%s, Group:%s)"
                  % (subinterface, group))
        self._edit_running_config(confstr, action)

    def _get_interface_cfg(self, interface):
        ioscfg = self._get_running_config()
        parse = ciscoconfparse.CiscoConfParse(ioscfg)
        return parse.find_children('interface ' + interface)

    def _nat_rules_for_internet_access(self, acl_no, network,
                                       netmask,
                                       inner_intfc,
                                       outer_intfc,
                                       vrf_name):
        """Configure the NAT rules for an internal network.

        Configuring NAT rules in the CSR1kv is a three step process. First
        create an ACL for the IP range of the internal network. Then enable
        dynamic source NATing on the external interface of the CSR for this
        ACL and VRF of the neutron router. Finally enable NAT on the
        interfaces of the CSR where the internal and external networks are
        connected.

        :param acl_no: ACL number of the internal network.
        :param network: internal network
        :param netmask: netmask of the internal network.
        :param inner_intfc: (name of) interface connected to the internal
        network
        :param outer_intfc: (name of) interface connected to the external
        network
        :param vrf_name: VRF corresponding to this virtual router
        :return: True if configuration succeeded
        :raises: neutron.plugins.cisco.cfg_agent.cfg_exceptions.
        CSR1kvConfigException
        """
        conn = self._get_connection()
        # Duplicate ACL creation throws error, so checking
        # it first. Remove it in future as this is not common in production
        acl_present = self._check_acl(acl_no, network, netmask)
        if not acl_present:
            confstr = snippets.CREATE_ACL % (acl_no, network, netmask)
            rpc_obj = conn.edit_config(target='running', config=confstr)
            self._check_response(rpc_obj, 'CREATE_ACL')

        confstr = snippets.SET_DYN_SRC_TRL_INTFC % (acl_no, outer_intfc,
                                                    vrf_name)
        rpc_obj = conn.edit_config(target='running', config=confstr)
        self._check_response(rpc_obj, 'CREATE_SNAT')

        confstr = snippets.SET_NAT % (inner_intfc, 'inside')
        rpc_obj = conn.edit_config(target='running', config=confstr)
        self._check_response(rpc_obj, 'SET_NAT')

        confstr = snippets.SET_NAT % (outer_intfc, 'outside')
        rpc_obj = conn.edit_config(target='running', config=confstr)
        self._check_response(rpc_obj, 'SET_NAT')

    def _add_interface_nat(self, intfc_name, intfc_type):
        conn = self._get_connection()
        confstr = snippets.SET_NAT % (intfc_name, intfc_type)
        rpc_obj = conn.edit_config(target='running', config=confstr)
        self._check_response(rpc_obj, 'SET_NAT ' + intfc_type)

    def _remove_interface_nat(self, intfc_name, intfc_type):
        conn = self._get_connection()
        confstr = snippets.REMOVE_NAT % (intfc_name, intfc_type)
        rpc_obj = conn.edit_config(target='running', config=confstr)
        self._check_response(rpc_obj, 'REMOVE_NAT ' + intfc_type)

    def _remove_dyn_nat_rule(self, acl_no, outer_intfc_name, vrf_name):
        conn = self._get_connection()
        confstr = snippets.SNAT_CFG % (acl_no, outer_intfc_name, vrf_name)
        if self._cfg_exists(confstr):
            confstr = snippets.REMOVE_DYN_SRC_TRL_INTFC % (acl_no,
                                                           outer_intfc_name,
                                                           vrf_name)
            rpc_obj = conn.edit_config(target='running', config=confstr)
            self._check_response(rpc_obj, 'REMOVE_DYN_SRC_TRL_INTFC')

        confstr = snippets.REMOVE_ACL % acl_no
        rpc_obj = conn.edit_config(target='running', config=confstr)
        self._check_response(rpc_obj, 'REMOVE_ACL')

    def _remove_dyn_nat_translations(self):
        conn = self._get_connection()
        confstr = snippets.CLEAR_DYN_NAT_TRANS
        rpc_obj = conn.edit_config(target='running', config=confstr)
        self._check_response(rpc_obj, 'CLEAR_DYN_NAT_TRANS')

    def _add_floating_ip(self, floating_ip, fixed_ip, vrf):
        conn = self._get_connection()
        confstr = snippets.SET_STATIC_SRC_TRL % (fixed_ip, floating_ip, vrf)
        rpc_obj = conn.edit_config(target='running', config=confstr)
        self._check_response(rpc_obj, 'SET_STATIC_SRC_TRL')

    def _remove_floating_ip(self, floating_ip, fixed_ip, vrf):
        conn = self._get_connection()
        confstr = snippets.REMOVE_STATIC_SRC_TRL % (fixed_ip, floating_ip, vrf)
        rpc_obj = conn.edit_config(target='running', config=confstr)
        self._check_response(rpc_obj, 'REMOVE_STATIC_SRC_TRL')

    def _get_floating_ip_cfg(self):
        ioscfg = self._get_running_config()
        parse = ciscoconfparse.CiscoConfParse(ioscfg)
        res = parse.find_lines('ip nat inside source static')
        return res

    def _add_static_route(self, dest, dest_mask, next_hop, vrf):
        conn = self._get_connection()
        confstr = snippets.SET_IP_ROUTE % (vrf, dest, dest_mask, next_hop)
        rpc_obj = conn.edit_config(target='running', config=confstr)
        self._check_response(rpc_obj, 'SET_IP_ROUTE')

    def _remove_static_route(self, dest, dest_mask, next_hop, vrf):
        conn = self._get_connection()
        confstr = snippets.REMOVE_IP_ROUTE % (vrf, dest, dest_mask, next_hop)
        rpc_obj = conn.edit_config(target='running', config=confstr)
        self._check_response(rpc_obj, 'REMOVE_IP_ROUTE')

    def _get_static_route_cfg(self):
        ioscfg = self._get_running_config()
        parse = ciscoconfparse.CiscoConfParse(ioscfg)
        return parse.find_lines('ip route')

    def _add_default_static_route(self, gw_ip, vrf):
        conn = self._get_connection()
        confstr = snippets.DEFAULT_ROUTE_CFG % (vrf, gw_ip)
        if not self._cfg_exists(confstr):
            confstr = snippets.SET_DEFAULT_ROUTE % (vrf, gw_ip)
            rpc_obj = conn.edit_config(target='running', config=confstr)
            self._check_response(rpc_obj, 'SET_DEFAULT_ROUTE')

    def _remove_default_static_route(self, gw_ip, vrf):
        conn = self._get_connection()
        confstr = snippets.DEFAULT_ROUTE_CFG % (vrf, gw_ip)
        if self._cfg_exists(confstr):
            confstr = snippets.REMOVE_DEFAULT_ROUTE % (vrf, gw_ip)
            rpc_obj = conn.edit_config(target='running', config=confstr)
            self._check_response(rpc_obj, 'REMOVE_DEFAULT_ROUTE')

    def _edit_running_config(self, confstr, snippet):
        conn = self._get_connection()
        rpc_obj = conn.edit_config(target='running', config=confstr)
        self._check_response(rpc_obj, snippet)

    @staticmethod
    def _check_response(rpc_obj, snippet_name):
        """This function checks the rpc response object for status.

        This function takes as input the response rpc_obj and the snippet name
        that was executed. It parses it to see, if the last edit operation was
        a success or not.
            <?xml version="1.0" encoding="UTF-8"?>
            <rpc-reply message-id="urn:uuid:81bf8082-....-b69a-000c29e1b85c"
                       xmlns="urn:ietf:params:netconf:base:1.0">
                <ok />
            </rpc-reply>
        In case of error, CSR1kv sends a response as follows.
        We take the error type and tag.
            <?xml version="1.0" encoding="UTF-8"?>
            <rpc-reply message-id="urn:uuid:81bf8082-....-b69a-000c29e1b85c"
            xmlns="urn:ietf:params:netconf:base:1.0">
                <rpc-error>
                    <error-type>protocol</error-type>
                    <error-tag>operation-failed</error-tag>
                    <error-severity>error</error-severity>
                </rpc-error>
            </rpc-reply>
        :return: True if the config operation completed successfully
        :raises: neutron.plugins.cisco.cfg_agent.cfg_exceptions.
        CSR1kvConfigException
        """
        LOG.debug("RPCReply for %(snippet_name)s is %(rpc_obj)s",
                  {'snippet_name': snippet_name, 'rpc_obj': rpc_obj.xml})
        xml_str = rpc_obj.xml
        if "<ok />" in xml_str:
            LOG.debug("RPCReply for %s is OK", snippet_name)
            LOG.info(_("%s successfully executed"), snippet_name)
            return True
        # Not Ok, we throw a ConfigurationException
        e_type = rpc_obj._root[0][0].text
        e_tag = rpc_obj._root[0][1].text
        params = {'snippet': snippet_name, 'type': e_type, 'tag': e_tag}
        raise cfg_exc.CSR1kvConfigException(**params)
