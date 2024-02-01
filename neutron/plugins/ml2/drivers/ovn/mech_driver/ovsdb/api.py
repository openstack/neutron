# Copyright 2019 Red Hat, Inc.
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

import abc

from ovsdbapp import api

from neutron.common.ovn import constants as ovn_const


class API(api.API, metaclass=abc.ABCMeta):

    @abc.abstractmethod
    def create_lswitch_port(self, lport_name, lswitch_name, may_exist=True,
                            **columns):
        """Create a command to add an OVN logical switch port

        :param lport_name:    The name of the lport
        :type lport_name:     string
        :param lswitch_name:  The name of the lswitch the lport is created on
        :type lswitch_name:   string
        :param may_exist:     Do not fail if lport already exists
        :type may_exist:      bool
        :param columns:       Dictionary of port columns
                              Supported columns: macs, external_ids,
                                                 parent_name, tag, enabled
        :type columns:        dictionary
        :returns:             :class:`Command` with no result
        """

    @abc.abstractmethod
    def set_lswitch_port(self, lport_name, external_ids_update=None,
                         if_exists=True, **columns):
        """Create a command to set OVN logical switch port fields

        :param lport_name:    The name of the lport
        :type lport_name:     string
        :param external_ids_update: Dictionary of keys to be updated
                              individually in the external IDs dictionary.
                              If "external_ids" is defined in "columns",
                              "external_ids" will override any
                              "external_ids_update" value.
        :type external_ids_update: dictionary
        :param if_exists:     Do not fail if lport does not exist
        :type if_exists:      bool
        :param columns:       Dictionary of port columns
                              Supported columns: macs, external_ids,
                                                 parent_name, tag, enabled
        :type columns:        dictionary
        :returns:             :class:`Command` with no result
        """

    @abc.abstractmethod
    def delete_lswitch_port(self, lport_name=None, lswitch_name=None,
                            ext_id=None, if_exists=True):
        """Create a command to delete an OVN logical switch port

        :param lport_name:    The name of the lport
        :type lport_name:     string
        :param lswitch_name:  The name of the lswitch
        :type lswitch_name:   string
        :param ext_id:        The external id of the lport
        :type ext_id:         pair of <ext_id_key ,ext_id_value>
        :param if_exists:     Do not fail if the lport does not exist
        :type if_exists:      bool
        :returns:             :class:`Command` with no result
        """

    @abc.abstractmethod
    def update_lrouter(self, name, if_exists=True, **columns):
        """Update a command to add an OVN lrouter

        :param name:         The id of the lrouter
        :type name:          string
        :param if_exists:    Do not fail if the lrouter does not exist
        :type if_exists:     bool
        :param columns:      Dictionary of lrouter columns
                             Supported columns: external_ids, default_gw, ip
        :type columns:       dictionary
        :returns:            :class:`Command` with no result
        """

    @abc.abstractmethod
    def add_lrouter_port(self, name, lrouter, may_exist=True,
                         **columns):
        """Create a command to add an OVN lrouter port

        :param name:         The unique name of the lrouter port
        :type name:          string
        :param lrouter:      The unique name of the lrouter
        :type lrouter:       string
        :param lswitch:      The unique name of the lswitch
        :type lswitch:       string
        :param may_exist:    If true, do not fail if lrouter port set
                             already exists.
        :type may_exist:     bool
        :param columns:      Dictionary of lrouter columns
                             Supported columns: external_ids, mac, network
        :type columns:       dictionary
        :returns:            :class:`Command` with no result
        """

    @abc.abstractmethod
    def update_lrouter_port(self, name, if_exists=True, **columns):
        """Update a command to add an OVN lrouter port

        :param name:         The unique name of the lrouter port
        :type name:          string
        :param if_exists:    Do not fail if the lrouter port does not exist
        :type if_exists:     bool
        :param columns:      Dictionary of lrouter columns
                             Supported columns: networks
        :type columns:       dictionary
        :returns:            :class:`Command` with no result
        """

    @abc.abstractmethod
    def schedule_unhosted_gateways(self, g_name, sb_api, plugin, port_physnets,
                                   all_gw_chassis, chassis_with_physnets,
                                   chassis_with_azs):
        """Schedule unhosted gateways

        :param g_name:                The unique name of the lrouter port
        :type g_name:                 string
        :param sb_api:                IDL for the OVN SB API
        :type class:                  :class:`OvsdbSbOvnIdl`
        :param plugin:                The L3 plugin to call back to for lookups
        :type plugin:                 :class:`OVNL3RouterPlugin`
        :param port_physnets:         Map of lrouter ports and their physnets
        :type port_physnets:          Dict[string,string]
        :param all_gw_chassis:        List of gateway chassis
        :type all_gw_chassis:         List[Option[string,:class:`RowView`]]
        :param chassis_with_physnets: Map of chassis and their physnets
        :type chassis_with_physnets:  Dict[string,Set[string]]
        :param chassis_with_azs:      Map of chassis and their AZs
        :type chassis_with_azs:       Dict[string,Set[string]]
        """

    @abc.abstractmethod
    def schedule_new_gateway(self, g_name, sb_api, lrouter_name, plugin,
                             physnet, az_hints):
        """Schedule new gateway

        :param g_name:       The unique name of the lrouter port
        :type g_name:        string
        :param sb_api:       IDL for the OVN SB API
        :type class:         :class:`OvsdbSbOvnIdl`
        :param lrouter_name: The unique name of the lrouter
        :type lrouter_name:  string
        :param plugin:       The L3 plugin to call back to for lookups
        :type plugin:        :class:`OVNL3RouterPlugin`
        :param physnet:      Physnet for lrouter port
        :type physnet:       string
        :param az_hints:     Availability zone hints for router resource
        :type az_hints:      List[string]
        """

    @abc.abstractmethod
    def delete_lrouter_port(self, name, lrouter, if_exists=True):
        """Create a command to delete an OVN lrouter port

        :param name:         The unique name of the lport
        :type name:          string
        :param lrouter:      The unique name of the lrouter
        :type lrouter:       string
        :param if_exists:    Do not fail if the lrouter port does not exist
        :type if_exists:     bool
        :returns:            :class:`Command` with no result
        """

    @abc.abstractmethod
    def set_lrouter_port_in_lswitch_port(
            self, lswitch_port, lrouter_port, is_gw_port=False, if_exists=True,
            lsp_address=ovn_const.DEFAULT_ADDR_FOR_LSP_WITH_PEER):
        """Create a command to set lswitch_port as lrouter_port

        :param lswitch_port: The name of logical switch port
        :type lswitch_port:  string
        :param lrouter_port: The name of logical router port
        :type lrouter_port:  string
        :param is_gw_port:   True if logical router port is gw port
        :type is_gw_port:    bool
        :param if_exists:    Do not fail if the lswitch port does not exist
        :type if_exists:     bool
        :param lsp_address:  logical switch port's addresses to set
        :type lsp_address:   string or list of strings
        :returns:            :class:`Command` with no result
        """

    @abc.abstractmethod
    def set_router_mac_age_limit(self, router=None):
        """Set the OVN MAC_Binding age threshold

        :param router: The name or UUID of a router, or None for all routers
        :type router:  uuid.UUID or string or None
        :returns:      :class:`Command` with no result
        """

    @abc.abstractmethod
    def add_acl(self, lswitch, lport, **columns):
        """Create an ACL for a logical port.

        :param lswitch:      The logical switch the port is attached to.
        :type lswitch:       string
        :param lport:        The logical port this ACL is associated with.
        :type lport:         string
        :param columns:      Dictionary of ACL columns
                             Supported columns: see ACL table in OVN_Northbound
        :type columns:       dictionary
        """

    @abc.abstractmethod
    def delete_acl(self, lswitch, lport, if_exists=True):
        """Delete all ACLs for a logical port.

        :param lswitch:      The logical switch the port is attached to.
        :type lswitch:       string
        :param lport:        The logical port this ACL is associated with.
        :type lport:         string
        :param if_exists:    Do not fail if the ACL for this lport does not
                             exist
        :type if_exists:     bool
        """

    @abc.abstractmethod
    def update_acls(self, lswitch_names, port_list, acl_new_values_dict,
                    need_compare=True, is_add_acl=True):
        """Update the list of acls on logical switches with new values.

        :param lswitch_names:         List of logical switch names
        :type lswitch_name:           []
        :param port_list:             Iterator of list of ports
        :type port_list:              []
        :param acl_new_values_dict:   Dictionary of acls indexed by port id
        :type acl_new_values_dict:    {}
        :param need_compare:          If acl_new_values_dict need compare
                                      with existing acls
        :type need_compare:           bool
        :is_add_acl:                  If updating is caused by adding acl
        :type is_add_acl:             bool
        """

    @abc.abstractmethod
    def get_acl_by_id(self, acl_id):
        """Get an ACL by its ID.

        :param acl_id:                ID of the ACL to lookup
        :type acl_id:                 string
        :returns                      The ACL row or None:
        """

    @abc.abstractmethod
    def add_static_route(self, lrouter, maintain_bfd=False, **columns):
        """Add static route to logical router.

        :param lrouter:      The unique name of the lrouter
        :type lrouter:       string
        :param maintain_bfd: Ensure a BFD record exists for the static route.
        :type maintain_bfd:  bool
        :param columns:      Dictionary of static columns
                             Supported columns: prefix, nexthop, valid
        :type columns:       dictionary
        :returns:            :class:`Command` with no result
        """

    @abc.abstractmethod
    def set_static_route(self, sroute, **columns):
        """Update static route columns in a logical router.

        :param sroute:       The unique identifier of the LRSR
        :type sroute:        string
        :param columns:      Dictionary of static columns
                             Supported columns: prefix, nexthop, external_ids
        :type columns:       dictionary
        :returns:            :class:`Command` with no result
        """

    @abc.abstractmethod
    def get_all_chassis_gateway_bindings(self,
                                         chassis_candidate_list=None):
        """Return a dictionary of chassis name:list of gateways

        :param chassis_candidate_list:  List of possible chassis candidates
        :type chassis_candidate_list:   []
        :returns:                       {} of chassis to routers mapping
        """

    @abc.abstractmethod
    def get_gateway_chassis_binding(self, gateway_id):
        """Return the list of chassis to which the gateway is bound to

        As one gateway can be hosted by multiple chassis, this method is
        returning a list of those chassis ordered by priority. This means
        that the first element of the list is the chassis hosting the
        gateway with the highest priority (which will likely be where
        the router port is going to be active).

        :param gateway_id:     The gateway id
        :type gateway_id:      string
        :returns:              a list of strings with the chassis names
        """

    @abc.abstractmethod
    def get_gateway_chassis_az_hints(self, gateway_id):
        """Return the list of availability zone hints

        :param gateway_id:     The gateway id
        :type gateway_id:      string
        :returns:              a list of strings with the availability zones
        """

    @abc.abstractmethod
    def get_unhosted_gateways(self, port_physnet_dict, chassis_physnets,
                              gw_chassis, chassis_with_azs):
        """Return a list of gateways not hosted on chassis

        :param port_physnet_dict: Dictionary of gateway ports and their physnet
        :param chassis_physnets:  Dictionary of chassis and physnets
        :param gw_chassis:        List of gateway chassis provided by admin
                                  through ovn-cms-options
        :param chassis_with_azs:  Dictionary of chassis and available zones
        :returns:                 List of gateways not hosted on a valid
                                  chassis
        """

    @abc.abstractmethod
    def add_dhcp_options(self, subnet_id, port_id=None, may_exist=True,
                         **columns):
        """Adds the DHCP options specified in the @columns in DHCP_Options

        If the DHCP options already exist in the DHCP_Options table for
        the @subnet_id (and @lsp_name), updates the row, else creates a new
        row.

        :param subnet_id:      The subnet id to which the DHCP options belong
                               to
        :type subnet_id:       string
        :param port_id:        The port id to which the DHCP options belong to
                               if specified
        :type port_id:         string
        :param may_exist:      If true, checks if the DHCP options for
                               subnet_id exists or not. If it already exists,
                               it updates the row with the columns specified.
                               Else creates a new row.
        :type may_exist:       bool
        :type columns:         Dictionary of DHCP_Options columns
                               Supported columns: see DHCP_Options table in
                               OVN_Northbound
        :returns:            :class:`Command` with no result
        """

    @abc.abstractmethod
    def delete_dhcp_options(self, row_uuid, if_exists=True):
        """Deletes the row in DHCP_Options with the @row_uuid

        :param row_uuid:       The UUID of the row to be deleted.
        :type row_uuid:        string
        :param if_exists:      Do not fail if the DHCP_Options row does not
                               exist
        :type if_exists:       bool
        """

    @abc.abstractmethod
    def get_subnet_dhcp_options(self, subnet_id, with_ports=False):
        """Returns the Subnet DHCP options as a dictionary

        :param subnet_id:      The subnet id whose DHCP options are returned
        :type subnet_id:       string
        :param with_ports:     If True, also returns the ports DHCP options.
        :type with_ports:      bool
        :returns:              Returns a dictionary containing two keys:
                               subnet and ports.
        """

    @abc.abstractmethod
    def get_subnets_dhcp_options(self, subnet_ids):
        """Returns the Subnets DHCP options as list of dictionary

        :param subnet_ids:     The subnet ids whose DHCP options are returned
        :type subnet_ids:      list of string
        :returns:              Returns the columns of the DHCP_Options as list
                               of dictionary. Empty list is returned if no
                               DHCP_Options matched found.
        """

    @abc.abstractmethod
    def get_sg_port_groups(self):
        """Gets port groups in the OVN_Northbound DB that map to SGs.

        :returns: dictionary indexed by name, DB columns as values
        """

    @abc.abstractmethod
    def get_router_port_options(self, lsp_name):
        """Get options set for lsp of type router

        :returns: router port options
        """

    @abc.abstractmethod
    def add_nat_rule_in_lrouter(self, lrouter, **columns):
        """Add NAT rule in logical router


        :param lrouter:      The unique name of the lrouter
        :type lrouter:       string
        :param columns:      Dictionary of nat columns
                             Supported columns: type, logical_ip, external_ip
        :type columns:       dictionary
        :returns:            :class:`Command` with no result
        """

    @abc.abstractmethod
    def delete_nat_rule_in_lrouter(self, lrouter, type, logical_ip,
                                   external_ip, if_exists=True):
        """Delete NAT rule in logical router

        :param lrouter:      The unique name of the lrouter
        :type lrouter:       string
        :param type:         Type of nat. Supported values are 'snat', 'dnat'
                             and 'dnat_and_snat'
        :type type:          string
        :param logical_ip:   IP or network that needs to be natted
        :type logical_ip:    string
        :param external_ip:  External IP to be used for nat
        :type external_ip:   string
        :param if_exists:    Do not fail if the Logical_Router row does not
                             exist
        :type if_exists:     bool
        :returns:            :class:`Command` with no result
        """

    @abc.abstractmethod
    def get_lrouter_nat_rules(self, lrouter):
        """Returns the nat rules of a router

        :param lrouter: The unique name of the router
        :type lrouter:  string
        :returns:       A list of nat rules of the router, with each item
                        as a dict with the keys - 'external_ip', 'logical_ip'
                        'type' and 'uuid' of the row.
        """

    @abc.abstractmethod
    def set_nat_rule_in_lrouter(self, lrouter, nat_rule_uuid, **columns):
        """Sets the NAT rule fields

        :param lrouter: The unique name of the router to which this the
                        NAT rule belongs to.
        :type lrouter:  string
        :param nat_rule_uuid:  The uuid of the NAT rule row to be updated.
        :type nat_rule_uuid:   string
        :type columns:       dictionary
        :returns:            :class:`Command` with no result
        """

    @abc.abstractmethod
    def get_lswitch(self, lswitch_name):
        """Returns the logical switch

        :param lswitch_name: The unique name of the logical switch
        :type lswitch_name: string
        :returns: Returns logical switch or None
        """

    @abc.abstractmethod
    def get_ls_and_dns_record(self, lswitch_name):
        """Returns the logical switch and 'dns' records

        :param lswitch_name: The unique name of the logical switch
        :type lswitch_name: string
        :returns: Returns logical switch and dns records as a tuple
        """

    @abc.abstractmethod
    def get_floatingip(self, fip_id):
        """Get a Floating IP by its ID

        :param fip_id: The floating IP id
        :type fip_id: string
        :returns: The NAT rule row or None
        """

    def check_revision_number(self, name, resource, resource_type,
                              if_exists=True):
        """Compare the revision number from Neutron and OVN.

        Check if the revision number in OVN is lower than the one from
        the Neutron resource, otherwise raise RevisionConflict and abort
        the transaction.

        :param name:          The unique name of the resource
        :type name:           string
        :param resource:      The neutron resource object
        :type resource:       dictionary
        :param resource_type: The resource object type
        :type resource_type:  dictionary
        :param if_exists:     Do not fail if resource does not exist
        :type if_exists:      bool
        :returns:             :class:`Command` with no result
        :raise:               RevisionConflict if the revision number in
                              OVN is equal or higher than the neutron object
        """

    @abc.abstractmethod
    def get_lswitch_port(self, lsp_name):
        """Get a Logical Switch Port by its name.

        :param lsp_name: The Logical Switch Port name
        :type lsp_name: string
        :returns: The Logical Switch Port row or None
        """

    @abc.abstractmethod
    def get_lrouter(self, lrouter_name):
        """Get a Logical Router by its name

        :param lrouter_name: The name of the logical router
        :type lrouter_name: string
        :returns: The Logical_Router row or None
        """

    @abc.abstractmethod
    def delete_lrouter_ext_gw(self, lrouter_name, maintain_bfd=True):
        """Delete Logical Router external gateway.

        :param lrouter_name: The name of the logical router
        :type lrouter_name: string
        :param maintain_bfd: Ensure any existing BFD record is removed.
        :type maintain_bfd:  bool
        :returns: :class:`Command` with no result
        """

    @abc.abstractmethod
    def set_lswitch_port_to_virtual_type(self, lport_name, vip,
                                         virtual_parent, if_exists=True):
        """Set the type of a given port to "virtual".

        Set the type of a given port to "virtual" and all its related
        options.

        :param lport_name:      The name of the lport
        :type lport_name:       string
        :param vip:             The virtual ip
        :type vip:              string
        :param virtual_parent:  The name of the parent lport
        :type virtual_parent:   string
        :param if_exists:       Do not fail if lport does not exist
        :type if_exists:        bool
        :returns:               :class:`Command` with no result
        """

    @abc.abstractmethod
    def unset_lswitch_port_to_virtual_type(self, lport_name,
                                           virtual_parent, if_exists=True):
        """Unset the type of a given port from "virtual".

        Unset the type of a given port from "virtual" and all its related
        options.

        :param lport_name:      The name of the lport
        :type lport_name:       string
        :param virtual_parent:  The name of the parent lport
        :type virtual_parent:   string
        :param if_exists:       Do not fail if lport does not exist
        :type if_exists:        bool
        :returns:               :class:`Command` with no result
        """

    @abc.abstractmethod
    def update_lb_external_ids(self, lb_name, values, if_exists=True):
        """Set the external_ids field of a given Load Balancer.

        :param lb_name:         The name of the load_balancer
        :type lb_name:          string
        :param values:          Values to be set in external_ids
        :type values:           dict
        :param if_exists:       Do not fail if lb_name does not exist
        :type if_exists:        bool
        :returns:               :class:`Command` with no result
        """

    @abc.abstractmethod
    def get_router_floatingip_lbs(self, lrouter_name):
        """Get Load Balancers used as port forwarding by a Logical Router.

        :param lrouter_name: The name of the logical router
        :type lrouter_name: string
        :returns: a list of Load_Balancer rows matched
        """

    @abc.abstractmethod
    def get_floatingip_in_nat_or_lb(self, fip_id):
        """Get a Floating IP from either NAT or Load Balancer table by its ID

        NAT rows in OVN are mapped for floating IPs, except for port
        forwarding. In such cases, Load Balancer table is used . This function
        returns a row from NAT, if there is one. Otherwise, it will lookup
        for the FIP ID in the LB table and return the first match.

        :param fip_id: The floating IP id
        :type fip_id: string
        :returns: The NAT rule row or Load_Balancer row or None
        """

    @abc.abstractmethod
    def set_nb_global_options(self, key, value):
        """Set NB_Global options configuration"""


class SbAPI(api.API, metaclass=abc.ABCMeta):

    @abc.abstractmethod
    def chassis_exists(self, hostname):
        """Test if chassis for given hostname exists.

        @param hostname:       The hostname of the chassis
        @type hostname:        string
        :returns:              True if the chassis exists, else False.
        """

    @abc.abstractmethod
    def get_chassis_hostname_and_physnets(self):
        """Return a dict contains hostname and physnets mapping.

        Hostname will be dict key, and a list of physnets will be dict
        value. And hostname and physnets are related to the same host.
        """

    @abc.abstractmethod
    def get_gateway_chassis_from_cms_options(self, name_only=True):
        """Get chassis eligible for external connectivity from CMS options.

        When admin wants to enable router gateway on few chassis,
        he would set the external_ids as

        ovs-vsctl set open .
           external_ids:ovn-cms-options="enable-chassis-as-gw"
        In this function, we parse ovn-cms-options and return these chassis

        :param name_only: Return only the chassis names instead of
                          objects. Defaults to True.
        :returns: List with chassis.
        """

    @abc.abstractmethod
    def get_extport_chassis_from_cms_options(self):
        """Get chassis eligible for hosting external ports from CMS options.

        When admin wants to enable hosting external ports on different
        chassis than gateway chassis as

        ovs-vsctl set open .
           external_ids:ovn-cms-options="enable-chassis-as-extport-host"
        In this function, we parse ovn-cms-options and return these chassis

        :returns: List with chassis
        """

    @abc.abstractmethod
    def get_chassis_and_physnets(self):
        """Return a dict contains chassis name and physnets mapping.

        Chassis name will be dict key, and a list of physnets will be dict
        value. And chassis name and physnets are related to the same chassis.
        """

    @abc.abstractmethod
    def get_all_chassis(self, chassis_type=None):
        """Return a list of all chassis which match the compute_type

        :param chassis_type:    The type of chassis
        :type chassis_type:     string
        """

    @abc.abstractmethod
    def get_chassis_host_for_port(self, port_id):
        """Return a list of Chassis name hosting the port

        :param port_id: The port ID
        :type port_id:  string
        """
