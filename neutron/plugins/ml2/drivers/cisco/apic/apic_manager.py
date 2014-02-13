# Copyright (c) 2014 Cisco Systems Inc.
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
#
# @author: Arvind Somya (asomya@cisco.com), Cisco Systems Inc.

import itertools
import uuid

from oslo.config import cfg

from neutron.openstack.common import excutils
from neutron.plugins.ml2.drivers.cisco.apic import apic_client
from neutron.plugins.ml2.drivers.cisco.apic import apic_model
from neutron.plugins.ml2.drivers.cisco.apic import config
from neutron.plugins.ml2.drivers.cisco.apic import exceptions as cexc

AP_NAME = 'openstack'
CONTEXT_ENFORCED = '1'
CONTEXT_UNENFORCED = '2'
CONTEXT_DEFAULT = 'default'
DN_KEY = 'dn'
PORT_DN_PATH = 'topology/pod-1/paths-%s/pathep-[eth%s]'
SCOPE_GLOBAL = 'global'
SCOPE_TENANT = 'tenant'
TENANT_COMMON = 'common'


def group_by_ranges(i):
    """Group a list of numbers into tuples representing contiguous ranges."""
    for a, b in itertools.groupby(enumerate(sorted(i)), lambda (x, y): y - x):
        b = list(b)
        yield b[0][1], b[-1][1]


class APICManager(object):
    """Class to manage APIC translations and workflow.

    This class manages translation from Neutron objects to APIC
    managed objects and contains workflows to implement these
    translations.
    """
    def __init__(self):
        self.db = apic_model.ApicDbModel()

        apic_conf = cfg.CONF.ml2_cisco_apic
        self.switch_dict = config.create_switch_dictionary()

        # Connect to the the APIC
        self.apic = apic_client.RestClient(
            apic_conf.apic_host,
            apic_conf.apic_port,
            apic_conf.apic_username,
            apic_conf.apic_password
        )

        self.port_profiles = {}
        self.vmm_domain = None
        self.phys_domain = None
        self.vlan_ns = None
        self.node_profiles = {}
        self.entity_profile = None
        self.function_profile = None
        self.clear_node_profiles = apic_conf.apic_clear_node_profiles

    def ensure_infra_created_on_apic(self):
        """Ensure the infrastructure is setup.

        Loop over the switch dictionary from the config and
        setup profiles for switches, modules and ports
        """
        # Loop over switches
        for switch in self.switch_dict:
            # Create a node profile for this switch
            self.ensure_node_profile_created_for_switch(switch)

            # Check if a port profile exists for this node
            ppname = self.check_infra_port_profiles(switch)

            # Gather port ranges for this switch
            modules = self.gather_infra_module_ports(switch)

            # Setup each module and port range
            for module in modules:
                profile = self.db.get_profile_for_module(switch, ppname,
                                                         module)
                if not profile:
                    # Create host port selector for this module
                    hname = uuid.uuid4()
                    try:
                        self.apic.infraHPortS.create(ppname, hname, 'range')
                        # Add relation to the function profile
                        fpdn = self.function_profile[DN_KEY]
                        self.apic.infraRsAccBaseGrp.create(ppname, hname,
                                                           'range', tDn=fpdn)
                        modules[module].sort()
                    except (cexc.ApicResponseNotOk, KeyError):
                        with excutils.save_and_reraise_exception():
                            self.apic.infraHPortS.delete(ppname, hname,
                                                         'range')
                else:
                    hname = profile.hpselc_id

                ranges = group_by_ranges(modules[module])
                # Add this module and ports to the profile
                for prange in ranges:
                    # Check if this port block is already added to the profile
                    if not self.db.get_profile_for_module_and_ports(
                            switch, ppname, module, prange[0], prange[-1]):
                        # Create port block for this port range
                        pbname = uuid.uuid4()
                        self.apic.infraPortBlk.create(ppname, hname, 'range',
                                                      pbname, fromCard=module,
                                                      toCard=module,
                                                      fromPort=str(prange[0]),
                                                      toPort=str(prange[-1]))
                        # Add DB row
                        self.db.add_profile_for_module_and_ports(
                            switch, ppname, hname, module,
                            prange[0], prange[-1])

    def check_infra_port_profiles(self, switch):
        """Check and create infra port profiles for a node."""
        sprofile = self.db.get_port_profile_for_node(switch)
        ppname = None
        if not sprofile:
            # Generate uuid for port profile name
            ppname = uuid.uuid4()
            try:
                # Create port profile for this switch
                pprofile = self.ensure_port_profile_created_on_apic(ppname)
                # Add port profile to node profile
                ppdn = pprofile[DN_KEY]
                self.apic.infraRsAccPortP.create(switch, ppdn)
            except (cexc.ApicResponseNotOk, KeyError):
                with excutils.save_and_reraise_exception():
                    # Delete port profile
                    self.apic.infraAccPortP.delete(ppname)
        else:
            ppname = sprofile.profile_id

        return ppname

    def gather_infra_module_ports(self, switch):
        """Build modules and ports per module dictionary."""
        ports = self.switch_dict[switch]
        # Gather common modules
        modules = {}
        for port in ports:
            module, sw_port = port.split('/')
            if module not in modules:
                modules[module] = []
            modules[module].append(int(sw_port))

        return modules

    def ensure_context_unenforced(self, tenant_id=TENANT_COMMON,
                                  name=CONTEXT_DEFAULT):
        """Set the specified tenant's context to unenforced."""
        ctx = self.apic.fvCtx.get(tenant_id, name)
        if not ctx:
            self.apic.fvCtx.create(tenant_id, name,
                                   pcEnfPref=CONTEXT_UNENFORCED)
        elif ctx['pcEnfPref'] != CONTEXT_UNENFORCED:
            self.apic.fvCtx.update(tenant_id, name,
                                   pcEnfPref=CONTEXT_UNENFORCED)

    def ensure_context_enforced(self, tenant_id=TENANT_COMMON,
                                name=CONTEXT_DEFAULT):
        """Set the specified tenant's context to enforced."""
        ctx = self.apic.fvCtx.get(tenant_id, name)
        if not ctx:
            self.apic.fvCtx.create(tenant_id, name, pcEnfPref=CONTEXT_ENFORCED)
        elif ctx['pcEnfPref'] != CONTEXT_ENFORCED:
            self.apic.fvCtx.update(tenant_id, name, pcEnfPref=CONTEXT_ENFORCED)

    def ensure_entity_profile_created_on_apic(self, name):
        """Create the infrastructure entity profile."""
        if self.clear_node_profiles:
            self.apic.infraAttEntityP.delete(name)
        self.entity_profile = self.apic.infraAttEntityP.get(name)
        if not self.entity_profile:
            try:
                phys_dn = self.phys_domain[DN_KEY]
                self.apic.infraAttEntityP.create(name)
                # Attach phys domain to entity profile
                self.apic.infraRsDomP.create(name, phys_dn)
                self.entity_profile = self.apic.infraAttEntityP.get(name)
            except (cexc.ApicResponseNotOk, KeyError):
                with excutils.save_and_reraise_exception():
                    # Delete the created entity profile
                    self.apic.infraAttEntityP.delete(name)

    def ensure_function_profile_created_on_apic(self, name):
        """Create the infrastructure function profile."""
        if self.clear_node_profiles:
            self.apic.infraAccPortGrp.delete(name)
        self.function_profile = self.apic.infraAccPortGrp.get(name)
        if not self.function_profile:
            try:
                self.apic.infraAccPortGrp.create(name)
                # Attach entity profile to function profile
                entp_dn = self.entity_profile[DN_KEY]
                self.apic.infraRsAttEntP.create(name, tDn=entp_dn)
                self.function_profile = self.apic.infraAccPortGrp.get(name)
            except (cexc.ApicResponseNotOk, KeyError):
                with excutils.save_and_reraise_exception():
                    # Delete the created function profile
                    self.apic.infraAccPortGrp.delete(name)

    def ensure_node_profile_created_for_switch(self, switch_id):
        """Creates a switch node profile.

        Create a node profile for a switch and add a switch
        to the leaf node selector
        """
        if self.clear_node_profiles:
            self.apic.infraNodeP.delete(switch_id)
            self.db.delete_profile_for_node(switch_id)
        sobj = self.apic.infraNodeP.get(switch_id)
        if not sobj:
            try:
                # Create Node profile
                self.apic.infraNodeP.create(switch_id)
                # Create leaf selector
                lswitch_id = uuid.uuid4()
                self.apic.infraLeafS.create(switch_id, lswitch_id, 'range')
                # Add leaf nodes to the selector
                name = uuid.uuid4()
                self.apic.infraNodeBlk.create(switch_id, lswitch_id, 'range',
                                              name, from_=switch_id,
                                              to_=switch_id)
                sobj = self.apic.infraNodeP.get(switch_id)
            except (cexc.ApicResponseNotOk, KeyError):
                with excutils.save_and_reraise_exception():
                    # Remove the node profile
                    self.apic.infraNodeP.delete(switch_id)

        self.node_profiles[switch_id] = {
            'object': sobj
        }

    def ensure_port_profile_created_on_apic(self, name):
        """Create a port profile."""
        try:
            self.apic.infraAccPortP.create(name)
            return self.apic.infraAccPortP.get(name)
        except (cexc.ApicResponseNotOk, KeyError):
            with excutils.save_and_reraise_exception():
                self.apic.infraAccPortP.delete(name)

    def ensure_vmm_domain_created_on_apic(self, vmm_name,
                                          vlan_ns=None, vxlan_ns=None):
        """Create Virtual Machine Manager domain.

        Creates the VMM domain on the APIC and adds a VLAN or VXLAN
        namespace to that VMM domain.
        TODO (asomya): Add VXLAN support
        """
        provider = 'VMware'
        if self.clear_node_profiles:
            self.apic.vmmDomP.delete(provider, vmm_name)
        self.vmm_domain = self.apic.vmmDomP.get(provider, vmm_name)
        if not self.vmm_domain:
            try:
                self.apic.vmmDomP.create(provider, vmm_name)
                if vlan_ns:
                    vlan_ns_dn = vlan_ns[DN_KEY]
                    self.apic.infraRsVlanNs__vmm.create(provider, vmm_name,
                                                        tDn=vlan_ns_dn)
                self.vmm_domain = self.apic.vmmDomP.get(provider, vmm_name)
            except (cexc.ApicResponseNotOk, KeyError):
                with excutils.save_and_reraise_exception():
                    # Delete the VMM domain
                    self.apic.vmmDomP.delete(provider, vmm_name)

    def ensure_phys_domain_created_on_apic(self, phys_name,
                                           vlan_ns=None):
        """Create Virtual Machine Manager domain.

        Creates the VMM domain on the APIC and adds a VLAN or VXLAN
        namespace to that VMM domain.
        TODO (asomya): Add VXLAN support
        """
        if self.clear_node_profiles:
            self.apic.physDomP.delete(phys_name)
        self.phys_domain = self.apic.physDomP.get(phys_name)
        if not self.phys_domain:
            try:
                self.apic.physDomP.create(phys_name)
                if vlan_ns:
                    vlan_ns_dn = vlan_ns[DN_KEY]
                    self.apic.infraRsVlanNs__phys.create(phys_name,
                                                         tDn=vlan_ns_dn)
                self.phys_domain = self.apic.physDomP.get(phys_name)
            except (cexc.ApicResponseNotOk, KeyError):
                with excutils.save_and_reraise_exception():
                    # Delete the physical domain
                    self.apic.physDomP.delete(phys_name)

    def ensure_vlan_ns_created_on_apic(self, name, vlan_min, vlan_max):
        """Creates a static VLAN namespace with the given vlan range."""
        ns_args = name, 'static'
        if self.clear_node_profiles:
            self.apic.fvnsVlanInstP.delete(name, 'dynamic')
            self.apic.fvnsVlanInstP.delete(*ns_args)
        self.vlan_ns = self.apic.fvnsVlanInstP.get(*ns_args)
        if not self.vlan_ns:
            try:
                self.apic.fvnsVlanInstP.create(*ns_args)
                vlan_min = 'vlan-' + vlan_min
                vlan_max = 'vlan-' + vlan_max
                ns_blk_args = name, 'static', vlan_min, vlan_max
                vlan_encap = self.apic.fvnsEncapBlk__vlan.get(*ns_blk_args)
                if not vlan_encap:
                    ns_kw_args = {
                        'name': 'encap',
                        'from': vlan_min,
                        'to': vlan_max
                    }
                    self.apic.fvnsEncapBlk__vlan.create(*ns_blk_args,
                                                        **ns_kw_args)
                self.vlan_ns = self.apic.fvnsVlanInstP.get(*ns_args)
                return self.vlan_ns
            except (cexc.ApicResponseNotOk, KeyError):
                with excutils.save_and_reraise_exception():
                    # Delete the vlan namespace
                    self.apic.fvnsVlanInstP.delete(*ns_args)

    def ensure_tenant_created_on_apic(self, tenant_id):
        """Make sure a tenant exists on the APIC."""
        if not self.apic.fvTenant.get(tenant_id):
            self.apic.fvTenant.create(tenant_id)

    def ensure_bd_created_on_apic(self, tenant_id, bd_id):
        """Creates a Bridge Domain on the APIC."""
        if not self.apic.fvBD.get(tenant_id, bd_id):
            try:
                self.apic.fvBD.create(tenant_id, bd_id)
                # Add default context to the BD
                self.ensure_context_enforced()
                self.apic.fvRsCtx.create(tenant_id, bd_id,
                                         tnFvCtxName=CONTEXT_DEFAULT)
            except (cexc.ApicResponseNotOk, KeyError):
                with excutils.save_and_reraise_exception():
                    # Delete the bridge domain
                    self.apic.fvBD.delete(tenant_id, bd_id)

    def delete_bd_on_apic(self, tenant_id, bd_id):
        """Deletes a Bridge Domain from the APIC."""
        self.apic.fvBD.delete(tenant_id, bd_id)

    def ensure_subnet_created_on_apic(self, tenant_id, bd_id, gw_ip):
        """Creates a subnet on the APIC

        The gateway ip (gw_ip) should be specified as a CIDR
        e.g. 10.0.0.1/24
        """
        if not self.apic.fvSubnet.get(tenant_id, bd_id, gw_ip):
            self.apic.fvSubnet.create(tenant_id, bd_id, gw_ip)

    def ensure_filter_created_on_apic(self, tenant_id, filter_id):
        """Create a filter on the APIC."""
        if not self.apic.vzFilter.get(tenant_id, filter_id):
            self.apic.vzFilter.create(tenant_id, filter_id)

    def ensure_epg_created_for_network(self, tenant_id, network_id, net_name):
        """Creates an End Point Group on the APIC.

        Create a new EPG on the APIC for the network spcified. This information
        is also tracked in the local DB and associate the bridge domain for the
        network with the EPG created.
        """
        # Check if an EPG is already present for this network
        epg = self.db.get_epg_for_network(network_id)
        if epg:
            return epg

        # Create a new EPG on the APIC
        epg_uid = '-'.join([str(net_name), str(uuid.uuid4())])
        try:
            self.apic.fvAEPg.create(tenant_id, AP_NAME, epg_uid)

            # Add bd to EPG
            bd = self.apic.fvBD.get(tenant_id, network_id)
            bd_name = bd['name']

            # Create fvRsBd
            self.apic.fvRsBd.create(tenant_id, AP_NAME, epg_uid,
                                    tnFvBDName=bd_name)

            # Add EPG to physical domain
            phys_dn = self.phys_domain[DN_KEY]
            self.apic.fvRsDomAtt.create(tenant_id, AP_NAME, epg_uid, phys_dn)
        except (cexc.ApicResponseNotOk, KeyError):
            with excutils.save_and_reraise_exception():
                # Delete the EPG
                self.apic.fvAEPg.delete(tenant_id, AP_NAME, epg_uid)

        # Stick it in the DB
        epg = self.db.write_epg_for_network(network_id, epg_uid)

        return epg

    def delete_epg_for_network(self, tenant_id, network_id):
        """Deletes the EPG from the APIC and removes it from the DB."""
        # Check if an EPG is already present for this network
        epg = self.db.get_epg_for_network(network_id)
        if not epg:
            return False

        # Delete this epg
        self.apic.fvAEPg.delete(tenant_id, AP_NAME, epg.epg_id)
        # Remove DB row
        self.db.delete_epg(epg)

    def create_tenant_filter(self, tenant_id):
        """Creates a tenant filter and a generic entry under it."""
        fuuid = uuid.uuid4()
        try:
            # Create a new tenant filter
            self.apic.vzFilter.create(tenant_id, fuuid)
            # Create a new entry
            euuid = uuid.uuid4()
            self.apic.vzEntry.create(tenant_id, fuuid, euuid)
            return fuuid
        except (cexc.ApicResponseNotOk, KeyError):
            with excutils.save_and_reraise_exception():
                self.apic.vzFilter.delete(tenant_id, fuuid)

    def set_contract_for_epg(self, tenant_id, epg_id,
                             contract_id, provider=False):
        """Set the contract for an EPG.

        By default EPGs are consumers to a contract. Set provider flag
        for a single EPG to act as a contract provider.
        """
        if provider:
            try:
                self.apic.fvRsProv.create(tenant_id, AP_NAME,
                                          epg_id, contract_id)
                self.db.set_provider_contract(epg_id)
                self.make_tenant_contract_global(tenant_id)
            except (cexc.ApicResponseNotOk, KeyError):
                with excutils.save_and_reraise_exception():
                    self.make_tenant_contract_local(tenant_id)
                    self.apic.fvRsProv.delete(tenant_id, AP_NAME,
                                              epg_id, contract_id)
        else:
            self.apic.fvRsCons.create(tenant_id, AP_NAME, epg_id, contract_id)

    def delete_contract_for_epg(self, tenant_id, epg_id,
                                contract_id, provider=False):
        """Delete the contract for an End Point Group.

        Check if the EPG was a provider and attempt to grab another contract
        consumer from the DB and set that as the new contract provider.
        """
        if provider:
            self.apic.fvRsProv.delete(tenant_id, AP_NAME, epg_id, contract_id)
            self.db.unset_provider_contract(epg_id)
            # Pick out another EPG to set as contract provider
            epg = self.db.get_an_epg(epg_id)
            self.update_contract_for_epg(tenant_id, epg.epg_id,
                                         contract_id, True)
        else:
            self.apic.fvRsCons.delete(tenant_id, AP_NAME, epg_id, contract_id)

    def update_contract_for_epg(self, tenant_id, epg_id,
                                contract_id, provider=False):
        """Updates the contract for an End Point Group."""
        self.apic.fvRsCons.delete(tenant_id, AP_NAME, epg_id, contract_id)
        self.set_contract_for_epg(tenant_id, epg_id, contract_id, provider)

    def create_tenant_contract(self, tenant_id):
        """Creates a tenant contract.

        Create a tenant contract if one doesn't exist. Also create a
        subject, filter and entry and set the filters to allow all
        protocol traffic on all ports
        """
        contract = self.db.get_contract_for_tenant(tenant_id)
        if not contract:
            cuuid = uuid.uuid4()
            try:
                # Create contract
                self.apic.vzBrCP.create(tenant_id, cuuid, scope=SCOPE_TENANT)
                acontract = self.apic.vzBrCP.get(tenant_id, cuuid)
                # Create subject
                suuid = uuid.uuid4()
                self.apic.vzSubj.create(tenant_id, cuuid, suuid)
                # Create filter and entry
                tfilter = self.create_tenant_filter(tenant_id)
                # Create interm and outterm
                self.apic.vzInTerm.create(tenant_id, cuuid, suuid)
                self.apic.vzRsFiltAtt__In.create(tenant_id, cuuid,
                                                 suuid, tfilter)
                self.apic.vzOutTerm.create(tenant_id, cuuid, suuid)
                self.apic.vzRsFiltAtt__Out.create(tenant_id, cuuid,
                                                  suuid, tfilter)
                # Create contract interface
                iuuid = uuid.uuid4()
                self.apic.vzCPIf.create(tenant_id, iuuid)
                self.apic.vzRsIf.create(tenant_id, iuuid,
                                        tDn=acontract[DN_KEY])
                # Store contract in DB
                contract = self.db.write_contract_for_tenant(tenant_id,
                                                             cuuid, tfilter)
            except (cexc.ApicResponseNotOk, KeyError):
                with excutils.save_and_reraise_exception():
                    # Delete tenant contract
                    self.apic.vzBrCP.delete(tenant_id, cuuid)

        return contract

    def make_tenant_contract_global(self, tenant_id):
        """Mark the tenant contract's scope to global."""
        contract = self.db.get_contract_for_tenant(tenant_id)
        self.apic.vzBrCP.update(tenant_id, contract.contract_id,
                                scope=SCOPE_GLOBAL)

    def make_tenant_contract_local(self, tenant_id):
        """Mark the tenant contract's scope to tenant."""
        contract = self.db.get_contract_for_tenant(tenant_id)
        self.apic.vzBrCP.update(tenant_id, contract.contract_id,
                                scope=SCOPE_TENANT)

    def ensure_path_created_for_port(self, tenant_id, network_id,
                                     host_id, encap, net_name):
        """Create path attribute for an End Point Group."""
        encap = 'vlan-' + str(encap)
        epg = self.ensure_epg_created_for_network(tenant_id, network_id,
                                                  net_name)
        eid = epg.epg_id

        # Get attached switch and port for this host
        host_config = config.get_switch_and_port_for_host(host_id)
        if not host_config:
            raise cexc.ApicHostNotConfigured(host=host_id)
        switch, port = host_config
        pdn = PORT_DN_PATH % (switch, port)

        # Check if exists
        patt = self.apic.fvRsPathAtt.get(tenant_id, AP_NAME, eid, pdn)
        if not patt:
            self.apic.fvRsPathAtt.create(tenant_id, AP_NAME, eid, pdn,
                                         encap=encap, mode="regular",
                                         instrImedcy="immediate")
