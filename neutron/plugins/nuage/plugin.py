# Copyright 2014 Alcatel-Lucent USA Inc.
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
# @author: Ronak Shah, Nuage Networks, Alcatel-Lucent USA Inc.


import re

import netaddr
from oslo.config import cfg
from sqlalchemy.orm import exc

from neutron.api import extensions as neutron_extensions
from neutron.api.v2 import attributes
from neutron.common import constants as os_constants
from neutron.common import exceptions as n_exc
from neutron.db import api as db
from neutron.db import db_base_plugin_v2
from neutron.db import external_net_db
from neutron.db import l3_db
from neutron.db import models_v2
from neutron.db import quota_db  # noqa
from neutron.extensions import portbindings
from neutron.openstack.common import excutils
from neutron.openstack.common import importutils
from neutron.plugins.nuage.common import config
from neutron.plugins.nuage.common import constants
from neutron.plugins.nuage.common import exceptions as nuage_exc
from neutron.plugins.nuage import extensions
from neutron.plugins.nuage.extensions import netpartition
from neutron.plugins.nuage import nuagedb
from neutron import policy


class NuagePlugin(db_base_plugin_v2.NeutronDbPluginV2,
                  external_net_db.External_net_db_mixin,
                  l3_db.L3_NAT_db_mixin,
                  netpartition.NetPartitionPluginBase):
    """Class that implements Nuage Networks' plugin functionality."""
    supported_extension_aliases = ["router", "binding", "external-net",
                                   "net-partition", "nuage-router",
                                   "nuage-subnet", "quotas"]

    binding_view = "extension:port_binding:view"

    def __init__(self):
        super(NuagePlugin, self).__init__()
        neutron_extensions.append_api_extensions_path(extensions.__path__)
        config.nuage_register_cfg_opts()
        self.nuageclient_init()
        net_partition = cfg.CONF.RESTPROXY.default_net_partition_name
        self._create_default_net_partition(net_partition)

    def nuageclient_init(self):
        server = cfg.CONF.RESTPROXY.server
        serverauth = cfg.CONF.RESTPROXY.serverauth
        serverssl = cfg.CONF.RESTPROXY.serverssl
        base_uri = cfg.CONF.RESTPROXY.base_uri
        auth_resource = cfg.CONF.RESTPROXY.auth_resource
        organization = cfg.CONF.RESTPROXY.organization
        nuageclient = importutils.import_module('nuagenetlib.nuageclient')
        self.nuageclient = nuageclient.NuageClient(server, base_uri,
                                                   serverssl, serverauth,
                                                   auth_resource,
                                                   organization)

    def _resource_finder(self, context, for_resource, resource, user_req):
        match = re.match(attributes.UUID_PATTERN, user_req[resource])
        if match:
            obj_lister = getattr(self, "get_%s" % resource)
            found_resource = obj_lister(context, user_req[resource])
            if not found_resource:
                msg = (_("%(resource)s with id %(resource_id)s does not "
                         "exist") % {'resource': resource,
                                     'resource_id': user_req[resource]})
                raise n_exc.BadRequest(resource=for_resource, msg=msg)
        else:
            filter = {'name': [user_req[resource]]}
            obj_lister = getattr(self, "get_%ss" % resource)
            found_resource = obj_lister(context, filters=filter)
            if not found_resource:
                msg = (_("Either %(resource)s %(req_resource)s not found "
                         "or you dont have credential to access it")
                       % {'resource': resource,
                          'req_resource': user_req[resource]})
                raise n_exc.BadRequest(resource=for_resource, msg=msg)
            if len(found_resource) > 1:
                msg = (_("More than one entry found for %(resource)s "
                         "%(req_resource)s. Use id instead")
                       % {'resource': resource,
                          'req_resource': user_req[resource]})
                raise n_exc.BadRequest(resource=for_resource, msg=msg)
            found_resource = found_resource[0]
        return found_resource

    def _update_port_ip(self, context, port, new_ip):
        subid = port['fixed_ips'][0]['subnet_id']
        new_fixed_ips = {}
        new_fixed_ips['subnet_id'] = subid
        new_fixed_ips['ip_address'] = new_ip
        ips, prev_ips = self._update_ips_for_port(context,
                                                  port["network_id"],
                                                  port['id'],
                                                  port["fixed_ips"],
                                                  [new_fixed_ips])

        # Update ips if necessary
        for ip in ips:
            allocated = models_v2.IPAllocation(
                network_id=port['network_id'], port_id=port['id'],
                ip_address=ip['ip_address'], subnet_id=ip['subnet_id'])
            context.session.add(allocated)

    def _create_update_port(self, context, port,
                            port_mapping, subnet_mapping):
        filters = {'device_id': [port['device_id']]}
        ports = self.get_ports(context, filters)
        netpart_id = subnet_mapping['net_partition_id']
        net_partition = nuagedb.get_net_partition_by_id(context.session,
                                                        netpart_id)
        params = {
            'id': port['device_id'],
            'mac': port['mac_address'],
            'parent_id': subnet_mapping['nuage_subnet_id'],
            'net_partition': net_partition,
            'ip': None,
            'no_of_ports': len(ports),
            'tenant': port['tenant_id']
        }
        if port_mapping['static_ip']:
            params['ip'] = port['fixed_ips'][0]['ip_address']

        nuage_vm = self.nuageclient.create_vms(params)
        if nuage_vm:
            if port['fixed_ips'][0]['ip_address'] != str(nuage_vm['ip']):
                self._update_port_ip(context, port, nuage_vm['ip'])
            port_dict = {
                'nuage_vport_id': nuage_vm['vport_id'],
                'nuage_vif_id': nuage_vm['vif_id']
            }
            nuagedb.update_port_vport_mapping(port_mapping,
                                              port_dict)

    def create_port(self, context, port):
        session = context.session
        with session.begin(subtransactions=True):
            p = port['port']
            port = super(NuagePlugin, self).create_port(context, port)
            device_owner = port.get('device_owner', None)
            if (device_owner and
                device_owner not in constants.AUTO_CREATE_PORT_OWNERS):
                if 'fixed_ips' not in port or len(port['fixed_ips']) == 0:
                    return self._extend_port_dict_binding(context, port)
                subnet_id = port['fixed_ips'][0]['subnet_id']
                subnet_mapping = nuagedb.get_subnet_l2dom_by_id(session,
                                                                subnet_id)
                if subnet_mapping:
                    static_ip = False
                    if (attributes.is_attr_set(p['fixed_ips']) and
                        'ip_address' in p['fixed_ips'][0]):
                        static_ip = True
                    nuage_vport_id = None
                    nuage_vif_id = None
                    port_mapping = nuagedb.add_port_vport_mapping(
                        session,
                        port['id'],
                        nuage_vport_id,
                        nuage_vif_id,
                        static_ip)
                    port_prefix = constants.NOVA_PORT_OWNER_PREF
                    if port['device_owner'].startswith(port_prefix):
                        #This request is coming from nova
                        try:
                            self._create_update_port(context, port,
                                                     port_mapping,
                                                     subnet_mapping)
                        except Exception:
                            with excutils.save_and_reraise_exception():
                                super(NuagePlugin, self).delete_port(
                                    context,
                                    port['id'])
        return self._extend_port_dict_binding(context, port)

    def update_port(self, context, id, port):
        p = port['port']
        if p.get('device_owner', '').startswith(
            constants.NOVA_PORT_OWNER_PREF):
            session = context.session
            with session.begin(subtransactions=True):
                port = self._get_port(context, id)
                port.update(p)
                if 'fixed_ips' not in port or len(port['fixed_ips']) == 0:
                    return self._make_port_dict(port)
                subnet_id = port['fixed_ips'][0]['subnet_id']
                subnet_mapping = nuagedb.get_subnet_l2dom_by_id(session,
                                                                subnet_id)
                if not subnet_mapping:
                    msg = (_("Subnet %s not found on VSD") % subnet_id)
                    raise n_exc.BadRequest(resource='port', msg=msg)
                port_mapping = nuagedb.get_port_mapping_by_id(session,
                                                              id)
                if not port_mapping:
                    msg = (_("Port-Mapping for port %s not "
                             " found on VSD") % id)
                    raise n_exc.BadRequest(resource='port', msg=msg)
                if not port_mapping['nuage_vport_id']:
                    self._create_update_port(context, port,
                                             port_mapping, subnet_mapping)
                updated_port = self._make_port_dict(port)
        else:
            updated_port = super(NuagePlugin, self).update_port(context, id,
                                                                port)
        return updated_port

    def delete_port(self, context, id, l3_port_check=True):
        if l3_port_check:
            self.prevent_l3_port_deletion(context, id)
        port = self._get_port(context, id)
        port_mapping = nuagedb.get_port_mapping_by_id(context.session,
                                                      id)
        # This is required for to pass ut test_floatingip_port_delete
        self.disassociate_floatingips(context, id)
        if not port['fixed_ips']:
            return super(NuagePlugin, self).delete_port(context, id)

        sub_id = port['fixed_ips'][0]['subnet_id']
        subnet_mapping = nuagedb.get_subnet_l2dom_by_id(context.session,
                                                        sub_id)
        if not subnet_mapping:
            return super(NuagePlugin, self).delete_port(context, id)

        netpart_id = subnet_mapping['net_partition_id']
        net_partition = nuagedb.get_net_partition_by_id(context.session,
                                                        netpart_id)
        # Need to call this explicitly to delete vport_vporttag_mapping
        if constants.NOVA_PORT_OWNER_PREF in port['device_owner']:
            # This was a VM Port
            filters = {'device_id': [port['device_id']]}
            ports = self.get_ports(context, filters)
            params = {
                'no_of_ports': len(ports),
                'net_partition': net_partition,
                'tenant': port['tenant_id'],
                'mac': port['mac_address'],
                'nuage_vif_id': port_mapping['nuage_vif_id'],
                'id': port['device_id']
            }
            self.nuageclient.delete_vms(params)
        super(NuagePlugin, self).delete_port(context, id)

    def _check_view_auth(self, context, resource, action):
        return policy.check(context, action, resource)

    def _extend_port_dict_binding(self, context, port):
        if self._check_view_auth(context, port, self.binding_view):
            port[portbindings.VIF_TYPE] = portbindings.VIF_TYPE_OVS
            port[portbindings.VIF_DETAILS] = {
                portbindings.CAP_PORT_FILTER: False
            }
        return port

    def get_port(self, context, id, fields=None):
        port = super(NuagePlugin, self).get_port(context, id, fields)
        return self._fields(self._extend_port_dict_binding(context, port),
                            fields)

    def get_ports(self, context, filters=None, fields=None):
        ports = super(NuagePlugin, self).get_ports(context, filters, fields)
        return [self._fields(self._extend_port_dict_binding(context, port),
                             fields) for port in ports]

    def _check_router_subnet_for_tenant(self, context):
        # Search router and subnet tables.
        # If no entry left delete user and group from VSD
        filters = {'tenant_id': [context.tenant]}
        routers = self.get_routers(context, filters=filters)
        subnets = self.get_subnets(context, filters=filters)
        return bool(routers or subnets)

    def create_network(self, context, network):
        net = network['network']
        with context.session.begin(subtransactions=True):
            net = super(NuagePlugin, self).create_network(context,
                                                          network)
            self._process_l3_create(context, net, network['network'])
        return net

    def update_network(self, context, id, network):
        with context.session.begin(subtransactions=True):
            net = super(NuagePlugin, self).update_network(context, id,
                                                          network)
            self._process_l3_update(context, net, network['network'])
        return net

    def delete_network(self, context, id):
        filter = {'network_id': [id]}
        subnets = self.get_subnets(context, filters=filter)
        for subnet in subnets:
            self.delete_subnet(context, subnet['id'])
        super(NuagePlugin, self).delete_network(context, id)

    def _get_net_partition_for_subnet(self, context, subnet):
        subn = subnet['subnet']
        ent = subn.get('net_partition', None)
        if not ent:
            def_net_part = cfg.CONF.RESTPROXY.default_net_partition_name
            net_partition = nuagedb.get_net_partition_by_name(context.session,
                                                              def_net_part)
        else:
            net_partition = self._resource_finder(context, 'subnet',
                                                  'net_partition', subn)
        if not net_partition:
            msg = _('Either net_partition is not provided with subnet OR '
                    'default net_partition is not created at the start')
            raise n_exc.BadRequest(resource='subnet', msg=msg)
        return net_partition

    def _validate_create_subnet(self, subnet):
        if ('host_routes' in subnet and
            attributes.is_attr_set(subnet['host_routes'])):
            msg = 'host_routes extensions not supported for subnets'
            raise nuage_exc.OperationNotSupported(msg=msg)
        if subnet['gateway_ip'] is None:
            msg = "no-gateway option not supported with subnets"
            raise nuage_exc.OperationNotSupported(msg=msg)

    def create_subnet(self, context, subnet):
        subn = subnet['subnet']
        net_id = subn['network_id']

        if self._network_is_external(context, net_id):
            return super(NuagePlugin, self).create_subnet(context, subnet)

        self._validate_create_subnet(subn)

        net_partition = self._get_net_partition_for_subnet(context, subnet)
        neutron_subnet = super(NuagePlugin, self).create_subnet(context,
                                                                subnet)
        net = netaddr.IPNetwork(neutron_subnet['cidr'])
        params = {
            'net_partition': net_partition,
            'tenant_id': neutron_subnet['tenant_id'],
            'net': net
        }
        try:
            nuage_subnet = self.nuageclient.create_subnet(neutron_subnet,
                                                          params)
        except Exception:
            with excutils.save_and_reraise_exception():
                super(NuagePlugin, self).delete_subnet(context,
                                                       neutron_subnet['id'])

        if nuage_subnet:
            l2dom_id = str(nuage_subnet['nuage_l2template_id'])
            user_id = nuage_subnet['nuage_userid']
            group_id = nuage_subnet['nuage_groupid']
            id = nuage_subnet['nuage_l2domain_id']
            session = context.session
            with session.begin(subtransactions=True):
                nuagedb.add_subnetl2dom_mapping(session,
                                                neutron_subnet['id'],
                                                id,
                                                net_partition['id'],
                                                l2dom_id=l2dom_id,
                                                nuage_user_id=user_id,
                                                nuage_group_id=group_id)
        return neutron_subnet

    def delete_subnet(self, context, id):
        subnet = self.get_subnet(context, id)
        if self._network_is_external(context, subnet['network_id']):
            return super(NuagePlugin, self).delete_subnet(context, id)

        subnet_l2dom = nuagedb.get_subnet_l2dom_by_id(context.session, id)
        if subnet_l2dom:
            template_id = subnet_l2dom['nuage_l2dom_tmplt_id']
            try:
                self.nuageclient.delete_subnet(subnet_l2dom['nuage_subnet_id'],
                                               template_id)
            except Exception:
                msg = (_('Unable to complete operation on subnet %s.'
                         'One or more ports have an IP allocation '
                         'from this subnet.') % id)
                raise n_exc.BadRequest(resource='subnet', msg=msg)
        super(NuagePlugin, self).delete_subnet(context, id)
        if subnet_l2dom and not self._check_router_subnet_for_tenant(context):
            self.nuageclient.delete_user(subnet_l2dom['nuage_user_id'])
            self.nuageclient.delete_group(subnet_l2dom['nuage_group_id'])

    def add_router_interface(self, context, router_id, interface_info):
        session = context.session
        with session.begin(subtransactions=True):
            rtr_if_info = super(NuagePlugin,
                                self).add_router_interface(context,
                                                           router_id,
                                                           interface_info)
            subnet_id = rtr_if_info['subnet_id']
            subn = self.get_subnet(context, subnet_id)

            rtr_zone_mapping = nuagedb.get_rtr_zone_mapping(session,
                                                            router_id)
            ent_rtr_mapping = nuagedb.get_ent_rtr_mapping_by_rtrid(session,
                                                                   router_id)
            subnet_l2dom = nuagedb.get_subnet_l2dom_by_id(session,
                                                          subnet_id)
            if not rtr_zone_mapping or not ent_rtr_mapping:
                super(NuagePlugin,
                      self).remove_router_interface(context,
                                                    router_id,
                                                    interface_info)
                msg = (_("Router %s does not hold default zone OR "
                         "net_partition mapping. Router-IF add failed")
                       % router_id)
                raise n_exc.BadRequest(resource='router', msg=msg)

            if not subnet_l2dom:
                super(NuagePlugin,
                      self).remove_router_interface(context,
                                                    router_id,
                                                    interface_info)
                msg = (_("Subnet %s does not hold Nuage VSD reference. "
                         "Router-IF add failed") % subnet_id)
                raise n_exc.BadRequest(resource='subnet', msg=msg)

            if (subnet_l2dom['net_partition_id'] !=
                ent_rtr_mapping['net_partition_id']):
                super(NuagePlugin,
                      self).remove_router_interface(context,
                                                    router_id,
                                                    interface_info)
                msg = (_("Subnet %(subnet)s and Router %(router)s belong to "
                         "different net_partition Router-IF add "
                         "not permitted") % {'subnet': subnet_id,
                                             'router': router_id})
                raise n_exc.BadRequest(resource='subnet', msg=msg)
            nuage_subnet_id = subnet_l2dom['nuage_subnet_id']
            nuage_l2dom_tmplt_id = subnet_l2dom['nuage_l2dom_tmplt_id']
            if self.nuageclient.vms_on_l2domain(nuage_subnet_id):
                super(NuagePlugin,
                      self).remove_router_interface(context,
                                                    router_id,
                                                    interface_info)
                msg = (_("Subnet %s has one or more active VMs "
                       "Router-IF add not permitted") % subnet_id)
                raise n_exc.BadRequest(resource='subnet', msg=msg)
            self.nuageclient.delete_subnet(nuage_subnet_id,
                                           nuage_l2dom_tmplt_id)
            net = netaddr.IPNetwork(subn['cidr'])
            params = {
                'net': net,
                'zone_id': rtr_zone_mapping['nuage_zone_id']
            }
            if not attributes.is_attr_set(subn['gateway_ip']):
                subn['gateway_ip'] = str(netaddr.IPAddress(net.first + 1))
            try:
                nuage_subnet = self.nuageclient.create_domain_subnet(subn,
                                                                     params)
            except Exception:
                with excutils.save_and_reraise_exception():
                    super(NuagePlugin,
                          self).remove_router_interface(context,
                                                        router_id,
                                                        interface_info)
            if nuage_subnet:
                ns_dict = {}
                ns_dict['nuage_subnet_id'] = nuage_subnet['nuage_subnetid']
                ns_dict['nuage_l2dom_tmplt_id'] = None
                nuagedb.update_subnetl2dom_mapping(subnet_l2dom,
                                                   ns_dict)
        return rtr_if_info

    def remove_router_interface(self, context, router_id, interface_info):
        if 'subnet_id' in interface_info:
            subnet_id = interface_info['subnet_id']
            subnet = self.get_subnet(context, subnet_id)
            found = False
            try:
                filters = {'device_id': [router_id],
                           'device_owner':
                           [os_constants.DEVICE_OWNER_ROUTER_INTF],
                           'network_id': [subnet['network_id']]}
                ports = self.get_ports(context, filters)

                for p in ports:
                    if p['fixed_ips'][0]['subnet_id'] == subnet_id:
                        found = True
                        break
            except exc.NoResultFound:
                msg = (_("No router interface found for Router %s. "
                         "Router-IF delete failed") % router_id)
                raise n_exc.BadRequest(resource='router', msg=msg)

            if not found:
                msg = (_("No router interface found for Router %s. "
                         "Router-IF delete failed") % router_id)
                raise n_exc.BadRequest(resource='router', msg=msg)
        elif 'port_id' in interface_info:
            port_db = self._get_port(context, interface_info['port_id'])
            if not port_db:
                msg = (_("No router interface found for Router %s. "
                         "Router-IF delete failed") % router_id)
                raise n_exc.BadRequest(resource='router', msg=msg)
            subnet_id = port_db['fixed_ips'][0]['subnet_id']

        session = context.session
        with session.begin(subtransactions=True):
            subnet_l2dom = nuagedb.get_subnet_l2dom_by_id(session,
                                                          subnet_id)
            nuage_subn_id = subnet_l2dom['nuage_subnet_id']
            if self.nuageclient.vms_on_l2domain(nuage_subn_id):
                msg = (_("Subnet %s has one or more active VMs "
                         "Router-IF delete not permitted") % subnet_id)
                raise n_exc.BadRequest(resource='subnet', msg=msg)

            neutron_subnet = self.get_subnet(context, subnet_id)
            ent_rtr_mapping = nuagedb.get_ent_rtr_mapping_by_rtrid(
                context.session,
                router_id)
            if not ent_rtr_mapping:
                msg = (_("Router %s does not hold net_partition "
                         "assoc on Nuage VSD. Router-IF delete failed")
                       % router_id)
                raise n_exc.BadRequest(resource='router', msg=msg)
            net = netaddr.IPNetwork(neutron_subnet['cidr'])
            net_part_id = ent_rtr_mapping['net_partition_id']
            net_partition = self.get_net_partition(context,
                                                   net_part_id)
            params = {
                'net_partition': net_partition,
                'tenant_id': neutron_subnet['tenant_id'],
                'net': net
            }
            nuage_subnet = self.nuageclient.create_subnet(neutron_subnet,
                                                          params)
            self.nuageclient.delete_domain_subnet(nuage_subn_id)
            info = super(NuagePlugin,
                         self).remove_router_interface(context, router_id,
                                                       interface_info)
            if nuage_subnet:
                tmplt_id = str(nuage_subnet['nuage_l2template_id'])
                ns_dict = {}
                ns_dict['nuage_subnet_id'] = nuage_subnet['nuage_l2domain_id']
                ns_dict['nuage_l2dom_tmplt_id'] = tmplt_id
                nuagedb.update_subnetl2dom_mapping(subnet_l2dom,
                                                   ns_dict)
        return info

    def _get_net_partition_for_router(self, context, router):
        rtr = router['router']
        ent = rtr.get('net_partition', None)
        if not ent:
            def_net_part = cfg.CONF.RESTPROXY.default_net_partition_name
            net_partition = nuagedb.get_net_partition_by_name(context.session,
                                                              def_net_part)
        else:
            net_partition = self._resource_finder(context, 'router',
                                                  'net_partition', rtr)
        if not net_partition:
            msg = _("Either net_partition is not provided with router OR "
                    "default net_partition is not created at the start")
            raise n_exc.BadRequest(resource='router', msg=msg)
        return net_partition

    def create_router(self, context, router):
        net_partition = self._get_net_partition_for_router(context, router)
        neutron_router = super(NuagePlugin, self).create_router(context,
                                                                router)
        params = {
            'net_partition': net_partition,
            'tenant_id': neutron_router['tenant_id']
        }
        try:
            nuage_router = self.nuageclient.create_router(neutron_router,
                                                          router['router'],
                                                          params)
        except Exception:
            with excutils.save_and_reraise_exception():
                super(NuagePlugin, self).delete_router(context,
                                                       neutron_router['id'])
        if nuage_router:
            user_id = nuage_router['nuage_userid']
            group_id = nuage_router['nuage_groupid']
            with context.session.begin(subtransactions=True):
                nuagedb.add_entrouter_mapping(context.session,
                                              net_partition['id'],
                                              neutron_router['id'],
                                              nuage_router['nuage_domain_id'])
                nuagedb.add_rtrzone_mapping(context.session,
                                            neutron_router['id'],
                                            nuage_router['nuage_def_zone_id'],
                                            nuage_user_id=user_id,
                                            nuage_group_id=group_id)
        return neutron_router

    def delete_router(self, context, id):
        session = context.session
        ent_rtr_mapping = nuagedb.get_ent_rtr_mapping_by_rtrid(session,
                                                               id)
        if ent_rtr_mapping:
            nuage_router_id = ent_rtr_mapping['nuage_router_id']
            self.nuageclient.delete_router(nuage_router_id)
        router_zone = nuagedb.get_rtr_zone_mapping(session, id)
        super(NuagePlugin, self).delete_router(context, id)
        if router_zone and not self._check_router_subnet_for_tenant(context):
            self.nuageclient.delete_user(router_zone['nuage_user_id'])
            self.nuageclient.delete_group(router_zone['nuage_group_id'])

    def _make_net_partition_dict(self, net_partition, fields=None):
        res = {
            'id': net_partition['id'],
            'name': net_partition['name'],
            'l3dom_tmplt_id': net_partition['l3dom_tmplt_id'],
            'l2dom_tmplt_id': net_partition['l2dom_tmplt_id'],
        }
        return self._fields(res, fields)

    def _create_net_partition(self, session, net_part_name):
        fip_quota = cfg.CONF.RESTPROXY.default_floatingip_quota
        params = {
            "name": net_part_name,
            "fp_quota": str(fip_quota)
        }
        nuage_net_partition = self.nuageclient.create_net_partition(params)
        net_partitioninst = None
        if nuage_net_partition:
            nuage_entid = nuage_net_partition['nuage_entid']
            l3dom_id = nuage_net_partition['l3dom_id']
            l2dom_id = nuage_net_partition['l2dom_id']
            with session.begin():
                net_partitioninst = nuagedb.add_net_partition(session,
                                                              nuage_entid,
                                                              l3dom_id,
                                                              l2dom_id,
                                                              net_part_name)
        if not net_partitioninst:
            return {}
        return self._make_net_partition_dict(net_partitioninst)

    def _create_default_net_partition(self, default_net_part):
        self.nuageclient.check_del_def_net_partition(default_net_part)
        session = db.get_session()
        net_partition = nuagedb.get_net_partition_by_name(session,
                                                          default_net_part)
        if net_partition:
            with session.begin(subtransactions=True):
                nuagedb.delete_net_partition(session, net_partition)

        self._create_net_partition(session, default_net_part)

    def create_net_partition(self, context, net_partition):
        ent = net_partition['net_partition']
        session = context.session
        return self._create_net_partition(session, ent["name"])

    def delete_net_partition(self, context, id):
        ent_rtr_mapping = nuagedb.get_ent_rtr_mapping_by_entid(
            context.session,
            id)
        if ent_rtr_mapping:
            msg = (_("One or more router still attached to "
                     "net_partition %s.") % id)
            raise n_exc.BadRequest(resource='net_partition', msg=msg)
        net_partition = nuagedb.get_net_partition_by_id(context.session, id)
        if not net_partition:
            msg = (_("NetPartition with %s does not exist") % id)
            raise n_exc.BadRequest(resource='net_partition', msg=msg)
        l3dom_tmplt_id = net_partition['l3dom_tmplt_id']
        l2dom_tmplt_id = net_partition['l2dom_tmplt_id']
        self.nuageclient.delete_net_partition(net_partition['id'],
                                              l3dom_id=l3dom_tmplt_id,
                                              l2dom_id=l2dom_tmplt_id)
        with context.session.begin(subtransactions=True):
            nuagedb.delete_net_partition(context.session,
                                         net_partition)

    def get_net_partition(self, context, id, fields=None):
        net_partition = nuagedb.get_net_partition_by_id(context.session,
                                                        id)
        return self._make_net_partition_dict(net_partition)

    def get_net_partitions(self, context, filters=None, fields=None):
        net_partitions = nuagedb.get_net_partitions(context.session,
                                                    filters=filters,
                                                    fields=fields)
        return [self._make_net_partition_dict(net_partition, fields)
                for net_partition in net_partitions]
