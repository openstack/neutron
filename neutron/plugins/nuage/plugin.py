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

import copy
import re

import netaddr
from oslo_concurrency import lockutils
from oslo_config import cfg
from oslo_utils import excutils
from oslo_utils import importutils
from sqlalchemy.orm import exc

from neutron.api import extensions as neutron_extensions
from neutron.api.v2 import attributes
from neutron.common import constants as os_constants
from neutron.common import exceptions as n_exc
from neutron.common import utils
from neutron.db import api as db
from neutron.db import db_base_plugin_v2
from neutron.db import external_net_db
from neutron.db import extraroute_db
from neutron.db import l3_db
from neutron.db import quota_db  # noqa
from neutron.db import securitygroups_db as sg_db
from neutron.extensions import external_net
from neutron.extensions import l3
from neutron.extensions import portbindings
from neutron.extensions import providernet as pnet
from neutron.extensions import securitygroup as ext_sg
from neutron.openstack.common import log as logging
from neutron.openstack.common import loopingcall
from neutron.plugins.nuage.common import config
from neutron.plugins.nuage.common import constants
from neutron.plugins.nuage.common import exceptions as nuage_exc
from neutron.plugins.nuage import extensions
from neutron.plugins.nuage.extensions import netpartition
from neutron.plugins.nuage import nuagedb
from neutron.plugins.nuage import syncmanager
from neutron import policy

LOG = logging.getLogger(__name__)


class NuagePlugin(db_base_plugin_v2.NeutronDbPluginV2,
                  external_net_db.External_net_db_mixin,
                  extraroute_db.ExtraRoute_db_mixin,
                  l3_db.L3_NAT_db_mixin,
                  netpartition.NetPartitionPluginBase,
                  sg_db.SecurityGroupDbMixin):
    """Class that implements Nuage Networks' plugin functionality."""
    supported_extension_aliases = ["router", "binding", "external-net",
                                   "net-partition", "nuage-router",
                                   "nuage-subnet", "quotas", "provider",
                                   "extraroute", "security-group"]

    binding_view = "extension:port_binding:view"

    def __init__(self):
        super(NuagePlugin, self).__init__()
        neutron_extensions.append_api_extensions_path(extensions.__path__)
        config.nuage_register_cfg_opts()
        self.nuageclient_init()
        net_partition = cfg.CONF.RESTPROXY.default_net_partition_name
        self._create_default_net_partition(net_partition)
        if cfg.CONF.SYNCMANAGER.enable_sync:
            self.syncmanager = syncmanager.SyncManager(self.nuageclient)
            self._synchronization_thread()

    db_base_plugin_v2.NeutronDbPluginV2.register_dict_extend_funcs(
        attributes.NETWORKS, ['_extend_network_dict_provider_nuage'])

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

    def _synchronization_thread(self):
        sync_interval = cfg.CONF.SYNCMANAGER.sync_interval
        fip_quota = str(cfg.CONF.RESTPROXY.default_floatingip_quota)
        if sync_interval > 0:
            sync_loop = loopingcall.FixedIntervalLoopingCall(
                self.syncmanager.synchronize, fip_quota)
            sync_loop.start(interval=sync_interval)
        else:
            self.syncmanager.synchronize(fip_quota)

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

    def _create_update_port(self, context, port, np_name):
        filters = {'device_id': [port['device_id']]}
        ports = self.get_ports(context, filters)
        params = {
            'port_id': port['id'],
            'id': port['device_id'],
            'mac': port['mac_address'],
            'netpart_name': np_name,
            'ip': port['fixed_ips'][0]['ip_address'],
            'no_of_ports': len(ports),
            'tenant': port['tenant_id'],
            'neutron_id': port['fixed_ips'][0]['subnet_id']
        }
        self.nuageclient.create_vms(params)

    def _get_router_by_subnet(self, context, subnet_id):
        filters = {
            'fixed_ips': {'subnet_id': [subnet_id]},
            'device_owner': [os_constants.DEVICE_OWNER_ROUTER_INTF]
        }
        router_port = self.get_ports(context, filters=filters)
        if not router_port:
            msg = (_("Router for subnet %s not found ") % subnet_id)
            raise n_exc.BadRequest(resource='port', msg=msg)
        return router_port[0]['device_id']

    def _process_port_create_security_group(self, context, port,
                                            sec_group):
        if not attributes.is_attr_set(sec_group):
            port[ext_sg.SECURITYGROUPS] = []
            return
        port_id = port['id']
        with context.session.begin(subtransactions=True):
            for sg_id in sec_group:
                super(NuagePlugin,
                      self)._create_port_security_group_binding(context,
                                                                port_id,
                                                                sg_id)
        try:
            vptag_vport_list = []
            for sg_id in sec_group:
                params = {
                    'neutron_port_id': port_id
                }
                nuage_port = self.nuageclient.get_nuage_port_by_id(params)
                if nuage_port and nuage_port.get('nuage_vport_id'):
                    nuage_vport_id = nuage_port['nuage_vport_id']
                    sg = self._get_security_group(context, sg_id)
                    sg_rules = self.get_security_group_rules(
                                        context,
                                        {'security_group_id': [sg_id]})
                    sg_params = {
                        'nuage_port': nuage_port,
                        'sg': sg,
                        'sg_rules': sg_rules
                    }
                    nuage_vptag_id = (
                        self.nuageclient.process_port_create_security_group(
                                                                    sg_params))
                    vptag_vport = {
                        'nuage_vporttag_id': nuage_vptag_id
                    }
                    vptag_vport_list.append(vptag_vport)

            if vptag_vport_list:
                params = {
                    'vptag_vport_list': vptag_vport_list,
                    'nuage_vport_id': nuage_vport_id
                }
                self.nuageclient.update_nuage_vport(params)
        except Exception:
            with excutils.save_and_reraise_exception():
                for sg_id in sec_group:
                    super(NuagePlugin,
                          self)._delete_port_security_group_bindings(context,
                                                                 port_id)
        # Convert to list as a set might be passed here and
        # this has to be serialized
        port[ext_sg.SECURITYGROUPS] = (list(sec_group) if sec_group else [])

    def _delete_port_security_group_bindings(self, context, port_id):
        super(NuagePlugin,
              self)._delete_port_security_group_bindings(context, port_id)
        self.nuageclient.delete_port_security_group_bindings(port_id)

    @lockutils.synchronized('create_port', 'nuage-port', external=True)
    def create_port(self, context, port):
        session = context.session
        with session.begin(subtransactions=True):
            p = port['port']
            self._ensure_default_security_group_on_port(context, port)
            port = super(NuagePlugin, self).create_port(context, port)
            device_owner = port.get('device_owner', None)
            if device_owner not in constants.AUTO_CREATE_PORT_OWNERS:
                if 'fixed_ips' not in port or len(port['fixed_ips']) == 0:
                    return self._extend_port_dict_binding(context, port)
                subnet_id = port['fixed_ips'][0]['subnet_id']
                subnet_mapping = nuagedb.get_subnet_l2dom_by_id(session,
                                                                subnet_id)
                if subnet_mapping:
                    port_prefix = constants.NOVA_PORT_OWNER_PREF
                    if port['device_owner'].startswith(port_prefix):
                        #This request is coming from nova
                        try:
                            net_partition = nuagedb.get_net_partition_by_id(
                                session,
                                subnet_mapping['net_partition_id'])
                            self._create_update_port(
                                context,
                                port,
                                net_partition['name'])
                        except Exception:
                            with excutils.save_and_reraise_exception():
                                super(NuagePlugin, self).delete_port(
                                    context,
                                    port['id'])
                    if ext_sg.SECURITYGROUPS in p:
                        self._process_port_create_security_group(
                            context,
                            port,
                            p[ext_sg.SECURITYGROUPS])
        return self._extend_port_dict_binding(context, port)

    def update_port(self, context, id, port):
        p = port['port']
        sg_groups = None
        if p.get('device_owner', '').startswith(
            constants.NOVA_PORT_OWNER_PREF):
            session = context.session
            with session.begin(subtransactions=True):
                port = self._get_port(context, id)
                port.update(p)
                if not port.get('fixed_ips'):
                    return self._make_port_dict(port)
                subnet_id = port['fixed_ips'][0]['subnet_id']

                subnet_mapping = nuagedb.get_subnet_l2dom_by_id(session,
                                                                subnet_id)
                if not subnet_mapping:
                    msg = (_("Subnet %s not found on VSD") % subnet_id)
                    raise n_exc.BadRequest(resource='port', msg=msg)

                params = {
                    'neutron_port_id': id,
                }
                nuage_port = self.nuageclient.get_nuage_port_by_id(params)
                if not nuage_port or not nuage_port.get('nuage_vport_id'):
                    net_partition = nuagedb.get_net_partition_by_id(
                        session, subnet_mapping['net_partition_id'])
                    self._create_update_port(context, port,
                                             net_partition['name'])
                self._check_floatingip_update(context, port)
                updated_port = self._make_port_dict(port)
                sg_port = self._extend_port_dict_security_group(
                    updated_port,
                    port
                )
                sg_groups = sg_port[ext_sg.SECURITYGROUPS]
        else:
            updated_port = super(NuagePlugin, self).update_port(context, id,
                                                                port)
            if not updated_port.get('fixed_ips'):
                return updated_port
            subnet_id = updated_port['fixed_ips'][0]['subnet_id']
            subnet_mapping = nuagedb.get_subnet_l2dom_by_id(context.session,
                                                            subnet_id)
        if subnet_mapping:
            if sg_groups:
                self._delete_port_security_group_bindings(context,
                                                          updated_port['id'])
                self._process_port_create_security_group(context,
                                                         updated_port,
                                                         sg_groups)
            elif ext_sg.SECURITYGROUPS in p:
                self._delete_port_security_group_bindings(context,
                                                          updated_port['id'])
                self._process_port_create_security_group(
                    context,
                    updated_port,
                    p[ext_sg.SECURITYGROUPS]
                )
        return updated_port

    def _delete_nuage_vport(self, context, port, np_name):
        nuage_vif_id = None
        params = {
            'neutron_port_id': port['id'],
        }
        nuage_port = self.nuageclient.get_nuage_port_by_id(params)

        if constants.NOVA_PORT_OWNER_PREF in port['device_owner']:
            # This was a VM Port
            if nuage_port:
                nuage_vif_id = nuage_port['nuage_vif_id']
            filters = {'device_id': [port['device_id']]}
            ports = self.get_ports(context, filters)
            params = {
                'no_of_ports': len(ports),
                'netpart_name': np_name,
                'tenant': port['tenant_id'],
                'mac': port['mac_address'],
                'nuage_vif_id': nuage_vif_id,
                'id': port['device_id']
            }
            self.nuageclient.delete_vms(params)

    @lockutils.synchronized('delete-port', 'nuage-del', external=True)
    def delete_port(self, context, id, l3_port_check=True):
        if l3_port_check:
            self.prevent_l3_port_deletion(context, id)
        port = self._get_port(context, id)
        # This is required for to pass ut test_floatingip_port_delete
        self.disassociate_floatingips(context, id)
        if not port['fixed_ips']:
            return super(NuagePlugin, self).delete_port(context, id)

        sub_id = port['fixed_ips'][0]['subnet_id']

        subnet_mapping = nuagedb.get_subnet_l2dom_by_id(context.session,
                                                        sub_id)
        if not subnet_mapping:
            return super(NuagePlugin, self).delete_port(context, id)

        # Need to call this explicitly to delete vport to vporttag binding
        if ext_sg.SECURITYGROUPS in port:
            self.nuageclient.delete_port_security_group_bindings(id)

        netpart_id = subnet_mapping['net_partition_id']
        net_partition = nuagedb.get_net_partition_by_id(context.session,
                                                        netpart_id)
        self._delete_nuage_vport(context, port, net_partition['name'])
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

    def _check_router_subnet_for_tenant(self, context, tenant_id):
        # Search router and subnet tables.
        # If no entry left delete user and group from VSD
        filters = {'tenant_id': [tenant_id]}
        routers = self.get_routers(context, filters=filters)
        subnets = self.get_subnets(context, filters=filters)
        return bool(routers or subnets)

    def _extend_network_dict_provider_nuage(self, network, net_db,
                                            net_binding=None):
        binding = net_db.pnetbinding if net_db else net_binding
        if binding:
            network[pnet.NETWORK_TYPE] = binding.network_type
            network[pnet.PHYSICAL_NETWORK] = binding.physical_network
            network[pnet.SEGMENTATION_ID] = binding.vlan_id

    def _process_provider_create(self, context, attrs):
        network_type = attrs.get(pnet.NETWORK_TYPE)
        physical_network = attrs.get(pnet.PHYSICAL_NETWORK)
        segmentation_id = attrs.get(pnet.SEGMENTATION_ID)

        network_type_set = attributes.is_attr_set(network_type)
        physical_network_set = attributes.is_attr_set(physical_network)
        segmentation_id_set = attributes.is_attr_set(segmentation_id)

        if not (network_type_set or physical_network_set or
                segmentation_id_set):
            return None, None, None
        if not network_type_set:
            msg = _("provider:network_type required")
            raise n_exc.InvalidInput(error_message=msg)
        elif network_type != 'vlan':
            msg = (_("provider:network_type %s not supported in VSP")
                   % network_type)
            raise nuage_exc.NuageBadRequest(msg=msg)
        if not physical_network_set:
            msg = _("provider:physical_network required")
            raise nuage_exc.NuageBadRequest(msg=msg)
        if not segmentation_id_set:
            msg = _("provider:segmentation_id required")
            raise nuage_exc.NuageBadRequest(msg=msg)

        self.nuageclient.validate_provider_network(network_type,
                                                   physical_network,
                                                   segmentation_id)

        return network_type, physical_network, segmentation_id

    def create_network(self, context, network):
        binding = None
        (network_type, physical_network,
         vlan_id) = self._process_provider_create(context,
                                                  network['network'])
        with context.session.begin(subtransactions=True):
            self._ensure_default_security_group(
                context,
                network['network']['tenant_id']
            )
            net = super(NuagePlugin, self).create_network(context,
                                                          network)
            self._process_l3_create(context, net, network['network'])
            if network_type == 'vlan':
                binding = nuagedb.add_network_binding(context.session,
                                            net['id'],
                                            network_type,
                                            physical_network, vlan_id)
            self._extend_network_dict_provider_nuage(net, None, binding)
        return net

    def _validate_update_network(self, context, id, network):
        req_data = network['network']
        is_external_set = req_data.get(external_net.EXTERNAL)
        if not attributes.is_attr_set(is_external_set):
            return (None, None)
        neutron_net = self.get_network(context, id)
        if neutron_net.get(external_net.EXTERNAL) == is_external_set:
            return (None, None)
        subnet = self._validate_nuage_sharedresource(context, 'network', id)
        if subnet and not is_external_set:
            msg = _('External network with subnets can not be '
                    'changed to non-external network')
            raise nuage_exc.OperationNotSupported(msg=msg)
        if is_external_set:
            # Check if there are vm ports attached to this network
            # If there are, then updating the network is not allowed
            ports = self.get_ports(context, filters={'network_id': [id]})
            for p in ports:
                if p['device_owner'].startswith(
                        constants.NOVA_PORT_OWNER_PREF):
                    raise n_exc.NetworkInUse(net_id=id)
        return (is_external_set, subnet)

    def update_network(self, context, id, network):
        pnet._raise_if_updates_provider_attributes(network['network'])
        with context.session.begin(subtransactions=True):
            is_external_set, subnet = self._validate_update_network(context,
                                                                    id,
                                                                    network)
            net = super(NuagePlugin, self).update_network(context, id,
                                                          network)
            self._process_l3_update(context, net, network['network'])
            if subnet and is_external_set:
                subn = subnet[0]
                subnet_l2dom = nuagedb.get_subnet_l2dom_by_id(context.session,
                                                              subn['id'])
                if subnet_l2dom:
                    user_id = subnet_l2dom['nuage_user_id']
                    group_id = subnet_l2dom['nuage_group_id']
                    self.nuageclient.delete_subnet(subn['id'])
                    nuagedb.delete_subnetl2dom_mapping(context.session,
                                                       subnet_l2dom)
                    if not self._check_router_subnet_for_tenant(
                            context, subn['tenant_id']):
                        self.nuageclient.delete_user(user_id)
                        self.nuageclient.delete_group(group_id)

                    self._add_nuage_sharedresource(subnet[0],
                                                   id,
                                                   constants.SR_TYPE_FLOATING)
        return net

    def delete_network(self, context, id):
        with context.session.begin(subtransactions=True):
            self._process_l3_delete(context, id)
            filter = {'network_id': [id]}
            subnets = self.get_subnets(context, filters=filter)
            for subnet in subnets:
                self.delete_subnet(context, subnet['id'])
            super(NuagePlugin, self).delete_network(context, id)

    def _get_net_partition_for_subnet(self, context, subnet):
        ent = subnet.get('net_partition', None)
        if not ent:
            def_net_part = cfg.CONF.RESTPROXY.default_net_partition_name
            net_partition = nuagedb.get_net_partition_by_name(context.session,
                                                              def_net_part)
        else:
            net_partition = self._resource_finder(context, 'subnet',
                                                  'net_partition', subnet)
        if not net_partition:
            msg = _('Either net_partition is not provided with subnet OR '
                    'default net_partition is not created at the start')
            raise n_exc.BadRequest(resource='subnet', msg=msg)
        return net_partition

    @staticmethod
    def _validate_create_subnet(subnet):
        if (attributes.is_attr_set(subnet['gateway_ip'])
            and netaddr.IPAddress(subnet['gateway_ip'])
            not in netaddr.IPNetwork(subnet['cidr'])):
            msg = "Gateway IP outside of the subnet CIDR "
            raise nuage_exc.NuageBadRequest(msg=msg)

    def _validate_create_provider_subnet(self, context, net_id):
        net_filter = {'network_id': [net_id]}
        existing_subn = self.get_subnets(context, filters=net_filter)
        if len(existing_subn) > 0:
            msg = _('Only one subnet is allowed per '
                    'Provider network %s') % net_id
            raise nuage_exc.OperationNotSupported(msg=msg)

    def _delete_nuage_sharedresource(self, net_id):
        self.nuageclient.delete_nuage_sharedresource(net_id)

    def _validate_nuage_sharedresource(self, context, resource, net_id):
        filter = {'network_id': [net_id]}
        existing_subn = self.get_subnets(context, filters=filter)
        if len(existing_subn) > 1:
            msg = _('Only one subnet is allowed per '
                    'external network %s') % net_id
            raise nuage_exc.OperationNotSupported(msg=msg)
        return existing_subn

    def _add_nuage_sharedresource(self, subnet, net_id, type):
        net = netaddr.IPNetwork(subnet['cidr'])
        params = {
            'neutron_subnet': subnet,
            'net': net,
            'type': type,
            'net_id': net_id
        }
        self.nuageclient.create_nuage_sharedresource(params)

    def _create_nuage_sharedresource(self, context, subnet, type):
        subn = subnet['subnet']
        net_id = subn['network_id']
        self._validate_nuage_sharedresource(context, 'subnet', net_id)
        with context.session.begin(subtransactions=True):
            subn = super(NuagePlugin, self).create_subnet(context, subnet)
            self._add_nuage_sharedresource(subn, net_id, type)
            return subn

    def _create_port_gateway(self, context, subnet, gw_ip=None):
        if gw_ip is not None:
            fixed_ip = [{'ip_address': gw_ip, 'subnet_id': subnet['id']}]
        else:
            fixed_ip = [{'subnet_id': subnet['id']}]

        port_dict = dict(port=dict(
            name='',
            device_id='',
            admin_state_up=True,
            network_id=subnet['network_id'],
            tenant_id=subnet['tenant_id'],
            fixed_ips=fixed_ip,
            mac_address=attributes.ATTR_NOT_SPECIFIED,
            device_owner=os_constants.DEVICE_OWNER_DHCP))
        port = super(NuagePlugin, self).create_port(context, port_dict)
        return port

    def _delete_port_gateway(self, context, ports):
        for port in ports:
            super(NuagePlugin, self).delete_port(context, port['id'])

    def _create_nuage_subnet(self, context, neutron_subnet, netpart_id,
                             l2dom_template_id, pnet_binding):
        net = netaddr.IPNetwork(neutron_subnet['cidr'])
        # list(net)[-1] is the broadcast
        last_address = neutron_subnet['allocation_pools'][-1]['end']
        gw_port = self._create_port_gateway(context, neutron_subnet,
                                            last_address)
        params = {
            'netpart_id': netpart_id,
            'tenant_id': neutron_subnet['tenant_id'],
            'net': net,
            'l2dom_tmplt_id': l2dom_template_id,
            'pnet_binding': pnet_binding,
            'dhcp_ip': gw_port['fixed_ips'][0]['ip_address']
        }
        try:
            nuage_subnet = self.nuageclient.create_subnet(neutron_subnet,
                                                          params)
        except Exception:
            with excutils.save_and_reraise_exception():
                self._delete_port_gateway(context, [gw_port])
                super(NuagePlugin, self).delete_subnet(context,
                                                       neutron_subnet['id'])

        if nuage_subnet:
            l2dom_id = str(nuage_subnet['nuage_l2template_id'])
            user_id = nuage_subnet['nuage_userid']
            group_id = nuage_subnet['nuage_groupid']
            id = nuage_subnet['nuage_l2domain_id']
            with context.session.begin(subtransactions=True):
                nuagedb.add_subnetl2dom_mapping(context.session,
                                                neutron_subnet['id'],
                                                id,
                                                netpart_id,
                                                l2dom_id=l2dom_id,
                                                nuage_user_id=user_id,
                                                nuage_group_id=group_id)

    def create_subnet(self, context, subnet):
        subn = subnet['subnet']
        net_id = subn['network_id']

        if self._network_is_external(context, net_id):
            return self._create_nuage_sharedresource(
                context, subnet, constants.SR_TYPE_FLOATING)
        pnet_binding = nuagedb.get_network_binding(context.session, net_id)
        if pnet_binding:
            self._validate_create_provider_subnet(context, net_id)

        self._validate_create_subnet(subn)

        net_partition = self._get_net_partition_for_subnet(context, subn)
        neutron_subnet = super(NuagePlugin, self).create_subnet(context,
                                                                subnet)
        self._create_nuage_subnet(context, neutron_subnet, net_partition['id'],
                                  subn['nuage_subnet_template'],
                                  pnet_binding)
        return neutron_subnet

    def update_subnet(self, context, id, subnet):
        subn = copy.deepcopy(subnet['subnet'])
        subnet_l2dom = nuagedb.get_subnet_l2dom_by_id(context.session,
                                                      id)
        params = {
            'parent_id': subnet_l2dom['nuage_subnet_id'],
            'type': subnet_l2dom['nuage_l2dom_tmplt_id']
        }
        with context.session.begin(subtransactions=True):
            neutron_subnet = super(NuagePlugin, self).update_subnet(context,
                                                                    id, subnet)
            self.nuageclient.update_subnet(subn, params)
            return neutron_subnet

    def delete_subnet(self, context, id):
        subnet = self.get_subnet(context, id)
        if self._network_is_external(context, subnet['network_id']):
            super(NuagePlugin, self).delete_subnet(context, id)
            return self._delete_nuage_sharedresource(id)

        filters = {'fixed_ips': {'subnet_id': [id]}}
        ports = self.get_ports(context, filters)
        for port in ports:
            if port['device_owner'] != os_constants.DEVICE_OWNER_DHCP:
                raise n_exc.SubnetInUse(subnet_id=id)

        subnet_l2dom = nuagedb.get_subnet_l2dom_by_id(context.session, id)
        if subnet_l2dom:
            try:
                self.nuageclient.delete_subnet(id)
            except Exception:
                msg = (_('Unable to complete operation on subnet %s.'
                         'One or more ports have an IP allocation '
                         'from this subnet.') % id)
                raise n_exc.BadRequest(resource='subnet', msg=msg)
        super(NuagePlugin, self).delete_subnet(context, id)
        if subnet_l2dom and not self._check_router_subnet_for_tenant(
                context, subnet['tenant_id']):
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
            ent_rtr_mapping = nuagedb.get_ent_rtr_mapping_by_rtrid(session,
                                                                   router_id)
            nuage_zone = self.nuageclient.get_zone_by_routerid(router_id)
            if not nuage_zone or not ent_rtr_mapping:
                super(NuagePlugin,
                      self).remove_router_interface(context,
                                                    router_id,
                                                    interface_info)
                msg = (_("Router %s does not hold default zone OR "
                         "domain in VSD. Router-IF add failed")
                       % router_id)
                raise n_exc.BadRequest(resource='router', msg=msg)

            subnet_l2dom = nuagedb.get_subnet_l2dom_by_id(session,
                                                          subnet_id)
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
            if self.nuageclient.vms_on_l2domain(nuage_subnet_id):
                super(NuagePlugin,
                      self).remove_router_interface(context,
                                                    router_id,
                                                    interface_info)
                msg = (_("Subnet %s has one or more active VMs "
                       "Router-IF add not permitted") % subnet_id)
                raise n_exc.BadRequest(resource='subnet', msg=msg)
            self.nuageclient.delete_subnet(subnet_id)
            net = netaddr.IPNetwork(subn['cidr'])
            pnet_binding = nuagedb.get_network_binding(context.session,
                                                       subn['network_id'])
            params = {
                'net': net,
                'zone_id': nuage_zone['nuage_zone_id'],
                'neutron_subnet_id': subnet_id,
                'pnet_binding': pnet_binding
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
            if not subnet_l2dom:
                return super(NuagePlugin,
                             self).remove_router_interface(context,
                                                           router_id,
                                                           interface_info)
            nuage_subn_id = subnet_l2dom['nuage_subnet_id']
            if self.nuageclient.vms_on_subnet(nuage_subn_id):
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
            netpart_id = ent_rtr_mapping['net_partition_id']
            pnet_binding = nuagedb.get_network_binding(
                context.session, neutron_subnet['network_id'])
            params = {
                'tenant_id': neutron_subnet['tenant_id'],
                'net': net,
                'netpart_id': netpart_id,
                'nuage_subn_id': nuage_subn_id,
                'neutron_subnet': neutron_subnet,
                'pnet_binding': pnet_binding
            }
            nuage_subnet = self.nuageclient.remove_router_interface(params)
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

    def _get_net_partition_for_router(self, context, rtr):
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
            with context.session.begin(subtransactions=True):
                nuagedb.add_entrouter_mapping(context.session,
                                              net_partition['id'],
                                              neutron_router['id'],
                                              nuage_router['nuage_domain_id'])

        return neutron_router

    def _validate_nuage_staticroutes(self, old_routes, added, removed):
        cidrs = []
        for old in old_routes:
            if old not in removed:
                ip = netaddr.IPNetwork(old['destination'])
                cidrs.append(ip)
        for route in added:
            ip = netaddr.IPNetwork(route['destination'])
            matching = netaddr.all_matching_cidrs(ip.ip, cidrs)
            if matching:
                msg = _('for same subnet, multiple static routes not allowed')
                raise n_exc.BadRequest(resource='router', msg=msg)
            cidrs.append(ip)

    def update_router(self, context, id, router):
        r = router['router']
        with context.session.begin(subtransactions=True):
            if 'routes' in r:
                old_routes = self._get_extra_routes_by_router_id(context,
                                                                 id)
                added, removed = utils.diff_list_of_dict(old_routes,
                                                         r['routes'])
                self._validate_nuage_staticroutes(old_routes, added, removed)

                ent_rtr_mapping = nuagedb.get_ent_rtr_mapping_by_rtrid(
                    context.session, id)
                if not ent_rtr_mapping:
                    msg = (_("Router %s does not hold net-partition "
                             "assoc on VSD. extra-route failed") % id)
                    raise n_exc.BadRequest(resource='router', msg=msg)
                # Let it do internal checks first and verify it.
                router_updated = super(NuagePlugin,
                                       self).update_router(context,
                                                           id,
                                                           router)
                for route in removed:
                    destaddr = route['destination']
                    cidr = destaddr.split('/')
                    params = {
                        "address": cidr[0],
                        "nexthop": route['nexthop'],
                        "nuage_domain_id": ent_rtr_mapping['nuage_router_id']
                    }
                    self.nuageclient.delete_nuage_staticroute(params)

                for route in added:
                    params = {
                        'parent_id': ent_rtr_mapping['nuage_router_id'],
                        'net': netaddr.IPNetwork(route['destination']),
                        'nexthop': route['nexthop']
                    }
                    self.nuageclient.create_nuage_staticroute(
                        params)
            else:
                router_updated = super(NuagePlugin, self).update_router(
                    context, id, router)
        return router_updated

    def delete_router(self, context, id):
        neutron_router = self.get_router(context, id)
        session = context.session
        ent_rtr_mapping = nuagedb.get_ent_rtr_mapping_by_rtrid(session,
                                                               id)
        if ent_rtr_mapping:
            filters = {
                'device_id': [id],
                'device_owner': [os_constants.DEVICE_OWNER_ROUTER_INTF]
            }
            ports = self.get_ports(context, filters)
            if ports:
                raise l3.RouterInUse(router_id=id)
            nuage_domain_id = ent_rtr_mapping['nuage_router_id']
            self.nuageclient.delete_router(nuage_domain_id)

        super(NuagePlugin, self).delete_router(context, id)

        if not self._check_router_subnet_for_tenant(
                context, neutron_router['tenant_id']):
            user_id, group_id = self.nuageclient.get_usergroup(
                neutron_router['tenant_id'],
                ent_rtr_mapping['net_partition_id'])
            self.nuageclient.delete_user(user_id)
            self.nuageclient.delete_group(group_id)

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
        def_netpart = self.nuageclient.get_def_netpartition_data(
            default_net_part)
        session = db.get_session()
        if def_netpart:
            net_partition = nuagedb.get_net_partition_by_name(
                session, default_net_part)
            with session.begin(subtransactions=True):
                if net_partition:
                    nuagedb.delete_net_partition(session, net_partition)
                net_part = nuagedb.add_net_partition(session,
                                                     def_netpart['np_id'],
                                                     def_netpart['l3dom_tid'],
                                                     def_netpart['l2dom_tid'],
                                                     default_net_part)
                return self._make_net_partition_dict(net_part)
        else:
            return self._create_net_partition(session, default_net_part)

    def create_net_partition(self, context, net_partition):
        ent = net_partition['net_partition']
        session = context.session
        return self._create_net_partition(session, ent["name"])

    def delete_net_partition(self, context, id):
        ent_rtr_mapping = nuagedb.get_ent_rtr_mapping_by_entid(context.session,
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

    def _check_floatingip_update(self, context, port):
        filter = {'fixed_port_id': [port['id']]}
        local_fip = self.get_floatingips(context,
                                         filters=filter)
        if local_fip:
            fip = local_fip[0]
            self._create_update_floatingip(context,
                                           fip, port['id'])

    def _create_update_floatingip(self, context,
                                  neutron_fip, port_id):
        rtr_id = neutron_fip['router_id']
        net_id = neutron_fip['floating_network_id']
        subn = nuagedb.get_ipalloc_for_fip(context.session,
                                           net_id,
                                           neutron_fip['floating_ip_address'])

        fip_pool = self.nuageclient.get_nuage_fip_pool_by_id(subn['subnet_id'])
        if not fip_pool:
            msg = _('sharedresource %s not found on VSD') % subn['subnet_id']
            raise n_exc.BadRequest(resource='floatingip',
                                   msg=msg)

        ent_rtr_mapping = nuagedb.get_ent_rtr_mapping_by_rtrid(context.session,
                                                               rtr_id)
        if not ent_rtr_mapping:
            msg = _('router %s is not associated with '
                    'any net-partition') % rtr_id
            raise n_exc.BadRequest(resource='floatingip',
                                   msg=msg)

        params = {
            'router_id': ent_rtr_mapping['nuage_router_id'],
            'fip_id': neutron_fip['id'],
            'neutron_fip': neutron_fip
        }

        fip = self.nuageclient.get_nuage_fip_by_id(params)
        if not fip:
            params = {
                'nuage_rtr_id': ent_rtr_mapping['nuage_router_id'],
                'nuage_fippool_id': fip_pool['nuage_fip_pool_id'],
                'neutron_fip_ip': neutron_fip['floating_ip_address'],
                'neutron_fip_id': neutron_fip['id']
            }
            nuage_fip_id = self.nuageclient.create_nuage_floatingip(params)
        else:
            nuage_fip_id = fip['nuage_fip_id']

        # Update VM if required
        params = {
            'neutron_port_id': port_id,
            'nuage_fip_id': nuage_fip_id,
            'nuage_rtr_id': ent_rtr_mapping['nuage_router_id']
        }
        nuage_port = self.nuageclient.get_nuage_port_by_id(params)
        if nuage_port:
            if (nuage_port['nuage_domain_id']) != (
                    ent_rtr_mapping['nuage_router_id']):
                msg = _('Floating IP can not be associated to VM in '
                        'different router context')
                raise nuage_exc.OperationNotSupported(msg=msg)

            params = {
                'nuage_vport_id': nuage_port['nuage_vport_id'],
                'nuage_fip_id': nuage_fip_id
            }
            self.nuageclient.update_nuage_vm_vport(params)

    def create_floatingip(self, context, floatingip):
        fip = floatingip['floatingip']
        with context.session.begin(subtransactions=True):
            neutron_fip = super(NuagePlugin, self).create_floatingip(
                context, floatingip)
            if not neutron_fip['router_id']:
                return neutron_fip
            try:
                self._create_update_floatingip(context, neutron_fip,
                                               fip['port_id'])
            except (nuage_exc.OperationNotSupported, n_exc.BadRequest):
                with excutils.save_and_reraise_exception():
                    super(NuagePlugin, self).delete_floatingip(
                        context, neutron_fip['id'])
            return neutron_fip

    def disassociate_floatingips(self, context, port_id, do_notify=True):
        router_ids = super(NuagePlugin, self).disassociate_floatingips(
            context, port_id, do_notify=do_notify)

        params = {
            'neutron_port_id': port_id,
        }
        nuage_port = self.nuageclient.get_nuage_port_by_id(params)
        if nuage_port:
            params = {
                'nuage_vport_id': nuage_port['nuage_vport_id'],
                'nuage_fip_id': None
            }
            self.nuageclient.update_nuage_vm_vport(params)

        return router_ids

    def update_floatingip(self, context, id, floatingip):
        fip = floatingip['floatingip']
        orig_fip = self._get_floatingip(context, id)
        port_id = orig_fip['fixed_port_id']
        router_ids = []
        with context.session.begin(subtransactions=True):
            neutron_fip = super(NuagePlugin, self).update_floatingip(
                context, id, floatingip)
            if fip['port_id'] is not None:
                if not neutron_fip['router_id']:
                    ret_msg = 'floating-ip is not associated yet'
                    raise n_exc.BadRequest(resource='floatingip',
                                           msg=ret_msg)

                try:
                    self._create_update_floatingip(context,
                                                   neutron_fip,
                                                   fip['port_id'])
                except nuage_exc.OperationNotSupported:
                    with excutils.save_and_reraise_exception():
                        router_ids = super(
                            NuagePlugin, self).disassociate_floatingips(
                                context, fip['port_id'], do_notify=False)
                except n_exc.BadRequest:
                    with excutils.save_and_reraise_exception():
                        super(NuagePlugin, self).delete_floatingip(context,
                                                                   id)
            else:
                params = {
                    'neutron_port_id': port_id,
                }
                nuage_port = self.nuageclient.get_nuage_port_by_id(params)
                if nuage_port:
                    params = {
                        'nuage_vport_id': nuage_port['nuage_vport_id'],
                        'nuage_fip_id': None
                    }
                    self.nuageclient.update_nuage_vm_vport(params)

        # now that we've left db transaction, we are safe to notify
        self.notify_routers_updated(context, router_ids)

        return neutron_fip

    def delete_floatingip(self, context, fip_id):
        fip = self._get_floatingip(context, fip_id)
        port_id = fip['fixed_port_id']
        with context.session.begin(subtransactions=True):
            if port_id:
                params = {
                    'neutron_port_id': port_id,
                }
                nuage_port = self.nuageclient.get_nuage_port_by_id(params)
                if (nuage_port and
                    nuage_port['nuage_vport_id'] is not None):
                    params = {
                        'nuage_vport_id': nuage_port['nuage_vport_id'],
                        'nuage_fip_id': None
                    }
                    self.nuageclient.update_nuage_vm_vport(params)
                    LOG.debug("Floating-ip %(fip)s is disassociated from "
                              "vport %(vport)s",
                              {'fip': fip_id,
                               'vport': nuage_port['nuage_vport_id']})

                router_id = fip['router_id']
            else:
                router_id = fip['last_known_router_id']

            if router_id:
                ent_rtr_mapping = nuagedb.get_ent_rtr_mapping_by_rtrid(
                    context.session,
                    router_id)
                if not ent_rtr_mapping:
                    msg = _('router %s is not associated with '
                            'any net-partition') % router_id
                    raise n_exc.BadRequest(resource='floatingip',
                                       msg=msg)
                params = {
                    'router_id': ent_rtr_mapping['nuage_router_id'],
                    'fip_id': fip_id
                }
                fip = self.nuageclient.get_nuage_fip_by_id(params)
                if fip:
                    self.nuageclient.delete_nuage_floatingip(
                        fip['nuage_fip_id'])
                    LOG.debug('Floating-ip %s deleted from VSD', fip_id)

            super(NuagePlugin, self).delete_floatingip(context, fip_id)

    def delete_security_group(self, context, id):
        filters = {'security_group_id': [id]}
        ports = self._get_port_security_group_bindings(context,
                                                       filters)
        if ports:
            raise ext_sg.SecurityGroupInUse(id=id)
        sg_rules = self.get_security_group_rules(context,
                                                 {'security_group_id': [id]})

        if sg_rules:
            self.nuageclient.delete_nuage_sgrule(sg_rules)
        self.nuageclient.delete_nuage_secgroup(id)

        super(NuagePlugin, self).delete_security_group(context, id)

    def create_security_group_rule(self, context, security_group_rule):
        sg_rule = security_group_rule['security_group_rule']
        self.nuageclient.validate_nuage_sg_rule_definition(sg_rule)
        sg_id = sg_rule['security_group_id']

        local_sg_rule = super(NuagePlugin,
                              self).create_security_group_rule(
                                        context, security_group_rule)

        try:
            nuage_vptag = self.nuageclient.get_sg_vptag_mapping(sg_id)
            if nuage_vptag:
                sg_params = {
                    'sg_id': sg_id,
                    'neutron_sg_rule': local_sg_rule,
                    'vptag': nuage_vptag
                }
                self.nuageclient.create_nuage_sgrule(sg_params)
        except Exception:
            with excutils.save_and_reraise_exception():
                super(NuagePlugin,
                      self).delete_security_group_rule(context,
                                                   local_sg_rule['id'])

        return local_sg_rule

    def delete_security_group_rule(self, context, id):
        local_sg_rule = self.get_security_group_rule(context, id)
        super(NuagePlugin, self).delete_security_group_rule(context, id)
        self.nuageclient.delete_nuage_sgrule([local_sg_rule])
