# Copyright 2013 VMware, Inc.

# All Rights Reserved
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

from oslo.config import cfg

from neutron.api.v2 import attributes as attr
from neutron.common import constants as const
from neutron.common import exceptions as n_exc
from neutron.db import db_base_plugin_v2
from neutron.db import l3_db
from neutron.extensions import external_net
from neutron.openstack.common import excutils
from neutron.openstack.common import log as logging
from neutron.plugins.vmware.common import exceptions as p_exc
from neutron.plugins.vmware.dhcp_meta import constants as d_const
from neutron.plugins.vmware.nsxlib import lsn as lsn_api

LOG = logging.getLogger(__name__)


dhcp_opts = [
    cfg.ListOpt('extra_domain_name_servers',
                deprecated_group='NVP_DHCP',
                default=[],
                help=_('Comma separated list of additional '
                       'domain name servers')),
    cfg.StrOpt('domain_name',
               deprecated_group='NVP_DHCP',
               default='openstacklocal',
               help=_('Domain to use for building the hostnames')),
    cfg.IntOpt('default_lease_time', default=43200,
               deprecated_group='NVP_DHCP',
               help=_("Default DHCP lease time")),
]


metadata_opts = [
    cfg.StrOpt('metadata_server_address',
               deprecated_group='NVP_METADATA',
               default='127.0.0.1',
               help=_("IP address used by Metadata server.")),
    cfg.IntOpt('metadata_server_port',
               deprecated_group='NVP_METADATA',
               default=8775,
               help=_("TCP Port used by Metadata server.")),
    cfg.StrOpt('metadata_shared_secret',
               deprecated_group='NVP_METADATA',
               default='',
               help=_('Shared secret to sign instance-id request'),
               secret=True)
]


def register_dhcp_opts(config):
    config.CONF.register_opts(dhcp_opts, group="NSX_DHCP")


def register_metadata_opts(config):
    config.CONF.register_opts(metadata_opts, group="NSX_METADATA")


class DhcpAgentNotifyAPI(object):

    def __init__(self, plugin, lsn_manager):
        self.plugin = plugin
        self.lsn_manager = lsn_manager
        self._handle_subnet_dhcp_access = {'create': self._subnet_create,
                                           'update': self._subnet_update,
                                           'delete': self._subnet_delete}

    def notify(self, context, data, methodname):
        [resource, action, _e] = methodname.split('.')
        if resource == 'subnet':
            self._handle_subnet_dhcp_access[action](context, data['subnet'])
        elif resource == 'port' and action == 'update':
            self._port_update(context, data['port'])

    def _port_update(self, context, port):
        # With no fixed IP's there's nothing that can be updated
        if not port["fixed_ips"]:
            return
        network_id = port['network_id']
        subnet_id = port["fixed_ips"][0]['subnet_id']
        filters = {'network_id': [network_id]}
        # Because NSX does not support updating a single host entry we
        # got to build the whole list from scratch and update in bulk
        ports = self.plugin.get_ports(context, filters)
        if not ports:
            return
        dhcp_conf = [
            {'mac_address': p['mac_address'],
             'ip_address': p["fixed_ips"][0]['ip_address']}
            for p in ports if is_user_port(p)
        ]
        meta_conf = [
            {'instance_id': p['device_id'],
             'ip_address': p["fixed_ips"][0]['ip_address']}
            for p in ports if is_user_port(p, check_dev_id=True)
        ]
        self.lsn_manager.lsn_port_update(
            context, network_id, subnet_id, dhcp=dhcp_conf, meta=meta_conf)

    def _subnet_create(self, context, subnet, clean_on_err=True):
        if subnet['enable_dhcp']:
            network_id = subnet['network_id']
            # Create port for DHCP service
            dhcp_port = {
                "name": "",
                "admin_state_up": True,
                "device_id": "",
                "device_owner": const.DEVICE_OWNER_DHCP,
                "network_id": network_id,
                "tenant_id": subnet["tenant_id"],
                "mac_address": attr.ATTR_NOT_SPECIFIED,
                "fixed_ips": [{"subnet_id": subnet['id']}]
            }
            try:
                # This will end up calling handle_port_dhcp_access
                # down below as well as handle_port_metadata_access
                self.plugin.create_port(context, {'port': dhcp_port})
            except p_exc.PortConfigurationError as e:
                err_msg = (_("Error while creating subnet %(cidr)s for "
                             "network %(network)s. Please, contact "
                             "administrator") %
                           {"cidr": subnet["cidr"],
                            "network": network_id})
                LOG.error(err_msg)
                db_base_plugin_v2.NeutronDbPluginV2.delete_port(
                    self.plugin, context, e.port_id)
                if clean_on_err:
                    self.plugin.delete_subnet(context, subnet['id'])
                raise n_exc.Conflict()

    def _subnet_update(self, context, subnet):
        network_id = subnet['network_id']
        try:
            lsn_id, lsn_port_id = self.lsn_manager.lsn_port_get(
                context, network_id, subnet['id'])
            self.lsn_manager.lsn_port_dhcp_configure(
                context, lsn_id, lsn_port_id, subnet)
        except p_exc.LsnPortNotFound:
            # It's possible that the subnet was created with dhcp off;
            # check if the subnet was uplinked onto a router, and if so
            # remove the patch attachment between the metadata port and
            # the lsn port, in favor on the one we'll be creating during
            # _subnet_create
            self.lsn_manager.lsn_port_dispose(
                context, network_id, d_const.METADATA_MAC)
            # also, check that a dhcp port exists first and provision it
            # accordingly
            filters = dict(network_id=[network_id],
                           device_owner=[const.DEVICE_OWNER_DHCP])
            ports = self.plugin.get_ports(context, filters=filters)
            if ports:
                handle_port_dhcp_access(
                    self.plugin, context, ports[0], 'create_port')
            else:
                self._subnet_create(context, subnet, clean_on_err=False)

    def _subnet_delete(self, context, subnet):
        # FIXME(armando-migliaccio): it looks like that a subnet filter
        # is ineffective; so filter by network for now.
        network_id = subnet['network_id']
        filters = dict(network_id=[network_id],
                       device_owner=[const.DEVICE_OWNER_DHCP])
        # FIXME(armando-migliaccio): this may be race-y
        ports = self.plugin.get_ports(context, filters=filters)
        if ports:
            # This will end up calling handle_port_dhcp_access
            # down below as well as handle_port_metadata_access
            self.plugin.delete_port(context, ports[0]['id'])


def is_user_port(p, check_dev_id=False):
    usable = p['fixed_ips'] and p['device_owner'] not in d_const.SPECIAL_OWNERS
    return usable if not check_dev_id else usable and p['device_id']


def check_services_requirements(cluster):
    ver = cluster.api_client.get_version()
    # It sounds like 4.1 is the first one where DHCP in NSX
    # will have the experimental feature
    if ver.major >= 4 and ver.minor >= 1:
        cluster_id = cfg.CONF.default_service_cluster_uuid
        if not lsn_api.service_cluster_exists(cluster, cluster_id):
            raise p_exc.ServiceClusterUnavailable(cluster_id=cluster_id)
    else:
        raise p_exc.InvalidVersion(version=ver)


def handle_network_dhcp_access(plugin, context, network, action):
    LOG.info(_("Performing DHCP %(action)s for resource: %(resource)s")
             % {"action": action, "resource": network})
    if action == 'create_network':
        network_id = network['id']
        if network.get(external_net.EXTERNAL):
            LOG.info(_("Network %s is external: no LSN to create"), network_id)
            return
        plugin.lsn_manager.lsn_create(context, network_id)
    elif action == 'delete_network':
        # NOTE(armando-migliaccio): on delete_network, network
        # is just the network id
        network_id = network
        plugin.lsn_manager.lsn_delete_by_network(context, network_id)
    LOG.info(_("Logical Services Node for network "
               "%s configured successfully"), network_id)


def handle_port_dhcp_access(plugin, context, port, action):
    LOG.info(_("Performing DHCP %(action)s for resource: %(resource)s")
             % {"action": action, "resource": port})
    if port["device_owner"] == const.DEVICE_OWNER_DHCP:
        network_id = port["network_id"]
        if action == "create_port":
            # at this point the port must have a subnet and a fixed ip
            subnet_id = port["fixed_ips"][0]['subnet_id']
            subnet = plugin.get_subnet(context, subnet_id)
            subnet_data = {
                "mac_address": port["mac_address"],
                "ip_address": subnet['cidr'],
                "subnet_id": subnet['id']
            }
            try:
                plugin.lsn_manager.lsn_port_dhcp_setup(
                    context, network_id, port['id'], subnet_data, subnet)
            except p_exc.PortConfigurationError:
                err_msg = (_("Error while configuring DHCP for "
                             "port %s"), port['id'])
                LOG.error(err_msg)
                raise n_exc.NeutronException()
        elif action == "delete_port":
            plugin.lsn_manager.lsn_port_dispose(context, network_id,
                                                port['mac_address'])
    elif port["device_owner"] != const.DEVICE_OWNER_DHCP:
        if port.get("fixed_ips"):
            # do something only if there are IP's and dhcp is enabled
            subnet_id = port["fixed_ips"][0]['subnet_id']
            if not plugin.get_subnet(context, subnet_id)['enable_dhcp']:
                LOG.info(_("DHCP is disabled for subnet %s: nothing "
                           "to do"), subnet_id)
                return
            host_data = {
                "mac_address": port["mac_address"],
                "ip_address": port["fixed_ips"][0]['ip_address']
            }
            network_id = port["network_id"]
            if action == "create_port":
                handler = plugin.lsn_manager.lsn_port_dhcp_host_add
            elif action == "delete_port":
                handler = plugin.lsn_manager.lsn_port_dhcp_host_remove
            try:
                handler(context, network_id, subnet_id, host_data)
            except p_exc.PortConfigurationError:
                with excutils.save_and_reraise_exception():
                    if action == 'create_port':
                        db_base_plugin_v2.NeutronDbPluginV2.delete_port(
                            plugin, context, port['id'])
    LOG.info(_("DHCP for port %s configured successfully"), port['id'])


def handle_port_metadata_access(plugin, context, port, is_delete=False):
    if is_user_port(port, check_dev_id=True):
        network_id = port["network_id"]
        network = plugin.get_network(context, network_id)
        if network[external_net.EXTERNAL]:
            LOG.info(_("Network %s is external: nothing to do"), network_id)
            return
        subnet_id = port["fixed_ips"][0]['subnet_id']
        host_data = {
            "instance_id": port["device_id"],
            "tenant_id": port["tenant_id"],
            "ip_address": port["fixed_ips"][0]['ip_address']
        }
        LOG.info(_("Configuring metadata entry for port %s"), port)
        if not is_delete:
            handler = plugin.lsn_manager.lsn_port_meta_host_add
        else:
            handler = plugin.lsn_manager.lsn_port_meta_host_remove
        try:
            handler(context, network_id, subnet_id, host_data)
        except p_exc.PortConfigurationError:
            with excutils.save_and_reraise_exception():
                if not is_delete:
                    db_base_plugin_v2.NeutronDbPluginV2.delete_port(
                        plugin, context, port['id'])
        LOG.info(_("Metadata for port %s configured successfully"), port['id'])


def handle_router_metadata_access(plugin, context, router_id, interface=None):
    LOG.info(_("Handle metadata access via router: %(r)s and "
               "interface %(i)s") % {'r': router_id, 'i': interface})
    if interface:
        try:
            plugin.get_port(context, interface['port_id'])
            is_enabled = True
        except n_exc.NotFound:
            is_enabled = False
        subnet_id = interface['subnet_id']
        try:
            plugin.lsn_manager.lsn_metadata_configure(
                context, subnet_id, is_enabled)
        except p_exc.NsxPluginException:
            with excutils.save_and_reraise_exception():
                if is_enabled:
                    l3_db.L3_NAT_db_mixin.remove_router_interface(
                        plugin, context, router_id, interface)
    LOG.info(_("Metadata for router %s handled successfully"), router_id)
