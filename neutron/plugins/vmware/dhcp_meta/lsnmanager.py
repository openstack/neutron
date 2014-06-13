# Copyright 2014 VMware, Inc.
#
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

from neutron.common import exceptions as n_exc
from neutron.openstack.common.db import exception as db_exc
from neutron.openstack.common import excutils
from neutron.openstack.common import log as logging
from neutron.plugins.vmware.api_client import exception as api_exc
from neutron.plugins.vmware.common import exceptions as p_exc
from neutron.plugins.vmware.common import nsx_utils
from neutron.plugins.vmware.dbexts import lsn_db
from neutron.plugins.vmware.dhcp_meta import constants as const
from neutron.plugins.vmware.nsxlib import lsn as lsn_api
from neutron.plugins.vmware.nsxlib import switch as switch_api

LOG = logging.getLogger(__name__)

META_CONF = 'metadata-proxy'
DHCP_CONF = 'dhcp'


lsn_opts = [
    cfg.BoolOpt('sync_on_missing_data', default=False,
                help=_('Pull LSN information from NSX in case it is missing '
                       'from the local data store. This is useful to rebuild '
                       'the local store in case of server recovery.'))
]


def register_lsn_opts(config):
    config.CONF.register_opts(lsn_opts, "NSX_LSN")


class LsnManager(object):
    """Manage LSN entities associated with networks."""

    def __init__(self, plugin):
        self.plugin = plugin

    @property
    def cluster(self):
        return self.plugin.cluster

    def lsn_exists(self, context, network_id):
        """Return True if a Logical Service Node exists for the network."""
        return self.lsn_get(
            context, network_id, raise_on_err=False) is not None

    def lsn_get(self, context, network_id, raise_on_err=True):
        """Retrieve the LSN id associated to the network."""
        try:
            return lsn_api.lsn_for_network_get(self.cluster, network_id)
        except (n_exc.NotFound, api_exc.NsxApiException):
            logger = raise_on_err and LOG.error or LOG.warn
            logger(_('Unable to find Logical Service Node for '
                     'network %s'), network_id)
            if raise_on_err:
                raise p_exc.LsnNotFound(entity='network',
                                        entity_id=network_id)

    def lsn_create(self, context, network_id):
        """Create a LSN associated to the network."""
        try:
            return lsn_api.lsn_for_network_create(self.cluster, network_id)
        except api_exc.NsxApiException:
            err_msg = _('Unable to create LSN for network %s') % network_id
            raise p_exc.NsxPluginException(err_msg=err_msg)

    def lsn_delete(self, context, lsn_id):
        """Delete a LSN given its id."""
        try:
            lsn_api.lsn_delete(self.cluster, lsn_id)
        except (n_exc.NotFound, api_exc.NsxApiException):
            LOG.warn(_('Unable to delete Logical Service Node %s'), lsn_id)

    def lsn_delete_by_network(self, context, network_id):
        """Delete a LSN associated to the network."""
        lsn_id = self.lsn_get(context, network_id, raise_on_err=False)
        if lsn_id:
            self.lsn_delete(context, lsn_id)

    def lsn_port_get(self, context, network_id, subnet_id, raise_on_err=True):
        """Retrieve LSN and LSN port for the network and the subnet."""
        lsn_id = self.lsn_get(context, network_id, raise_on_err=raise_on_err)
        if lsn_id:
            try:
                lsn_port_id = lsn_api.lsn_port_by_subnet_get(
                    self.cluster, lsn_id, subnet_id)
            except (n_exc.NotFound, api_exc.NsxApiException):
                logger = raise_on_err and LOG.error or LOG.warn
                logger(_('Unable to find Logical Service Node Port for '
                         'LSN %(lsn_id)s and subnet %(subnet_id)s')
                       % {'lsn_id': lsn_id, 'subnet_id': subnet_id})
                if raise_on_err:
                    raise p_exc.LsnPortNotFound(lsn_id=lsn_id,
                                                entity='subnet',
                                                entity_id=subnet_id)
                return (lsn_id, None)
            else:
                return (lsn_id, lsn_port_id)
        else:
            return (None, None)

    def lsn_port_get_by_mac(self, context, network_id, mac, raise_on_err=True):
        """Retrieve LSN and LSN port given network and mac address."""
        lsn_id = self.lsn_get(context, network_id, raise_on_err=raise_on_err)
        if lsn_id:
            try:
                lsn_port_id = lsn_api.lsn_port_by_mac_get(
                    self.cluster, lsn_id, mac)
            except (n_exc.NotFound, api_exc.NsxApiException):
                logger = raise_on_err and LOG.error or LOG.warn
                logger(_('Unable to find Logical Service Node Port for '
                         'LSN %(lsn_id)s and mac address %(mac)s')
                       % {'lsn_id': lsn_id, 'mac': mac})
                if raise_on_err:
                    raise p_exc.LsnPortNotFound(lsn_id=lsn_id,
                                                entity='MAC',
                                                entity_id=mac)
                return (lsn_id, None)
            else:
                return (lsn_id, lsn_port_id)
        else:
            return (None, None)

    def lsn_port_create(self, context, lsn_id, subnet_info):
        """Create and return LSN port for associated subnet."""
        try:
            return lsn_api.lsn_port_create(self.cluster, lsn_id, subnet_info)
        except n_exc.NotFound:
            raise p_exc.LsnNotFound(entity='', entity_id=lsn_id)
        except api_exc.NsxApiException:
            err_msg = _('Unable to create port for LSN  %s') % lsn_id
            raise p_exc.NsxPluginException(err_msg=err_msg)

    def lsn_port_delete(self, context, lsn_id, lsn_port_id):
        """Delete a LSN port from the Logical Service Node."""
        try:
            lsn_api.lsn_port_delete(self.cluster, lsn_id, lsn_port_id)
        except (n_exc.NotFound, api_exc.NsxApiException):
            LOG.warn(_('Unable to delete LSN Port %s'), lsn_port_id)

    def lsn_port_dispose(self, context, network_id, mac_address):
        """Delete a LSN port given the network and the mac address."""
        lsn_id, lsn_port_id = self.lsn_port_get_by_mac(
            context, network_id, mac_address, raise_on_err=False)
        if lsn_port_id:
            self.lsn_port_delete(context, lsn_id, lsn_port_id)
            if mac_address == const.METADATA_MAC:
                try:
                    lswitch_port_id = switch_api.get_port_by_neutron_tag(
                        self.cluster, network_id,
                        const.METADATA_PORT_ID)['uuid']
                    switch_api.delete_port(
                        self.cluster, network_id, lswitch_port_id)
                except (n_exc.PortNotFoundOnNetwork,
                        api_exc.NsxApiException):
                    LOG.warn(_("Metadata port not found while attempting "
                               "to delete it from network %s"), network_id)
        else:
            LOG.warn(_("Unable to find Logical Services Node "
                       "Port with MAC %s"), mac_address)

    def lsn_port_dhcp_setup(
        self, context, network_id, port_id, port_data, subnet_config=None):
        """Connect network to LSN via specified port and port_data."""
        try:
            lsn_id = None
            switch_id = nsx_utils.get_nsx_switch_ids(
                context.session, self.cluster, network_id)[0]
            lswitch_port_id = switch_api.get_port_by_neutron_tag(
                self.cluster, switch_id, port_id)['uuid']
            lsn_id = self.lsn_get(context, network_id)
            lsn_port_id = self.lsn_port_create(context, lsn_id, port_data)
        except (n_exc.NotFound, p_exc.NsxPluginException):
            raise p_exc.PortConfigurationError(
                net_id=network_id, lsn_id=lsn_id, port_id=port_id)
        else:
            try:
                lsn_api.lsn_port_plug_network(
                    self.cluster, lsn_id, lsn_port_id, lswitch_port_id)
            except p_exc.LsnConfigurationConflict:
                self.lsn_port_delete(context, lsn_id, lsn_port_id)
                raise p_exc.PortConfigurationError(
                    net_id=network_id, lsn_id=lsn_id, port_id=port_id)
            if subnet_config:
                self.lsn_port_dhcp_configure(
                    context, lsn_id, lsn_port_id, subnet_config)
            else:
                return (lsn_id, lsn_port_id)

    def lsn_port_metadata_setup(self, context, lsn_id, subnet):
        """Connect subnet to specified LSN."""
        data = {
            "mac_address": const.METADATA_MAC,
            "ip_address": subnet['cidr'],
            "subnet_id": subnet['id']
        }
        network_id = subnet['network_id']
        tenant_id = subnet['tenant_id']
        lswitch_port_id = None
        try:
            switch_id = nsx_utils.get_nsx_switch_ids(
                context.session, self.cluster, network_id)[0]
            lswitch_port_id = switch_api.create_lport(
                self.cluster, switch_id, tenant_id,
                const.METADATA_PORT_ID, const.METADATA_PORT_NAME,
                const.METADATA_DEVICE_ID, True)['uuid']
            lsn_port_id = self.lsn_port_create(context, lsn_id, data)
        except (n_exc.NotFound, p_exc.NsxPluginException,
                api_exc.NsxApiException):
            raise p_exc.PortConfigurationError(
                net_id=network_id, lsn_id=lsn_id, port_id=lswitch_port_id)
        else:
            try:
                lsn_api.lsn_port_plug_network(
                    self.cluster, lsn_id, lsn_port_id, lswitch_port_id)
            except p_exc.LsnConfigurationConflict:
                self.lsn_port_delete(self.cluster, lsn_id, lsn_port_id)
                switch_api.delete_port(
                    self.cluster, network_id, lswitch_port_id)
                raise p_exc.PortConfigurationError(
                    net_id=network_id, lsn_id=lsn_id, port_id=lsn_port_id)

    def lsn_port_dhcp_configure(self, context, lsn_id, lsn_port_id, subnet):
        """Enable/disable dhcp services with the given config options."""
        is_enabled = subnet["enable_dhcp"]
        dhcp_options = {
            "domain_name": cfg.CONF.NSX_DHCP.domain_name,
            "default_lease_time": cfg.CONF.NSX_DHCP.default_lease_time,
        }
        dns_servers = cfg.CONF.NSX_DHCP.extra_domain_name_servers or []
        dns_servers.extend(subnet["dns_nameservers"])
        if subnet['gateway_ip']:
            dhcp_options["routers"] = subnet["gateway_ip"]
        if dns_servers:
            dhcp_options["domain_name_servers"] = ",".join(dns_servers)
        if subnet["host_routes"]:
            dhcp_options["classless_static_routes"] = (
                ",".join(subnet["host_routes"])
            )
        try:
            lsn_api.lsn_port_dhcp_configure(
                self.cluster, lsn_id, lsn_port_id, is_enabled, dhcp_options)
        except (n_exc.NotFound, api_exc.NsxApiException):
            err_msg = (_('Unable to configure dhcp for Logical Service '
                         'Node %(lsn_id)s and port %(lsn_port_id)s')
                       % {'lsn_id': lsn_id, 'lsn_port_id': lsn_port_id})
            LOG.error(err_msg)
            raise p_exc.NsxPluginException(err_msg=err_msg)

    def lsn_metadata_configure(self, context, subnet_id, is_enabled):
        """Configure metadata service for the specified subnet."""
        subnet = self.plugin.get_subnet(context, subnet_id)
        network_id = subnet['network_id']
        meta_conf = cfg.CONF.NSX_METADATA
        metadata_options = {
            'metadata_server_ip': meta_conf.metadata_server_address,
            'metadata_server_port': meta_conf.metadata_server_port,
            'metadata_proxy_shared_secret': meta_conf.metadata_shared_secret
        }
        try:
            lsn_id = self.lsn_get(context, network_id)
            lsn_api.lsn_metadata_configure(
                self.cluster, lsn_id, is_enabled, metadata_options)
        except (p_exc.LsnNotFound, api_exc.NsxApiException):
            err_msg = (_('Unable to configure metadata '
                         'for subnet %s') % subnet_id)
            LOG.error(err_msg)
            raise p_exc.NsxPluginException(err_msg=err_msg)
        if is_enabled:
            try:
                # test that the lsn port exists
                self.lsn_port_get(context, network_id, subnet_id)
            except p_exc.LsnPortNotFound:
                # this might happen if subnet had dhcp off when created
                # so create one, and wire it
                self.lsn_port_metadata_setup(context, lsn_id, subnet)
        else:
            self.lsn_port_dispose(context, network_id, const.METADATA_MAC)

    def _lsn_port_host_conf(self, context, network_id, subnet_id, data, hdlr):
        lsn_id, lsn_port_id = self.lsn_port_get(
            context, network_id, subnet_id, raise_on_err=False)
        try:
            if lsn_id and lsn_port_id:
                hdlr(self.cluster, lsn_id, lsn_port_id, data)
        except (n_exc.NotFound, api_exc.NsxApiException):
            LOG.error(_('Error while configuring LSN '
                        'port %s'), lsn_port_id)
            raise p_exc.PortConfigurationError(
                net_id=network_id, lsn_id=lsn_id, port_id=lsn_port_id)

    def lsn_port_dhcp_host_add(self, context, network_id, subnet_id, host):
        """Add dhcp host entry to LSN port configuration."""
        self._lsn_port_host_conf(context, network_id, subnet_id, host,
                                 lsn_api.lsn_port_dhcp_host_add)

    def lsn_port_dhcp_host_remove(self, context, network_id, subnet_id, host):
        """Remove dhcp host entry from LSN port configuration."""
        self._lsn_port_host_conf(context, network_id, subnet_id, host,
                                 lsn_api.lsn_port_dhcp_host_remove)

    def lsn_port_meta_host_add(self, context, network_id, subnet_id, host):
        """Add dhcp host entry to LSN port configuration."""
        self._lsn_port_host_conf(context, network_id, subnet_id, host,
                                 lsn_api.lsn_port_metadata_host_add)

    def lsn_port_meta_host_remove(self, context, network_id, subnet_id, host):
        """Remove dhcp host entry from LSN port configuration."""
        self._lsn_port_host_conf(context, network_id, subnet_id, host,
                                 lsn_api.lsn_port_metadata_host_remove)

    def lsn_port_update(
        self, context, network_id, subnet_id, dhcp=None, meta=None):
        """Update the specified configuration for the LSN port."""
        if not dhcp and not meta:
            return
        try:
            lsn_id, lsn_port_id = self.lsn_port_get(
                context, network_id, subnet_id, raise_on_err=False)
            if dhcp and lsn_id and lsn_port_id:
                lsn_api.lsn_port_host_entries_update(
                    self.cluster, lsn_id, lsn_port_id, DHCP_CONF, dhcp)
            if meta and lsn_id and lsn_port_id:
                lsn_api.lsn_port_host_entries_update(
                    self.cluster, lsn_id, lsn_port_id, META_CONF, meta)
        except api_exc.NsxApiException:
            raise p_exc.PortConfigurationError(
                net_id=network_id, lsn_id=lsn_id, port_id=lsn_port_id)


class PersistentLsnManager(LsnManager):
    """Add local persistent state to LSN Manager."""

    def __init__(self, plugin):
        super(PersistentLsnManager, self).__init__(plugin)
        self.sync_on_missing = cfg.CONF.NSX_LSN.sync_on_missing_data

    def lsn_get(self, context, network_id, raise_on_err=True):
        try:
            obj = lsn_db.lsn_get_for_network(
                context, network_id, raise_on_err=raise_on_err)
            return obj.lsn_id if obj else None
        except p_exc.LsnNotFound:
            with excutils.save_and_reraise_exception() as ctxt:
                ctxt.reraise = False
                if self.sync_on_missing:
                    lsn_id = super(PersistentLsnManager, self).lsn_get(
                        context, network_id, raise_on_err=raise_on_err)
                    self.lsn_save(context, network_id, lsn_id)
                    return lsn_id
                if raise_on_err:
                    ctxt.reraise = True

    def lsn_save(self, context, network_id, lsn_id):
        """Save LSN-Network mapping to the DB."""
        try:
            lsn_db.lsn_add(context, network_id, lsn_id)
        except db_exc.DBError:
            err_msg = _('Unable to save LSN for network %s') % network_id
            LOG.exception(err_msg)
            raise p_exc.NsxPluginException(err_msg=err_msg)

    def lsn_create(self, context, network_id):
        lsn_id = super(PersistentLsnManager,
                       self).lsn_create(context, network_id)
        try:
            self.lsn_save(context, network_id, lsn_id)
        except p_exc.NsxPluginException:
            with excutils.save_and_reraise_exception():
                super(PersistentLsnManager, self).lsn_delete(context, lsn_id)
        return lsn_id

    def lsn_delete(self, context, lsn_id):
        lsn_db.lsn_remove(context, lsn_id)
        super(PersistentLsnManager, self).lsn_delete(context, lsn_id)

    def lsn_port_get(self, context, network_id, subnet_id, raise_on_err=True):
        try:
            obj = lsn_db.lsn_port_get_for_subnet(
                context, subnet_id, raise_on_err=raise_on_err)
            return (obj.lsn_id, obj.lsn_port_id) if obj else (None, None)
        except p_exc.LsnPortNotFound:
            with excutils.save_and_reraise_exception() as ctxt:
                ctxt.reraise = False
                if self.sync_on_missing:
                    lsn_id, lsn_port_id = (
                        super(PersistentLsnManager, self).lsn_port_get(
                            context, network_id, subnet_id,
                            raise_on_err=raise_on_err))
                    mac_addr = lsn_api.lsn_port_info_get(
                        self.cluster, lsn_id, lsn_port_id)['mac_address']
                    self.lsn_port_save(
                        context, lsn_port_id, subnet_id, mac_addr, lsn_id)
                    return (lsn_id, lsn_port_id)
                if raise_on_err:
                    ctxt.reraise = True

    def lsn_port_get_by_mac(self, context, network_id, mac, raise_on_err=True):
        try:
            obj = lsn_db.lsn_port_get_for_mac(
                context, mac, raise_on_err=raise_on_err)
            return (obj.lsn_id, obj.lsn_port_id) if obj else (None, None)
        except p_exc.LsnPortNotFound:
            with excutils.save_and_reraise_exception() as ctxt:
                ctxt.reraise = False
                if self.sync_on_missing:
                    lsn_id, lsn_port_id = (
                        super(PersistentLsnManager, self).lsn_port_get_by_mac(
                            context, network_id, mac,
                            raise_on_err=raise_on_err))
                    subnet_id = lsn_api.lsn_port_info_get(
                        self.cluster, lsn_id, lsn_port_id).get('subnet_id')
                    self.lsn_port_save(
                        context, lsn_port_id, subnet_id, mac, lsn_id)
                    return (lsn_id, lsn_port_id)
                if raise_on_err:
                    ctxt.reraise = True

    def lsn_port_save(self, context, lsn_port_id, subnet_id, mac_addr, lsn_id):
        """Save LSN Port information to the DB."""
        try:
            lsn_db.lsn_port_add_for_lsn(
                context, lsn_port_id, subnet_id, mac_addr, lsn_id)
        except db_exc.DBError:
            err_msg = _('Unable to save LSN port for subnet %s') % subnet_id
            LOG.exception(err_msg)
            raise p_exc.NsxPluginException(err_msg=err_msg)

    def lsn_port_create(self, context, lsn_id, subnet_info):
        lsn_port_id = super(PersistentLsnManager,
                            self).lsn_port_create(context, lsn_id, subnet_info)
        try:
            self.lsn_port_save(context, lsn_port_id, subnet_info['subnet_id'],
                               subnet_info['mac_address'], lsn_id)
        except p_exc.NsxPluginException:
            with excutils.save_and_reraise_exception():
                super(PersistentLsnManager, self).lsn_port_delete(
                    context, lsn_id, lsn_port_id)
        return lsn_port_id

    def lsn_port_delete(self, context, lsn_id, lsn_port_id):
        lsn_db.lsn_port_remove(context, lsn_port_id)
        super(PersistentLsnManager, self).lsn_port_delete(
            context, lsn_id, lsn_port_id)
