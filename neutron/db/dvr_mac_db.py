# Copyright 2014 Hewlett-Packard Development Company, L.P.
# All rights reserved.
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

from neutron_lib import constants
from neutron_lib import exceptions as n_exc
from neutron_lib.plugins import directory
from oslo_config import cfg
from oslo_db import exception as db_exc
from oslo_log import helpers as log_helpers
from oslo_log import log as logging
from sqlalchemy import or_
from sqlalchemy.orm import exc

from neutron._i18n import _, _LE
from neutron.callbacks import events
from neutron.callbacks import registry
from neutron.callbacks import resources
from neutron.common import _deprecate
from neutron.common import utils
from neutron.db import api as db_api
from neutron.db.models import dvr as dvr_models
from neutron.db import models_v2
from neutron.extensions import dvr as ext_dvr
from neutron.extensions import portbindings

_deprecate._moved_global('DistributedVirtualRouterMacAddress',
                         new_module=dvr_models)

LOG = logging.getLogger(__name__)


dvr_mac_address_opts = [
    cfg.StrOpt('dvr_base_mac',
               default="fa:16:3f:00:00:00",
               help=_("The base mac address used for unique "
                      "DVR instances by Neutron. The first 3 octets will "
                      "remain unchanged. If the 4th octet is not 00, it will "
                      "also be used. The others will be randomly generated. "
                      "The 'dvr_base_mac' *must* be different from "
                      "'base_mac' to avoid mixing them up with MAC's "
                      "allocated for tenant ports. A 4 octet example would be "
                      "dvr_base_mac = fa:16:3f:4f:00:00. The default is 3 "
                      "octet")),
]
cfg.CONF.register_opts(dvr_mac_address_opts)


@db_api.retry_if_session_inactive()
def _delete_mac_associated_with_agent(resource, event, trigger, context, agent,
                                      **kwargs):
    host = agent['host']
    plugin = directory.get_plugin()
    if [a for a in plugin.get_agents(context, filters={'host': [host]})
            if a['id'] != agent['id']]:
        # there are still agents on this host, don't mess with the mac entry
        # until they are all deleted.
        return
    try:
        with db_api.context_manager.writer.using(context):
            entry = (context.session.query(
                        dvr_models.DistributedVirtualRouterMacAddress).
                     filter(
                        dvr_models.DistributedVirtualRouterMacAddress.host ==
                        host).
                     one())
            context.session.delete(entry)
    except exc.NoResultFound:
        return
    # notify remaining agents so they cleanup flows
    dvr_macs = plugin.get_dvr_mac_address_list(context)
    plugin.notifier.dvr_mac_address_update(context, dvr_macs)


class DVRDbMixin(ext_dvr.DVRMacAddressPluginBase):
    """Mixin class to add dvr mac address to db_plugin_base_v2."""

    def __new__(cls, *args, **kwargs):
        registry.subscribe(_delete_mac_associated_with_agent,
                           resources.AGENT, events.BEFORE_DELETE)
        return super(DVRDbMixin, cls).__new__(cls)

    @property
    def plugin(self):
        try:
            if self._plugin is not None:
                return self._plugin
        except AttributeError:
            pass
        self._plugin = directory.get_plugin()
        return self._plugin

    @db_api.context_manager.reader
    def _get_dvr_mac_address_by_host(self, context, host):
        try:
            query = context.session.query(
                dvr_models.DistributedVirtualRouterMacAddress)
            dvrma = query.filter(
                dvr_models.DistributedVirtualRouterMacAddress.host == host
            ).one()
        except exc.NoResultFound:
            raise ext_dvr.DVRMacAddressNotFound(host=host)
        return dvrma

    @utils.transaction_guard
    @db_api.retry_if_session_inactive()
    def _create_dvr_mac_address_retry(self, context, host, base_mac):
        with db_api.context_manager.writer.using(context):
            mac_address = utils.get_random_mac(base_mac)
            dvr_mac_binding = dvr_models.DistributedVirtualRouterMacAddress(
                host=host, mac_address=mac_address)
            context.session.add(dvr_mac_binding)
            LOG.debug("Generated DVR mac for host %(host)s "
                      "is %(mac_address)s",
                      {'host': host, 'mac_address': mac_address})
        dvr_macs = self.get_dvr_mac_address_list(context)
        # TODO(vivek): improve scalability of this fanout by
        # sending a single mac address rather than the entire set
        self.notifier.dvr_mac_address_update(context, dvr_macs)
        return self._make_dvr_mac_address_dict(dvr_mac_binding)

    def _create_dvr_mac_address(self, context, host):
        """Create DVR mac address for a given host."""
        base_mac = cfg.CONF.dvr_base_mac.split(':')
        try:
            return self._create_dvr_mac_address_retry(context, host, base_mac)
        except db_exc.DBDuplicateEntry:
            LOG.error(_LE("MAC generation error after %s attempts"),
                      db_api.MAX_RETRIES)
        raise ext_dvr.MacAddressGenerationFailure(host=host)

    @db_api.context_manager.reader
    def get_dvr_mac_address_list(self, context):
        return (context.session.
                query(dvr_models.DistributedVirtualRouterMacAddress).all())

    def get_dvr_mac_address_by_host(self, context, host):
        """Determine the MAC for the DVR port associated to host."""
        if not host:
            return

        try:
            return self._get_dvr_mac_address_by_host(context, host)
        except ext_dvr.DVRMacAddressNotFound:
            return self._create_dvr_mac_address(context, host)

    def _make_dvr_mac_address_dict(self, dvr_mac_entry, fields=None):
        return {'host': dvr_mac_entry['host'],
                'mac_address': dvr_mac_entry['mac_address']}

    @log_helpers.log_method_call
    @db_api.retry_if_session_inactive()
    def get_ports_on_host_by_subnet(self, context, host, subnet):
        """Returns DVR serviced ports on a given subnet in the input host

        This method returns ports that need to be serviced by DVR.
        :param context: rpc request context
        :param host: host id to match and extract ports of interest
        :param subnet: subnet id to match and extract ports of interest
        :returns list -- Ports on the given subnet in the input host
        """
        filters = {'fixed_ips': {'subnet_id': [subnet]},
                   portbindings.HOST_ID: [host]}
        ports_query = self.plugin._get_ports_query(context, filters=filters)
        owner_filter = or_(
            models_v2.Port.device_owner.startswith(
                constants.DEVICE_OWNER_COMPUTE_PREFIX),
            models_v2.Port.device_owner.in_(
                utils.get_other_dvr_serviced_device_owners()))
        ports_query = ports_query.filter(owner_filter)
        ports = [
            self.plugin._make_port_dict(port, process_extensions=False)
            for port in ports_query.all()
        ]
        LOG.debug("Returning list of dvr serviced ports on host %(host)s"
                  " for subnet %(subnet)s ports %(ports)s",
                  {'host': host, 'subnet': subnet,
                   'ports': ports})
        return ports

    @log_helpers.log_method_call
    @db_api.retry_if_session_inactive()
    def get_subnet_for_dvr(self, context, subnet, fixed_ips=None):
        if fixed_ips:
            subnet_data = fixed_ips[0]['subnet_id']
        else:
            subnet_data = subnet
        try:
            subnet_info = self.plugin.get_subnet(
                context, subnet_data)
        except n_exc.SubnetNotFound:
            return {}
        else:
            # retrieve the gateway port on this subnet
            if fixed_ips:
                ip_address = fixed_ips[0]['ip_address']
            else:
                ip_address = subnet_info['gateway_ip']

            filter = {'fixed_ips': {'subnet_id': [subnet],
                                    'ip_address': [ip_address]}}

            internal_gateway_ports = self.plugin.get_ports(
                context, filters=filter)
            if not internal_gateway_ports:
                LOG.error(_LE("Could not retrieve gateway port "
                              "for subnet %s"), subnet_info)
                return {}
            internal_port = internal_gateway_ports[0]
            subnet_info['gateway_mac'] = internal_port['mac_address']
            return subnet_info


_deprecate._MovedGlobals()
