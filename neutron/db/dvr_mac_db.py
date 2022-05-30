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

import netaddr

from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib import constants
from neutron_lib.db import api as db_api
from neutron_lib import exceptions as n_exc
from neutron_lib.exceptions import dvr as dvr_exc
from neutron_lib.objects import exceptions
from neutron_lib.plugins import directory
from neutron_lib.utils import net
from oslo_config import cfg
from oslo_log import helpers as log_helpers
from oslo_log import log as logging
from sqlalchemy import or_

from neutron.common import utils
from neutron.conf.db import dvr_mac_db
from neutron.conf.db import l3_dvr_db
from neutron.db import models_v2
from neutron.extensions import dvr as ext_dvr
from neutron.objects import router
from neutron.plugins.ml2 import models as ml2_models


LOG = logging.getLogger(__name__)


dvr_mac_db.register_db_dvr_mac_opts()
l3_dvr_db.register_db_l3_dvr_opts()


@db_api.CONTEXT_READER
def get_ports_query_by_subnet_and_ip(context, subnet, ip_addresses=None):
    query = context.session.query(models_v2.Port)
    query = query.join(models_v2.IPAllocation)
    query = query.filter(
        models_v2.Port.id == models_v2.IPAllocation.port_id,
        models_v2.IPAllocation.subnet_id == subnet)
    if ip_addresses:
        query = query.filter(
            models_v2.IPAllocation.ip_address.in_(ip_addresses))
    return query.all()


@registry.has_registry_receivers
class DVRDbMixin(ext_dvr.DVRMacAddressPluginBase):
    """Mixin class to add dvr mac address to db_plugin_base_v2."""

    @property
    def plugin(self):
        try:
            if self._plugin is not None:
                return self._plugin
        except AttributeError:
            pass
        self._plugin = directory.get_plugin()
        return self._plugin

    @staticmethod
    @db_api.retry_if_session_inactive()
    def _db_delete_mac_associated_with_agent(context, agent):
        host = agent['host']
        plugin = directory.get_plugin()
        if [a for a in plugin.get_agents(context, filters={'host': [host]})
                if a['id'] != agent['id']]:
            # there are still agents on this host, don't mess with the mac
            # entry until they are all deleted.
            return

        if not router.DVRMacAddress.delete_objects(context, host=host):
            return

        # notify remaining agents so they cleanup flows
        dvr_macs = plugin.get_dvr_mac_address_list(context)
        plugin.notifier.dvr_mac_address_update(context, dvr_macs)

    @staticmethod
    @registry.receives(resources.AGENT, [events.BEFORE_DELETE])
    def _delete_mac_associated_with_agent(resource, event,
                                          trigger, payload=None):

        DVRDbMixin._db_delete_mac_associated_with_agent(
            payload.context, payload.latest_state)

    @db_api.CONTEXT_READER
    def _get_dvr_mac_address_by_host(self, context, host):
        dvr_obj = router.DVRMacAddress.get_object(context, host=host)
        if not dvr_obj:
            raise dvr_exc.DVRMacAddressNotFound(host=host)
        return self._make_dvr_mac_address_dict(dvr_obj)

    @utils.transaction_guard
    @db_api.retry_if_session_inactive()
    def _create_dvr_mac_address_retry(self, context, host, base_mac):
        with db_api.CONTEXT_WRITER.using(context):
            mac_address = net.get_random_mac(base_mac)
            dvr_mac_binding = router.DVRMacAddress(
                context, host=host, mac_address=netaddr.EUI(mac_address))
            dvr_mac_binding.create()
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
        except exceptions.NeutronDbObjectDuplicateEntry:
            LOG.error("MAC generation error after %s attempts",
                      db_api.MAX_RETRIES)
        raise n_exc.HostMacAddressGenerationFailure(host=host)

    @db_api.CONTEXT_READER
    def get_dvr_mac_address_list(self, context):
        return [
            dvr_mac.to_dict()
            for dvr_mac in router.DVRMacAddress.get_objects(context)
        ]

    def get_dvr_mac_address_by_host(self, context, host):
        """Determine the MAC for the DVR port associated to host."""
        if not host:
            return

        try:
            return self._get_dvr_mac_address_by_host(context, host)
        except dvr_exc.DVRMacAddressNotFound:
            return self._create_dvr_mac_address(context, host)

    def _make_dvr_mac_address_dict(self, dvr_mac_entry, fields=None):
        return {'host': dvr_mac_entry['host'],
                'mac_address': str(dvr_mac_entry['mac_address'])}

    @log_helpers.log_method_call
    @db_api.retry_if_session_inactive()
    def get_ports_on_host_by_subnet(self, context, host, subnet):
        """Returns DVR serviced ports on a given subnet in the input host

        This method returns ports that need to be serviced by DVR.
        :param context: rpc request context
        :param host: host id to match and extract ports of interest
        :param subnet: subnet id to match and extract ports of interest
        :returns: list -- Ports on the given subnet in the input host
        """

        host_dvr_for_dhcp = cfg.CONF.host_dvr_for_dhcp

        query = context.session.query(models_v2.Port)
        query = query.join(ml2_models.PortBinding)
        query = query.join(models_v2.IPAllocation)
        query = query.filter(
            models_v2.Port.id == ml2_models.PortBinding.port_id,
            models_v2.Port.id == models_v2.IPAllocation.port_id,
            ml2_models.PortBinding.host == host,
            models_v2.IPAllocation.subnet_id == subnet)
        owner_filter = or_(
            models_v2.Port.device_owner.startswith(
                constants.DEVICE_OWNER_COMPUTE_PREFIX),
            models_v2.Port.device_owner.in_(
                utils.get_other_dvr_serviced_device_owners(host_dvr_for_dhcp)))

        ports_query = query.filter(owner_filter)

        ports = [
            self.plugin._make_port_dict(port, process_extensions=False,
                                        with_fixed_ips=False)
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

            internal_gateway_ports = get_ports_query_by_subnet_and_ip(
                context, subnet, [ip_address])

            if not internal_gateway_ports:
                LOG.error("Could not retrieve gateway port "
                          "for subnet %s", subnet_info)
                return {}
            internal_port = internal_gateway_ports[0]
            subnet_info['gateway_mac'] = internal_port['mac_address']
            return subnet_info
