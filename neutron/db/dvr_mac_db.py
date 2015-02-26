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

from oslo_config import cfg
from oslo_db import exception as db_exc
from oslo_log import log as logging
import sqlalchemy as sa
from sqlalchemy.orm import exc

from neutron.common import exceptions as q_exc
from neutron.common import log
from neutron.common import utils
from neutron.db import model_base
from neutron.extensions import dvr as ext_dvr
from neutron.extensions import portbindings
from neutron.i18n import _LE
from neutron import manager


LOG = logging.getLogger(__name__)


dvr_mac_address_opts = [
    cfg.StrOpt('dvr_base_mac',
               default="fa:16:3f:00:00:00",
               help=_('The base mac address used for unique '
                      'DVR instances by Neutron')),
]
cfg.CONF.register_opts(dvr_mac_address_opts)


class DistributedVirtualRouterMacAddress(model_base.BASEV2):
    """Represents a v2 neutron distributed virtual router mac address."""

    __tablename__ = 'dvr_host_macs'

    host = sa.Column(sa.String(255), primary_key=True, nullable=False)
    mac_address = sa.Column(sa.String(32), nullable=False, unique=True)


class DVRDbMixin(ext_dvr.DVRMacAddressPluginBase):
    """Mixin class to add dvr mac address to db_plugin_base_v2."""

    @property
    def plugin(self):
        try:
            if self._plugin is not None:
                return self._plugin
        except AttributeError:
            pass
        self._plugin = manager.NeutronManager.get_plugin()
        return self._plugin

    def _get_dvr_mac_address_by_host(self, context, host):
        try:
            query = context.session.query(DistributedVirtualRouterMacAddress)
            dvrma = query.filter(
                DistributedVirtualRouterMacAddress.host == host).one()
        except exc.NoResultFound:
            raise ext_dvr.DVRMacAddressNotFound(host=host)
        return dvrma

    def _create_dvr_mac_address(self, context, host):
        """Create DVR mac address for a given host."""
        base_mac = cfg.CONF.dvr_base_mac.split(':')
        max_retries = cfg.CONF.mac_generation_retries
        for attempt in reversed(range(max_retries)):
            try:
                with context.session.begin(subtransactions=True):
                    mac_address = utils.get_random_mac(base_mac)
                    dvr_mac_binding = DistributedVirtualRouterMacAddress(
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
            except db_exc.DBDuplicateEntry:
                LOG.debug("Generated DVR mac %(mac)s exists."
                          " Remaining attempts %(attempts_left)s.",
                          {'mac': mac_address, 'attempts_left': attempt})
        LOG.error(_LE("MAC generation error after %s attempts"), max_retries)
        raise ext_dvr.MacAddressGenerationFailure(host=host)

    def delete_dvr_mac_address(self, context, host):
        query = context.session.query(DistributedVirtualRouterMacAddress)
        (query.
         filter(DistributedVirtualRouterMacAddress.host == host).
         delete(synchronize_session=False))

    def get_dvr_mac_address_list(self, context):
        with context.session.begin(subtransactions=True):
            return (context.session.
                    query(DistributedVirtualRouterMacAddress).all())

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

    @log.log
    def get_ports_on_host_by_subnet(self, context, host, subnet):
        """Returns ports of interest, on a given subnet in the input host

        This method returns ports that need to be serviced by DVR.
        :param context: rpc request context
        :param host: host id to match and extract ports of interest
        :param subnet: subnet id to match and extract ports of interest
        :returns list -- Ports on the given subnet in the input host
        """
        # FIXME(vivek, salv-orlando): improve this query by adding the
        # capability of filtering by binding:host_id
        ports_by_host = []
        filter = {'fixed_ips': {'subnet_id': [subnet]}}
        ports = self.plugin.get_ports(context, filters=filter)
        LOG.debug("List of Ports on subnet %(subnet)s at host %(host)s "
                  "received as %(ports)s",
                  {'subnet': subnet, 'host': host, 'ports': ports})
        for port in ports:
            device_owner = port['device_owner']
            if (utils.is_dvr_serviced(device_owner)):
                if port[portbindings.HOST_ID] == host:
                    port_dict = self.plugin._make_port_dict(port,
                        process_extensions=False)
                    ports_by_host.append(port_dict)
        LOG.debug("Returning list of dvr serviced ports on host %(host)s"
                  " for subnet %(subnet)s ports %(ports)s",
                  {'host': host, 'subnet': subnet,
                   'ports': ports_by_host})
        return ports_by_host

    @log.log
    def get_subnet_for_dvr(self, context, subnet):
        try:
            subnet_info = self.plugin.get_subnet(context, subnet)
        except q_exc.SubnetNotFound:
            return {}
        else:
            # retrieve the gateway port on this subnet
            filter = {'fixed_ips': {'subnet_id': [subnet],
                                    'ip_address': [subnet_info['gateway_ip']]}}
            internal_gateway_ports = self.plugin.get_ports(
                context, filters=filter)
            if not internal_gateway_ports:
                LOG.error(_LE("Could not retrieve gateway port "
                              "for subnet %s"), subnet_info)
                return {}
            internal_port = internal_gateway_ports[0]
            subnet_info['gateway_mac'] = internal_port['mac_address']
            return subnet_info
