# Copyright (c) 2013 OpenStack Foundation
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
import abc

from oslo_config import cfg
from oslo_db import exception as db_exc
from oslo_log import log

from neutron.common import exceptions as exc
from neutron.common import topics
from neutron.db import api as db_api
from neutron.i18n import _LI, _LW
from neutron.plugins.common import utils as plugin_utils
from neutron.plugins.ml2 import driver_api as api
from neutron.plugins.ml2.drivers import helpers

LOG = log.getLogger(__name__)

TUNNEL = 'tunnel'


class TunnelTypeDriver(helpers.SegmentTypeDriver):
    """Define stable abstract interface for ML2 type drivers.

    tunnel type networks rely on tunnel endpoints. This class defines abstract
    methods to manage these endpoints.
    """

    def __init__(self, model):
        super(TunnelTypeDriver, self).__init__(model)
        self.segmentation_key = next(iter(self.primary_keys))

    @abc.abstractmethod
    def sync_allocations(self):
        """Synchronize type_driver allocation table with configured ranges."""

    @abc.abstractmethod
    def add_endpoint(self, ip, host):
        """Register the endpoint in the type_driver database.

        param ip: the IP address of the endpoint
        param host: the Host name of the endpoint
        """

    @abc.abstractmethod
    def get_endpoints(self):
        """Get every endpoint managed by the type_driver

        :returns a list of dict [{ip_address:endpoint_ip, host:endpoint_host},
        ..]
        """

    @abc.abstractmethod
    def get_endpoint_by_host(self, host):
        """Get endpoint for a given host managed by the type_driver

        param host: the Host name of the endpoint

        if host found in type_driver database
           :returns db object for that particular host
        else
           :returns None
        """

    @abc.abstractmethod
    def get_endpoint_by_ip(self, ip):
        """Get endpoint for a given tunnel ip managed by the type_driver

        param ip: the IP address of the endpoint

        if ip found in type_driver database
           :returns db object for that particular ip
        else
           :returns None
        """

    @abc.abstractmethod
    def delete_endpoint(self, ip):
        """Delete the endpoint in the type_driver database.

        param ip: the IP address of the endpoint
        """

    def _initialize(self, raw_tunnel_ranges):
        self.tunnel_ranges = []
        self._parse_tunnel_ranges(raw_tunnel_ranges, self.tunnel_ranges)
        self.sync_allocations()

    def _parse_tunnel_ranges(self, tunnel_ranges, current_range):
        for entry in tunnel_ranges:
            entry = entry.strip()
            try:
                tun_min, tun_max = entry.split(':')
                tun_min = tun_min.strip()
                tun_max = tun_max.strip()
                tunnel_range = int(tun_min), int(tun_max)
            except ValueError as ex:
                raise exc.NetworkTunnelRangeError(tunnel_range=entry, error=ex)
            plugin_utils.verify_tunnel_range(tunnel_range, self.get_type())
            current_range.append(tunnel_range)
        LOG.info(_LI("%(type)s ID ranges: %(range)s"),
                 {'type': self.get_type(), 'range': current_range})

    def is_partial_segment(self, segment):
        return segment.get(api.SEGMENTATION_ID) is None

    def validate_provider_segment(self, segment):
        physical_network = segment.get(api.PHYSICAL_NETWORK)
        if physical_network:
            msg = _("provider:physical_network specified for %s "
                    "network") % segment.get(api.NETWORK_TYPE)
            raise exc.InvalidInput(error_message=msg)

        for key, value in segment.items():
            if value and key not in [api.NETWORK_TYPE,
                                     api.SEGMENTATION_ID]:
                msg = (_("%(key)s prohibited for %(tunnel)s provider network"),
                       {'key': key, 'tunnel': segment.get(api.NETWORK_TYPE)})
                raise exc.InvalidInput(error_message=msg)

    def reserve_provider_segment(self, session, segment):
        if self.is_partial_segment(segment):
            alloc = self.allocate_partially_specified_segment(session)
            if not alloc:
                raise exc.NoNetworkAvailable()
        else:
            segmentation_id = segment.get(api.SEGMENTATION_ID)
            alloc = self.allocate_fully_specified_segment(
                session, **{self.segmentation_key: segmentation_id})
            if not alloc:
                raise exc.TunnelIdInUse(tunnel_id=segmentation_id)
        return {api.NETWORK_TYPE: self.get_type(),
                api.PHYSICAL_NETWORK: None,
                api.SEGMENTATION_ID: getattr(alloc, self.segmentation_key),
                api.MTU: self.get_mtu()}

    def allocate_tenant_segment(self, session):
        alloc = self.allocate_partially_specified_segment(session)
        if not alloc:
            return
        return {api.NETWORK_TYPE: self.get_type(),
                api.PHYSICAL_NETWORK: None,
                api.SEGMENTATION_ID: getattr(alloc, self.segmentation_key),
                api.MTU: self.get_mtu()}

    def release_segment(self, session, segment):
        tunnel_id = segment[api.SEGMENTATION_ID]

        inside = any(lo <= tunnel_id <= hi for lo, hi in self.tunnel_ranges)

        info = {'type': self.get_type(), 'id': tunnel_id}
        with session.begin(subtransactions=True):
            query = (session.query(self.model).
                     filter_by(**{self.segmentation_key: tunnel_id}))
            if inside:
                count = query.update({"allocated": False})
                if count:
                    LOG.debug("Releasing %(type)s tunnel %(id)s to pool",
                              info)
            else:
                count = query.delete()
                if count:
                    LOG.debug("Releasing %(type)s tunnel %(id)s outside pool",
                              info)

        if not count:
            LOG.warning(_LW("%(type)s tunnel %(id)s not found"), info)

    def get_allocation(self, session, tunnel_id):
        return (session.query(self.model).
                filter_by(**{self.segmentation_key: tunnel_id}).
                first())

    def get_mtu(self, physical_network=None):
        seg_mtu = super(TunnelTypeDriver, self).get_mtu()
        mtu = []
        if seg_mtu > 0:
            mtu.append(seg_mtu)
        if cfg.CONF.ml2.path_mtu > 0:
            mtu.append(cfg.CONF.ml2.path_mtu)
        return min(mtu) if mtu else 0


class EndpointTunnelTypeDriver(TunnelTypeDriver):

    def __init__(self, segment_model, endpoint_model):
        super(EndpointTunnelTypeDriver, self).__init__(segment_model)
        self.endpoint_model = endpoint_model
        self.segmentation_key = next(iter(self.primary_keys))

    def get_endpoint_by_host(self, host):
        LOG.debug("get_endpoint_by_host() called for host %s", host)
        session = db_api.get_session()
        return (session.query(self.endpoint_model).
                filter_by(host=host).first())

    def get_endpoint_by_ip(self, ip):
        LOG.debug("get_endpoint_by_ip() called for ip %s", ip)
        session = db_api.get_session()
        return (session.query(self.endpoint_model).
                filter_by(ip_address=ip).first())

    def delete_endpoint(self, ip):
        LOG.debug("delete_endpoint() called for ip %s", ip)
        session = db_api.get_session()
        with session.begin(subtransactions=True):
            (session.query(self.endpoint_model).
             filter_by(ip_address=ip).delete())

    def _get_endpoints(self):
        LOG.debug("_get_endpoints() called")
        session = db_api.get_session()
        return session.query(self.endpoint_model)

    def _add_endpoint(self, ip, host, **kwargs):
        LOG.debug("_add_endpoint() called for ip %s", ip)
        session = db_api.get_session()
        try:
            endpoint = self.endpoint_model(ip_address=ip, host=host, **kwargs)
            endpoint.save(session)
        except db_exc.DBDuplicateEntry:
            endpoint = (session.query(self.endpoint_model).
                        filter_by(ip_address=ip).one())
            LOG.warning(_LW("Endpoint with ip %s already exists"), ip)
        return endpoint


class TunnelRpcCallbackMixin(object):

    def setup_tunnel_callback_mixin(self, notifier, type_manager):
        self._notifier = notifier
        self._type_manager = type_manager

    def tunnel_sync(self, rpc_context, **kwargs):
        """Update new tunnel.

        Updates the database with the tunnel IP. All listening agents will also
        be notified about the new tunnel IP.
        """
        tunnel_ip = kwargs.get('tunnel_ip')
        if not tunnel_ip:
            msg = _("Tunnel IP value needed by the ML2 plugin")
            raise exc.InvalidInput(error_message=msg)

        tunnel_type = kwargs.get('tunnel_type')
        if not tunnel_type:
            msg = _("Network type value needed by the ML2 plugin")
            raise exc.InvalidInput(error_message=msg)

        host = kwargs.get('host')
        driver = self._type_manager.drivers.get(tunnel_type)
        if driver:
            # The given conditional statements will verify the following
            # things:
            # 1. If host is not passed from an agent, it is a legacy mode.
            # 2. If passed host and tunnel_ip are not found in the DB,
            #    it is a new endpoint.
            # 3. If host is passed from an agent and it is not found in DB
            #    but the passed tunnel_ip is found, delete the endpoint
            #    from DB and add the endpoint with (tunnel_ip, host),
            #    it is an upgrade case.
            # 4. If passed host is found in DB and passed tunnel ip is not
            #    found, delete the endpoint belonging to that host and
            #    add endpoint with latest (tunnel_ip, host), it is a case
            #    where local_ip of an agent got changed.
            if host:
                host_endpoint = driver.obj.get_endpoint_by_host(host)
                ip_endpoint = driver.obj.get_endpoint_by_ip(tunnel_ip)

                if (ip_endpoint and ip_endpoint.host is None
                    and host_endpoint is None):
                    driver.obj.delete_endpoint(ip_endpoint.ip_address)
                elif (ip_endpoint and ip_endpoint.host != host):
                    msg = (_("Tunnel IP %(ip)s in use with host %(host)s"),
                           {'ip': ip_endpoint.ip_address,
                            'host': ip_endpoint.host})
                    raise exc.InvalidInput(error_message=msg)
                elif (host_endpoint and host_endpoint.ip_address != tunnel_ip):
                    # Notify all other listening agents to delete stale tunnels
                    self._notifier.tunnel_delete(rpc_context,
                        host_endpoint.ip_address, tunnel_type)
                    driver.obj.delete_endpoint(host_endpoint.ip_address)

            tunnel = driver.obj.add_endpoint(tunnel_ip, host)
            tunnels = driver.obj.get_endpoints()
            entry = {'tunnels': tunnels}
            # Notify all other listening agents
            self._notifier.tunnel_update(rpc_context, tunnel.ip_address,
                                         tunnel_type)
            # Return the list of tunnels IP's to the agent
            return entry
        else:
            msg = _("Network type value '%s' not supported") % tunnel_type
            raise exc.InvalidInput(error_message=msg)


class TunnelAgentRpcApiMixin(object):

    def _get_tunnel_update_topic(self):
        return topics.get_topic_name(self.topic,
                                     TUNNEL,
                                     topics.UPDATE)

    def tunnel_update(self, context, tunnel_ip, tunnel_type):
        cctxt = self.client.prepare(topic=self._get_tunnel_update_topic(),
                                    fanout=True)
        cctxt.cast(context, 'tunnel_update', tunnel_ip=tunnel_ip,
                   tunnel_type=tunnel_type)

    def _get_tunnel_delete_topic(self):
        return topics.get_topic_name(self.topic,
                                     TUNNEL,
                                     topics.DELETE)

    def tunnel_delete(self, context, tunnel_ip, tunnel_type):
        cctxt = self.client.prepare(topic=self._get_tunnel_delete_topic(),
                                    fanout=True)
        cctxt.cast(context, 'tunnel_delete', tunnel_ip=tunnel_ip,
                   tunnel_type=tunnel_type)
