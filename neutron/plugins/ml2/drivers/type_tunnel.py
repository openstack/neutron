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
import itertools
import operator

import netaddr
from neutron_lib.agent import topics
from neutron_lib import constants as p_const
from neutron_lib import context
from neutron_lib.db import api as db_api
from neutron_lib import exceptions as exc
from neutron_lib.plugins import constants as plugin_constants
from neutron_lib.plugins import directory
from neutron_lib.plugins.ml2 import api
from neutron_lib.plugins import utils as plugin_utils
from oslo_config import cfg
from oslo_db import exception as db_exc
from oslo_log import log
from oslo_utils import uuidutils
from sqlalchemy import or_

from neutron._i18n import _
from neutron.objects import network_segment_range as range_obj
from neutron.plugins.ml2.drivers import helpers
from neutron.services.network_segment_range import plugin as range_plugin

LOG = log.getLogger(__name__)

TUNNEL = 'tunnel'


def chunks(iterable, chunk_size):
    """Chunks data into chunk with size<=chunk_size."""
    iterator = iter(iterable)
    chunk = list(itertools.islice(iterator, 0, chunk_size))
    while chunk:
        yield chunk
        chunk = list(itertools.islice(iterator, 0, chunk_size))


class _TunnelTypeDriverBase(helpers.SegmentTypeDriver, metaclass=abc.ABCMeta):

    BULK_SIZE = 100

    def __init__(self, model):
        super(_TunnelTypeDriverBase, self).__init__(model)
        self.segmentation_key = next(iter(self.primary_keys))

    @abc.abstractmethod
    def add_endpoint(self, ip, host):
        """Register the endpoint in the type_driver database.

        :param ip: the IP address of the endpoint
        :param host: the Host name of the endpoint
        """

    @abc.abstractmethod
    def get_endpoints(self):
        """Get every endpoint managed by the type_driver

        :returns: a list of dict [{ip_address:endpoint_ip, host:endpoint_host},
         ..]
        """

    @abc.abstractmethod
    def get_endpoint_by_host(self, host):
        """Get endpoint for a given host managed by the type_driver

        :param host: the Host name of the endpoint

        if host found in type_driver database
           :returns: db object for that particular host
        else
           :returns: None
        """

    @abc.abstractmethod
    def get_endpoint_by_ip(self, ip):
        """Get endpoint for a given tunnel ip managed by the type_driver

        :param ip: the IP address of the endpoint

        if ip found in type_driver database
           :returns: db object for that particular ip
        else
           :returns: None
        """

    @abc.abstractmethod
    def delete_endpoint(self, ip):
        """Delete the endpoint in the type_driver database.

        :param ip: the IP address of the endpoint
        """

    @abc.abstractmethod
    def delete_endpoint_by_host_or_ip(self, host, ip):
        """Delete the endpoint in the type_driver database.

        This function will delete any endpoint matching the specified
        ip or host.

        :param host: the host name of the endpoint
        :param ip: the IP address of the endpoint
        """

    def _initialize(self, raw_tunnel_ranges):
        self.tunnel_ranges = []
        self._parse_tunnel_ranges(raw_tunnel_ranges, self.tunnel_ranges)
        if not range_plugin.is_network_segment_range_enabled():
            # service plugins are initialized/loaded after the ML2 driver
            # initialization. Thus, we base on the information whether
            # ``network_segment_range`` service plugin is enabled/defined in
            # ``neutron.conf`` to decide whether to skip the first time sync
            # allocation during driver initialization, instead of using the
            # directory.get_plugin() method - the normal way used elsewhere to
            # check if a plugin is loaded.
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
        LOG.info("%(type)s ID ranges: %(range)s",
                 {'type': self.get_type(), 'range': current_range})

    @db_api.retry_db_errors
    def _populate_new_default_network_segment_ranges(self):
        ctx = context.get_admin_context()
        for tun_min, tun_max in self.tunnel_ranges:
            res = {
                'id': uuidutils.generate_uuid(),
                'name': '',
                'default': True,
                'shared': True,
                'network_type': self.get_type(),
                'minimum': tun_min,
                'maximum': tun_max}
            with db_api.CONTEXT_WRITER.using(ctx):
                new_default_range_obj = (
                    range_obj.NetworkSegmentRange(ctx, **res))
                new_default_range_obj.create()

    @db_api.retry_db_errors
    def _get_network_segment_ranges_from_db(self):
        ranges = []
        ctx = context.get_admin_context()
        with db_api.CONTEXT_READER.using(ctx):
            range_objs = (range_obj.NetworkSegmentRange.get_objects(
                ctx, network_type=self.get_type()))
            for obj in range_objs:
                ranges.append((obj['minimum'], obj['maximum']))

        return ranges

    def initialize_network_segment_range_support(self):
        self._delete_expired_default_network_segment_ranges()
        self._populate_new_default_network_segment_ranges()
        # Override self.tunnel_ranges with the network segment range
        # information from DB and then do a sync_allocations since the
        # segment range service plugin has not yet been loaded at this
        # initialization time.
        self.tunnel_ranges = self._get_network_segment_ranges_from_db()
        self.sync_allocations()

    def update_network_segment_range_allocations(self):
        self.sync_allocations()

    @db_api.retry_db_errors
    def sync_allocations(self):
        # determine current configured allocatable tunnel ids
        tunnel_ids = set()
        ranges = self.get_network_segment_ranges()
        for tun_min, tun_max in ranges:
            tunnel_ids |= set(range(tun_min, tun_max + 1))

        tunnel_id_getter = operator.attrgetter(self.segmentation_key)
        tunnel_col = getattr(self.model, self.segmentation_key)
        ctx = context.get_admin_context()
        with db_api.CONTEXT_WRITER.using(ctx):
            # remove from table unallocated tunnels not currently allocatable
            # fetch results as list via all() because we'll be iterating
            # through them twice
            allocs = ctx.session.query(self.model).all()

            # collect those vnis that needs to be deleted from db
            unallocateds = (
                tunnel_id_getter(a) for a in allocs if not a.allocated)
            to_remove = (x for x in unallocateds if x not in tunnel_ids)
            # Immediately delete tunnels in chunks. This leaves no work for
            # flush at the end of transaction
            for chunk in chunks(to_remove, self.BULK_SIZE):
                (ctx.session.query(self.model).filter(tunnel_col.in_(chunk)).
                 filter_by(allocated=False).delete(synchronize_session=False))

            # collect vnis that need to be added
            existings = {tunnel_id_getter(a) for a in allocs}
            missings = list(tunnel_ids - existings)
            for chunk in chunks(missings, self.BULK_SIZE):
                bulk = [{self.segmentation_key: x, 'allocated': False}
                        for x in chunk]
                ctx.session.execute(self.model.__table__.insert(), bulk)

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

    def get_mtu(self, physical_network=None):
        seg_mtu = super(_TunnelTypeDriverBase, self).get_mtu()
        mtu = []
        if seg_mtu > 0:
            mtu.append(seg_mtu)
        if cfg.CONF.ml2.path_mtu > 0:
            mtu.append(cfg.CONF.ml2.path_mtu)
        version = cfg.CONF.ml2.overlay_ip_version
        ip_header_length = p_const.IP_HEADER_LENGTH[version]
        return min(mtu) - ip_header_length if mtu else 0

    def get_network_segment_ranges(self):
        """Get the driver network segment ranges.

        Queries all tunnel network segment ranges from DB if the
        ``NETWORK_SEGMENT_RANGE`` service plugin is enabled. Otherwise,
        they will be loaded from the host config file - `ml2_conf.ini`.
        """
        ranges = self.tunnel_ranges
        if directory.get_plugin(plugin_constants.NETWORK_SEGMENT_RANGE):
            ranges = self._get_network_segment_ranges_from_db()

        return ranges


class ML2TunnelTypeDriver(_TunnelTypeDriverBase, metaclass=abc.ABCMeta):
    """Define stable abstract interface for ML2 type drivers.

    tunnel type networks rely on tunnel endpoints. This class defines abstract
    methods to manage these endpoints.

    ML2 type driver that passes context as argument to functions:
    - reserve_provider_segment
    - allocate_tenant_segment
    - release_segment
    - get_allocation
    """

    def reserve_provider_segment(self, context, segment, filters=None):
        if self.is_partial_segment(segment):
            filters = filters or {}
            alloc = self.allocate_partially_specified_segment(context,
                                                              **filters)
            if not alloc:
                raise exc.NoNetworkAvailable()
        else:
            segmentation_id = segment.get(api.SEGMENTATION_ID)
            alloc = self.allocate_fully_specified_segment(
                context, **{self.segmentation_key: segmentation_id})
            if not alloc:
                raise exc.TunnelIdInUse(tunnel_id=segmentation_id)
        return {api.NETWORK_TYPE: self.get_type(),
                api.PHYSICAL_NETWORK: None,
                api.SEGMENTATION_ID: getattr(alloc, self.segmentation_key),
                api.MTU: self.get_mtu()}

    def allocate_tenant_segment(self, context, filters=None):
        filters = filters or {}
        alloc = self.allocate_partially_specified_segment(context, **filters)
        if not alloc:
            return
        return {api.NETWORK_TYPE: self.get_type(),
                api.PHYSICAL_NETWORK: None,
                api.SEGMENTATION_ID: getattr(alloc, self.segmentation_key),
                api.MTU: self.get_mtu()}

    def release_segment(self, context, segment):
        tunnel_id = segment[api.SEGMENTATION_ID]

        ranges = self.get_network_segment_ranges()
        inside = any(lo <= tunnel_id <= hi for lo, hi in ranges)

        info = {'type': self.get_type(), 'id': tunnel_id}
        with db_api.CONTEXT_WRITER.using(context):
            query = (context.session.query(self.model).
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
            LOG.warning("%(type)s tunnel %(id)s not found", info)

    @db_api.CONTEXT_READER
    def get_allocation(self, context, tunnel_id):
        return (context.session.query(self.model).
                filter_by(**{self.segmentation_key: tunnel_id}).
                first())


class EndpointTunnelTypeDriver(ML2TunnelTypeDriver):

    def __init__(self, segment_model, endpoint_model):
        super(EndpointTunnelTypeDriver, self).__init__(segment_model)
        self.endpoint_model = endpoint_model.db_model
        self.segmentation_key = next(iter(self.primary_keys))

    def get_endpoint_by_host(self, host):
        LOG.debug("get_endpoint_by_host() called for host %s", host)
        ctx = context.get_admin_context()
        with db_api.CONTEXT_READER.using(ctx):
            return (ctx.session.query(self.endpoint_model).
                    filter_by(host=host).first())

    def get_endpoint_by_ip(self, ip):
        LOG.debug("get_endpoint_by_ip() called for ip %s", ip)
        ctx = context.get_admin_context()
        with db_api.CONTEXT_READER.using(ctx):
            return (ctx.session.query(self.endpoint_model).
                    filter_by(ip_address=ip).first())

    def delete_endpoint(self, ip):
        LOG.debug("delete_endpoint() called for ip %s", ip)
        ctx = context.get_admin_context()
        with db_api.CONTEXT_WRITER.using(ctx):
            ctx.session.query(self.endpoint_model).filter_by(
                ip_address=ip).delete()

    def delete_endpoint_by_host_or_ip(self, host, ip):
        LOG.debug("delete_endpoint_by_host_or_ip() called for "
                  "host %(host)s or %(ip)s", {'host': host, 'ip': ip})
        ctx = context.get_admin_context()
        with db_api.CONTEXT_WRITER.using(ctx):
            ctx.session.query(self.endpoint_model).filter(
                or_(self.endpoint_model.host == host,
                    self.endpoint_model.ip_address == ip)).delete()

    def _get_endpoints(self):
        LOG.debug("_get_endpoints() called")
        ctx = context.get_admin_context()
        with db_api.CONTEXT_READER.using(ctx):
            return ctx.session.query(self.endpoint_model).all()

    def _add_endpoint(self, ip, host, **kwargs):
        LOG.debug("_add_endpoint() called for ip %s", ip)
        ctx = context.get_admin_context()

        try:
            with db_api.CONTEXT_WRITER.using(ctx):
                endpoint = self.endpoint_model(ip_address=ip, host=host,
                                               **kwargs)
                endpoint.save(ctx.session)
        except db_exc.DBDuplicateEntry:
            with db_api.CONTEXT_READER.using(ctx):
                endpoint = (ctx.session.query(self.endpoint_model).
                            filter_by(ip_address=ip).one())
                LOG.warning("Endpoint with ip %s already exists", ip)
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

        host = kwargs.get('host')
        version = netaddr.IPAddress(tunnel_ip).version
        if version != cfg.CONF.ml2.overlay_ip_version:
            msg = (_("Tunnel IP version does not match ML2 "
                     "overlay_ip_version: %(overlay)s, host: %(host)s, "
                     "tunnel_ip: %(ip)s"),
                   {'overlay': cfg.CONF.ml2.overlay_ip_version,
                    'host': host, 'ip': tunnel_ip})
            raise exc.InvalidInput(error_message=msg)

        tunnel_type = kwargs.get('tunnel_type')
        if not tunnel_type:
            msg = _("Network type value needed by the ML2 plugin")
            raise exc.InvalidInput(error_message=msg)

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
            # 5. If the passed host had another ip in the DB the host-id has
            #    roamed to a different IP then delete any reference to the new
            #    local_ip or the host id. Don't notify tunnel_delete for the
            #    old IP since that one could have been taken by a different
            #    agent host-id (neutron-ovs-cleanup should be used to clean up
            #    the stale endpoints).
            #    Finally create a new endpoint for the (tunnel_ip, host).
            if host:
                host_endpoint = driver.obj.get_endpoint_by_host(host)
                ip_endpoint = driver.obj.get_endpoint_by_ip(tunnel_ip)

                if (ip_endpoint and ip_endpoint.host is None and
                        host_endpoint is None):
                    driver.obj.delete_endpoint(ip_endpoint.ip_address)
                elif (ip_endpoint and ip_endpoint.host != host):
                    LOG.info(
                        "Tunnel IP %(ip)s was used by host %(host)s and "
                        "will be assigned to %(new_host)s",
                        {'ip': ip_endpoint.ip_address,
                         'host': ip_endpoint.host,
                         'new_host': host})
                    driver.obj.delete_endpoint_by_host_or_ip(
                        host, ip_endpoint.ip_address)
                elif (host_endpoint and host_endpoint.ip_address != tunnel_ip):
                    # Notify all other listening agents to delete stale tunnels
                    self._notifier.tunnel_delete(
                        rpc_context, host_endpoint.ip_address, tunnel_type)
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
            msg = (_("Network type value %(type)s not supported, "
                     "host: %(host)s with tunnel IP: %(ip)s") %
                   {'type': tunnel_type,
                    'host': host or 'legacy mode (no host provided by agent)',
                    'ip': tunnel_ip})
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
