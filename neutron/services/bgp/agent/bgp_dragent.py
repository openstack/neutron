# Copyright 2016 Huawei Technologies India Pvt. Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import collections

from oslo_config import cfg
from oslo_log import log as logging
import oslo_messaging
from oslo_service import loopingcall
from oslo_service import periodic_task
from oslo_utils import importutils

from neutron.agent import rpc as agent_rpc
from neutron.common import constants
from neutron.common import rpc as n_rpc
from neutron.common import topics
from neutron.common import utils
from neutron import context
from neutron.extensions import bgp as bgp_ext
from neutron._i18n import _, _LE, _LI, _LW
from neutron import manager
from neutron.services.bgp.common import constants as bgp_consts
from neutron.services.bgp.driver import exceptions as driver_exc

LOG = logging.getLogger(__name__)


class BgpDrAgent(manager.Manager):
    """BGP Dynamic Routing agent service manager.

    Note that the public methods of this class are exposed as the server side
    of an rpc interface.  The neutron server uses
    neutron.api.rpc.agentnotifiers.bgp_dr_rpc_agent_api.
    BgpDrAgentNotifyApi as the client side to execute the methods
    here. For more information about changing rpc interfaces, see
    doc/source/devref/rpc_api.rst.

    API version history:
        1.0 initial Version
    """
    target = oslo_messaging.Target(version='1.0')

    def __init__(self, host, conf=None):
        super(BgpDrAgent, self).__init__()
        self.initialize_driver(conf)
        self.needs_resync_reasons = collections.defaultdict(list)
        self.needs_full_sync_reason = None

        self.cache = BgpSpeakerCache()
        self.context = context.get_admin_context_without_session()
        self.plugin_rpc = BgpDrPluginApi(bgp_consts.BGP_PLUGIN,
                                         self.context, host)

    def initialize_driver(self, conf):
        self.conf = conf or cfg.CONF.BGP
        try:
            self.dr_driver_cls = (
                    importutils.import_object(self.conf.bgp_speaker_driver,
                                              self.conf))
        except ImportError:
            LOG.exception(_LE("Error while importing BGP speaker driver %s"),
                          self.conf.bgp_speaker_driver)
            raise SystemExit(1)

    def _handle_driver_failure(self, bgp_speaker_id, method, driver_exec):
        self.schedule_resync(reason=driver_exec,
                             speaker_id=bgp_speaker_id)
        LOG.error(_LE('Call to driver for BGP Speaker %(bgp_speaker)s '
                      '%(method)s has failed with exception '
                      '%(driver_exec)s.'),
                  {'bgp_speaker': bgp_speaker_id,
                   'method': method,
                   'driver_exec': driver_exec})

    def after_start(self):
        self.run()
        LOG.info(_LI("BGP Dynamic Routing agent started"))

    def run(self):
        """Activate BGP Dynamic Routing agent."""
        self.sync_state(self.context)
        self.periodic_resync(self.context)

    @utils.synchronized('bgp-dragent')
    def sync_state(self, context, full_sync=None, bgp_speakers=None):
        try:
            hosted_bgp_speakers = self.plugin_rpc.get_bgp_speakers(context)
            hosted_bgp_speaker_ids = [bgp_speaker['id']
                                      for bgp_speaker in hosted_bgp_speakers]
            cached_bgp_speakers = self.cache.get_bgp_speaker_ids()
            for bgp_speaker_id in cached_bgp_speakers:
                if bgp_speaker_id not in hosted_bgp_speaker_ids:
                    self.remove_bgp_speaker_from_dragent(bgp_speaker_id)

            resync_all = not bgp_speakers or full_sync
            only_bs = set() if resync_all else set(bgp_speakers)
            for hosted_bgp_speaker in hosted_bgp_speakers:
                hosted_bs_id = hosted_bgp_speaker['id']
                if resync_all or hosted_bs_id in only_bs:
                    if not self.cache.is_bgp_speaker_added(hosted_bs_id):
                        self.safe_configure_dragent_for_bgp_speaker(
                            hosted_bgp_speaker)
                        continue
                    self.sync_bgp_speaker(hosted_bgp_speaker)
                    resync_reason = "Periodic route cache refresh"
                    self.schedule_resync(speaker_id=hosted_bs_id,
                                         reason=resync_reason)
        except Exception as e:
            self.schedule_full_resync(reason=e)
            LOG.error(_LE('Unable to sync BGP speaker state.'))

    def sync_bgp_speaker(self, bgp_speaker):
        # sync BGP Speakers
        bgp_peer_ips = set(
            [bgp_peer['peer_ip'] for bgp_peer in bgp_speaker['peers']])
        cached_bgp_peer_ips = set(
            self.cache.get_bgp_peer_ips(bgp_speaker['id']))
        removed_bgp_peer_ips = cached_bgp_peer_ips - bgp_peer_ips

        for bgp_peer_ip in removed_bgp_peer_ips:
            self.remove_bgp_peer_from_bgp_speaker(bgp_speaker['id'],
                                                  bgp_peer_ip)
        if bgp_peer_ips:
            self.add_bgp_peers_to_bgp_speaker(bgp_speaker)

        # sync advertise routes
        cached_adv_routes = self.cache.get_adv_routes(bgp_speaker['id'])
        adv_routes = bgp_speaker['advertised_routes']
        if cached_adv_routes == adv_routes:
            return

        for cached_route in cached_adv_routes:
            if cached_route not in adv_routes:
                self.withdraw_route_via_bgp_speaker(bgp_speaker['id'],
                                                    bgp_speaker['local_as'],
                                                    cached_route)

        self.advertise_routes_via_bgp_speaker(bgp_speaker)

    @utils.exception_logger()
    def _periodic_resync_helper(self, context):
        """Resync the BgpDrAgent state at the configured interval."""
        if self.needs_resync_reasons or self.needs_full_sync_reason:
            full_sync = self.needs_full_sync_reason
            reasons = self.needs_resync_reasons
            # Reset old reasons
            self.needs_full_sync_reason = None
            self.needs_resync_reasons = collections.defaultdict(list)
            if full_sync:
                LOG.debug("resync all: %(reason)s", {"reason": full_sync})
            for bgp_speaker, reason in reasons.items():
                LOG.debug("resync (%(bgp_speaker)s): %(reason)s",
                          {"reason": reason, "bgp_speaker": bgp_speaker})
            self.sync_state(
                context, full_sync=full_sync, bgp_speakers=reasons.keys())

    # NOTE: spacing is set 1 sec. The actual interval is controlled
    # by neutron/service.py which defaults to CONF.periodic_interval
    @periodic_task.periodic_task(spacing=1)
    def periodic_resync(self, context):
        LOG.debug("Started periodic resync.")
        self._periodic_resync_helper(context)

    @utils.synchronized('bgp-dr-agent')
    def bgp_speaker_create_end(self, context, payload):
        """Handle bgp_speaker_create_end notification event."""
        bgp_speaker_id = payload['bgp_speaker']['id']
        LOG.debug('Received BGP speaker create notification for '
                  'speaker_id=%(speaker_id)s from the neutron server.',
                  {'speaker_id': bgp_speaker_id})
        self.add_bgp_speaker_helper(bgp_speaker_id)

    @utils.synchronized('bgp-dr-agent')
    def bgp_speaker_remove_end(self, context, payload):
        """Handle bgp_speaker_create_end notification event."""

        bgp_speaker_id = payload['bgp_speaker']['id']
        LOG.debug('Received BGP speaker remove notification for '
                  'speaker_id=%(speaker_id)s from the neutron server.',
                  {'speaker_id': bgp_speaker_id})
        self.remove_bgp_speaker_from_dragent(bgp_speaker_id)

    @utils.synchronized('bgp-dr-agent')
    def bgp_peer_association_end(self, context, payload):
        """Handle bgp_peer_association_end notification event."""

        bgp_peer_id = payload['bgp_peer']['peer_id']
        bgp_speaker_id = payload['bgp_peer']['speaker_id']
        LOG.debug('Received BGP peer associate notification for '
                  'speaker_id=%(speaker_id)s peer_id=%(peer_id)s '
                  'from the neutron server.',
                  {'speaker_id': bgp_speaker_id,
                   'peer_id': bgp_peer_id})
        self.add_bgp_peer_helper(bgp_speaker_id, bgp_peer_id)

    @utils.synchronized('bgp-dr-agent')
    def bgp_peer_disassociation_end(self, context, payload):
        """Handle bgp_peer_disassociation_end notification event."""

        bgp_peer_ip = payload['bgp_peer']['peer_ip']
        bgp_speaker_id = payload['bgp_peer']['speaker_id']
        LOG.debug('Received BGP peer disassociate notification for '
                  'speaker_id=%(speaker_id)s peer_ip=%(peer_ip)s '
                  'from the neutron server.',
                  {'speaker_id': bgp_speaker_id,
                   'peer_ip': bgp_peer_ip})
        self.remove_bgp_peer_from_bgp_speaker(bgp_speaker_id, bgp_peer_ip)

    @utils.synchronized('bgp-dr-agent')
    def bgp_routes_advertisement_end(self, context, payload):
        """Handle bgp_routes_advertisement_end notification event."""

        bgp_speaker_id = payload['advertise_routes']['speaker_id']
        LOG.debug('Received routes advertisement end notification '
                  'for speaker_id=%(speaker_id)s from the neutron server.',
                  {'speaker_id': bgp_speaker_id})
        routes = payload['advertise_routes']['routes']
        self.add_routes_helper(bgp_speaker_id, routes)

    @utils.synchronized('bgp-dr-agent')
    def bgp_routes_withdrawal_end(self, context, payload):
        """Handle bgp_routes_withdrawal_end notification event."""

        bgp_speaker_id = payload['withdraw_routes']['speaker_id']
        LOG.debug('Received route withdrawal notification for '
                  'speaker_id=%(speaker_id)s from the neutron server.',
                  {'speaker_id': bgp_speaker_id})
        routes = payload['withdraw_routes']['routes']
        self.withdraw_routes_helper(bgp_speaker_id, routes)

    def add_bgp_speaker_helper(self, bgp_speaker_id):
        """Add BGP speaker."""
        bgp_speaker = self.safe_get_bgp_speaker_info(bgp_speaker_id)
        if bgp_speaker:
            self.add_bgp_speaker_on_dragent(bgp_speaker)

    def add_bgp_peer_helper(self, bgp_speaker_id, bgp_peer_id):
        """Add BGP peer."""
        # Ideally BGP Speaker must be added by now, If not then let's
        # re-sync.
        if not self.cache.is_bgp_speaker_added(bgp_speaker_id):
            self.schedule_resync(speaker_id=bgp_speaker_id,
                                 reason="BGP Speaker Out-of-sync")
            return

        bgp_peer = self.safe_get_bgp_peer_info(bgp_speaker_id,
                                               bgp_peer_id)
        if bgp_peer:
            bgp_speaker_as = self.cache.get_bgp_speaker_local_as(
                                                            bgp_speaker_id)
            self.add_bgp_peer_to_bgp_speaker(bgp_speaker_id,
                                             bgp_speaker_as,
                                             bgp_peer)

    def add_routes_helper(self, bgp_speaker_id, routes):
        """Advertise routes to BGP speaker."""
        # Ideally BGP Speaker must be added by now, If not then let's
        # re-sync.
        if not self.cache.is_bgp_speaker_added(bgp_speaker_id):
            self.schedule_resync(speaker_id=bgp_speaker_id,
                                 reason="BGP Speaker Out-of-sync")
            return

        bgp_speaker_as = self.cache.get_bgp_speaker_local_as(bgp_speaker_id)
        for route in routes:
            self.advertise_route_via_bgp_speaker(bgp_speaker_id,
                                                 bgp_speaker_as,
                                                 route)
            if self.is_resync_scheduled(bgp_speaker_id):
                break

    def withdraw_routes_helper(self, bgp_speaker_id, routes):
        """Withdraw routes advertised by BGP speaker."""
        # Ideally BGP Speaker must be added by now, If not then let's
        # re-sync.
        if not self.cache.is_bgp_speaker_added(bgp_speaker_id):
            self.schedule_resync(speaker_id=bgp_speaker_id,
                                 reason="BGP Speaker Out-of-sync")
            return

        bgp_speaker_as = self.cache.get_bgp_speaker_local_as(bgp_speaker_id)
        for route in routes:
            self.withdraw_route_via_bgp_speaker(bgp_speaker_id,
                                                bgp_speaker_as,
                                                route)
            if self.is_resync_scheduled(bgp_speaker_id):
                break

    def safe_get_bgp_speaker_info(self, bgp_speaker_id):
        try:
            bgp_speaker = self.plugin_rpc.get_bgp_speaker_info(self.context,
                                                               bgp_speaker_id)
            if not bgp_speaker:
                LOG.warning(_LW('BGP Speaker %s has been deleted.'),
                            bgp_speaker_id)
            return bgp_speaker
        except Exception as e:
            self.schedule_resync(speaker_id=bgp_speaker_id,
                                 reason=e)
            LOG.error(_LE('BGP Speaker %(bgp_speaker)s info call '
                          'failed with reason=%(e)s.'),
                      {'bgp_speaker': bgp_speaker_id, 'e': e})

    def safe_get_bgp_peer_info(self, bgp_speaker_id, bgp_peer_id):
        try:
            bgp_peer = self.plugin_rpc.get_bgp_peer_info(self.context,
                                                         bgp_peer_id)
            if not bgp_peer:
                LOG.warning(_LW('BGP Peer %s has been deleted.'), bgp_peer)
            return bgp_peer
        except Exception as e:
            self.schedule_resync(speaker_id=bgp_speaker_id,
                                 reason=e)
            LOG.error(_LE('BGP peer %(bgp_peer)s info call '
                          'failed with reason=%(e)s.'),
                      {'bgp_peer': bgp_peer_id, 'e': e})

    @utils.exception_logger()
    def safe_configure_dragent_for_bgp_speaker(self, bgp_speaker):
        try:
            self.add_bgp_speaker_on_dragent(bgp_speaker)
        except (bgp_ext.BgpSpeakerNotFound, RuntimeError):
            LOG.warning(_LW('BGP speaker %s may have been deleted and its '
                            'resources may have already been disposed.'),
                     bgp_speaker['id'])

    def add_bgp_speaker_on_dragent(self, bgp_speaker):
        # Caching BGP speaker details in BGPSpeakerCache. Will be used
        # during smooth.
        self.cache.put_bgp_speaker(bgp_speaker)

        LOG.debug('Calling driver for adding BGP speaker %(speaker_id)s,'
                  ' speaking for local_as %(local_as)s',
                  {'speaker_id': bgp_speaker['id'],
                   'local_as': bgp_speaker['local_as']})
        try:
            self.dr_driver_cls.add_bgp_speaker(bgp_speaker['local_as'])
        except driver_exc.BgpSpeakerAlreadyScheduled:
            return
        except Exception as e:
            self._handle_driver_failure(bgp_speaker['id'],
                                        'add_bgp_speaker', e)

        # Add peer and route information to the driver.
        self.add_bgp_peers_to_bgp_speaker(bgp_speaker)
        self.advertise_routes_via_bgp_speaker(bgp_speaker)
        self.schedule_resync(speaker_id=bgp_speaker['id'],
                             reason="Periodic route cache refresh")

    def remove_bgp_speaker_from_dragent(self, bgp_speaker_id):
        if self.cache.is_bgp_speaker_added(bgp_speaker_id):
            bgp_speaker_as = self.cache.get_bgp_speaker_local_as(
                                                        bgp_speaker_id)
            self.cache.remove_bgp_speaker_by_id(bgp_speaker_id)

            LOG.debug('Calling driver for removing BGP speaker %(speaker_as)s',
                      {'speaker_as': bgp_speaker_as})
            try:
                self.dr_driver_cls.delete_bgp_speaker(bgp_speaker_as)
            except Exception as e:
                self._handle_driver_failure(bgp_speaker_id,
                                            'remove_bgp_speaker', e)
            return

        # Ideally, only the added speakers can be removed by the neutron
        # server. Looks like there might be some synchronization
        # issue between the server and the agent. Let's initiate a re-sync
        # to resolve the issue.
        self.schedule_resync(speaker_id=bgp_speaker_id,
                             reason="BGP Speaker Out-of-sync")

    def add_bgp_peers_to_bgp_speaker(self, bgp_speaker):
        for bgp_peer in bgp_speaker['peers']:
            self.add_bgp_peer_to_bgp_speaker(bgp_speaker['id'],
                                             bgp_speaker['local_as'],
                                             bgp_peer)
            if self.is_resync_scheduled(bgp_speaker['id']):
                break

    def add_bgp_peer_to_bgp_speaker(self, bgp_speaker_id,
                                    bgp_speaker_as, bgp_peer):
        if self.cache.get_bgp_peer_by_ip(bgp_speaker_id, bgp_peer['peer_ip']):
            return

        self.cache.put_bgp_peer(bgp_speaker_id, bgp_peer)

        LOG.debug('Calling driver interface for adding BGP peer %(peer_ip)s '
                  'remote_as=%(remote_as)s to BGP Speaker running for '
                  'local_as=%(local_as)d',
                  {'peer_ip': bgp_peer['peer_ip'],
                   'remote_as': bgp_peer['remote_as'],
                   'local_as': bgp_speaker_as})
        try:
            self.dr_driver_cls.add_bgp_peer(bgp_speaker_as,
                                            bgp_peer['peer_ip'],
                                            bgp_peer['remote_as'],
                                            bgp_peer['auth_type'],
                                            bgp_peer['password'])
        except Exception as e:
            self._handle_driver_failure(bgp_speaker_id,
                                        'add_bgp_peer', e)

    def remove_bgp_peer_from_bgp_speaker(self, bgp_speaker_id, bgp_peer_ip):
        # Ideally BGP Speaker must be added by now, If not then let's
        # re-sync.
        if not self.cache.is_bgp_speaker_added(bgp_speaker_id):
            self.schedule_resync(speaker_id=bgp_speaker_id,
                                 reason="BGP Speaker Out-of-sync")
            return

        if self.cache.is_bgp_peer_added(bgp_speaker_id, bgp_peer_ip):
            self.cache.remove_bgp_peer_by_ip(bgp_speaker_id, bgp_peer_ip)

            bgp_speaker_as = self.cache.get_bgp_speaker_local_as(
                                                        bgp_speaker_id)

            LOG.debug('Calling driver interface to remove BGP peer '
                      '%(peer_ip)s from BGP Speaker running for '
                      'local_as=%(local_as)d',
                      {'peer_ip': bgp_peer_ip, 'local_as': bgp_speaker_as})
            try:
                self.dr_driver_cls.delete_bgp_peer(bgp_speaker_as,
                                                   bgp_peer_ip)
            except Exception as e:
                self._handle_driver_failure(bgp_speaker_id,
                                            'remove_bgp_peer', e)
            return

        # Ideally, only the added peers can be removed by the neutron
        # server. Looks like there might be some synchronization
        # issue between the server and the agent. Let's initiate a re-sync
        # to resolve the issue.
        self.schedule_resync(speaker_id=bgp_speaker_id,
                             reason="BGP Peer Out-of-sync")

    def advertise_routes_via_bgp_speaker(self, bgp_speaker):
        for route in bgp_speaker['advertised_routes']:
            self.advertise_route_via_bgp_speaker(bgp_speaker['id'],
                                                 bgp_speaker['local_as'],
                                                 route)
            if self.is_resync_scheduled(bgp_speaker['id']):
                break

    def advertise_route_via_bgp_speaker(self, bgp_speaker_id,
                                        bgp_speaker_as, route):
        if self.cache.is_route_advertised(bgp_speaker_id, route):
            # Requested route already advertised. Hence, Nothing to be done.
            return
        self.cache.put_adv_route(bgp_speaker_id, route)

        LOG.debug('Calling driver for advertising prefix: %(cidr)s, '
                  'next_hop: %(nexthop)s',
                  {'cidr': route['destination'],
                   'nexthop': route['next_hop']})
        try:
            self.dr_driver_cls.advertise_route(bgp_speaker_as,
                                               route['destination'],
                                               route['next_hop'])
        except Exception as e:
            self._handle_driver_failure(bgp_speaker_id,
                                        'advertise_route', e)

    def withdraw_route_via_bgp_speaker(self, bgp_speaker_id,
                                       bgp_speaker_as, route):
        if self.cache.is_route_advertised(bgp_speaker_id, route):
            self.cache.remove_adv_route(bgp_speaker_id, route)
            LOG.debug('Calling driver for withdrawing prefix: %(cidr)s, '
                  'next_hop: %(nexthop)s',
                  {'cidr': route['destination'],
                   'nexthop': route['next_hop']})
            try:
                self.dr_driver_cls.withdraw_route(bgp_speaker_as,
                                                  route['destination'],
                                                  route['next_hop'])
            except Exception as e:
                self._handle_driver_failure(bgp_speaker_id,
                                            'withdraw_route', e)
            return

        # Ideally, only the advertised routes can be withdrawn by the
        # neutron server. Looks like there might be some synchronization
        # issue between the server and the agent. Let's initiate a re-sync
        # to resolve the issue.
        self.schedule_resync(speaker_id=bgp_speaker_id,
                             reason="Advertised routes Out-of-sync")

    def schedule_full_resync(self, reason):
        LOG.debug('Recording full resync request for all BGP Speakers '
                  'with reason=%s', reason)
        self.needs_full_sync_reason = reason

    def schedule_resync(self, reason, speaker_id):
        """Schedule a full resync for a given BGP Speaker.
        If no BGP Speaker is specified, resync all BGP Speakers.
        """
        LOG.debug('Recording resync request for BGP Speaker %s '
                  'with reason=%s', speaker_id, reason)
        self.needs_resync_reasons[speaker_id].append(reason)

    def is_resync_scheduled(self, bgp_speaker_id):
        if bgp_speaker_id not in self.needs_resync_reasons:
            return False

        reason = self.needs_resync_reasons[bgp_speaker_id]
        # Re-sync scheduled for the queried BGP speaker. No point
        # continuing further. Let's stop processing and wait for
        # re-sync to happen.
        LOG.debug('Re-sync already scheduled for BGP Speaker %s '
                  'with reason=%s', bgp_speaker_id, reason)
        return True


class BgpDrPluginApi(object):
    """Agent side of BgpDrAgent RPC API.

    This class implements the client side of an rpc interface.
    The server side of this interface can be found in
    neutron.api.rpc.handlers.bgp_speaker_rpc.BgpSpeakerRpcCallback.
    For more information about changing rpc interfaces, see
    doc/source/devref/rpc_api.rst.

    API version history:
        1.0 - Initial version.
    """
    def __init__(self, topic, context, host):
        self.context = context
        self.host = host
        target = oslo_messaging.Target(topic=topic, version='1.0')
        self.client = n_rpc.get_client(target)

    def get_bgp_speakers(self, context):
        """Make a remote process call to retrieve all BGP speakers info."""
        cctxt = self.client.prepare()
        return cctxt.call(context, 'get_bgp_speakers', host=self.host)

    def get_bgp_speaker_info(self, context, bgp_speaker_id):
        """Make a remote process call to retrieve a BGP speaker info."""
        cctxt = self.client.prepare()
        return cctxt.call(context, 'get_bgp_speaker_info',
                          bgp_speaker_id=bgp_speaker_id)

    def get_bgp_peer_info(self, context, bgp_peer_id):
        """Make a remote process call to retrieve a BGP peer info."""
        cctxt = self.client.prepare()
        return cctxt.call(context, 'get_bgp_peer_info',
                          bgp_peer_id=bgp_peer_id)


class BgpSpeakerCache(object):
    """Agent cache of the current BGP speaker state.

    This class is designed to support the advertisement for
    multiple BGP speaker via a single driver interface.

    Version history:
        1.0 - Initial version for caching the state of BGP speaker.
    """
    def __init__(self):
        self.cache = {}

    def get_bgp_speaker_ids(self):
        return self.cache.keys()

    def put_bgp_speaker(self, bgp_speaker):
        if bgp_speaker['id'] in self.cache:
            self.remove_bgp_speaker_by_id(self.cache[bgp_speaker['id']])
        self.cache[bgp_speaker['id']] = {'bgp_speaker': bgp_speaker,
                                         'peers': {},
                                         'advertised_routes': []}

    def get_bgp_speaker_by_id(self, bgp_speaker_id):
        if bgp_speaker_id in self.cache:
            return self.cache[bgp_speaker_id]['bgp_speaker']

    def get_bgp_speaker_local_as(self, bgp_speaker_id):
        bgp_speaker = self.get_bgp_speaker_by_id(bgp_speaker_id)
        if bgp_speaker:
            return bgp_speaker['local_as']

    def is_bgp_speaker_added(self, bgp_speaker_id):
        return self.get_bgp_speaker_by_id(bgp_speaker_id)

    def remove_bgp_speaker_by_id(self, bgp_speaker_id):
        if bgp_speaker_id in self.cache:
            del self.cache[bgp_speaker_id]

    def put_bgp_peer(self, bgp_speaker_id, bgp_peer):
        if bgp_peer['peer_ip'] in self.get_bgp_peer_ips(bgp_speaker_id):
            del self.cache[bgp_speaker_id]['peers'][bgp_peer['peer_ip']]

        self.cache[bgp_speaker_id]['peers'][bgp_peer['peer_ip']] = bgp_peer

    def is_bgp_peer_added(self, bgp_speaker_id, bgp_peer_ip):
        return self.get_bgp_peer_by_ip(bgp_speaker_id, bgp_peer_ip)

    def get_bgp_peer_ips(self, bgp_speaker_id):
        bgp_speaker = self.get_bgp_speaker_by_id(bgp_speaker_id)
        if bgp_speaker:
            return self.cache[bgp_speaker_id]['peers'].keys()

    def get_bgp_peer_by_ip(self, bgp_speaker_id, bgp_peer_ip):
        bgp_speaker = self.get_bgp_speaker_by_id(bgp_speaker_id)
        if bgp_speaker:
            return self.cache[bgp_speaker_id]['peers'].get(bgp_peer_ip)

    def remove_bgp_peer_by_ip(self, bgp_speaker_id, bgp_peer_ip):
        if bgp_peer_ip in self.get_bgp_peer_ips(bgp_speaker_id):
            del self.cache[bgp_speaker_id]['peers'][bgp_peer_ip]

    def put_adv_route(self, bgp_speaker_id, route):
        self.cache[bgp_speaker_id]['advertised_routes'].append(route)

    def is_route_advertised(self, bgp_speaker_id, route):
        routes = self.cache[bgp_speaker_id]['advertised_routes']
        for r in routes:
            if r['destination'] == route['destination'] and (
                    r['next_hop'] == route['next_hop']):
                return True
        return False

    def remove_adv_route(self, bgp_speaker_id, route):
        routes = self.cache[bgp_speaker_id]['advertised_routes']
        updated_routes = [r for r in routes if (
            r['destination'] != route['destination'])]
        self.cache[bgp_speaker_id]['advertised_routes'] = updated_routes

    def get_adv_routes(self, bgp_speaker_id):
        return self.cache[bgp_speaker_id]['advertised_routes']

    def get_state(self):
        bgp_speaker_ids = self.get_bgp_speaker_ids()
        num_bgp_speakers = len(bgp_speaker_ids)
        num_bgp_peers = 0
        num_advertised_routes = 0
        for bgp_speaker_id in bgp_speaker_ids:
            bgp_speaker = self.get_bgp_speaker_by_id(bgp_speaker_id)
            num_bgp_peers += len(bgp_speaker['peers'])
            num_advertised_routes += len(bgp_speaker['advertised_routes'])
        return {'bgp_speakers': num_bgp_speakers,
                'bgp_peers': num_bgp_peers,
                'advertise_routes': num_advertised_routes}


class BgpDrAgentWithStateReport(BgpDrAgent):
    def __init__(self, host, conf=None):
        super(BgpDrAgentWithStateReport,
              self).__init__(host, conf)
        self.state_rpc = agent_rpc.PluginReportStateAPI(topics.PLUGIN)
        self.agent_state = {
            'agent_type': bgp_consts.AGENT_TYPE_BGP_ROUTING,
            'binary': 'neutron-bgp-dragent',
            'configurations': {},
            'host': host,
            'topic': bgp_consts.BGP_DRAGENT,
            'start_flag': True}
        report_interval = cfg.CONF.AGENT.report_interval
        if report_interval:
            self.heartbeat = loopingcall.FixedIntervalLoopingCall(
                self._report_state)
            self.heartbeat.start(interval=report_interval)

    def _report_state(self):
        LOG.debug("Report state task started")
        try:
            self.agent_state.get('configurations').update(
                self.cache.get_state())
            ctx = context.get_admin_context_without_session()
            agent_status = self.state_rpc.report_state(ctx, self.agent_state,
                                                       True)
            if agent_status == constants.AGENT_REVIVED:
                LOG.info(_LI("Agent has just been revived. "
                             "Scheduling full sync"))
                self.schedule_full_resync(
                        reason=_("Agent has just been revived"))
        except AttributeError:
            # This means the server does not support report_state
            LOG.warning(_LW("Neutron server does not support state report. "
                            "State report for this agent will be disabled."))
            self.heartbeat.stop()
            self.run()
            return
        except Exception:
            LOG.exception(_LE("Failed reporting state!"))
            return
        if self.agent_state.pop('start_flag', None):
            self.run()

    def agent_updated(self, context, payload):
        """Handle the agent_updated notification event."""
        self.schedule_full_resync(
                reason=_("BgpDrAgent updated: %s") % payload)
        LOG.info(_LI("agent_updated by server side %s!"), payload)

    def after_start(self):
        LOG.info(_LI("BGP dynamic routing agent started"))
