# Copyright 2016 Huawei Technologies India Pvt. Ltd.
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

from oslo_log import log as logging
from oslo_utils import encodeutils
from ryu.services.protocols.bgp import bgpspeaker
from ryu.services.protocols.bgp.rtconf.neighbors import CONNECT_MODE_ACTIVE

from neutron.services.bgp.driver import base
from neutron.services.bgp.driver import exceptions as bgp_driver_exc
from neutron.services.bgp.driver import utils
from neutron._i18n import _LE, _LI

LOG = logging.getLogger(__name__)


# Function for logging BGP peer and path changes.
def bgp_peer_down_cb(remote_ip, remote_as):
    LOG.info(_LI('BGP Peer %(peer_ip)s for remote_as=%(peer_as)d went DOWN.'),
             {'peer_ip': remote_ip, 'peer_as': remote_as})


def bgp_peer_up_cb(remote_ip, remote_as):
    LOG.info(_LI('BGP Peer %(peer_ip)s for remote_as=%(peer_as)d is UP.'),
             {'peer_ip': remote_ip, 'peer_as': remote_as})


def best_path_change_cb(event):
    LOG.info(_LI("Best path change observed. cidr=%(prefix)s, "
                 "nexthop=%(nexthop)s, remote_as=%(remote_as)d, "
                 "is_withdraw=%(is_withdraw)s"),
             {'prefix': event.prefix, 'nexthop': event.nexthop,
              'remote_as': event.remote_as,
              'is_withdraw': event.is_withdraw})


class RyuBgpDriver(base.BgpDriverBase):
    """BGP speaker implementation via Ryu."""

    def __init__(self, cfg):
        LOG.info(_LI('Initializing Ryu driver for BGP Speaker functionality.'))
        self._read_config(cfg)

        # Note: Even though Ryu can only support one BGP speaker as of now,
        # we have tried making the framework generic for the future purposes.
        self.cache = utils.BgpMultiSpeakerCache()

    def _read_config(self, cfg):
        if cfg is None or cfg.bgp_router_id is None:
            # If either cfg or router_id is not specified, raise voice
            LOG.error(_LE('BGP router-id MUST be specified for the correct '
                          'functional working.'))
        else:
            self.routerid = cfg.bgp_router_id
            LOG.info(_LI('Initialized Ryu BGP Speaker driver interface with '
                         'bgp_router_id=%s'), self.routerid)

    def add_bgp_speaker(self, speaker_as):
        curr_speaker = self.cache.get_bgp_speaker(speaker_as)
        if curr_speaker is not None:
            raise bgp_driver_exc.BgpSpeakerAlreadyScheduled(
                                                    current_as=speaker_as,
                                                    rtid=self.routerid)

        # Ryu can only support One speaker
        if self.cache.get_hosted_bgp_speakers_count() == 1:
            raise bgp_driver_exc.BgpSpeakerMaxScheduled(count=1)

        # Validate input parameters.
        # speaker_as must be an integer in the allowed range.
        utils.validate_as_num('local_as', speaker_as)

        # Notify Ryu about BGP Speaker addition.
        # Please note: Since, only the route-advertisement support is
        # implemented we are explicitly setting the bgp_server_port
        # attribute to 0 which disables listening on port 179.
        curr_speaker = bgpspeaker.BGPSpeaker(as_number=speaker_as,
                             router_id=self.routerid, bgp_server_port=0,
                             best_path_change_handler=best_path_change_cb,
                             peer_down_handler=bgp_peer_down_cb,
                             peer_up_handler=bgp_peer_up_cb)
        LOG.info(_LI('Added BGP Speaker for local_as=%(as)d with '
                     'router_id= %(rtid)s.'),
                 {'as': speaker_as, 'rtid': self.routerid})

        self.cache.put_bgp_speaker(speaker_as, curr_speaker)

    def delete_bgp_speaker(self, speaker_as):
        curr_speaker = self.cache.get_bgp_speaker(speaker_as)
        if not curr_speaker:
            raise bgp_driver_exc.BgpSpeakerNotAdded(local_as=speaker_as,
                                                    rtid=self.routerid)
        # Notify Ryu about BGP Speaker deletion
        curr_speaker.shutdown()
        LOG.info(_LI('Removed BGP Speaker for local_as=%(as)d with '
                     'router_id=%(rtid)s.'),
                 {'as': speaker_as, 'rtid': self.routerid})
        self.cache.remove_bgp_speaker(speaker_as)

    def add_bgp_peer(self, speaker_as, peer_ip, peer_as,
                     auth_type='none', password=None):
        curr_speaker = self.cache.get_bgp_speaker(speaker_as)
        if not curr_speaker:
            raise bgp_driver_exc.BgpSpeakerNotAdded(local_as=speaker_as,
                                                    rtid=self.routerid)

        # Validate peer_ip and peer_as.
        utils.validate_as_num('remote_as', peer_as)
        utils.validate_string(peer_ip)
        utils.validate_auth(auth_type, password)
        if password is not None:
            password = encodeutils.to_utf8(password)

        # Notify Ryu about BGP Peer addition
        curr_speaker.neighbor_add(address=peer_ip,
                                  remote_as=peer_as,
                                  password=password,
                                  connect_mode=CONNECT_MODE_ACTIVE)
        LOG.info(_LI('Added BGP Peer %(peer)s for remote_as=%(as)d to '
                     'BGP Speaker running for local_as=%(local_as)d.'),
                 {'peer': peer_ip, 'as': peer_as, 'local_as': speaker_as})

    def delete_bgp_peer(self, speaker_as, peer_ip):
        curr_speaker = self.cache.get_bgp_speaker(speaker_as)
        if not curr_speaker:
            raise bgp_driver_exc.BgpSpeakerNotAdded(local_as=speaker_as,
                                                    rtid=self.routerid)
        # Validate peer_ip. It must be a string.
        utils.validate_string(peer_ip)

        # Notify Ryu about BGP Peer removal
        curr_speaker.neighbor_del(address=peer_ip)
        LOG.info(_LI('Removed BGP Peer %(peer)s from BGP Speaker '
                     'running for local_as=%(local_as)d.'),
                 {'peer': peer_ip, 'local_as': speaker_as})

    def advertise_route(self, speaker_as, cidr, nexthop):
        curr_speaker = self.cache.get_bgp_speaker(speaker_as)
        if not curr_speaker:
            raise bgp_driver_exc.BgpSpeakerNotAdded(local_as=speaker_as,
                                                    rtid=self.routerid)

        # Validate cidr and nexthop. Both must be strings.
        utils.validate_string(cidr)
        utils.validate_string(nexthop)

        # Notify Ryu about route advertisement
        curr_speaker.prefix_add(prefix=cidr, next_hop=nexthop)
        LOG.info(_LI('Route cidr=%(prefix)s, nexthop=%(nexthop)s is '
                     'advertised for BGP Speaker running for '
                     'local_as=%(local_as)d.'),
                 {'prefix': cidr, 'nexthop': nexthop, 'local_as': speaker_as})

    def withdraw_route(self, speaker_as, cidr, nexthop=None):
        curr_speaker = self.cache.get_bgp_speaker(speaker_as)
        if not curr_speaker:
            raise bgp_driver_exc.BgpSpeakerNotAdded(local_as=speaker_as,
                                                    rtid=self.routerid)
        # Validate cidr. It must be a string.
        utils.validate_string(cidr)

        # Notify Ryu about route withdrawal
        curr_speaker.prefix_del(prefix=cidr)
        LOG.info(_LI('Route cidr=%(prefix)s is withdrawn from BGP Speaker '
                     'running for local_as=%(local_as)d.'),
                 {'prefix': cidr, 'local_as': speaker_as})

    def get_bgp_speaker_statistics(self, speaker_as):
        LOG.info(_LI('Collecting BGP Speaker statistics for local_as=%d.'),
                 speaker_as)
        curr_speaker = self.cache.get_bgp_speaker(speaker_as)
        if not curr_speaker:
            raise bgp_driver_exc.BgpSpeakerNotAdded(local_as=speaker_as,
                                                    rtid=self.routerid)

        # TODO(vikram): Filter and return the necessary information.
        # Will be done as part of new RFE requirement
        # https://bugs.launchpad.net/neutron/+bug/1527993
        return curr_speaker.neighbor_state_get()

    def get_bgp_peer_statistics(self, speaker_as, peer_ip):
        LOG.info(_LI('Collecting BGP Peer statistics for peer_ip=%(peer)s, '
                     'running in speaker_as=%(speaker_as)d '),
                 {'peer': peer_ip, 'speaker_as': speaker_as})
        curr_speaker = self.cache.get_bgp_speaker(speaker_as)
        if not curr_speaker:
            raise bgp_driver_exc.BgpSpeakerNotAdded(local_as=speaker_as,
                                                    rtid=self.routerid)

        # TODO(vikram): Filter and return the necessary information.
        # Will be done as part of new RFE requirement
        # https://bugs.launchpad.net/neutron/+bug/1527993
        return curr_speaker.neighbor_state_get(address=peer_ip)
