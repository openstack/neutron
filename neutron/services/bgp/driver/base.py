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

import abc
import six


@six.add_metaclass(abc.ABCMeta)
class BgpDriverBase(object):
    """Base class for BGP Speaking drivers.

    Any class which provides BGP functionality should extend this
    defined base class.
    """

    @abc.abstractmethod
    def add_bgp_speaker(self, speaker_as):
        """Add a BGP speaker.

        :param speaker_as: Specifies BGP Speaker autonomous system number.
                           Must be an integer between MIN_ASNUM and MAX_ASNUM.
        :type speaker_as: integer
        :raises: BgpSpeakerAlreadyScheduled, BgpSpeakerMaxScheduled,
                 InvalidParamType, InvalidParamRange
        """

    @abc.abstractmethod
    def delete_bgp_speaker(self, speaker_as):
        """Deletes BGP speaker.

        :param speaker_as: Specifies BGP Speaker autonomous system number.
                           Must be an integer between MIN_ASNUM and MAX_ASNUM.
        :type speaker_as: integer
        :raises: BgpSpeakerNotAdded
        """

    @abc.abstractmethod
    def add_bgp_peer(self, speaker_as, peer_ip, peer_as,
                     auth_type='none', password=None):
        """Add a new BGP peer.

        :param speaker_as: Specifies BGP Speaker autonomous system number.
                           Must be an integer between MIN_ASNUM and MAX_ASNUM.
        :type speaker_as: integer
        :param peer_ip: Specifies the IP address of the peer.
        :type peer_ip: string
        :param peer_as: Specifies Autonomous Number of the peer.
                        Must be an integer between MIN_ASNUM and MAX_ASNUM.
        :type peer_as: integer
        :param auth_type: Specifies authentication type.
                          By default, authentication will be disabled.
        :type auth_type: value in SUPPORTED_AUTH_TYPES
        :param password: Authentication password.By default, authentication
                         will be disabled.
        :type password: string
        :raises: BgpSpeakerNotAdded, InvalidParamType, InvalidParamRange,
                 InvaildAuthType, PasswordNotSpecified
        """

    @abc.abstractmethod
    def delete_bgp_peer(self, speaker_as, peer_ip):
        """Delete a BGP peer associated with the given peer IP

        :param speaker_as: Specifies BGP Speaker autonomous system number.
                           Must be an integer between MIN_ASNUM and MAX_ASNUM.
        :type speaker_as: integer
        :param peer_ip: Specifies the IP address of the peer. Must be the
                        string representation of an IP address.
        :type peer_ip: string
        :raises: BgpSpeakerNotAdded, BgpPeerNotAdded
        """

    @abc.abstractmethod
    def advertise_route(self, speaker_as, cidr, nexthop):
        """Add a new prefix to advertise.

        :param speaker_as: Specifies BGP Speaker autonomous system number.
                           Must be an integer between MIN_ASNUM and MAX_ASNUM.
        :type speaker_as: integer
        :param cidr: CIDR of the network to advertise. Must be the string
                     representation of an IP network (e.g., 10.1.1.0/24)
        :type cidr: string
        :param nexthop: Specifies the next hop address for the above
                        prefix.
        :type nexthop: string
        :raises: BgpSpeakerNotAdded, InvalidParamType
        """

    @abc.abstractmethod
    def withdraw_route(self, speaker_as, cidr, nexthop=None):
        """Withdraw an advertised prefix.

        :param speaker_as: Specifies BGP Speaker autonomous system number.
                           Must be an integer between MIN_ASNUM and MAX_ASNUM.
        :type speaker_as: integer
        :param cidr: CIDR of the network to withdraw. Must be the string
                     representation of an IP network (e.g., 10.1.1.0/24)
        :type cidr: string
        :param nexthop: Specifies the next hop address for the above
                        prefix.
        :type nexthop: string
        :raises: BgpSpeakerNotAdded, RouteNotAdvertised, InvalidParamType
        """

    @abc.abstractmethod
    def get_bgp_speaker_statistics(self, speaker_as):
        """Collect BGP Speaker statistics.

        :param speaker_as: Specifies BGP Speaker autonomous system number.
                           Must be an integer between MIN_ASNUM and MAX_ASNUM.
        :type speaker_as: integer
        :raises: BgpSpeakerNotAdded
        :returns: bgp_speaker_stats: string
        """

    @abc.abstractmethod
    def get_bgp_peer_statistics(self, speaker_as, peer_ip, peer_as):
        """Collect BGP Peer statistics.

        :param speaker_as: Specifies BGP Speaker autonomous system number.
                           Must be an integer between MIN_ASNUM and MAX_ASNUM.
        :type speaker_as: integer
        :param peer_ip: Specifies the IP address of the peer.
        :type peer_ip: string
        :param peer_as: Specifies the AS number of the peer. Must be an
                        integer between MIN_ASNUM and MAX_ASNUM.
        :type peer_as: integer                    .
        :raises: BgpSpeakerNotAdded, BgpPeerNotAdded
        :returns: bgp_peer_stats: string
        """
