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

import oslo_messaging

from neutron.common import rpc as n_rpc
from neutron.services.bgp.common import constants as bgp_consts


class BgpDrAgentNotifyApi(object):
    """API for plugin to notify BGP DrAgent.

    This class implements the client side of an rpc interface.  The server side
    is neutron.services.bgp_speaker.agent.bgp_dragent.BgpDrAgent. For more
    information about rpc interfaces, please see doc/source/devref/rpc_api.rst.
    """

    def __init__(self, topic=bgp_consts.BGP_DRAGENT):
        target = oslo_messaging.Target(topic=topic, version='1.0')
        self.client = n_rpc.get_client(target)
        self.topic = topic

    def bgp_routes_advertisement(self, context, bgp_speaker_id,
                                 routes, host):
        """Tell BgpDrAgent to begin advertising the given route.

        Invoked on FIP association, adding router port to a tenant network,
        and new DVR port-host bindings, and subnet creation(?).
        """
        self._notification_host_cast(context, 'bgp_routes_advertisement_end',
                {'advertise_routes': {'speaker_id': bgp_speaker_id,
                                      'routes': routes}}, host)

    def bgp_routes_withdrawal(self, context, bgp_speaker_id,
                              routes, host):
        """Tell BgpDrAgent to stop advertising the given route.

        Invoked on FIP disassociation, removal of a router port on a
        network, and removal of DVR port-host binding, and subnet delete(?).
        """
        self._notification_host_cast(context, 'bgp_routes_withdrawal_end',
                {'withdraw_routes': {'speaker_id': bgp_speaker_id,
                                     'routes': routes}}, host)

    def bgp_peer_disassociated(self, context, bgp_speaker_id,
                               bgp_peer_ip, host):
        """Tell BgpDrAgent about a new BGP Peer association.

        This effectively tells the BgpDrAgent to stop a peering session.
        """
        self._notification_host_cast(context, 'bgp_peer_disassociation_end',
                {'bgp_peer': {'speaker_id': bgp_speaker_id,
                              'peer_ip': bgp_peer_ip}}, host)

    def bgp_peer_associated(self, context, bgp_speaker_id,
                            bgp_peer_id, host):
        """Tell BgpDrAgent about a BGP Peer disassociation.

        This effectively tells the bgp_dragent to open a peering session.
        """
        self._notification_host_cast(context, 'bgp_peer_association_end',
                {'bgp_peer': {'speaker_id': bgp_speaker_id,
                              'peer_id': bgp_peer_id}}, host)

    def bgp_speaker_created(self, context, bgp_speaker_id, host):
        """Tell BgpDrAgent about the creation of a BGP Speaker.

        Because a BGP Speaker can be created with BgpPeer binding in place,
        we need to inform the BgpDrAgent of a new BGP Speaker in case a
        peering session needs to opened immediately.
        """
        self._notification_host_cast(context, 'bgp_speaker_create_end',
                {'bgp_speaker': {'id': bgp_speaker_id}}, host)

    def bgp_speaker_removed(self, context, bgp_speaker_id, host):
        """Tell BgpDrAgent about the removal of a BGP Speaker.

        Because a BGP Speaker can be removed with BGP Peer binding in
        place, we need to inform the BgpDrAgent of the removal of a
        BGP Speaker in case peering sessions need to be stopped.
        """
        self._notification_host_cast(context, 'bgp_speaker_remove_end',
                {'bgp_speaker': {'id': bgp_speaker_id}}, host)

    def _notification_host_cast(self, context, method, payload, host):
        """Send payload to BgpDrAgent in the cast mode"""
        cctxt = self.client.prepare(topic=self.topic, server=host)
        cctxt.cast(context, method, payload=payload)

    def _notification_host_call(self, context, method, payload, host):
        """Send payload to BgpDrAgent in the call mode"""
        cctxt = self.client.prepare(topic=self.topic, server=host)
        cctxt.call(context, method, payload=payload)
