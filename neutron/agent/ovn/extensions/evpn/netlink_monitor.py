# Copyright 2026 Red Hat, Inc.
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

import re

from oslo_log import log

from neutron.agent.ovn.extensions.evpn import constants as evpn_const
from neutron.agent.ovn.extensions.evpn import exceptions as evpn_exc

LOG = log.getLogger(__name__)
# EVPN VRF name has EVPN_VRF_NAME_LEN characters:
#   EVPN_VRF_PREFIX followed by
#   the first 12 characters of the logical router's UUID
EVPN_VRF_RE = re.compile(evpn_const.EVPN_VRF_PREFIX + r'[0-9a-f\-]{12}$')


class VrfHandler:
    """Handle netlink messages for EVPN VRF interfaces.

    Filters for VRF interfaces whose name starts with the EVPN VRF
    prefix (vr<LR uuid>).  Tracks known VRFs to deduplicate RTM_NEWLINK
    messages from state changes.
    """

    def __init__(self):
        self._known_vrfs = set()
        self._replay_vrfs = None

    def _is_in_replay(self):
        return self._replay_vrfs is not None

    @staticmethod
    def _is_vrf_msg(msg):
        link_kind = msg.get_nested('IFLA_LINKINFO', 'IFLA_INFO_KIND')
        return link_kind == evpn_const.EVPN_LINK_KIND_VRF

    @staticmethod
    def _is_evpn_vrf(ifname):
        return EVPN_VRF_RE.match(ifname)

    def _parse_evpn_vrf(self, msg):
        """Parse EVPN VRF name from a netlink message."""
        if self._is_vrf_msg(msg):
            ifname = msg.get_attr('IFLA_IFNAME')
            if self._is_evpn_vrf(ifname):
                return ifname
            raise evpn_exc.UnknownVrfMessage
        raise evpn_exc.UnknownMessage

    def replay_start(self):
        self._replay_vrfs = set()

    def replay_end(self):
        self._known_vrfs = self._replay_vrfs
        self._replay_vrfs = None

    def handle_newlink(self, msg):
        try:
            evpnvrf = self._parse_evpn_vrf(msg)
        except (evpn_exc.UnknownMessage, evpn_exc.UnknownVrfMessage):
            # This is not an EVPN VRF
            return
        if self._is_in_replay():
            self._replay_vrfs.add(evpnvrf)
            LOG.info("VRF previously created: %s", evpnvrf)
        else:
            # The kernel sends multiple RTM_NEWLINK messages during VRF
            # creation; only process the first one.
            if evpnvrf not in self._known_vrfs:
                self._known_vrfs.add(evpnvrf)
                LOG.info("VRF created: %s", evpnvrf)

    def handle_dellink(self, msg):
        try:
            evpnvrf = self._parse_evpn_vrf(msg)
        except (evpn_exc.UnknownMessage, evpn_exc.UnknownVrfMessage):
            # This is not an EVPN VRF
            return
        self._known_vrfs.discard(evpnvrf)
        LOG.info("VRF deleted: %s", evpnvrf)
