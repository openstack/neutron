# Copyright 2013 Brocade Communications System, Inc.
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


"""A Vlan Bitmap class to handle allocation/de-allocation of vlan ids."""
from six import moves

from neutron.common import constants
from neutron.plugins.brocade.db import models as brocade_db


MIN_VLAN = constants.MIN_VLAN_TAG + 1
MAX_VLAN = constants.MAX_VLAN_TAG


class VlanBitmap(object):
    """Setup a vlan bitmap for allocation/de-allocation."""

    # Keep track of the vlans that have been allocated/de-allocated
    # uses a bitmap to do this

    def __init__(self, ctxt):
        """Initialize the vlan as a set."""
        self.vlans = set(int(net['vlan'])
                         for net in brocade_db.get_networks(ctxt)
                         if net['vlan']
                         )

    def get_next_vlan(self, vlan_id=None):
        """Try to get a specific vlan if requested or get the next vlan."""
        min_vlan_search = vlan_id or MIN_VLAN
        max_vlan_search = (vlan_id + 1) if vlan_id else MAX_VLAN

        for vlan in moves.xrange(min_vlan_search, max_vlan_search):
            if vlan not in self.vlans:
                self.vlans.add(vlan)
                return vlan

    def release_vlan(self, vlan_id):
        """Return the vlan to the pool."""
        if vlan_id in self.vlans:
            self.vlans.remove(vlan_id)
