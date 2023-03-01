# Copyright (c) 2023 Canonical Ltd.
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

from neutron_lib import exceptions as e

from neutron._i18n import _


# TODO(haleyb): Move to n-lib
class NetworkMTUSubnetConflict(e.Conflict):
    """A conflict error due to MTU being invalid on said network.

    :param net_id: The UUID of the network
    :param    mtu: The minimum MTU required by a subnet for the network
    """
    message = _("MTU of %(net_id)s is not valid, subnet requires a "
                "minimum of %(mtu)s")
