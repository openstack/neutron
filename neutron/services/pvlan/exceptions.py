# Copyright (c) 2026 Red Hat Inc.
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

from neutron_lib import exceptions as n_exc

from neutron._i18n import _


class PVLANNotEnabledOnNetwork(n_exc.BadRequest):
    message = _('PVLAN is not enabled on network %(network_id)s.')


class PVLANCannotSetCommunityName(n_exc.BadRequest):
    message = _(
        'PVLAN community name cannot be set if port type is not '
        '"community" for this port: %(port_id)s.'
    )


class PVLANCommunityNameRequired(n_exc.BadRequest):
    message = _(
        'Community name is required for ports with PVLAN type '
        '"community": %(port_id)s.'
    )


class PVLANPortSecurityDisabled(n_exc.BadRequest):
    message = _(
        'Port security is disabled for port %(port_id)s, cannot set PVLAN.'
    )


class PVLANNetworkPortSecurityDisabled(n_exc.BadRequest):
    message = _(
        'Port security is disabled on network %(network_id)s, '
        'cannot enable PVLAN.'
    )


class PVLANUnsupportedType(n_exc.BadRequest):
    message = _(
        'Unsupported PVLAN type %(pvlan_type)s for port %(port_id)s.'
    )
