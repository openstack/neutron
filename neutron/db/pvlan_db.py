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

import sqlalchemy as sa

from neutron_lib.db import model_query
from neutron_lib.services.pvlan import constants as pvlan_const

from neutron.db.models import pvlan as pvlan_models
from neutron.db import models_v2


def _network_pvlan_result_filter_hook(query, filters):
    vals = filters and filters.get(pvlan_const.PVLAN, [])
    if not vals:
        return query
    if vals[0]:
        return query.filter(
            models_v2.Network.pvlan.has(
                pvlan_models.NetworkPVLAN.pvlan == sa.true()))
    return query.filter(
        ~models_v2.Network.pvlan.has(
            pvlan_models.NetworkPVLAN.pvlan == sa.true()))


def _port_pvlan_type_result_filter_hook(query, filters):
    vals = filters and filters.get(pvlan_const.PVLAN_TYPE, [])
    if not vals:
        return query
    return query.filter(
        models_v2.Port.pvlan.has(
            pvlan_models.PortPVLAN.pvlan_type.in_(vals)))


def _port_pvlan_community_result_filter_hook(query, filters):
    vals = filters and filters.get(pvlan_const.PVLAN_COMMUNITY, [])
    if not vals:
        return query
    return query.filter(
        models_v2.Port.pvlan.has(
            pvlan_models.PortPVLAN.pvlan_community.in_(vals)))


class PVLANDbMixin:
    """Mixin class to add PVLAN filter hooks."""

    def __new__(cls, *args, **kwargs):
        model_query.register_hook(
            models_v2.Network,
            "pvlan_network",
            query_hook=None,
            filter_hook=None,
            result_filters=_network_pvlan_result_filter_hook,
        )
        model_query.register_hook(
            models_v2.Port,
            "pvlan_port_type",
            query_hook=None,
            filter_hook=None,
            result_filters=_port_pvlan_type_result_filter_hook,
        )
        model_query.register_hook(
            models_v2.Port,
            "pvlan_port_community",
            query_hook=None,
            filter_hook=None,
            result_filters=_port_pvlan_community_result_filter_hook,
        )
        return super().__new__(cls, *args, **kwargs)
