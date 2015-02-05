# Copyright 2015 Cisco Systems, Inc.
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

import sqlalchemy as sa

from neutron.db import model_base


class PortProfile(model_base.BASEV2):

    """Port profiles created on the UCS Manager."""

    __tablename__ = 'ml2_ucsm_port_profiles'

    vlan_id = sa.Column(sa.Integer(), nullable=False, primary_key=True)
    profile_id = sa.Column(sa.String(64), nullable=False)
    created_on_ucs = sa.Column(sa.Boolean(), nullable=False)
