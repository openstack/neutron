# Copyright 2014 Cisco Systems, Inc.
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
#


from neutron.db import model_base
import sqlalchemy as sa


class ConfigProfile(model_base.BASEV2):
    """Cisco DFA network configuration profile.

    'id'   - UUID and is localy generated,
    'name' - profile name coming form DCNM.
    """
    __tablename__ = 'cisco_dfa_config_profiles'

    id = sa.Column(sa.String(36), primary_key=True)
    name = sa.Column(sa.String(255))
    forwarding_mode = sa.Column(sa.String(32))


class ConfigProfileBinding(model_base.BASEV2):
    """Represents a binding of Network to Config Profile.

    netwrok_id     - Network UUID,
    cfg_profile_id - UUID of config profile.
    """
    __tablename__ = 'cisco_dfa_config_profile_bindings'

    network_id = sa.Column(sa.String(36),
                           sa.ForeignKey('networks.id', ondelete="CASCADE"),
                           primary_key=True)
    cfg_profile_id = sa.Column(sa.String(36), primary_key=True)


class ProjectNameCache(model_base.BASEV2):
    """Cache project name and project ID for Cisco DFA.

    project_id   - project UUID,
    project_name - project name.
    """
    __tablename__ = 'cisco_dfa_project_cache'

    project_id = sa.Column(sa.String(36),
                           primary_key=True)
    project_name = sa.Column(sa.String(255))
