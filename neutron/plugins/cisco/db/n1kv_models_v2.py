# Copyright 2013 Cisco Systems, Inc.
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
import sqlalchemy as sa
from sqlalchemy import sql

from neutron.db import model_base
from neutron.db import models_v2
from neutron.plugins.cisco.common import cisco_constants


LOG = logging.getLogger(__name__)


class N1kvVlanAllocation(model_base.BASEV2):

    """Represents allocation state of vlan_id on physical network."""
    __tablename__ = 'cisco_n1kv_vlan_allocations'

    physical_network = sa.Column(sa.String(64),
                                 nullable=False,
                                 primary_key=True)
    vlan_id = sa.Column(sa.Integer, nullable=False, primary_key=True,
                        autoincrement=False)
    allocated = sa.Column(sa.Boolean, nullable=False, default=False,
                          server_default=sql.false())
    network_profile_id = sa.Column(sa.String(36),
                                   sa.ForeignKey('cisco_network_profiles.id',
                                                 ondelete="CASCADE"),
                                   nullable=False)


class N1kvVxlanAllocation(model_base.BASEV2):

    """Represents allocation state of vxlan_id."""
    __tablename__ = 'cisco_n1kv_vxlan_allocations'

    vxlan_id = sa.Column(sa.Integer, nullable=False, primary_key=True,
                         autoincrement=False)
    allocated = sa.Column(sa.Boolean, nullable=False, default=False,
                          server_default=sql.false())
    network_profile_id = sa.Column(sa.String(36),
                                   sa.ForeignKey('cisco_network_profiles.id',
                                                 ondelete="CASCADE"),
                                   nullable=False)


class N1kvPortBinding(model_base.BASEV2):

    """Represents binding of ports to policy profile."""
    __tablename__ = 'cisco_n1kv_port_bindings'

    port_id = sa.Column(sa.String(36),
                        sa.ForeignKey('ports.id', ondelete="CASCADE"),
                        primary_key=True)
    profile_id = sa.Column(sa.String(36),
                           sa.ForeignKey('cisco_policy_profiles.id'))


class N1kvNetworkBinding(model_base.BASEV2):

    """Represents binding of virtual network to physical realization."""
    __tablename__ = 'cisco_n1kv_network_bindings'

    network_id = sa.Column(sa.String(36),
                           sa.ForeignKey('networks.id', ondelete="CASCADE"),
                           primary_key=True)
    network_type = sa.Column(sa.String(32), nullable=False)
    physical_network = sa.Column(sa.String(64))
    segmentation_id = sa.Column(sa.Integer)
    multicast_ip = sa.Column(sa.String(32))
    profile_id = sa.Column(sa.String(36),
                           sa.ForeignKey('cisco_network_profiles.id'))


class N1kVmNetwork(model_base.BASEV2):

    """Represents VM Network information."""
    __tablename__ = 'cisco_n1kv_vmnetworks'

    name = sa.Column(sa.String(80), primary_key=True)
    profile_id = sa.Column(sa.String(36),
                           sa.ForeignKey('cisco_policy_profiles.id'))
    network_id = sa.Column(sa.String(36))
    port_count = sa.Column(sa.Integer)


class NetworkProfile(model_base.BASEV2, models_v2.HasId):

    """
    Nexus1000V Network Profiles

        segment_type - VLAN, OVERLAY, TRUNK, MULTI_SEGMENT
        sub_type - TRUNK_VLAN, TRUNK_VXLAN, native_vxlan, enhanced_vxlan
        segment_range - '<integer>-<integer>'
        multicast_ip_index - <integer>
        multicast_ip_range - '<ip>-<ip>'
        physical_network - Name for the physical network
    """
    __tablename__ = 'cisco_network_profiles'

    name = sa.Column(sa.String(255))
    segment_type = sa.Column(sa.Enum(cisco_constants.NETWORK_TYPE_VLAN,
                                     cisco_constants.NETWORK_TYPE_OVERLAY,
                                     cisco_constants.NETWORK_TYPE_TRUNK,
                                     cisco_constants.
                                     NETWORK_TYPE_MULTI_SEGMENT,
                                     name='segment_type'),
                             nullable=False)
    sub_type = sa.Column(sa.String(255))
    segment_range = sa.Column(sa.String(255))
    multicast_ip_index = sa.Column(sa.Integer, default=0,
                                   server_default='0')
    multicast_ip_range = sa.Column(sa.String(255))
    physical_network = sa.Column(sa.String(255))


class PolicyProfile(model_base.BASEV2):

    """
    Nexus1000V Network Profiles

        Both 'id' and 'name' are coming from Nexus1000V switch
    """
    __tablename__ = 'cisco_policy_profiles'

    id = sa.Column(sa.String(36), primary_key=True)
    name = sa.Column(sa.String(255))


class ProfileBinding(model_base.BASEV2):

    """
    Represents a binding of Network Profile
    or Policy Profile to tenant_id
    """
    __tablename__ = 'cisco_n1kv_profile_bindings'

    profile_type = sa.Column(sa.Enum(cisco_constants.NETWORK,
                                     cisco_constants.POLICY,
                                     name='profile_type'))
    tenant_id = sa.Column(sa.String(36),
                          primary_key=True,
                          default=cisco_constants.TENANT_ID_NOT_SET,
                          server_default=cisco_constants.TENANT_ID_NOT_SET)
    profile_id = sa.Column(sa.String(36), primary_key=True)


class N1kvTrunkSegmentBinding(model_base.BASEV2):

    """Represents binding of segments in trunk networks."""
    __tablename__ = 'cisco_n1kv_trunk_segments'

    trunk_segment_id = sa.Column(sa.String(36),
                                 sa.ForeignKey('networks.id',
                                               ondelete="CASCADE"),
                                 primary_key=True)
    segment_id = sa.Column(sa.String(36), nullable=False, primary_key=True)
    dot1qtag = sa.Column(sa.String(36), nullable=False, primary_key=True)


class N1kvMultiSegmentNetworkBinding(model_base.BASEV2):

    """Represents binding of segments in multi-segment networks."""
    __tablename__ = 'cisco_n1kv_multi_segments'

    multi_segment_id = sa.Column(sa.String(36),
                                 sa.ForeignKey('networks.id',
                                               ondelete="CASCADE"),
                                 primary_key=True)
    segment1_id = sa.Column(sa.String(36), nullable=False, primary_key=True)
    segment2_id = sa.Column(sa.String(36), nullable=False, primary_key=True)
    encap_profile_name = sa.Column(sa.String(36))
