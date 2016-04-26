# Copyright 2015 Huawei Technologies India Pvt Ltd, Inc.
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

from neutron_lib import constants
from neutron_lib.db import constants as db_const
from neutron_lib.db import model_base
import sqlalchemy as sa

from neutron.db.models import l3
from neutron.db import models_v2
from neutron.db import rbac_db_models
from neutron.db import standard_attr


class QosPolicy(standard_attr.HasStandardAttributes, model_base.BASEV2,
                model_base.HasId, model_base.HasProject):
    __tablename__ = 'qos_policies'
    name = sa.Column(sa.String(db_const.NAME_FIELD_SIZE))
    rbac_entries = sa.orm.relationship(rbac_db_models.QosPolicyRBAC,
                                       backref='qos_policy', lazy='subquery',
                                       cascade='all, delete, delete-orphan')
    api_collections = ['policies']
    collection_resource_map = {'policies': 'policy'}
    tag_support = True


class QosNetworkPolicyBinding(model_base.BASEV2):
    __tablename__ = 'qos_network_policy_bindings'
    policy_id = sa.Column(sa.String(36),
                          sa.ForeignKey('qos_policies.id',
                                        ondelete='CASCADE'),
                          nullable=False,
                          primary_key=True)
    network_id = sa.Column(sa.String(36),
                           sa.ForeignKey('networks.id',
                                         ondelete='CASCADE'),
                           nullable=False,
                           unique=True,
                           primary_key=True)
    revises_on_change = ('network', )
    network = sa.orm.relationship(
        models_v2.Network, load_on_pending=True,
        backref=sa.orm.backref("qos_policy_binding", uselist=False,
                               cascade='delete', lazy='joined'))


class QosFIPPolicyBinding(model_base.BASEV2):
    __tablename__ = 'qos_fip_policy_bindings'
    policy_id = sa.Column(sa.String(db_const.UUID_FIELD_SIZE),
                          sa.ForeignKey('qos_policies.id',
                                        ondelete='CASCADE'),
                          nullable=False,
                          primary_key=True)
    fip_id = sa.Column(sa.String(db_const.UUID_FIELD_SIZE),
                       sa.ForeignKey('floatingips.id',
                                     ondelete='CASCADE'),
                       nullable=False,
                       unique=True,
                       primary_key=True)
    revises_on_change = ('floatingip', )
    floatingip = sa.orm.relationship(
        l3.FloatingIP, load_on_pending=True,
        backref=sa.orm.backref("qos_policy_binding", uselist=False,
                               cascade='delete', lazy='joined'))


class QosPortPolicyBinding(model_base.BASEV2):
    __tablename__ = 'qos_port_policy_bindings'
    policy_id = sa.Column(sa.String(36),
                          sa.ForeignKey('qos_policies.id',
                                        ondelete='CASCADE'),
                          nullable=False,
                          primary_key=True)
    port_id = sa.Column(sa.String(36),
                        sa.ForeignKey('ports.id',
                                      ondelete='CASCADE'),
                        nullable=False,
                        unique=True,
                        primary_key=True)
    revises_on_change = ('port', )
    port = sa.orm.relationship(
        models_v2.Port, load_on_pending=True,
        backref=sa.orm.backref("qos_policy_binding", uselist=False,
                               cascade='delete', lazy='joined'))


class QosPolicyDefault(model_base.BASEV2,
                       model_base.HasProjectPrimaryKeyIndex):
    __tablename__ = 'qos_policies_default'
    qos_policy_id = sa.Column(sa.String(36),
                              sa.ForeignKey('qos_policies.id',
                                            ondelete='CASCADE'),
                              nullable=False)
    revises_on_change = ('qos_policy',)
    qos_policy = sa.orm.relationship(QosPolicy, load_on_pending=True)


class QosBandwidthLimitRule(model_base.HasId, model_base.BASEV2):
    __tablename__ = 'qos_bandwidth_limit_rules'
    qos_policy_id = sa.Column(sa.String(36),
                              sa.ForeignKey('qos_policies.id',
                                            ondelete='CASCADE'),
                              nullable=False)
    max_kbps = sa.Column(sa.Integer)
    max_burst_kbps = sa.Column(sa.Integer)
    revises_on_change = ('qos_policy', )
    qos_policy = sa.orm.relationship(QosPolicy, load_on_pending=True)
    direction = sa.Column(sa.Enum(constants.EGRESS_DIRECTION,
                                  constants.INGRESS_DIRECTION,
                                  name="directions"),
                          default=constants.EGRESS_DIRECTION,
                          server_default=constants.EGRESS_DIRECTION,
                          nullable=False)
    __table_args__ = (
        sa.UniqueConstraint(
            qos_policy_id, direction,
            name="qos_bandwidth_rules0qos_policy_id0direction"),
        model_base.BASEV2.__table_args__
    )


class QosDscpMarkingRule(model_base.HasId, model_base.BASEV2):
    __tablename__ = 'qos_dscp_marking_rules'
    qos_policy_id = sa.Column(sa.String(36),
                              sa.ForeignKey('qos_policies.id',
                                            ondelete='CASCADE'),
                              nullable=False,
                              unique=True)
    dscp_mark = sa.Column(sa.Integer)
    revises_on_change = ('qos_policy', )
    qos_policy = sa.orm.relationship(QosPolicy, load_on_pending=True)


class QosMinimumBandwidthRule(model_base.HasId, model_base.BASEV2):
    __tablename__ = 'qos_minimum_bandwidth_rules'
    qos_policy_id = sa.Column(sa.String(36),
                              sa.ForeignKey('qos_policies.id',
                                            ondelete='CASCADE'),
                              nullable=False,
                              index=True)
    min_kbps = sa.Column(sa.Integer)
    direction = sa.Column(sa.Enum(constants.EGRESS_DIRECTION,
                                  constants.INGRESS_DIRECTION,
                                  name='directions'),
                          nullable=False,
                          server_default=constants.EGRESS_DIRECTION)
    revises_on_change = ('qos_policy', )
    qos_policy = sa.orm.relationship(QosPolicy, load_on_pending=True)

    __table_args__ = (
        sa.UniqueConstraint(
            qos_policy_id, direction,
            name='qos_minimum_bandwidth_rules0qos_policy_id0direction'),
        model_base.BASEV2.__table_args__
    )
