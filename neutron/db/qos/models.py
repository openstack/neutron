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

import sqlalchemy as sa

from neutron.api.v2 import attributes as attrs
from neutron.db import model_base
from neutron.db import models_v2
from neutron.db import rbac_db_models


class QosPolicy(model_base.BASEV2, model_base.HasId, model_base.HasTenant):
    __tablename__ = 'qos_policies'
    name = sa.Column(sa.String(attrs.NAME_MAX_LEN))
    description = sa.Column(sa.String(attrs.DESCRIPTION_MAX_LEN))
    rbac_entries = sa.orm.relationship(rbac_db_models.QosPolicyRBAC,
                                       backref='qos_policy', lazy='joined',
                                       cascade='all, delete, delete-orphan')


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
    network = sa.orm.relationship(
        models_v2.Network,
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
    port = sa.orm.relationship(
        models_v2.Port,
        backref=sa.orm.backref("qos_policy_binding", uselist=False,
                               cascade='delete', lazy='joined'))


class QosBandwidthLimitRule(model_base.HasId, model_base.BASEV2):
    __tablename__ = 'qos_bandwidth_limit_rules'
    qos_policy_id = sa.Column(sa.String(36),
                              sa.ForeignKey('qos_policies.id',
                                            ondelete='CASCADE'),
                              nullable=False,
                              unique=True)
    max_kbps = sa.Column(sa.Integer)
    max_burst_kbps = sa.Column(sa.Integer)


class QosDscpMarkingRule(models_v2.HasId, model_base.BASEV2):
    __tablename__ = 'qos_dscp_marking_rules'
    qos_policy_id = sa.Column(sa.String(36),
                              sa.ForeignKey('qos_policies.id',
                                            ondelete='CASCADE'),
                              nullable=False,
                              unique=True)
    dscp_mark = sa.Column(sa.Integer)
