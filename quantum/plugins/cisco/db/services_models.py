# vim: tabstop=4 shiftwidth=4 softtabstop=4
# Copyright 2011, Cisco Systems, Inc.
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
# @author: Edgar Magana, Cisco Systems, Inc.

from sqlalchemy import Column, Integer, String

from quantum.plugins.cisco.db.l2network_models import L2NetworkBase
from quantum.plugins.cisco.db.models import BASE


class ServicesBinding(BASE, L2NetworkBase):
    """Represents a binding of L2 services to networks"""
    __tablename__ = 'services_bindings'

    id = Column(Integer, primary_key=True, autoincrement=True)
    service_id = Column(String(255))
    mngnet_id = Column(String(255))
    nbnet_id = Column(String(255))
    sbnet_id = Column(String(255))

    def __init__(self, service_id, mngnet_id, nbnet_id, sbnet_id):
        self.service_id = service_id
        self.mngnet_id = mngnet_id
        self.nbnet_id = nbnet_id
        self.sbnet_id = sbnet_id

    def __repr__(self):
        return "<ServicesBinding (%s,%d)>" % \
          (self.service_id, self.mngnet_id, self.nbnet_id, self.sbnet_id)
