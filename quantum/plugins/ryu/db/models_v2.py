# vim: tabstop=4 shiftwidth=4 softtabstop=4
# Copyright 2012 Isaku Yamahata <yamahata at private email ne jp>
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

from sqlalchemy import Column, Integer, String

from quantum.db import models_v2


class OFPServer(models_v2.model_base.BASEV2):
    """Openflow Server/API address"""
    __tablename__ = 'ofp_server'

    id = Column(Integer, primary_key=True, autoincrement=True)
    address = Column(String(255))       # netloc <host ip address>:<port>
    host_type = Column(String(255))     # server type
                                        # Controller, REST_API

    def __init__(self, address, host_type):
        self.address = address
        self.host_type = host_type

    def __repr__(self):
        return "<OFPServer(%s,%s,%s)>" % (self.id, self.address,
                                          self.host_type)
