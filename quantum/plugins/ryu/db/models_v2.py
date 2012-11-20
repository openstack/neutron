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

import sqlalchemy as sa

from quantum.db import model_base


class OFPServer(model_base.BASEV2):
    """Openflow Server/API address."""
    __tablename__ = 'ofp_server'

    id = sa.Column(sa.Integer, primary_key=True, autoincrement=True)
    address = sa.Column(sa.String(64))        # netloc <host ip address>:<port>
    host_type = sa.Column(sa.String(255))     # server type
                                              # Controller, REST_API

    def __repr__(self):
        return "<OFPServer(%s,%s,%s)>" % (self.id, self.address,
                                          self.host_type)


class TunnelKeyLast(model_base.BASEV2):
    """Lastly allocated Tunnel key. The next key allocation will be started
    from this value + 1
    """
    last_key = sa.Column(sa.Integer, primary_key=True)

    def __repr__(self):
        return "<TunnelKeyLast(%x)>" % self.last_key


class TunnelKey(model_base.BASEV2):
    """Netowrk ID <-> tunnel key mapping."""
    network_id = sa.Column(sa.String(36), sa.ForeignKey("networks.id"),
                           nullable=False)
    tunnel_key = sa.Column(sa.Integer, primary_key=True,
                           nullable=False, autoincrement=False)

    def __repr__(self):
        return "<TunnelKey(%s,%x)>" % (self.network_id, self.tunnel_key)
