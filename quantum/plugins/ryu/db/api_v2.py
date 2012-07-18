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

import quantum.db.api as db
from quantum.db.models_v2 import Network
from quantum.plugins.ryu.db import models_v2


def set_ofp_servers(hosts):
    session = db.get_session()
    session.query(models_v2.OFPServer).delete()
    for (host_address, host_type) in hosts:
        host = models_v2.OFPServer(host_address, host_type)
        session.add(host)
    session.flush()


def network_all_tenant_list():
    session = db.get_session()
    return session.query(Network).all()
