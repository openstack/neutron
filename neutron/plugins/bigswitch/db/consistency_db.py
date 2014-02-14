# Copyright 2014, Big Switch Networks
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

from neutron.db import api as db
from neutron.db import model_base
from neutron.openstack.common import log as logging

LOG = logging.getLogger(__name__)

'''
A simple table to store the latest consistency hash
received from a server in case neutron gets restarted.
'''


class ConsistencyHash(model_base.BASEV2):
    '''
    For now we only support one global state so the
    hash_id will always be '1'
    '''
    __tablename__ = 'consistencyhashes'
    hash_id = sa.Column(sa.String(255),
                        primary_key=True)
    hash = sa.Column(sa.String(255), nullable=False)


def get_consistency_hash(hash_id='1'):
    session = db.get_session()
    with session.begin(subtransactions=True):
        query = session.query(ConsistencyHash)
        res = query.filter_by(hash_id=hash_id).first()
    if not res:
        return False
    return res.hash


def put_consistency_hash(hash, hash_id='1'):
    session = db.get_session()
    with session.begin(subtransactions=True):
        conhash = ConsistencyHash(hash_id=hash_id, hash=hash)
        session.merge(conhash)
        LOG.debug(_("Consistency hash for group %(hash_id)s updated "
                    "to %(hash)s"), {'hash_id': hash_id, 'hash': hash})
