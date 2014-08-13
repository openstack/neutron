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


class ConsistencyHash(model_base.BASEV2):
    '''
    A simple table to store the latest consistency hash
    received from a server.
    For now we only support one global state so the
    hash_id will always be '1'
    '''
    __tablename__ = 'consistencyhashes'
    hash_id = sa.Column(sa.String(255),
                        primary_key=True)
    hash = sa.Column(sa.String(255), nullable=False)


class HashHandler(object):
    '''
    A wrapper object to keep track of the session between the read
    and the update operations.
    '''
    def __init__(self, context=None, hash_id='1'):
        self.hash_id = hash_id
        self.session = db.get_session() if not context else context.session
        self.hash_db_obj = None

    def read_for_update(self):
        # REVISIT(kevinbenton): locking here with the DB is prone to deadlocks
        # in various multi-REST-call scenarios (router intfs, flips, etc).
        # Since it doesn't work in Galera deployments anyway, another sync
        # mechanism will have to be introduced to prevent inefficient double
        # syncs in HA deployments.
        with self.session.begin(subtransactions=True):
            res = (self.session.query(ConsistencyHash).
                   filter_by(hash_id=self.hash_id).first())
        if not res:
            return ''
        self.hash_db_obj = res
        return res.hash

    def put_hash(self, hash):
        hash = hash or ''
        with self.session.begin(subtransactions=True):
            if self.hash_db_obj is not None:
                self.hash_db_obj.hash = hash
            else:
                conhash = ConsistencyHash(hash_id=self.hash_id, hash=hash)
                self.session.merge(conhash)
        LOG.debug(_("Consistency hash for group %(hash_id)s updated "
                    "to %(hash)s"), {'hash_id': self.hash_id, 'hash': hash})
