# Copyright 2011 VMware, Inc.
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

import copy
import weakref

from neutron_lib.db import api
from neutron_lib.db import model_base
from oslo_config import cfg
from oslo_log import log as logging
from osprofiler import opts as profiler_opts
import osprofiler.sqlalchemy
import sqlalchemy
from sqlalchemy import event  # noqa
from sqlalchemy import orm


def set_hook(engine):
    if (profiler_opts.is_trace_enabled() and
            profiler_opts.is_db_trace_enabled()):
        osprofiler.sqlalchemy.add_tracing(sqlalchemy, engine, 'neutron.db')


context_manager = api.get_context_manager()

# TODO(ihrachys) the hook assumes options defined by osprofiler, and the only
# public function that is provided by osprofiler that will register them is
# set_defaults, that's why we call it here even though we don't need to change
# defaults
profiler_opts.set_defaults(cfg.CONF)
context_manager.append_on_engine_create(set_hook)


MAX_RETRIES = 10
LOG = logging.getLogger(__name__)


def _copy_if_lds(item):
    """Deepcopy lists/dicts/sets, leave everything else alone."""
    return copy.deepcopy(item) if isinstance(item, (list, dict, set)) else item


@event.listens_for(orm.session.Session, "after_flush")
def add_to_rel_load_list(session, flush_context=None):
    # keep track of new items to load relationships on during commit
    session.info.setdefault('_load_rels', weakref.WeakSet()).update(
        session.new)


@event.listens_for(orm.session.Session, "before_commit")
def load_one_to_manys(session):
    # TODO(kevinbenton): we should be able to remove this after we
    # have eliminated all places where related objects are constructed
    # using a key rather than a relationship.

    # capture any new objects
    if session.new:
        session.flush()

    if session.transaction.nested:
        # wait until final commit
        return

    for new_object in session.info.pop('_load_rels', []):
        if new_object not in session:
            # don't load detached objects because that brings them back into
            # session
            continue
        state = sqlalchemy.inspect(new_object)

        # set up relationship loading so that we can call lazy
        # loaders on the object even though the ".key" is not set up yet
        # (normally happens by in after_flush_postexec, but we're trying
        # to do this more succinctly).  in this context this is only
        # setting a simple flag on the object's state.
        session.enable_relationship_loading(new_object)

        # look for eager relationships and do normal load.
        # For relationships where the related object is also
        # in the session these lazy loads will pull from the
        # identity map and not emit SELECT.  Otherwise, we are still
        # local in the transaction so a normal SELECT load will work fine.
        for relationship_attr in state.mapper.relationships:
            if relationship_attr.lazy not in ('joined', 'subquery'):
                # we only want to automatically load relationships that would
                # automatically load during a lookup operation
                continue
            if relationship_attr.key not in state.dict:
                getattr(new_object, relationship_attr.key)
                if relationship_attr.key not in state.dict:
                    msg = ("Relationship %s attributes must be loaded in db"
                           " object %s" % (relationship_attr.key, state.dict))
                    raise AssertionError(msg)


# Expire relationships when foreign key changes.
#
# NOTE(ihrachys) Arguably, it's a sqlalchemy anti-pattern to access child
# models directly and through parent relationships in the same session. But
# since OVO mechanism is built around synthetic fields that assume this mixed
# access is possible, we keep it here until we find a way to migrate OVO
# synthetic fields to better mechanism that would update child models via
# parents. Even with that, there are multiple places in plugin code where we
# mix access when using models directly; those occurrences would need to be
# fixed too to be able to remove this hook and explicit expire() calls.
#
# Adopted from the following recipe:
# https://bitbucket.org/zzzeek/sqlalchemy/wiki/UsageRecipes
# /ExpireRelationshipOnFKChange
#
# ...then massively changed to actually work for all neutron backref cases.
#
# TODO(ihrachys) at some point these event handlers should be extended to also
# automatically refresh values for expired attributes
def expire_for_fk_change(target, fk_value, relationship_prop, column_attr):
    """Expire relationship attributes when a many-to-one column changes."""

    sess = orm.object_session(target)

    # subnets and network's many-to-one relationship is used as example in the
    # comments in this function
    if sess is not None:
        # optional behavior #1 - expire the "Network.subnets"
        # collection on the existing "network" object
        if relationship_prop.back_populates and \
                relationship_prop.key in target.__dict__:
            obj = getattr(target, relationship_prop.key)
            if obj is not None and sqlalchemy.inspect(obj).persistent:
                sess.expire(obj, [relationship_prop.back_populates])

        # optional behavior #2 - expire the "Subnet.network"
        if sqlalchemy.inspect(target).persistent:
            sess.expire(target, [relationship_prop.key])

        # optional behavior #3 - "trick" the ORM by actually
        # setting the value ahead of time, then emitting a load
        # for the attribute so that the *new* Subnet.network
        # is loaded.  Then, expire Network.subnets on *that*.
        # Other techniques here including looking in the identity
        # map for "value", if this is a simple many-to-one get.
        if relationship_prop.back_populates:
            target.__dict__[column_attr] = fk_value
            new = getattr(target, relationship_prop.key)
            if new is not None:
                if sqlalchemy.inspect(new).persistent:
                    sess.expire(new, [relationship_prop.back_populates])
    else:
        # no Session yet, do it later. This path is reached from the 'expire'
        # listener setup by '_expire_prop_on_col' below, when a foreign key
        # is directly assigned to in the many to one side of a relationship.
        # i.e. assigning directly to Subnet.network_id before Subnet is added
        # to the session
        if target not in _emit_on_pending:
            _emit_on_pending[target] = []
        _emit_on_pending[target].append(
            (fk_value, relationship_prop, column_attr))


_emit_on_pending = weakref.WeakKeyDictionary()


@event.listens_for(orm.session.Session, "pending_to_persistent")
def _pending_callables(session, obj):
    """Expire relationships when a new object w/ a foreign key becomes
    persistent
    """
    if obj is None:
        return
    args = _emit_on_pending.pop(obj, [])
    for a in args:
        if a is not None:
            expire_for_fk_change(obj, *a)


@event.listens_for(orm.session.Session, "persistent_to_deleted")
def _persistent_to_deleted(session, obj):
    """Expire relationships when an object w/ a foreign key becomes deleted"""
    mapper = sqlalchemy.inspect(obj).mapper
    for prop in mapper.relationships:
        if prop.direction is orm.interfaces.MANYTOONE:
            for col in prop.local_columns:
                colkey = mapper.get_property_by_column(col).key
                expire_for_fk_change(obj, None, prop, colkey)


@event.listens_for(model_base.BASEV2, "attribute_instrument", propagate=True)
def _listen_for_changes(cls, key, inst):
    mapper = sqlalchemy.inspect(cls)
    if key not in mapper.relationships:
        return
    prop = inst.property

    if prop.direction is orm.interfaces.MANYTOONE:
        for col in prop.local_columns:
            colkey = mapper.get_property_by_column(col).key
            _expire_prop_on_col(cls, prop, colkey)
    elif prop.direction is orm.interfaces.ONETOMANY:
        remote_mapper = prop.mapper
        # the collection *has* to have a MANYTOONE backref so we
        # can look up the parent.  so here we make one if it doesn't
        # have it already, as is the case in this example
        if not prop.back_populates:
            name = "_%s_backref" % prop.key
            backref_prop = orm.relationship(
                prop.parent, back_populates=prop.key)

            remote_mapper.add_property(name, backref_prop)
            prop.back_populates = name


def _expire_prop_on_col(cls, prop, colkey):
    @event.listens_for(getattr(cls, colkey), "set")
    def expire(target, value, oldvalue, initiator):
        """Expire relationships when the foreign key attribute on
        an object changes
        """
        expire_for_fk_change(target, value, prop, colkey)
