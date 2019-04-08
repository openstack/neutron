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

from neutron_lib.api.definitions import revisionifmatch
from neutron_lib.db import api as db_api
from neutron_lib.db import resource_extend
from neutron_lib.services import base as service_base
from oslo_log import log as logging
import sqlalchemy
from sqlalchemy.orm import exc
from sqlalchemy.orm import session as se
import webob.exc

from neutron._i18n import _
from neutron.db import standard_attr

LOG = logging.getLogger(__name__)


@resource_extend.has_resource_extenders
class RevisionPlugin(service_base.ServicePluginBase):
    """Plugin to populate revision numbers into standard attr resources."""

    supported_extension_aliases = ['standard-attr-revisions',
                                   revisionifmatch.ALIAS]

    __filter_validation_support = True

    def __init__(self):
        super(RevisionPlugin, self).__init__()
        # background on these event hooks:
        # https://docs.sqlalchemy.org/en/latest/orm/session_events.html
        db_api.sqla_listen(se.Session, 'before_flush', self.bump_revisions)
        db_api.sqla_listen(
            se.Session, "after_flush_postexec",
            self._emit_related_revision_bumps)
        db_api.sqla_listen(se.Session, 'after_commit',
                           self._clear_rev_bumped_flags)
        db_api.sqla_listen(se.Session, 'after_rollback',
                           self._clear_rev_bumped_flags)

    def bump_revisions(self, session, context, instances):
        self._enforce_if_match_constraints(session)
        # bump revision number for any updated objects in the session
        self._bump_obj_revisions(
            session,
            [
                obj for obj in session.dirty
                if isinstance(obj, standard_attr.HasStandardAttributes)]
        )

        # see if any created/updated/deleted objects bump the revision
        # of another object
        objects_with_related_revisions = [
            o for o in session.deleted | session.dirty | session.new
            if getattr(o, 'revises_on_change', ())
        ]
        collected = session.info.setdefault('_related_bumped', set())
        self._collect_related_tobump(
            session, objects_with_related_revisions, collected)

    def _emit_related_revision_bumps(self, session, context):
        # within after_flush_postexec, emit an UPDATE statement to increment
        # revision flags for related objects that were located in the
        # before_flush phase.
        #
        # note that this event isn't called if the flush fails;
        # in that case, the transaction is rolled back and the
        # after_rollback event will invoke self._clear_rev_bumped_flags
        # to clean out state.
        collected = session.info.get('_related_bumped', None)
        if collected:
            try:
                self._bump_obj_revisions(
                    session, collected, version_check=False)
            finally:
                collected.clear()

    def _collect_related_tobump(self, session, objects, collected):
        for obj in objects:
            if obj in collected:
                continue
            for revises_col in getattr(obj, 'revises_on_change', ()):
                related_obj = self._find_related_obj(obj, revises_col)
                if not related_obj:
                    LOG.warning("Could not find related %(col)s for "
                                "resource %(obj)s to bump revision.",
                                {'obj': obj, 'col': revises_col})
                    continue
                # if related object revises others, bump those as well
                self._collect_related_tobump(session, [related_obj], collected)
                # no need to bump revisions on related objects being deleted
                if related_obj not in session.deleted:
                    collected.add(related_obj)
        return collected

    def get_plugin_type(self):
        return "revision_plugin"

    def get_plugin_description(self):
        return "Adds revision numbers to resources."

    @staticmethod
    @resource_extend.extends(
        list(standard_attr.get_standard_attr_resource_model_map()))
    def extend_resource_dict_revision(resource_res, resource_db):
        resource_res['revision_number'] = resource_db.revision_number

    def _find_related_obj(self, obj, relationship_col):
        """Gets a related object off of a relationship.

        Raises a runtime error if the relationship isn't configured correctly
        for revision bumping.
        """
        # first check to see if it's directly attached to the object already
        try:
            related_obj = getattr(obj, relationship_col)
        except exc.ObjectDeletedError:
            # object was in session but another writer deleted it
            return None

        if related_obj:
            return related_obj
        for rel in sqlalchemy.inspect(obj).mapper.relationships:
            if rel.key != relationship_col:
                continue
            if not rel.load_on_pending:
                raise RuntimeError(_("revises_on_change relationships must "
                                     "have load_on_pending set to True to "
                                     "bump parent revisions on create: %s")
                                   % relationship_col)

    def _clear_rev_bumped_flags(self, session):
        """This clears all flags on commit/rollback to enable rev bumps."""
        session.info.pop('_related_bumped', None)
        for inst in session:
            setattr(inst, '_rev_bumped', False)

    def _bump_obj_revisions(self, session, objects, version_check=True):
        """Increment object revisions.

        If version_check=True, uses SQLAlchemy ORM's compare-and-swap feature
        (known as "version_id_col" in the ORM mapping), which is part of the
        StandardAttribute class.

        If version_check=False, runs an UPDATE statement directly against
        the set of all StandardAttribute objects at once, without using
        any compare and swap logic.

        If a revision number constraint rule was associated with the Session,
        this is retrieved and each object is tested to see if it matches
        this condition; if so, the constraint is enforced.

        """

        # filter objects for which we've already bumped the revision
        to_bump = [
            obj for obj in objects if not getattr(obj, '_rev_bumped', False)]

        if not to_bump:
            return

        self._run_constrained_instance_match_check(session, to_bump)

        if not version_check:
            # this UPDATE statement could alternatively be written to run
            # as an UPDATE-per-object with Python-generated revision numbers
            # as parameters.
            session.query(standard_attr.StandardAttribute).filter(
                standard_attr.StandardAttribute.id.in_(
                    [obj._effective_standard_attribute_id for obj in to_bump]
                )
            ).update({
                # note that SQLAlchemy runs the onupdate function for
                # the updated_at column and applies it to the SET clause as
                # well.
                standard_attr.StandardAttribute.revision_number:
                standard_attr.StandardAttribute.revision_number + 1},
                synchronize_session=False)

            # run a SELECT to get back the new values we just generated.
            # if MySQL supported RETURNING, we could get these numbers
            # back from the UPDATE without running another SELECT.
            retrieve_revision_numbers = {
                row.id: (row.revision_number, row.updated_at)
                for row in
                session.query(
                    standard_attr.StandardAttribute.id,
                    standard_attr.StandardAttribute.revision_number,
                    standard_attr.StandardAttribute.updated_at,
                ).filter(
                    standard_attr.StandardAttribute.id.in_(
                        [
                            obj._effective_standard_attribute_id
                            for obj in to_bump
                        ]
                    )
                )
            }

        for obj in to_bump:
            if version_check:
                # full version check, run the ORM routine to UPDATE
                # the row with a WHERE clause
                obj.bump_revision()
            else:
                # no version check - get back what we did in our one-step
                # UPDATE statement and set it without causing change in
                # ORM flush state
                try:
                    new_version_id, new_updated_at = retrieve_revision_numbers[
                        obj._effective_standard_attribute_id
                    ]
                except KeyError:
                    # in case the object was deleted concurrently
                    LOG.warning(
                        "No standard attr row found for resource: %(obj)s",
                        {'obj': obj})
                else:
                    obj._set_updated_revision_number(
                        new_version_id, new_updated_at)
            setattr(obj, '_rev_bumped', True)

    def _run_constrained_instance_match_check(self, session, objects):
        instance, match = self._get_constrained_instance_match(session)
        for obj in objects:
            if instance and instance == obj:
                # one last check before bumping revision
                self._enforce_if_match_constraints(session)

    def _find_instance_by_column_value(self, session, model, column, value):
        """Lookup object in session or from DB based on a column's value."""
        for session_obj in session:
            if not isinstance(session_obj, model):
                continue
            if getattr(session_obj, column) == value:
                return session_obj
        # object isn't in session so we have to query for it
        related_obj = (session.query(model).filter_by(**{column: value}).
                       first())
        return related_obj

    def _get_constrained_instance_match(self, session):
        """Returns instance and constraint of if-match criterion if present.

        Checks the context associated with the session for compare-and-swap
        update revision number constraints. If one is found, this returns the
        instance that is constrained as well as the requested revision number
        to match.
        """
        context = session.info.get('using_context')
        criteria = context.get_transaction_constraint() if context else None
        if not criteria:
            return None, None
        match = criteria.if_revision_match
        mmap = standard_attr.get_standard_attr_resource_model_map()
        model = mmap.get(criteria.resource)
        if not model:
            msg = _("Revision matching not supported for this resource")
            raise exc.BadRequest(resource=criteria.resource, msg=msg)
        instance = self._find_instance_by_column_value(
            session, model, 'id', criteria.resource_id)
        return instance, match

    def _enforce_if_match_constraints(self, session):
        """Check for if-match constraints and raise exception if violated.

        We determine the collection being modified and look for any
        objects of the collection type in the dirty/deleted items in
        the session. If they don't match the revision_number constraint
        supplied, we throw an exception.

        We are protected from a concurrent update because if we match
        revision number here and another update commits to the database
        first, the compare and swap of revision_number will fail and a
        StaleDataError (or deadlock in galera multi-writer) will be raised,
        at which point this will be retried and fail to match.
        """
        instance, match = self._get_constrained_instance_match(session)
        if not instance or getattr(instance, '_rev_bumped', False):
            # no constraints present or constrain satisfied in this transaction
            return
        if instance.revision_number != match:
            raise RevisionNumberConstraintFailed(match,
                                                 instance.revision_number)


class RevisionNumberConstraintFailed(webob.exc.HTTPPreconditionFailed):

    def __init__(self, expected, current):
        detail = (_("Constrained to %(exp)s, but current revision is %(cur)s")
                  % {'exp': expected, 'cur': current})
        super(RevisionNumberConstraintFailed, self).__init__(detail=detail)
