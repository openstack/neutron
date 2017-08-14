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

from neutron_lib.services import base as service_base
from oslo_log import log as logging
import sqlalchemy
from sqlalchemy.orm import exc
from sqlalchemy.orm import session as se
import webob.exc

from neutron._i18n import _
from neutron.db import _resource_extend as resource_extend
from neutron.db import api as db_api
from neutron.db import standard_attr

LOG = logging.getLogger(__name__)


@resource_extend.has_resource_extenders
class RevisionPlugin(service_base.ServicePluginBase):
    """Plugin to populate revision numbers into standard attr resources."""

    supported_extension_aliases = ['standard-attr-revisions',
                                   'revision-if-match']

    def __init__(self):
        super(RevisionPlugin, self).__init__()
        db_api.sqla_listen(se.Session, 'before_flush', self.bump_revisions)
        db_api.sqla_listen(se.Session, 'after_commit',
                           self._clear_rev_bumped_flags)
        db_api.sqla_listen(se.Session, 'after_rollback',
                           self._clear_rev_bumped_flags)

    def bump_revisions(self, session, context, instances):
        self._enforce_if_match_constraints(session)
        # bump revision number for any updated objects in the session
        for obj in session.dirty:
            if isinstance(obj, standard_attr.HasStandardAttributes):
                self._bump_obj_revision(session, obj)

        # see if any created/updated/deleted objects bump the revision
        # of another object
        objects_with_related_revisions = [
            o for o in session.deleted | session.dirty | session.new
            if getattr(o, 'revises_on_change', ())
        ]
        for obj in objects_with_related_revisions:
            self._bump_related_revisions(session, obj)

    def _bump_related_revisions(self, session, obj):
        for revises_col in getattr(obj, 'revises_on_change', ()):
            try:
                related_obj = self._find_related_obj(session, obj, revises_col)
                if not related_obj:
                    LOG.warning("Could not find related %(col)s for "
                                "resource %(obj)s to bump revision.",
                                {'obj': obj, 'col': revises_col})
                    continue
                # if related object revises others, bump those as well
                self._bump_related_revisions(session, related_obj)
                # no need to bump revisions on related objects being deleted
                if related_obj not in session.deleted:
                    self._bump_obj_revision(session, related_obj)
            except exc.ObjectDeletedError:
                # object was in session but another writer deleted it
                pass

    def get_plugin_type(self):
        return "revision_plugin"

    def get_plugin_description(self):
        return "Adds revision numbers to resources."

    @staticmethod
    @resource_extend.extends(
        list(standard_attr.get_standard_attr_resource_model_map()))
    def extend_resource_dict_revision(resource_res, resource_db):
        resource_res['revision_number'] = resource_db.revision_number

    def _find_related_obj(self, session, obj, relationship_col):
        """Gets a related object off of a relationship.

        Raises a runtime error if the relationship isn't configured correctly
        for revision bumping.
        """
        # first check to see if it's directly attached to the object already
        related_obj = getattr(obj, relationship_col)
        if related_obj:
            return related_obj
        for rel in sqlalchemy.inspect(obj).mapper.relationships:
            if rel.key != relationship_col:
                continue
            if not rel.load_on_pending:
                raise RuntimeError(_("revises_on_change relationships must "
                                     "have load_on_pending set to True to "
                                     "bump parent revisions on create: %s"),
                                   relationship_col)

    def _clear_rev_bumped_flags(self, session):
        """This clears all flags on commit/rollback to enable rev bumps."""
        for inst in session:
            setattr(inst, '_rev_bumped', False)

    def _bump_obj_revision(self, session, obj):
        """Increment object revision in compare and swap fashion.

        Before the increment, this checks and enforces any revision number
        constraints.
        """
        if getattr(obj, '_rev_bumped', False):
            # we've already bumped the revision of this object in this txn
            return
        instance, match = self._get_constrained_instance_match(session)
        if instance and instance == obj:
            # one last check before bumping revision
            self._enforce_if_match_constraints(session)
        obj.bump_revision()
        setattr(obj, '_rev_bumped', True)

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
