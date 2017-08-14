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

"""
NOTE: This module shall not be used by external projects. It will be moved
      to neutron-lib in due course, and then it can be used from there.
"""

import contextlib

from neutron_lib.api import attributes
from oslo_log import log as logging
from oslo_utils import excutils
from sqlalchemy.ext import associationproxy


LOG = logging.getLogger(__name__)


@contextlib.contextmanager
def _noop_context_manager():
    yield


def safe_creation(context, create_fn, delete_fn, create_bindings,
                  transaction=True):
    '''This function wraps logic of object creation in safe atomic way.

    In case of exception, object is deleted.

    More information when this method could be used can be found in
    developer guide - Effective Neutron: Database interaction section.
    https://docs.openstack.org/neutron/latest/contributor/effective_neutron.html

    :param context: context

    :param create_fn: function without arguments that is called to create
        object and returns this object.

    :param delete_fn: function that is called to delete an object. It is
        called with object's id field as an argument.

    :param create_bindings: function that is called to create bindings for
        an object. It is called with object's id field as an argument.

    :param transaction: if true the whole operation will be wrapped in a
        transaction. if false, no transaction will be used.
    '''
    cm = (context.session.begin(subtransactions=True)
          if transaction else _noop_context_manager())
    with cm:
        obj = create_fn()
        try:
            value = create_bindings(obj['id'])
        except Exception:
            with excutils.save_and_reraise_exception():
                try:
                    delete_fn(obj['id'])
                except Exception as e:
                    LOG.error("Cannot clean up created object %(obj)s. "
                              "Exception: %(exc)s", {'obj': obj['id'],
                                                     'exc': e})
        return obj, value


def model_query_scope_is_project(context, model):
    # Unless a context has 'admin' or 'advanced-service' rights the
    # query will be scoped to a single project_id
    return ((not context.is_admin and hasattr(model, 'project_id')) and
            (not context.is_advsvc and hasattr(model, 'project_id')))


def model_query(context, model):
    query = context.session.query(model)
    # define basic filter condition for model query
    query_filter = None
    if model_query_scope_is_project(context, model):
        query_filter = (model.tenant_id == context.tenant_id)

    if query_filter is not None:
        query = query.filter(query_filter)
    return query


# NOTE: This used to be CommonDbMixin._fields()
def resource_fields(resource, fields):
    """Return only the resource items that are in fields.

    :param resource: a resource dictionary
    :type resource: dict
    :param fields: a list of fields to select from the resource
    :type fields: list

    """
    if fields:
        resource = {key: item for key, item in resource.items()
                    if key in fields}
    return attributes.populate_project_info(resource)


# NOTE: This used to be CommonDbMixin._filter_non_model_columns
def filter_non_model_columns(data, model):
    """Return the attributes from data which are model columns.

    Return a new dict with items from data that whose keys are columns in
    the model or are association proxies of the model.
    """
    columns = [c.name for c in model.__table__.columns]
    return dict((k, v) for (k, v) in
                data.items() if k in columns or
                isinstance(getattr(model, k, None),
                           associationproxy.AssociationProxy))


# NOTE: This used to be CommonDbMixin._get_marker_obj
def get_marker_obj(plugin, context, resource, limit, marker):
    """Retrieve a resource marker object.

    This function is used to invoke:
        plugin._get_<resource>(context, marker)
    It is used for pagination.

    :param plugin: The plugin processing the request.
    :param context: The request context.
    :param resource: The resource name.
    :param limit: Indicates if pagination is in effect.
    :param marker: The id of the marker object.
    """
    if limit and marker:
        return getattr(plugin, '_get_%s' % resource)(context, marker)
