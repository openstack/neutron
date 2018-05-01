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

from neutron_lib.db import utils as db_utils
from oslo_log import log as logging
from oslo_utils import excutils


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


def model_query(context, model):
    query = context.session.query(model)
    # define basic filter condition for model query
    query_filter = None
    if db_utils.model_query_scope_is_project(context, model):
        query_filter = (model.tenant_id == context.tenant_id)

    if query_filter is not None:
        query = query.filter(query_filter)
    return query
