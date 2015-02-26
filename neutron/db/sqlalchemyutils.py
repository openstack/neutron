# Copyright 2011 OpenStack Foundation.
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

from oslo_log import log as logging
from six import moves
import sqlalchemy
from sqlalchemy.orm import properties

from neutron.common import exceptions as n_exc


LOG = logging.getLogger(__name__)


def paginate_query(query, model, limit, sorts, marker_obj=None):
    """Returns a query with sorting / pagination criteria added.

    Pagination works by requiring a unique sort key, specified by sorts.
    (If sort keys is not unique, then we risk looping through values.)
    We use the last row in the previous page as the 'marker' for pagination.
    So we must return values that follow the passed marker in the order.
    With a single-valued sort key, this would be easy: sort_key > X.
    With a compound-values sort key, (k1, k2, k3) we must do this to repeat
    the lexicographical ordering:
    (k1 > X1) or (k1 == X1 && k2 > X2) or (k1 == X1 && k2 == X2 && k3 > X3)
    The reason of didn't use OFFSET clause was it don't scale, please refer
    discussion at https://lists.launchpad.net/openstack/msg02547.html

    We also have to cope with different sort directions.

    Typically, the id of the last row is used as the client-facing pagination
    marker, then the actual marker object must be fetched from the db and
    passed in to us as marker.

    :param query: the query object to which we should add paging/sorting
    :param model: the ORM model class
    :param limit: maximum number of items to return
    :param sorts: array of attributes and direction by which results should
                 be sorted
    :param marker: the last item of the previous page; we returns the next
                    results after this value.
    :rtype: sqlalchemy.orm.query.Query
    :return: The query with sorting/pagination added.
    """
    if not sorts:
        return query

    # A primary key must be specified in sort keys
    assert not (limit and
                len(set(dict(sorts).keys()) &
                    set(model.__table__.primary_key.columns.keys())) == 0)

    # Add sorting
    for sort_key, sort_direction in sorts:
        sort_dir_func = sqlalchemy.asc if sort_direction else sqlalchemy.desc
        try:
            sort_key_attr = getattr(model, sort_key)
        except AttributeError:
            # Extension attribute doesn't support for sorting. Because it
            # existed in attr_info, it will be catched at here
            msg = _("%s is invalid attribute for sort_key") % sort_key
            raise n_exc.BadRequest(resource=model.__tablename__, msg=msg)
        if isinstance(sort_key_attr.property, properties.RelationshipProperty):
            msg = _("The attribute '%(attr)s' is reference to other "
                    "resource, can't used by sort "
                    "'%(resource)s'") % {'attr': sort_key,
                                         'resource': model.__tablename__}
            raise n_exc.BadRequest(resource=model.__tablename__, msg=msg)
        query = query.order_by(sort_dir_func(sort_key_attr))

    # Add pagination
    if marker_obj:
        marker_values = [getattr(marker_obj, sort[0]) for sort in sorts]

        # Build up an array of sort criteria as in the docstring
        criteria_list = []
        for i, sort in enumerate(sorts):
            crit_attrs = [(getattr(model, sorts[j][0]) == marker_values[j])
                          for j in moves.xrange(i)]
            model_attr = getattr(model, sort[0])
            if sort[1]:
                crit_attrs.append((model_attr > marker_values[i]))
            else:
                crit_attrs.append((model_attr < marker_values[i]))

            criteria = sqlalchemy.sql.and_(*crit_attrs)
            criteria_list.append(criteria)

        f = sqlalchemy.sql.or_(*criteria_list)
        query = query.filter(f)

    if limit:
        query = query.limit(limit)

    return query
