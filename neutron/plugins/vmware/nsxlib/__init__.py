# Copyright 2014 VMware, Inc.
# All Rights Reserved
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

from oslo_serialization import jsonutils

from neutron.common import exceptions as exception
from neutron.openstack.common import log
from neutron.plugins.vmware.api_client import exception as api_exc
from neutron.plugins.vmware.common import exceptions as nsx_exc
from neutron import version

HTTP_GET = "GET"
HTTP_POST = "POST"
HTTP_DELETE = "DELETE"
HTTP_PUT = "PUT"
# Prefix to be used for all NSX API calls
URI_PREFIX = "/ws.v1"
NEUTRON_VERSION = version.version_info.release_string()

LOG = log.getLogger(__name__)


def _build_uri_path(resource,
                    resource_id=None,
                    parent_resource_id=None,
                    fields=None,
                    relations=None,
                    filters=None,
                    types=None,
                    is_attachment=False,
                    extra_action=None):
    resources = resource.split('/')
    res_path = resources[0]
    if resource_id:
        res_path += "/%s" % resource_id
    if len(resources) > 1:
        # There is also a parent resource to account for in the uri
        res_path = "%s/%s/%s" % (resources[1],
                                 parent_resource_id,
                                 res_path)
    if is_attachment:
        res_path = "%s/attachment" % res_path
    elif extra_action:
        res_path = "%s/%s" % (res_path, extra_action)
    params = []
    params.append(fields and "fields=%s" % fields)
    params.append(relations and "relations=%s" % relations)
    params.append(types and "types=%s" % types)
    if filters:
        sorted_filters = [
            '%s=%s' % (k, filters[k]) for k in sorted(filters.keys())
        ]
        params.extend(sorted_filters)
    uri_path = "%s/%s" % (URI_PREFIX, res_path)
    non_empty_params = [x for x in params if x is not None]
    if non_empty_params:
        query_string = '&'.join(non_empty_params)
        if query_string:
            uri_path += "?%s" % query_string
    return uri_path


def format_exception(etype, e, exception_locals):
    """Consistent formatting for exceptions.

    :param etype: a string describing the exception type.
    :param e: the exception.
    :param execption_locals: calling context local variable dict.
    :returns: a formatted string.
    """
    msg = [_("Error. %(type)s exception: %(exc)s.") %
           {'type': etype, 'exc': e}]
    l = dict((k, v) for k, v in exception_locals.iteritems()
             if k != 'request')
    msg.append(_("locals=[%s]") % str(l))
    return ' '.join(msg)


def do_request(*args, **kwargs):
    """Issue a request to the cluster specified in kwargs.

    :param args: a list of positional arguments.
    :param kwargs: a list of keyworkds arguments.
    :returns: the result of the operation loaded into a python
        object or None.
    """
    cluster = kwargs["cluster"]
    try:
        res = cluster.api_client.request(*args)
        if res:
            return jsonutils.loads(res)
    except api_exc.ResourceNotFound:
        raise exception.NotFound()
    except api_exc.ReadOnlyMode:
        raise nsx_exc.MaintenanceInProgress()


def get_single_query_page(path, cluster, page_cursor=None,
                          page_length=1000, neutron_only=True):
    params = []
    if page_cursor:
        params.append("_page_cursor=%s" % page_cursor)
    params.append("_page_length=%s" % page_length)
    # NOTE(salv-orlando): On the NSX backend the 'Quantum' tag is still
    # used for marking Neutron entities in order to preserve compatibility
    if neutron_only:
        params.append("tag_scope=quantum")
    query_params = "&".join(params)
    path = "%s%s%s" % (path, "&" if (path.find("?") != -1) else "?",
                       query_params)
    body = do_request(HTTP_GET, path, cluster=cluster)
    # Result_count won't be returned if _page_cursor is supplied
    return body['results'], body.get('page_cursor'), body.get('result_count')


def get_all_query_pages(path, cluster):
    need_more_results = True
    result_list = []
    page_cursor = None
    while need_more_results:
        results, page_cursor = get_single_query_page(
            path, cluster, page_cursor)[:2]
        if not page_cursor:
            need_more_results = False
        result_list.extend(results)
    return result_list


def mk_body(**kwargs):
    """Convenience function creates and dumps dictionary to string.

    :param kwargs: the key/value pirs to be dumped into a json string.
    :returns: a json string.
    """
    return jsonutils.dumps(kwargs, ensure_ascii=False)
