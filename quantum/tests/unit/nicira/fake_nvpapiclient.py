# Copyright 2012 Nicira Networks, Inc.
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
#

import json
import logging
import uuid
import urlparse

LOG = logging.getLogger("fake_nvpapiclient")
LOG.setLevel(logging.DEBUG)


class FakeClient:

    FAKE_GET_RESPONSES = {
        "lswitch": "fake_get_lswitch.json",
        "lport": "fake_get_lport.json",
        "lportstatus": "fake_get_lport_status.json"
    }

    FAKE_POST_RESPONSES = {
        "lswitch": "fake_post_lswitch.json",
        "lport": "fake_post_lport.json"
    }

    FAKE_PUT_RESPONSES = {
        "lswitch": "fake_post_lswitch.json",
        "lport": "fake_post_lport.json"
    }

    _fake_lswitch_dict = {}
    _fake_lport_dict = {}
    _fake_lportstatus_dict = {}

    def __init__(self, fake_files_path):
        self.fake_files_path = fake_files_path

    def _get_tag(self, resource, scope):
        tags = [tag['tag'] for tag in resource['tags']
                if tag['scope'] == scope]
        return len(tags) > 0 and tags[0]

    def _get_filters(self, querystring):
        if not querystring:
            return (None, None)
        params = urlparse.parse_qs(querystring)
        tag_filter = None
        attr_filter = None
        if 'tag' in params and 'tag_scope' in params:
            tag_filter = {'scope': params['tag_scope'][0],
                          'tag': params['tag'][0]}
        elif 'uuid' in params:
            attr_filter = {'uuid': params['uuid'][0]}
        return (tag_filter, attr_filter)

    def _add_lswitch(self, body):
        fake_lswitch = json.loads(body)
        fake_lswitch['uuid'] = str(uuid.uuid4())
        self._fake_lswitch_dict[fake_lswitch['uuid']] = fake_lswitch
        # put the tenant_id and the zone_uuid in the main dict
        # for simplyfying templating
        zone_uuid = fake_lswitch['transport_zones'][0]['zone_uuid']
        fake_lswitch['zone_uuid'] = zone_uuid
        fake_lswitch['tenant_id'] = self._get_tag(fake_lswitch, 'os_tid')
        return fake_lswitch

    def _add_lport(self, body, ls_uuid):
        fake_lport = json.loads(body)
        fake_lport['uuid'] = str(uuid.uuid4())
        # put the tenant_id and the ls_uuid in the main dict
        # for simplyfying templating
        fake_lport['ls_uuid'] = ls_uuid
        fake_lport['tenant_id'] = self._get_tag(fake_lport, 'os_tid')
        fake_lport['quantum_port_id'] = self._get_tag(fake_lport,
                                                      'q_port_id')
        fake_lport['quantum_device_id'] = self._get_tag(fake_lport, 'vm_id')
        self._fake_lport_dict[fake_lport['uuid']] = fake_lport

        fake_lswitch = self._fake_lswitch_dict[ls_uuid]
        fake_lport_status = fake_lport.copy()
        fake_lport_status['ls_tenant_id'] = fake_lswitch['tenant_id']
        fake_lport_status['ls_uuid'] = fake_lswitch['uuid']
        fake_lport_status['ls_name'] = fake_lswitch['display_name']
        fake_lport_status['ls_zone_uuid'] = fake_lswitch['zone_uuid']
        self._fake_lportstatus_dict[fake_lport['uuid']] = fake_lport_status
        return fake_lport

    def _get_resource_type(self, path):
        uri_split = path.split('/')
        resource_type = ('status' in uri_split and
                         'lport' in uri_split and 'lportstatus'
                         or 'lport' in uri_split and 'lport'
                         or 'lswitch' in uri_split and 'lswitch')
        switch_uuid = ('lswitch' in uri_split and
                       len(uri_split) > 3 and uri_split[3])
        port_uuid = ('lport' in uri_split and
                     len(uri_split) > 5 and uri_split[5])
        return (resource_type, switch_uuid, port_uuid)

    def _list(self, resource_type, response_file,
              switch_uuid=None, query=None):
        (tag_filter, attr_filter) = self._get_filters(query)

        with open("%s/%s" % (self.fake_files_path, response_file)) as f:
            response_template = f.read()
            res_dict = getattr(self, '_fake_%s_dict' % resource_type)
            if switch_uuid == "*":
                switch_uuid = None

            def _attr_match(res_uuid):
                if not attr_filter:
                    return True
                item = res_dict[res_uuid]
                for (attr, value) in attr_filter.iteritems():
                    if item.get(attr) != value:
                        return False
                return True

            def _tag_match(res_uuid):
                if not tag_filter:
                    return True
                return any([x['scope'] == tag_filter['scope'] and
                            x['tag'] == tag_filter['tag']
                            for x in res_dict[res_uuid]['tags']])

            def _lswitch_match(res_uuid):
                if (not switch_uuid or
                        res_dict[res_uuid].get('ls_uuid') == switch_uuid):
                    return True
                return False

            items = [json.loads(response_template % res_dict[res_uuid])
                     for res_uuid in res_dict
                     if (_lswitch_match(res_uuid) and
                         _tag_match(res_uuid) and
                         _attr_match(res_uuid))]

            return json.dumps({'results': items,
                               'result_count': len(items)})

    def _show(self, resource_type, response_file,
              switch_uuid, port_uuid=None):
        target_uuid = port_uuid or switch_uuid
        with open("%s/%s" % (self.fake_files_path, response_file)) as f:
            response_template = f.read()
            res_dict = getattr(self, '_fake_%s_dict' % resource_type)
            items = [json.loads(response_template % res_dict[res_uuid])
                     for res_uuid in res_dict if res_uuid == target_uuid]
            if items:
                return json.dumps(items[0])
            raise Exception("show: resource %s:%s not found" %
                            (resource_type, target_uuid))

    def handle_get(self, url):
        #TODO(salvatore-orlando): handle field selection
        parsedurl = urlparse.urlparse(url)
        (res_type, s_uuid, p_uuid) = self._get_resource_type(parsedurl.path)
        response_file = self.FAKE_GET_RESPONSES.get(res_type)
        if not response_file:
            raise Exception("resource not found")
        if res_type == 'lport':
            if p_uuid:
                return self._show(res_type, response_file, s_uuid, p_uuid)
            else:
                return self._list(res_type, response_file, s_uuid,
                                  query=parsedurl.query)
        elif res_type == 'lportstatus':
            return self._show(res_type, response_file, s_uuid, p_uuid)
        elif res_type == 'lswitch':
            if s_uuid:
                return self._show(res_type, response_file, s_uuid)
            else:
                return self._list(res_type, response_file,
                                  query=parsedurl.query)
        else:
            raise Exception("unknown resource:%s" % res_type)

    def handle_post(self, url, body):
        parsedurl = urlparse.urlparse(url)
        (res_type, s_uuid, _p) = self._get_resource_type(parsedurl.path)
        response_file = self.FAKE_POST_RESPONSES.get(res_type)
        if not response_file:
            raise Exception("resource not found")
        with open("%s/%s" % (self.fake_files_path, response_file)) as f:
            response_template = f.read()
            add_resource = getattr(self, '_add_%s' % res_type)
            args = [body]
            if s_uuid:
                args.append(s_uuid)
            response = response_template % add_resource(*args)
            return response

    def handle_put(self, url, body):
        parsedurl = urlparse.urlparse(url)
        (res_type, s_uuid, p_uuid) = self._get_resource_type(parsedurl.path)
        target_uuid = p_uuid or s_uuid
        response_file = self.FAKE_PUT_RESPONSES.get(res_type)
        if not response_file:
            raise Exception("resource not found")
        with open("%s/%s" % (self.fake_files_path, response_file)) as f:
            response_template = f.read()
            res_dict = getattr(self, '_fake_%s_dict' % res_type)
            resource = res_dict[target_uuid]
            resource.update(json.loads(body))
            response = response_template % resource
            return response

    def handle_delete(self, url):
        parsedurl = urlparse.urlparse(url)
        (res_type, s_uuid, p_uuid) = self._get_resource_type(parsedurl.path)
        target_uuid = p_uuid or s_uuid
        response_file = self.FAKE_PUT_RESPONSES.get(res_type)
        if not response_file:
            raise Exception("resource not found")
        res_dict = getattr(self, '_fake_%s_dict' % res_type)
        del res_dict[target_uuid]
        return ""

    def fake_request(self, *args, **kwargs):
        method = args[0]
        handler = getattr(self, "handle_%s" % method.lower())
        return handler(*args[1:])

    def reset_all(self):
        self._fake_lswitch_dict.clear()
        self._fake_lport_dict.clear()
        self._fake_lportstatus_dict.clear()
