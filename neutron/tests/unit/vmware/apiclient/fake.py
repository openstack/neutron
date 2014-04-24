# Copyright 2012 VMware, Inc.
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

import json

import six.moves.urllib.parse as urlparse

from neutron.openstack.common import log as logging
from neutron.openstack.common import uuidutils
from neutron.plugins.vmware.api_client import exception as api_exc


LOG = logging.getLogger(__name__)
MAX_NAME_LEN = 40


def _validate_name(name):
    if name and len(name) > MAX_NAME_LEN:
        raise Exception("Logical switch name exceeds %d characters",
                        MAX_NAME_LEN)


def _validate_resource(body):
    _validate_name(body.get('display_name'))


class FakeClient:

    LSWITCH_RESOURCE = 'lswitch'
    LPORT_RESOURCE = 'lport'
    LROUTER_RESOURCE = 'lrouter'
    NAT_RESOURCE = 'nat'
    LQUEUE_RESOURCE = 'lqueue'
    SECPROF_RESOURCE = 'securityprofile'
    LSWITCH_STATUS = 'lswitchstatus'
    LROUTER_STATUS = 'lrouterstatus'
    LSWITCH_LPORT_RESOURCE = 'lswitch_lport'
    LROUTER_LPORT_RESOURCE = 'lrouter_lport'
    LROUTER_NAT_RESOURCE = 'lrouter_nat'
    LSWITCH_LPORT_STATUS = 'lswitch_lportstatus'
    LSWITCH_LPORT_ATT = 'lswitch_lportattachment'
    LROUTER_LPORT_STATUS = 'lrouter_lportstatus'
    LROUTER_LPORT_ATT = 'lrouter_lportattachment'
    GWSERVICE_RESOURCE = 'gatewayservice'

    RESOURCES = [LSWITCH_RESOURCE, LROUTER_RESOURCE, LQUEUE_RESOURCE,
                 LPORT_RESOURCE, NAT_RESOURCE, SECPROF_RESOURCE,
                 GWSERVICE_RESOURCE]

    FAKE_GET_RESPONSES = {
        LSWITCH_RESOURCE: "fake_get_lswitch.json",
        LSWITCH_LPORT_RESOURCE: "fake_get_lswitch_lport.json",
        LSWITCH_LPORT_STATUS: "fake_get_lswitch_lport_status.json",
        LSWITCH_LPORT_ATT: "fake_get_lswitch_lport_att.json",
        LROUTER_RESOURCE: "fake_get_lrouter.json",
        LROUTER_LPORT_RESOURCE: "fake_get_lrouter_lport.json",
        LROUTER_LPORT_STATUS: "fake_get_lrouter_lport_status.json",
        LROUTER_LPORT_ATT: "fake_get_lrouter_lport_att.json",
        LROUTER_STATUS: "fake_get_lrouter_status.json",
        LROUTER_NAT_RESOURCE: "fake_get_lrouter_nat.json",
        SECPROF_RESOURCE: "fake_get_security_profile.json",
        LQUEUE_RESOURCE: "fake_get_lqueue.json",
        GWSERVICE_RESOURCE: "fake_get_gwservice.json"
    }

    FAKE_POST_RESPONSES = {
        LSWITCH_RESOURCE: "fake_post_lswitch.json",
        LROUTER_RESOURCE: "fake_post_lrouter.json",
        LSWITCH_LPORT_RESOURCE: "fake_post_lswitch_lport.json",
        LROUTER_LPORT_RESOURCE: "fake_post_lrouter_lport.json",
        LROUTER_NAT_RESOURCE: "fake_post_lrouter_nat.json",
        SECPROF_RESOURCE: "fake_post_security_profile.json",
        LQUEUE_RESOURCE: "fake_post_lqueue.json",
        GWSERVICE_RESOURCE: "fake_post_gwservice.json"
    }

    FAKE_PUT_RESPONSES = {
        LSWITCH_RESOURCE: "fake_post_lswitch.json",
        LROUTER_RESOURCE: "fake_post_lrouter.json",
        LSWITCH_LPORT_RESOURCE: "fake_post_lswitch_lport.json",
        LROUTER_LPORT_RESOURCE: "fake_post_lrouter_lport.json",
        LROUTER_NAT_RESOURCE: "fake_post_lrouter_nat.json",
        LSWITCH_LPORT_ATT: "fake_put_lswitch_lport_att.json",
        LROUTER_LPORT_ATT: "fake_put_lrouter_lport_att.json",
        SECPROF_RESOURCE: "fake_post_security_profile.json",
        LQUEUE_RESOURCE: "fake_post_lqueue.json",
        GWSERVICE_RESOURCE: "fake_post_gwservice.json"
    }

    MANAGED_RELATIONS = {
        LSWITCH_RESOURCE: [],
        LROUTER_RESOURCE: [],
        LSWITCH_LPORT_RESOURCE: ['LogicalPortAttachment'],
        LROUTER_LPORT_RESOURCE: ['LogicalPortAttachment'],
    }

    _validators = {
        LSWITCH_RESOURCE: _validate_resource,
        LSWITCH_LPORT_RESOURCE: _validate_resource,
        LROUTER_LPORT_RESOURCE: _validate_resource,
        SECPROF_RESOURCE: _validate_resource,
        LQUEUE_RESOURCE: _validate_resource,
        GWSERVICE_RESOURCE: _validate_resource
    }

    def __init__(self, fake_files_path):
        self.fake_files_path = fake_files_path
        self._fake_lswitch_dict = {}
        self._fake_lrouter_dict = {}
        self._fake_lswitch_lport_dict = {}
        self._fake_lrouter_lport_dict = {}
        self._fake_lrouter_nat_dict = {}
        self._fake_lswitch_lportstatus_dict = {}
        self._fake_lrouter_lportstatus_dict = {}
        self._fake_securityprofile_dict = {}
        self._fake_lqueue_dict = {}
        self._fake_gatewayservice_dict = {}

    def _get_tag(self, resource, scope):
        tags = [tag['tag'] for tag in resource['tags']
                if tag['scope'] == scope]
        return len(tags) > 0 and tags[0]

    def _get_filters(self, querystring):
        if not querystring:
            return (None, None, None, None)
        params = urlparse.parse_qs(querystring)
        tag_filter = None
        attr_filter = None
        if 'tag' in params and 'tag_scope' in params:
            tag_filter = {'scope': params['tag_scope'][0],
                          'tag': params['tag'][0]}
        elif 'uuid' in params:
            attr_filter = {'uuid': params['uuid'][0]}
        # Handle page length and page cursor parameter
        page_len = params.get('_page_length')
        page_cursor = params.get('_page_cursor')
        if page_len:
            page_len = int(page_len[0])
        else:
            # Explicitly set it to None (avoid 0 or empty list)
            page_len = None
        return (tag_filter, attr_filter, page_len, page_cursor)

    def _add_lswitch(self, body):
        fake_lswitch = json.loads(body)
        fake_lswitch['uuid'] = uuidutils.generate_uuid()
        self._fake_lswitch_dict[fake_lswitch['uuid']] = fake_lswitch
        # put the tenant_id and the zone_uuid in the main dict
        # for simplyfying templating
        zone_uuid = fake_lswitch['transport_zones'][0]['zone_uuid']
        fake_lswitch['zone_uuid'] = zone_uuid
        fake_lswitch['tenant_id'] = self._get_tag(fake_lswitch, 'os_tid')
        fake_lswitch['lport_count'] = 0
        # set status value
        fake_lswitch['status'] = 'true'
        return fake_lswitch

    def _build_lrouter(self, body, uuid=None):
        fake_lrouter = json.loads(body)
        if uuid:
            fake_lrouter['uuid'] = uuid
        fake_lrouter['tenant_id'] = self._get_tag(fake_lrouter, 'os_tid')
        default_nexthop = fake_lrouter['routing_config'].get(
            'default_route_next_hop')
        if default_nexthop:
            fake_lrouter['default_next_hop'] = default_nexthop.get(
                'gateway_ip_address', '0.0.0.0')
        else:
            fake_lrouter['default_next_hop'] = '0.0.0.0'
        # NOTE(salv-orlando): We won't make the Fake NSX API client
        # aware of NSX version. The long term plan is to replace it
        # with behavioral mocking of NSX API requests
        if 'distributed' not in fake_lrouter:
            fake_lrouter['distributed'] = False
        distributed_json = ('"distributed": %s,' %
                            str(fake_lrouter['distributed']).lower())
        fake_lrouter['distributed_json'] = distributed_json
        return fake_lrouter

    def _add_lrouter(self, body):
        fake_lrouter = self._build_lrouter(body,
                                           uuidutils.generate_uuid())
        self._fake_lrouter_dict[fake_lrouter['uuid']] = fake_lrouter
        fake_lrouter['lport_count'] = 0
        # set status value
        fake_lrouter['status'] = 'true'
        return fake_lrouter

    def _add_lqueue(self, body):
        fake_lqueue = json.loads(body)
        fake_lqueue['uuid'] = uuidutils.generate_uuid()
        self._fake_lqueue_dict[fake_lqueue['uuid']] = fake_lqueue
        return fake_lqueue

    def _add_lswitch_lport(self, body, ls_uuid):
        fake_lport = json.loads(body)
        new_uuid = uuidutils.generate_uuid()
        fake_lport['uuid'] = new_uuid
        # put the tenant_id and the ls_uuid in the main dict
        # for simplyfying templating
        fake_lport['ls_uuid'] = ls_uuid
        fake_lport['tenant_id'] = self._get_tag(fake_lport, 'os_tid')
        fake_lport['neutron_port_id'] = self._get_tag(fake_lport,
                                                      'q_port_id')
        fake_lport['neutron_device_id'] = self._get_tag(fake_lport, 'vm_id')
        fake_lport['att_type'] = "NoAttachment"
        fake_lport['att_info_json'] = ''
        self._fake_lswitch_lport_dict[fake_lport['uuid']] = fake_lport

        fake_lswitch = self._fake_lswitch_dict[ls_uuid]
        fake_lswitch['lport_count'] += 1
        fake_lport_status = fake_lport.copy()
        fake_lport_status['ls_tenant_id'] = fake_lswitch['tenant_id']
        fake_lport_status['ls_uuid'] = fake_lswitch['uuid']
        fake_lport_status['ls_name'] = fake_lswitch['display_name']
        fake_lport_status['ls_zone_uuid'] = fake_lswitch['zone_uuid']
        # set status value
        fake_lport['status'] = 'true'
        self._fake_lswitch_lportstatus_dict[new_uuid] = fake_lport_status
        return fake_lport

    def _build_lrouter_lport(self, body, new_uuid=None, lr_uuid=None):
        fake_lport = json.loads(body)
        if new_uuid:
            fake_lport['uuid'] = new_uuid
        # put the tenant_id and the le_uuid in the main dict
        # for simplyfying templating
        if lr_uuid:
            fake_lport['lr_uuid'] = lr_uuid
        fake_lport['tenant_id'] = self._get_tag(fake_lport, 'os_tid')
        fake_lport['neutron_port_id'] = self._get_tag(fake_lport,
                                                      'q_port_id')
        # replace ip_address with its json dump
        if 'ip_addresses' in fake_lport:
            ip_addresses_json = json.dumps(fake_lport['ip_addresses'])
            fake_lport['ip_addresses_json'] = ip_addresses_json
        return fake_lport

    def _add_lrouter_lport(self, body, lr_uuid):
        new_uuid = uuidutils.generate_uuid()
        fake_lport = self._build_lrouter_lport(body, new_uuid, lr_uuid)
        self._fake_lrouter_lport_dict[fake_lport['uuid']] = fake_lport
        try:
            fake_lrouter = self._fake_lrouter_dict[lr_uuid]
        except KeyError:
            raise api_exc.ResourceNotFound()
        fake_lrouter['lport_count'] += 1
        fake_lport_status = fake_lport.copy()
        fake_lport_status['lr_tenant_id'] = fake_lrouter['tenant_id']
        fake_lport_status['lr_uuid'] = fake_lrouter['uuid']
        fake_lport_status['lr_name'] = fake_lrouter['display_name']
        self._fake_lrouter_lportstatus_dict[new_uuid] = fake_lport_status
        return fake_lport

    def _add_securityprofile(self, body):
        fake_securityprofile = json.loads(body)
        fake_securityprofile['uuid'] = uuidutils.generate_uuid()
        fake_securityprofile['tenant_id'] = self._get_tag(
            fake_securityprofile, 'os_tid')

        fake_securityprofile['nova_spid'] = self._get_tag(fake_securityprofile,
                                                          'nova_spid')
        self._fake_securityprofile_dict[fake_securityprofile['uuid']] = (
            fake_securityprofile)
        return fake_securityprofile

    def _add_lrouter_nat(self, body, lr_uuid):
        fake_nat = json.loads(body)
        new_uuid = uuidutils.generate_uuid()
        fake_nat['uuid'] = new_uuid
        fake_nat['lr_uuid'] = lr_uuid
        self._fake_lrouter_nat_dict[fake_nat['uuid']] = fake_nat
        if 'match' in fake_nat:
            match_json = json.dumps(fake_nat['match'])
            fake_nat['match_json'] = match_json
        return fake_nat

    def _add_gatewayservice(self, body):
        fake_gwservice = json.loads(body)
        fake_gwservice['uuid'] = str(uuidutils.generate_uuid())
        fake_gwservice['tenant_id'] = self._get_tag(
            fake_gwservice, 'os_tid')
        # FIXME(salvatore-orlando): For simplicity we're managing only a
        # single device. Extend the fake client for supporting multiple devices
        first_gw = fake_gwservice['gateways'][0]
        fake_gwservice['transport_node_uuid'] = first_gw['transport_node_uuid']
        fake_gwservice['device_id'] = first_gw['device_id']
        self._fake_gatewayservice_dict[fake_gwservice['uuid']] = (
            fake_gwservice)
        return fake_gwservice

    def _build_relation(self, src, dst, resource_type, relation):
        if relation not in self.MANAGED_RELATIONS[resource_type]:
            return  # Relation is not desired in output
        if not '_relations' in src or not src['_relations'].get(relation):
            return  # Item does not have relation
        relation_data = src['_relations'].get(relation)
        dst_relations = dst.get('_relations', {})
        dst_relations[relation] = relation_data
        dst['_relations'] = dst_relations

    def _fill_attachment(self, att_data, ls_uuid=None,
                         lr_uuid=None, lp_uuid=None):
        new_data = att_data.copy()
        for k in ('ls_uuid', 'lr_uuid', 'lp_uuid'):
            if locals().get(k):
                new_data[k] = locals()[k]

        def populate_field(field_name):
            if field_name in att_data:
                new_data['%s_field' % field_name] = ('"%s" : "%s",'
                                                     % (field_name,
                                                        att_data[field_name]))
                del new_data[field_name]
            else:
                new_data['%s_field' % field_name] = ""

        for field in ['vif_uuid', 'peer_port_href', 'vlan_id',
                      'peer_port_uuid', 'l3_gateway_service_uuid']:
            populate_field(field)
        return new_data

    def _get_resource_type(self, path):
        """Get resource type.

        Identifies resource type and relevant uuids in the uri

        /ws.v1/lswitch/xxx
        /ws.v1/lswitch/xxx/status
        /ws.v1/lswitch/xxx/lport/yyy
        /ws.v1/lswitch/xxx/lport/yyy/status
        /ws.v1/lrouter/zzz
        /ws.v1/lrouter/zzz/status
        /ws.v1/lrouter/zzz/lport/www
        /ws.v1/lrouter/zzz/lport/www/status
        /ws.v1/lqueue/xxx
        """
        # The first element will always be 'ws.v1' - so we just discard it
        uri_split = path.split('/')[1:]
        # parse uri_split backwards
        suffix = ""
        idx = len(uri_split) - 1
        if 'status' in uri_split[idx]:
            suffix = "status"
            idx = idx - 1
        elif 'attachment' in uri_split[idx]:
            suffix = "attachment"
            idx = idx - 1
        # then check if we have an uuid
        uuids = []
        if uri_split[idx].replace('-', '') not in self.RESOURCES:
            uuids.append(uri_split[idx])
            idx = idx - 1
        resource_type = "%s%s" % (uri_split[idx], suffix)
        if idx > 1:
            uuids.insert(0, uri_split[idx - 1])
            resource_type = "%s_%s" % (uri_split[idx - 2], resource_type)
        return (resource_type.replace('-', ''), uuids)

    def _list(self, resource_type, response_file,
              parent_uuid=None, query=None, relations=None):
        (tag_filter, attr_filter,
         page_len, page_cursor) = self._get_filters(query)
        # result_count attribute in response should appear only when
        # page_cursor is not specified
        do_result_count = not page_cursor
        with open("%s/%s" % (self.fake_files_path, response_file)) as f:
            response_template = f.read()
            res_dict = getattr(self, '_fake_%s_dict' % resource_type)
            if parent_uuid == '*':
                parent_uuid = None
            # NSX raises ResourceNotFound if lswitch doesn't exist and is not *
            elif not res_dict and resource_type == self.LSWITCH_LPORT_RESOURCE:
                raise api_exc.ResourceNotFound()

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
                # verify that the switch exist
                if parent_uuid and not parent_uuid in self._fake_lswitch_dict:
                    raise Exception(_("lswitch:%s not found") % parent_uuid)
                if (not parent_uuid
                    or res_dict[res_uuid].get('ls_uuid') == parent_uuid):
                    return True
                return False

            def _lrouter_match(res_uuid):
                # verify that the router exist
                if parent_uuid and not parent_uuid in self._fake_lrouter_dict:
                    raise Exception(_("lrouter:%s not found") % parent_uuid)
                if (not parent_uuid or
                    res_dict[res_uuid].get('lr_uuid') == parent_uuid):
                    return True
                return False

            def _cursor_match(res_uuid, page_cursor):
                if not page_cursor:
                    return True
                if page_cursor == res_uuid:
                    # always return True once page_cursor has been found
                    page_cursor = None
                    return True
                return False

            def _build_item(resource):
                item = json.loads(response_template % resource)
                if relations:
                    for relation in relations:
                        self._build_relation(resource, item,
                                             resource_type, relation)
                return item

            for item in res_dict.itervalues():
                if 'tags' in item:
                    item['tags_json'] = json.dumps(item['tags'])
            if resource_type in (self.LSWITCH_LPORT_RESOURCE,
                                 self.LSWITCH_LPORT_ATT,
                                 self.LSWITCH_LPORT_STATUS):
                parent_func = _lswitch_match
            elif resource_type in (self.LROUTER_LPORT_RESOURCE,
                                   self.LROUTER_LPORT_ATT,
                                   self.LROUTER_NAT_RESOURCE,
                                   self.LROUTER_LPORT_STATUS):
                parent_func = _lrouter_match
            else:
                parent_func = lambda x: True

            items = [_build_item(res_dict[res_uuid])
                     for res_uuid in res_dict
                     if (parent_func(res_uuid) and
                         _tag_match(res_uuid) and
                         _attr_match(res_uuid) and
                         _cursor_match(res_uuid, page_cursor))]
            # Rather inefficient, but hey this is just a mock!
            next_cursor = None
            total_items = len(items)
            if page_len:
                try:
                    next_cursor = items[page_len]['uuid']
                except IndexError:
                    next_cursor = None
                items = items[:page_len]
            response_dict = {'results': items}
            if next_cursor:
                response_dict['page_cursor'] = next_cursor
            if do_result_count:
                response_dict['result_count'] = total_items
            return json.dumps(response_dict)

    def _show(self, resource_type, response_file,
              uuid1, uuid2=None, relations=None):
        target_uuid = uuid2 or uuid1
        if resource_type.endswith('attachment'):
            resource_type = resource_type[:resource_type.index('attachment')]
        with open("%s/%s" % (self.fake_files_path, response_file)) as f:
            response_template = f.read()
            res_dict = getattr(self, '_fake_%s_dict' % resource_type)
            for item in res_dict.itervalues():
                if 'tags' in item:
                    item['tags_json'] = json.dumps(item['tags'])

                # replace sec prof rules with their json dump
                def jsonify_rules(rule_key):
                    if rule_key in item:
                        rules_json = json.dumps(item[rule_key])
                        item['%s_json' % rule_key] = rules_json
                jsonify_rules('logical_port_egress_rules')
                jsonify_rules('logical_port_ingress_rules')

            items = [json.loads(response_template % res_dict[res_uuid])
                     for res_uuid in res_dict if res_uuid == target_uuid]
            if items:
                return json.dumps(items[0])
            raise api_exc.ResourceNotFound()

    def handle_get(self, url):
        #TODO(salvatore-orlando): handle field selection
        parsedurl = urlparse.urlparse(url)
        (res_type, uuids) = self._get_resource_type(parsedurl.path)
        relations = urlparse.parse_qs(parsedurl.query).get('relations')
        response_file = self.FAKE_GET_RESPONSES.get(res_type)
        if not response_file:
            raise api_exc.NsxApiException()
        if 'lport' in res_type or 'nat' in res_type:
            if len(uuids) > 1:
                return self._show(res_type, response_file, uuids[0],
                                  uuids[1], relations=relations)
            else:
                return self._list(res_type, response_file, uuids[0],
                                  query=parsedurl.query, relations=relations)
        elif ('lswitch' in res_type or
              'lrouter' in res_type or
              self.SECPROF_RESOURCE in res_type or
              self.LQUEUE_RESOURCE in res_type or
              'gatewayservice' in res_type):
            LOG.debug("UUIDS:%s", uuids)
            if uuids:
                return self._show(res_type, response_file, uuids[0],
                                  relations=relations)
            else:
                return self._list(res_type, response_file,
                                  query=parsedurl.query,
                                  relations=relations)
        else:
            raise Exception("unknown resource:%s" % res_type)

    def handle_post(self, url, body):
        parsedurl = urlparse.urlparse(url)
        (res_type, uuids) = self._get_resource_type(parsedurl.path)
        response_file = self.FAKE_POST_RESPONSES.get(res_type)
        if not response_file:
            raise Exception("resource not found")
        with open("%s/%s" % (self.fake_files_path, response_file)) as f:
            response_template = f.read()
            add_resource = getattr(self, '_add_%s' % res_type)
            body_json = json.loads(body)
            val_func = self._validators.get(res_type)
            if val_func:
                val_func(body_json)
            args = [body]
            if uuids:
                args.append(uuids[0])
            response = response_template % add_resource(*args)
            return response

    def handle_put(self, url, body):
        parsedurl = urlparse.urlparse(url)
        (res_type, uuids) = self._get_resource_type(parsedurl.path)
        response_file = self.FAKE_PUT_RESPONSES.get(res_type)
        if not response_file:
            raise Exception("resource not found")
        with open("%s/%s" % (self.fake_files_path, response_file)) as f:
            response_template = f.read()
            # Manage attachment operations
            is_attachment = False
            if res_type.endswith('attachment'):
                is_attachment = True
                res_type = res_type[:res_type.index('attachment')]
            res_dict = getattr(self, '_fake_%s_dict' % res_type)
            body_json = json.loads(body)
            val_func = self._validators.get(res_type)
            if val_func:
                val_func(body_json)
            try:
                resource = res_dict[uuids[-1]]
            except KeyError:
                raise api_exc.ResourceNotFound()
            if not is_attachment:
                edit_resource = getattr(self, '_build_%s' % res_type, None)
                if edit_resource:
                    body_json = edit_resource(body)
                resource.update(body_json)
            else:
                relations = resource.get("_relations", {})
                body_2 = json.loads(body)
                resource['att_type'] = body_2['type']
                relations['LogicalPortAttachment'] = body_2
                resource['_relations'] = relations
                if body_2['type'] == "PatchAttachment":
                    # We need to do a trick here
                    if self.LROUTER_RESOURCE in res_type:
                        res_type_2 = res_type.replace(self.LROUTER_RESOURCE,
                                                      self.LSWITCH_RESOURCE)
                    elif self.LSWITCH_RESOURCE in res_type:
                        res_type_2 = res_type.replace(self.LSWITCH_RESOURCE,
                                                      self.LROUTER_RESOURCE)
                    res_dict_2 = getattr(self, '_fake_%s_dict' % res_type_2)
                    body_2['peer_port_uuid'] = uuids[-1]
                    resource_2 = res_dict_2[json.loads(body)['peer_port_uuid']]
                    relations_2 = resource_2.get("_relations")
                    if not relations_2:
                        relations_2 = {}
                    relations_2['LogicalPortAttachment'] = body_2
                    resource_2['_relations'] = relations_2
                    resource['peer_port_uuid'] = body_2['peer_port_uuid']
                    resource['att_info_json'] = (
                        "\"peer_port_uuid\": \"%s\"," %
                        resource_2['uuid'])
                    resource_2['att_info_json'] = (
                        "\"peer_port_uuid\": \"%s\"," %
                        body_2['peer_port_uuid'])
                elif body_2['type'] == "L3GatewayAttachment":
                    resource['attachment_gwsvc_uuid'] = (
                        body_2['l3_gateway_service_uuid'])
                    resource['vlan_id'] = body_2.get('vlan_id')
                elif body_2['type'] == "L2GatewayAttachment":
                    resource['attachment_gwsvc_uuid'] = (
                        body_2['l2_gateway_service_uuid'])
                elif body_2['type'] == "VifAttachment":
                    resource['vif_uuid'] = body_2['vif_uuid']
                    resource['att_info_json'] = (
                        "\"vif_uuid\": \"%s\"," % body_2['vif_uuid'])

            if not is_attachment:
                response = response_template % resource
            else:
                if res_type == self.LROUTER_LPORT_RESOURCE:
                    lr_uuid = uuids[0]
                    ls_uuid = None
                elif res_type == self.LSWITCH_LPORT_RESOURCE:
                    ls_uuid = uuids[0]
                    lr_uuid = None
                lp_uuid = uuids[1]
                response = response_template % self._fill_attachment(
                    json.loads(body), ls_uuid, lr_uuid, lp_uuid)
            return response

    def handle_delete(self, url):
        parsedurl = urlparse.urlparse(url)
        (res_type, uuids) = self._get_resource_type(parsedurl.path)
        response_file = self.FAKE_PUT_RESPONSES.get(res_type)
        if not response_file:
            raise Exception("resource not found")
        res_dict = getattr(self, '_fake_%s_dict' % res_type)
        try:
            del res_dict[uuids[-1]]
        except KeyError:
            raise api_exc.ResourceNotFound()
        return ""

    def fake_request(self, *args, **kwargs):
        method = args[0]
        handler = getattr(self, "handle_%s" % method.lower())
        return handler(*args[1:])

    def reset_all(self):
        self._fake_lswitch_dict.clear()
        self._fake_lrouter_dict.clear()
        self._fake_lswitch_lport_dict.clear()
        self._fake_lrouter_lport_dict.clear()
        self._fake_lswitch_lportstatus_dict.clear()
        self._fake_lrouter_lportstatus_dict.clear()
        self._fake_lqueue_dict.clear()
        self._fake_securityprofile_dict.clear()
        self._fake_gatewayservice_dict.clear()
