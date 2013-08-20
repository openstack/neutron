# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2013 VMware, Inc
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
# @author: linb, VMware

import copy
import json

from neutron.openstack.common import uuidutils


class FakeVcns(object):

    def __init__(self, unique_router_name=True):
        self._jobs = {}
        self._job_idx = 0
        self._edges = {}
        self._edge_idx = 0
        self._lswitches = {}
        self._unique_router_name = unique_router_name
        self._fake_nvpapi = None

    def set_fake_nvpapi(self, fake_nvpapi):
        self._fake_nvpapi = fake_nvpapi

    def _validate_edge_name(self, name):
        for edge_id, edge in self._edges.iteritems():
            if edge['name'] == name:
                return False
        return True

    def deploy_edge(self, request):
        if (self._unique_router_name and
            not self._validate_edge_name(request['name'])):
            header = {
                'status': 400
            }
            msg = ('Edge name should be unique for tenant. Edge %s '
                   'already exists for default tenant.') % request['name']
            response = {
                'details': msg,
                'errorCode': 10085,
                'rootCauseString': None,
                'moduleName': 'vShield Edge',
                'errorData': None
            }
            return (header, json.dumps(response))

        self._job_idx = self._job_idx + 1
        job_id = "jobdata-%d" % self._job_idx
        self._edge_idx = self._edge_idx + 1
        edge_id = "edge-%d" % self._edge_idx
        self._jobs[job_id] = edge_id
        self._edges[edge_id] = {
            'name': request['name'],
            'request': request,
            'nat_rules': None,
            'nat_rule_id': 0
        }
        header = {
            'status': 200,
            'location': 'https://host/api/4.0/jobs/%s' % job_id
        }
        response = ''
        return (header, response)

    def get_edge_id(self, job_id):
        if job_id not in self._jobs:
            raise Exception(_("Job %s does not nexist") % job_id)

        header = {
            'status': 200
        }
        response = {
            'edgeId': self._jobs[job_id]
        }
        return (header, response)

    def get_edge_deploy_status(self, edge_id):
        if edge_id not in self._edges:
            raise Exception(_("Edge %s does not exist") % edge_id)
        header = {
            'status': 200,
        }
        response = {
            'systemStatus': 'good'
        }
        return (header, response)

    def delete_edge(self, edge_id):
        if edge_id not in self._edges:
            raise Exception(_("Edge %s does not exist") % edge_id)
        del self._edges[edge_id]
        header = {
            'status': 200
        }
        response = ''
        return (header, response)

    def update_interface(self, edge_id, vnic):
        header = {
            'status': 200
        }
        response = ''
        return (header, response)

    def get_nat_config(self, edge_id):
        if edge_id not in self._edges:
            raise Exception(_("Edge %s does not exist") % edge_id)
        edge = self._edges[edge_id]
        rules = edge['nat_rules']
        if rules is None:
            rules = {
                'rules': {
                    'natRulesDtos': []
                },
                'version': 1
            }
        header = {
            'status': 200
        }
        rules['version'] = 1
        return (header, rules)

    def update_nat_config(self, edge_id, nat):
        if edge_id not in self._edges:
            raise Exception(_("Edge %s does not exist") % edge_id)
        edge = self._edges[edge_id]
        max_rule_id = edge['nat_rule_id']
        rules = copy.deepcopy(nat)
        for rule in rules['rules']['natRulesDtos']:
            rule_id = rule.get('ruleId', 0)
            if rule_id > max_rule_id:
                max_rule_id = rule_id
        for rule in rules['rules']['natRulesDtos']:
            if 'ruleId' not in rule:
                max_rule_id = max_rule_id + 1
                rule['ruleId'] = max_rule_id
        edge['nat_rules'] = rules
        edge['nat_rule_id'] = max_rule_id
        header = {
            'status': 200
        }
        response = ''
        return (header, response)

    def delete_nat_rule(self, edge_id, rule_id):
        if edge_id not in self._edges:
            raise Exception(_("Edge %s does not exist") % edge_id)

        edge = self._edges[edge_id]
        rules = edge['nat_rules']
        rule_to_delete = None
        for rule in rules['rules']['natRulesDtos']:
            if rule_id == rule['ruleId']:
                rule_to_delete = rule
                break
        if rule_to_delete is None:
            raise Exception(_("Rule id %d doest not exist") % rule_id)

        rules['rules']['natRulesDtos'].remove(rule_to_delete)

        header = {
            'status': 200
        }
        response = ''
        return (header, response)

    def get_edge_status(self, edge_id):
        if edge_id not in self._edges:
            raise Exception(_("Edge %s does not exist") % edge_id)

        header = {
            'status': 200
        }
        response = {
            'edgeStatus': 'GREEN'
        }
        return (header, response)

    def get_edges(self):
        header = {
            'status': 200
        }
        edges = []
        for edge_id in self._edges:
            edges.append({
                'id': edge_id,
                'edgeStatus': 'GREEN'
            })
        response = {
            'edgePage': {
                'data': edges
            }
        }
        return (header, response)

    def update_routes(self, edge_id, routes):
        header = {
            'status': 200
        }
        response = ''
        return (header, response)

    def create_lswitch(self, lsconfig):
        # The lswitch is created via VCNS API so the fake nvpapi wont
        # see it. Added to fake nvpapi here.
        if self._fake_nvpapi:
            lswitch = self._fake_nvpapi._add_lswitch(json.dumps(lsconfig))
        else:
            lswitch = lsconfig
            lswitch['uuid'] = uuidutils.generate_uuid()
        self._lswitches[lswitch['uuid']] = lswitch
        header = {
            'status': 200
        }
        lswitch['_href'] = '/api/ws.v1/lswitch/%s' % lswitch['uuid']
        return (header, lswitch)

    def delete_lswitch(self, id):
        if id not in self._lswitches:
            raise Exception(_("Lswitch %s does not exist") % id)
        del self._lswitches[id]
        if self._fake_nvpapi:
            # TODO(fank): fix the hack
            del self._fake_nvpapi._fake_lswitch_dict[id]
        header = {
            'status': 200
        }
        response = ''
        return (header, response)

    def reset_all(self):
        self._jobs.clear()
        self._edges.clear()
        self._lswitches.clear()
