# Copyright 2013 OpenStack Foundation
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

import json
import urllib

from neutron.tests.tempest.common import service_client


class IdentityV3ClientJSON(service_client.ServiceClient):
    api_version = "v3"

    def create_user(self, user_name, password=None, project_id=None,
                    email=None, domain_id='default', **kwargs):
        """Creates a user."""
        en = kwargs.get('enabled', True)
        description = kwargs.get('description', None)
        default_project_id = kwargs.get('default_project_id')
        post_body = {
            'project_id': project_id,
            'default_project_id': default_project_id,
            'description': description,
            'domain_id': domain_id,
            'email': email,
            'enabled': en,
            'name': user_name,
            'password': password
        }
        post_body = json.dumps({'user': post_body})
        resp, body = self.post('users', post_body)
        self.expected_success(201, resp.status)
        body = json.loads(body)
        return service_client.ResponseBody(resp, body['user'])

    def update_user(self, user_id, name, **kwargs):
        """Updates a user."""
        body = self.get_user(user_id)
        email = kwargs.get('email', body['email'])
        en = kwargs.get('enabled', body['enabled'])
        project_id = kwargs.get('project_id', body['project_id'])
        if 'default_project_id' in body.keys():
            default_project_id = kwargs.get('default_project_id',
                                            body['default_project_id'])
        else:
            default_project_id = kwargs.get('default_project_id')
        description = kwargs.get('description', body['description'])
        domain_id = kwargs.get('domain_id', body['domain_id'])
        post_body = {
            'name': name,
            'email': email,
            'enabled': en,
            'project_id': project_id,
            'default_project_id': default_project_id,
            'id': user_id,
            'domain_id': domain_id,
            'description': description
        }
        post_body = json.dumps({'user': post_body})
        resp, body = self.patch('users/%s' % user_id, post_body)
        self.expected_success(200, resp.status)
        body = json.loads(body)
        return service_client.ResponseBody(resp, body['user'])

    def update_user_password(self, user_id, password, original_password):
        """Updates a user password."""
        update_user = {
            'password': password,
            'original_password': original_password
        }
        update_user = json.dumps({'user': update_user})
        resp, _ = self.post('users/%s/password' % user_id, update_user)
        self.expected_success(204, resp.status)
        return service_client.ResponseBody(resp)

    def list_user_projects(self, user_id):
        """Lists the projects on which a user has roles assigned."""
        resp, body = self.get('users/%s/projects' % user_id)
        self.expected_success(200, resp.status)
        body = json.loads(body)
        return service_client.ResponseBodyList(resp, body['projects'])

    def get_users(self, params=None):
        """Get the list of users."""
        url = 'users'
        if params:
            url += '?%s' % urllib.urlencode(params)
        resp, body = self.get(url)
        self.expected_success(200, resp.status)
        body = json.loads(body)
        return service_client.ResponseBodyList(resp, body['users'])

    def get_user(self, user_id):
        """GET a user."""
        resp, body = self.get("users/%s" % user_id)
        self.expected_success(200, resp.status)
        body = json.loads(body)
        return service_client.ResponseBody(resp, body['user'])

    def delete_user(self, user_id):
        """Deletes a User."""
        resp, body = self.delete("users/%s" % user_id)
        self.expected_success(204, resp.status)
        return service_client.ResponseBody(resp, body)

    def create_project(self, name, **kwargs):
        """Creates a project."""
        description = kwargs.get('description', None)
        en = kwargs.get('enabled', True)
        domain_id = kwargs.get('domain_id', 'default')
        post_body = {
            'description': description,
            'domain_id': domain_id,
            'enabled': en,
            'name': name
        }
        post_body = json.dumps({'project': post_body})
        resp, body = self.post('projects', post_body)
        self.expected_success(201, resp.status)
        body = json.loads(body)
        return service_client.ResponseBody(resp, body['project'])

    def list_projects(self, params=None):
        url = "projects"
        if params:
            url += '?%s' % urllib.urlencode(params)
        resp, body = self.get(url)
        self.expected_success(200, resp.status)
        body = json.loads(body)
        return service_client.ResponseBodyList(resp, body['projects'])

    def update_project(self, project_id, **kwargs):
        body = self.get_project(project_id)
        name = kwargs.get('name', body['name'])
        desc = kwargs.get('description', body['description'])
        en = kwargs.get('enabled', body['enabled'])
        domain_id = kwargs.get('domain_id', body['domain_id'])
        post_body = {
            'id': project_id,
            'name': name,
            'description': desc,
            'enabled': en,
            'domain_id': domain_id,
        }
        post_body = json.dumps({'project': post_body})
        resp, body = self.patch('projects/%s' % project_id, post_body)
        self.expected_success(200, resp.status)
        body = json.loads(body)
        return service_client.ResponseBody(resp, body['project'])

    def get_project(self, project_id):
        """GET a Project."""
        resp, body = self.get("projects/%s" % project_id)
        self.expected_success(200, resp.status)
        body = json.loads(body)
        return service_client.ResponseBody(resp, body['project'])

    def delete_project(self, project_id):
        """Delete a project."""
        resp, body = self.delete('projects/%s' % str(project_id))
        self.expected_success(204, resp.status)
        return service_client.ResponseBody(resp, body)

    def create_role(self, name):
        """Create a Role."""
        post_body = {
            'name': name
        }
        post_body = json.dumps({'role': post_body})
        resp, body = self.post('roles', post_body)
        self.expected_success(201, resp.status)
        body = json.loads(body)
        return service_client.ResponseBody(resp, body['role'])

    def get_role(self, role_id):
        """GET a Role."""
        resp, body = self.get('roles/%s' % str(role_id))
        self.expected_success(200, resp.status)
        body = json.loads(body)
        return service_client.ResponseBody(resp, body['role'])

    def list_roles(self):
        """Get the list of Roles."""
        resp, body = self.get("roles")
        self.expected_success(200, resp.status)
        body = json.loads(body)
        return service_client.ResponseBodyList(resp, body['roles'])

    def update_role(self, name, role_id):
        """Create a Role."""
        post_body = {
            'name': name
        }
        post_body = json.dumps({'role': post_body})
        resp, body = self.patch('roles/%s' % str(role_id), post_body)
        self.expected_success(200, resp.status)
        body = json.loads(body)
        return service_client.ResponseBody(resp, body['role'])

    def delete_role(self, role_id):
        """Delete a role."""
        resp, body = self.delete('roles/%s' % str(role_id))
        self.expected_success(204, resp.status)
        return service_client.ResponseBody(resp, body)

    def assign_user_role(self, project_id, user_id, role_id):
        """Add roles to a user on a project."""
        resp, body = self.put('projects/%s/users/%s/roles/%s' %
                              (project_id, user_id, role_id), None)
        self.expected_success(204, resp.status)
        return service_client.ResponseBody(resp, body)

    def create_domain(self, name, **kwargs):
        """Creates a domain."""
        description = kwargs.get('description', None)
        en = kwargs.get('enabled', True)
        post_body = {
            'description': description,
            'enabled': en,
            'name': name
        }
        post_body = json.dumps({'domain': post_body})
        resp, body = self.post('domains', post_body)
        self.expected_success(201, resp.status)
        body = json.loads(body)
        return service_client.ResponseBody(resp, body['domain'])

    def delete_domain(self, domain_id):
        """Delete a domain."""
        resp, body = self.delete('domains/%s' % str(domain_id))
        self.expected_success(204, resp.status)
        return service_client.ResponseBody(resp, body)

    def list_domains(self):
        """List Domains."""
        resp, body = self.get('domains')
        self.expected_success(200, resp.status)
        body = json.loads(body)
        return service_client.ResponseBodyList(resp, body['domains'])

    def update_domain(self, domain_id, **kwargs):
        """Updates a domain."""
        body = self.get_domain(domain_id)
        description = kwargs.get('description', body['description'])
        en = kwargs.get('enabled', body['enabled'])
        name = kwargs.get('name', body['name'])
        post_body = {
            'description': description,
            'enabled': en,
            'name': name
        }
        post_body = json.dumps({'domain': post_body})
        resp, body = self.patch('domains/%s' % domain_id, post_body)
        self.expected_success(200, resp.status)
        body = json.loads(body)
        return service_client.ResponseBody(resp, body['domain'])

    def get_domain(self, domain_id):
        """Get Domain details."""
        resp, body = self.get('domains/%s' % domain_id)
        self.expected_success(200, resp.status)
        body = json.loads(body)
        return service_client.ResponseBody(resp, body['domain'])

    def get_token(self, resp_token):
        """Get token details."""
        headers = {'X-Subject-Token': resp_token}
        resp, body = self.get("auth/tokens", headers=headers)
        self.expected_success(200, resp.status)
        body = json.loads(body)
        return service_client.ResponseBody(resp, body['token'])

    def delete_token(self, resp_token):
        """Deletes token."""
        headers = {'X-Subject-Token': resp_token}
        resp, body = self.delete("auth/tokens", headers=headers)
        self.expected_success(204, resp.status)
        return service_client.ResponseBody(resp, body)

    def create_group(self, name, **kwargs):
        """Creates a group."""
        description = kwargs.get('description', None)
        domain_id = kwargs.get('domain_id', 'default')
        project_id = kwargs.get('project_id', None)
        post_body = {
            'description': description,
            'domain_id': domain_id,
            'project_id': project_id,
            'name': name
        }
        post_body = json.dumps({'group': post_body})
        resp, body = self.post('groups', post_body)
        self.expected_success(201, resp.status)
        body = json.loads(body)
        return service_client.ResponseBody(resp, body['group'])

    def get_group(self, group_id):
        """Get group details."""
        resp, body = self.get('groups/%s' % group_id)
        self.expected_success(200, resp.status)
        body = json.loads(body)
        return service_client.ResponseBody(resp, body['group'])

    def list_groups(self):
        """Lists the groups."""
        resp, body = self.get('groups')
        self.expected_success(200, resp.status)
        body = json.loads(body)
        return service_client.ResponseBodyList(resp, body['groups'])

    def update_group(self, group_id, **kwargs):
        """Updates a group."""
        body = self.get_group(group_id)
        name = kwargs.get('name', body['name'])
        description = kwargs.get('description', body['description'])
        post_body = {
            'name': name,
            'description': description
        }
        post_body = json.dumps({'group': post_body})
        resp, body = self.patch('groups/%s' % group_id, post_body)
        self.expected_success(200, resp.status)
        body = json.loads(body)
        return service_client.ResponseBody(resp, body['group'])

    def delete_group(self, group_id):
        """Delete a group."""
        resp, body = self.delete('groups/%s' % str(group_id))
        self.expected_success(204, resp.status)
        return service_client.ResponseBody(resp, body)

    def add_group_user(self, group_id, user_id):
        """Add user into group."""
        resp, body = self.put('groups/%s/users/%s' % (group_id, user_id),
                              None)
        self.expected_success(204, resp.status)
        return service_client.ResponseBody(resp, body)

    def list_group_users(self, group_id):
        """List users in group."""
        resp, body = self.get('groups/%s/users' % group_id)
        self.expected_success(200, resp.status)
        body = json.loads(body)
        return service_client.ResponseBodyList(resp, body['users'])

    def list_user_groups(self, user_id):
        """Lists groups which a user belongs to."""
        resp, body = self.get('users/%s/groups' % user_id)
        self.expected_success(200, resp.status)
        body = json.loads(body)
        return service_client.ResponseBodyList(resp, body['groups'])

    def delete_group_user(self, group_id, user_id):
        """Delete user in group."""
        resp, body = self.delete('groups/%s/users/%s' % (group_id, user_id))
        self.expected_success(204, resp.status)
        return service_client.ResponseBody(resp, body)

    def assign_user_role_on_project(self, project_id, user_id, role_id):
        """Add roles to a user on a project."""
        resp, body = self.put('projects/%s/users/%s/roles/%s' %
                              (project_id, user_id, role_id), None)
        self.expected_success(204, resp.status)
        return service_client.ResponseBody(resp, body)

    def assign_user_role_on_domain(self, domain_id, user_id, role_id):
        """Add roles to a user on a domain."""
        resp, body = self.put('domains/%s/users/%s/roles/%s' %
                              (domain_id, user_id, role_id), None)
        self.expected_success(204, resp.status)
        return service_client.ResponseBody(resp, body)

    def list_user_roles_on_project(self, project_id, user_id):
        """list roles of a user on a project."""
        resp, body = self.get('projects/%s/users/%s/roles' %
                              (project_id, user_id))
        self.expected_success(200, resp.status)
        body = json.loads(body)
        return service_client.ResponseBodyList(resp, body['roles'])

    def list_user_roles_on_domain(self, domain_id, user_id):
        """list roles of a user on a domain."""
        resp, body = self.get('domains/%s/users/%s/roles' %
                              (domain_id, user_id))
        self.expected_success(200, resp.status)
        body = json.loads(body)
        return service_client.ResponseBodyList(resp, body['roles'])

    def revoke_role_from_user_on_project(self, project_id, user_id, role_id):
        """Delete role of a user on a project."""
        resp, body = self.delete('projects/%s/users/%s/roles/%s' %
                                 (project_id, user_id, role_id))
        self.expected_success(204, resp.status)
        return service_client.ResponseBody(resp, body)

    def revoke_role_from_user_on_domain(self, domain_id, user_id, role_id):
        """Delete role of a user on a domain."""
        resp, body = self.delete('domains/%s/users/%s/roles/%s' %
                                 (domain_id, user_id, role_id))
        self.expected_success(204, resp.status)
        return service_client.ResponseBody(resp, body)

    def assign_group_role_on_project(self, project_id, group_id, role_id):
        """Add roles to a user on a project."""
        resp, body = self.put('projects/%s/groups/%s/roles/%s' %
                              (project_id, group_id, role_id), None)
        self.expected_success(204, resp.status)
        return service_client.ResponseBody(resp, body)

    def assign_group_role_on_domain(self, domain_id, group_id, role_id):
        """Add roles to a user on a domain."""
        resp, body = self.put('domains/%s/groups/%s/roles/%s' %
                              (domain_id, group_id, role_id), None)
        self.expected_success(204, resp.status)
        return service_client.ResponseBody(resp, body)

    def list_group_roles_on_project(self, project_id, group_id):
        """list roles of a user on a project."""
        resp, body = self.get('projects/%s/groups/%s/roles' %
                              (project_id, group_id))
        self.expected_success(200, resp.status)
        body = json.loads(body)
        return service_client.ResponseBodyList(resp, body['roles'])

    def list_group_roles_on_domain(self, domain_id, group_id):
        """list roles of a user on a domain."""
        resp, body = self.get('domains/%s/groups/%s/roles' %
                              (domain_id, group_id))
        self.expected_success(200, resp.status)
        body = json.loads(body)
        return service_client.ResponseBodyList(resp, body['roles'])

    def revoke_role_from_group_on_project(self, project_id, group_id, role_id):
        """Delete role of a user on a project."""
        resp, body = self.delete('projects/%s/groups/%s/roles/%s' %
                                 (project_id, group_id, role_id))
        self.expected_success(204, resp.status)
        return service_client.ResponseBody(resp, body)

    def revoke_role_from_group_on_domain(self, domain_id, group_id, role_id):
        """Delete role of a user on a domain."""
        resp, body = self.delete('domains/%s/groups/%s/roles/%s' %
                                 (domain_id, group_id, role_id))
        self.expected_success(204, resp.status)
        return service_client.ResponseBody(resp, body)

    def create_trust(self, trustor_user_id, trustee_user_id, project_id,
                     role_names, impersonation, expires_at):
        """Creates a trust."""
        roles = [{'name': n} for n in role_names]
        post_body = {
            'trustor_user_id': trustor_user_id,
            'trustee_user_id': trustee_user_id,
            'project_id': project_id,
            'impersonation': impersonation,
            'roles': roles,
            'expires_at': expires_at
        }
        post_body = json.dumps({'trust': post_body})
        resp, body = self.post('OS-TRUST/trusts', post_body)
        self.expected_success(201, resp.status)
        body = json.loads(body)
        return service_client.ResponseBody(resp, body['trust'])

    def delete_trust(self, trust_id):
        """Deletes a trust."""
        resp, body = self.delete("OS-TRUST/trusts/%s" % trust_id)
        self.expected_success(204, resp.status)
        return service_client.ResponseBody(resp, body)

    def get_trusts(self, trustor_user_id=None, trustee_user_id=None):
        """GET trusts."""
        if trustor_user_id:
            resp, body = self.get("OS-TRUST/trusts?trustor_user_id=%s"
                                  % trustor_user_id)
        elif trustee_user_id:
            resp, body = self.get("OS-TRUST/trusts?trustee_user_id=%s"
                                  % trustee_user_id)
        else:
            resp, body = self.get("OS-TRUST/trusts")
        self.expected_success(200, resp.status)
        body = json.loads(body)
        return service_client.ResponseBodyList(resp, body['trusts'])

    def get_trust(self, trust_id):
        """GET trust."""
        resp, body = self.get("OS-TRUST/trusts/%s" % trust_id)
        self.expected_success(200, resp.status)
        body = json.loads(body)
        return service_client.ResponseBody(resp, body['trust'])

    def get_trust_roles(self, trust_id):
        """GET roles delegated by a trust."""
        resp, body = self.get("OS-TRUST/trusts/%s/roles" % trust_id)
        self.expected_success(200, resp.status)
        body = json.loads(body)
        return service_client.ResponseBodyList(resp, body['roles'])

    def get_trust_role(self, trust_id, role_id):
        """GET role delegated by a trust."""
        resp, body = self.get("OS-TRUST/trusts/%s/roles/%s"
                              % (trust_id, role_id))
        self.expected_success(200, resp.status)
        body = json.loads(body)
        return service_client.ResponseBody(resp, body['role'])

    def check_trust_role(self, trust_id, role_id):
        """HEAD Check if role is delegated by a trust."""
        resp, body = self.head("OS-TRUST/trusts/%s/roles/%s"
                               % (trust_id, role_id))
        self.expected_success(200, resp.status)
        return service_client.ResponseBody(resp, body)
