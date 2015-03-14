# Copyright (c) 2014 Hewlett-Packard Development Company, L.P.
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

import hashlib
import os

from oslo_concurrency import lockutils
from oslo_log import log as logging
import yaml

from neutron.tests.tempest.common import cred_provider
from neutron.tests.tempest import config
from neutron.tests.tempest import exceptions

CONF = config.CONF
LOG = logging.getLogger(__name__)


def read_accounts_yaml(path):
    yaml_file = open(path, 'r')
    accounts = yaml.load(yaml_file)
    return accounts


class Accounts(cred_provider.CredentialProvider):

    def __init__(self, name):
        super(Accounts, self).__init__(name)
        self.name = name
        if os.path.isfile(CONF.auth.test_accounts_file):
            accounts = read_accounts_yaml(CONF.auth.test_accounts_file)
            self.use_default_creds = False
        else:
            accounts = {}
            self.use_default_creds = True
        self.hash_dict = self.get_hash_dict(accounts)
        # FIXME(dhellmann): The configuration option is not part of
        # the API of the library, because if we change the option name
        # or group it will break this use. Tempest needs to set this
        # value somewhere that it owns, and then use
        # lockutils.set_defaults() to tell oslo.concurrency what value
        # to use.
        self.accounts_dir = os.path.join(CONF.oslo_concurrency.lock_path,
                                         'test_accounts')
        self.isolated_creds = {}

    @classmethod
    def _append_role(cls, role, account_hash, hash_dict):
        if role in hash_dict['roles']:
            hash_dict['roles'][role].append(account_hash)
        else:
            hash_dict['roles'][role] = [account_hash]
        return hash_dict

    @classmethod
    def get_hash_dict(cls, accounts):
        hash_dict = {'roles': {}, 'creds': {}}
        # Loop over the accounts read from the yaml file
        for account in accounts:
            roles = []
            types = []
            if 'roles' in account:
                roles = account.pop('roles')
            if 'types' in account:
                types = account.pop('types')
            temp_hash = hashlib.md5()
            temp_hash.update(str(account))
            temp_hash_key = temp_hash.hexdigest()
            hash_dict['creds'][temp_hash_key] = account
            for role in roles:
                hash_dict = cls._append_role(role, temp_hash_key,
                                             hash_dict)
            # If types are set for the account append the matching role
            # subdict with the hash
            for type in types:
                if type == 'admin':
                    hash_dict = cls._append_role(CONF.identity.admin_role,
                                                 temp_hash_key, hash_dict)
                elif type == 'operator':
                    hash_dict = cls._append_role(
                        CONF.object_storage.operator_role, temp_hash_key,
                        hash_dict)
                elif type == 'reseller_admin':
                    hash_dict = cls._append_role(
                        CONF.object_storage.reseller_admin_role,
                        temp_hash_key,
                        hash_dict)
        return hash_dict

    def is_multi_user(self):
        # Default credentials is not a valid option with locking Account
        if self.use_default_creds:
            raise exceptions.InvalidConfiguration(
                "Account file %s doesn't exist" % CONF.auth.test_accounts_file)
        else:
            return len(self.hash_dict['creds']) > 1

    def is_multi_tenant(self):
        return self.is_multi_user()

    def _create_hash_file(self, hash_string):
        path = os.path.join(os.path.join(self.accounts_dir, hash_string))
        if not os.path.isfile(path):
            with open(path, 'w') as fd:
                fd.write(self.name)
            return True
        return False

    @lockutils.synchronized('test_accounts_io', external=True)
    def _get_free_hash(self, hashes):
        # Cast as a list because in some edge cases a set will be passed in
        hashes = list(hashes)
        if not os.path.isdir(self.accounts_dir):
            os.mkdir(self.accounts_dir)
            # Create File from first hash (since none are in use)
            self._create_hash_file(hashes[0])
            return hashes[0]
        names = []
        for _hash in hashes:
            res = self._create_hash_file(_hash)
            if res:
                return _hash
            else:
                path = os.path.join(os.path.join(self.accounts_dir,
                                                 _hash))
                with open(path, 'r') as fd:
                    names.append(fd.read())
        msg = ('Insufficient number of users provided. %s have allocated all '
               'the credentials for this allocation request' % ','.join(names))
        raise exceptions.InvalidConfiguration(msg)

    def _get_match_hash_list(self, roles=None):
        hashes = []
        if roles:
            # Loop over all the creds for each role in the subdict and generate
            # a list of cred lists for each role
            for role in roles:
                temp_hashes = self.hash_dict['roles'].get(role, None)
                if not temp_hashes:
                    raise exceptions.InvalidConfiguration(
                        "No credentials with role: %s specified in the "
                        "accounts ""file" % role)
                hashes.append(temp_hashes)
            # Take the list of lists and do a boolean and between each list to
            # find the creds which fall under all the specified roles
            temp_list = set(hashes[0])
            for hash_list in hashes[1:]:
                temp_list = temp_list & set(hash_list)
            hashes = temp_list
        else:
            hashes = self.hash_dict['creds'].keys()
        # NOTE(mtreinish): admin is a special case because of the increased
        # privlege set which could potentially cause issues on tests where that
        # is not expected. So unless the admin role isn't specified do not
        # allocate admin.
        admin_hashes = self.hash_dict['roles'].get(CONF.identity.admin_role,
                                                   None)
        if ((not roles or CONF.identity.admin_role not in roles) and
                admin_hashes):
            useable_hashes = [x for x in hashes if x not in admin_hashes]
        else:
            useable_hashes = hashes
        return useable_hashes

    def _get_creds(self, roles=None):
        if self.use_default_creds:
            raise exceptions.InvalidConfiguration(
                "Account file %s doesn't exist" % CONF.auth.test_accounts_file)
        useable_hashes = self._get_match_hash_list(roles)
        free_hash = self._get_free_hash(useable_hashes)
        return self.hash_dict['creds'][free_hash]

    @lockutils.synchronized('test_accounts_io', external=True)
    def remove_hash(self, hash_string):
        hash_path = os.path.join(self.accounts_dir, hash_string)
        if not os.path.isfile(hash_path):
            LOG.warning('Expected an account lock file %s to remove, but '
                        'one did not exist' % hash_path)
        else:
            os.remove(hash_path)
            if not os.listdir(self.accounts_dir):
                os.rmdir(self.accounts_dir)

    def get_hash(self, creds):
        for _hash in self.hash_dict['creds']:
            # Comparing on the attributes that are expected in the YAML
            if all([getattr(creds, k) == self.hash_dict['creds'][_hash][k] for
                   k in creds.get_init_attributes()]):
                return _hash
        raise AttributeError('Invalid credentials %s' % creds)

    def remove_credentials(self, creds):
        _hash = self.get_hash(creds)
        self.remove_hash(_hash)

    def get_primary_creds(self):
        if self.isolated_creds.get('primary'):
            return self.isolated_creds.get('primary')
        creds = self._get_creds()
        primary_credential = cred_provider.get_credentials(**creds)
        self.isolated_creds['primary'] = primary_credential
        return primary_credential

    def get_alt_creds(self):
        if self.isolated_creds.get('alt'):
            return self.isolated_creds.get('alt')
        creds = self._get_creds()
        alt_credential = cred_provider.get_credentials(**creds)
        self.isolated_creds['alt'] = alt_credential
        return alt_credential

    def get_creds_by_roles(self, roles, force_new=False):
        roles = list(set(roles))
        exist_creds = self.isolated_creds.get(str(roles), None)
        # The force kwarg is used to allocate an additional set of creds with
        # the same role list. The index used for the previously allocation
        # in the isolated_creds dict will be moved.
        if exist_creds and not force_new:
            return exist_creds
        elif exist_creds and force_new:
            new_index = str(roles) + '-' + str(len(self.isolated_creds))
            self.isolated_creds[new_index] = exist_creds
        creds = self._get_creds(roles=roles)
        role_credential = cred_provider.get_credentials(**creds)
        self.isolated_creds[str(roles)] = role_credential
        return role_credential

    def clear_isolated_creds(self):
        for creds in self.isolated_creds.values():
            self.remove_credentials(creds)

    def get_admin_creds(self):
        return self.get_creds_by_roles([CONF.identity.admin_role])

    def is_role_available(self, role):
        if self.use_default_creds:
            return False
        else:
            if self.hash_dict['roles'].get(role):
                return True
            return False

    def admin_available(self):
        return self.is_role_available(CONF.identity.admin_role)


class NotLockingAccounts(Accounts):
    """Credentials provider which always returns the first and second
    configured accounts as primary and alt users.
    This credential provider can be used in case of serial test execution
    to preserve the current behaviour of the serial tempest run.
    """

    def _unique_creds(self, cred_arg=None):
        """Verify that the configured credentials are valid and distinct """
        if self.use_default_creds:
            try:
                user = self.get_primary_creds()
                alt_user = self.get_alt_creds()
                return getattr(user, cred_arg) != getattr(alt_user, cred_arg)
            except exceptions.InvalidCredentials as ic:
                msg = "At least one of the configured credentials is " \
                      "not valid: %s" % ic.message
                raise exceptions.InvalidConfiguration(msg)
        else:
            # TODO(andreaf) Add a uniqueness check here
            return len(self.hash_dict['creds']) > 1

    def is_multi_user(self):
        return self._unique_creds('username')

    def is_multi_tenant(self):
        return self._unique_creds('tenant_id')

    def get_creds(self, id, roles=None):
        try:
            hashes = self._get_match_hash_list(roles)
            # No need to sort the dict as within the same python process
            # the HASH seed won't change, so subsequent calls to keys()
            # will return the same result
            _hash = hashes[id]
        except IndexError:
            msg = 'Insufficient number of users provided'
            raise exceptions.InvalidConfiguration(msg)
        return self.hash_dict['creds'][_hash]

    def get_primary_creds(self):
        if self.isolated_creds.get('primary'):
            return self.isolated_creds.get('primary')
        if not self.use_default_creds:
            creds = self.get_creds(0)
            primary_credential = cred_provider.get_credentials(**creds)
        else:
            primary_credential = cred_provider.get_configured_credentials(
                'user')
        self.isolated_creds['primary'] = primary_credential
        return primary_credential

    def get_alt_creds(self):
        if self.isolated_creds.get('alt'):
            return self.isolated_creds.get('alt')
        if not self.use_default_creds:
            creds = self.get_creds(1)
            alt_credential = cred_provider.get_credentials(**creds)
        else:
            alt_credential = cred_provider.get_configured_credentials(
                'alt_user')
        self.isolated_creds['alt'] = alt_credential
        return alt_credential

    def clear_isolated_creds(self):
        self.isolated_creds = {}

    def get_admin_creds(self):
        if not self.use_default_creds:
            return self.get_creds_by_roles([CONF.identity.admin_role])
        else:
            creds = cred_provider.get_configured_credentials(
                "identity_admin", fill_in=False)
            self.isolated_creds['admin'] = creds
            return creds

    def get_creds_by_roles(self, roles, force_new=False):
        roles = list(set(roles))
        exist_creds = self.isolated_creds.get(str(roles), None)
        index = 0
        if exist_creds and not force_new:
            return exist_creds
        elif exist_creds and force_new:
            new_index = str(roles) + '-' + str(len(self.isolated_creds))
            self.isolated_creds[new_index] = exist_creds
            # Figure out how many existing creds for this roles set are present
            # use this as the index the returning hash list to ensure separate
            # creds are returned with force_new being True
            for creds_names in self.isolated_creds:
                if str(roles) in creds_names:
                    index = index + 1
        if not self.use_default_creds:
            creds = self.get_creds(index, roles=roles)
            role_credential = cred_provider.get_credentials(**creds)
            self.isolated_creds[str(roles)] = role_credential
        else:
            msg = "Default credentials can not be used with specifying "\
                  "credentials by roles"
            raise exceptions.InvalidConfiguration(msg)
        return role_credential
