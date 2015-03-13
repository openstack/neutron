# Copyright (c) 2014 Hewlett-Packard Development Company, L.P.
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.

import os

from neutron.tests.tempest.common import accounts
from neutron.tests.tempest.common import cred_provider
from neutron.tests.tempest.common import isolated_creds
from neutron.tests.tempest import config
from neutron.tests.tempest import exceptions

CONF = config.CONF


# Return the right implementation of CredentialProvider based on config
# Dropping interface and password, as they are never used anyways
# TODO(andreaf) Drop them from the CredentialsProvider interface completely
def get_isolated_credentials(name, network_resources=None,
                             force_tenant_isolation=False):
    # If a test requires a new account to work, it can have it via forcing
    # tenant isolation. A new account will be produced only for that test.
    # In case admin credentials are not available for the account creation,
    # the test should be skipped else it would fail.
    if CONF.auth.allow_tenant_isolation or force_tenant_isolation:
        return isolated_creds.IsolatedCreds(
            name=name,
            network_resources=network_resources)
    else:
        if CONF.auth.locking_credentials_provider:
            # Most params are not relevant for pre-created accounts
            return accounts.Accounts(name=name)
        else:
            return accounts.NotLockingAccounts(name=name)


# We want a helper function here to check and see if admin credentials
# are available so we can do a single call from skip_checks if admin
# creds area vailable.
def is_admin_available():
    is_admin = True
    # If tenant isolation is enabled admin will be available
    if CONF.auth.allow_tenant_isolation:
        return is_admin
    # Check whether test accounts file has the admin specified or not
    elif os.path.isfile(CONF.auth.test_accounts_file):
        check_accounts = accounts.Accounts(name='check_admin')
        if not check_accounts.admin_available():
            is_admin = False
    else:
        try:
            cred_provider.get_configured_credentials('identity_admin',
                                                     fill_in=False)
        except exceptions.InvalidConfiguration:
            is_admin = False
    return is_admin
