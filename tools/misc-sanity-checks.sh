#! /bin/sh

# Copyright (C) 2014 VA Linux Systems Japan K.K.
# Copyright (C) 2014 YAMAMOTO Takashi <yamamoto at valinux co jp>
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

TMPDIR=`mktemp -d /tmp/${0##*/}.XXXXXX` || exit 1
export TMPDIR
trap "rm -rf $TMPDIR" EXIT

FAILURES=$TMPDIR/failures


check_no_symlinks_allowed () {
    # Symlinks break the package build process, so ensure that they
    # do not slip in, except hidden symlinks.
    if [ $(find . -type l ! -path '*/.*' | wc -l) -ge 1 ]; then
        echo "Symlinks are not allowed!" >>$FAILURES
    fi
}


check_pot_files_errors () {
    # The job neutron-propose-translation-update does not update from
    # transifex since our po files contain duplicate entries where
    # obsolete entries duplicate normal entries. Prevent obsolete
    # entries to slip in
    find neutron -type f -regex '.*\.pot?' \
        -print0|xargs -0 -n 1 msgfmt --check-format \
        -o /dev/null
    if [ "$?" -ne 0 ]; then
        echo "PO files syntax is not correct!" >>$FAILURES
    fi
}


check_identical_policy_files () {
    # For unit tests, we maintain their own policy.json file to make test suite
    # independent of whether it's executed from the neutron source tree or from
    # site-packages installation path. We don't want two copies of the same
    # file to diverge, so checking that they are identical
    diff etc/policy.json neutron/tests/etc/policy.json 2>&1 > /dev/null
    if [ "$?" -ne 0 ]; then
        echo "policy.json files must be identical!" >>$FAILURES
    fi
}

# Add your checks here...
check_no_symlinks_allowed
check_pot_files_errors
check_identical_policy_files

# Fail, if there are emitted failures
if [ -f $FAILURES ]; then
    cat $FAILURES
    exit 1
fi
