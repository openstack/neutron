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

# The purpose of this script is to avoid casual introduction of more
# bash dependency.  Please consider alternatives before commiting code
# which uses bash specific features.

# Ignore comments, but include shebangs
OBSERVED=$(grep -E '^([^#]|#!).*bash' tox.ini tools/* | wc -l)
EXPECTED=5
if [ ${EXPECTED} -ne ${OBSERVED} ]; then
    echo Unexpected number of bash usages are detected.
    echo Please read the comment in $0
    exit 1
fi
exit 0
