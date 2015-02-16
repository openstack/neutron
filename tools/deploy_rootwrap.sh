#!/bin/bash

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

set -eu

if [ "$#" -ne 3 ]; then
  >&2 echo "Usage: $0 /path/to/neutron /path/to/target/etc /path/to/target/bin
Deploy Neutron's rootwrap configuration.

Warning: Any existing rootwrap files at the specified etc path will be
removed by this script.

Optional: set OS_SUDO_TESTING=1 to deploy the filters required by
Neutron's functional testing suite."
  exit 1
fi

OS_SUDO_TESTING=${OS_SUDO_TESTING:-0}

neutron_path=$1
target_etc_path=$2
target_bin_path=$3

src_conf_path=${neutron_path}/etc
src_conf=${src_conf_path}/rootwrap.conf
src_rootwrap_path=${src_conf_path}/neutron/rootwrap.d

dst_conf_path=${target_etc_path}/neutron
dst_conf=${dst_conf_path}/rootwrap.conf
dst_rootwrap_path=${dst_conf_path}/rootwrap.d

if [[ -d "$dst_rootwrap_path" ]]; then
    rm -rf ${dst_rootwrap_path}
fi
mkdir -p -m 755 ${dst_rootwrap_path}

cp -p ${src_rootwrap_path}/* ${dst_rootwrap_path}/
cp -p ${src_conf} ${dst_conf}
sed -i "s:^filters_path=.*$:filters_path=${dst_rootwrap_path}:" ${dst_conf}
sed -i "s:^\(exec_dirs=.*\)$:\1,${target_bin_path}:" ${dst_conf}

if [[ "$OS_SUDO_TESTING" = "1" ]]; then
    cp -p ${neutron_path}/neutron/tests/contrib/functional-testing.filters \
        ${dst_rootwrap_path}/
fi
