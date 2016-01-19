#!/usr/bin/env bash
# Copyright 2011 OpenStack Foundation.
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

tools_path=${tools_path:-$(dirname $0)}
venv_path=${venv_path:-${tools_path}}
venv_dir=${venv_name:-/../.venv}
TOOLS=${tools_path}
VENV=${venv:-${venv_path}/${venv_dir}}
source $VENV/bin/activate && "$@"
