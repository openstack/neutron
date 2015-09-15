#!/bin/bash
# Copyright (c) 2015 Mirantis, Inc.
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

# A script useful to develop changes to the codebase. It launches the pecan
# API server and will reload it whenever the code changes if inotifywait is
# installed.

inotifywait --help >/dev/null 2>&1
if [[ $? -ne 1 ]]; then
  USE_INOTIFY=0
else
  USE_INOTIFY=1
fi

DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )/../
source "$DIR/.tox/py27/bin/activate"
COMMAND="python -c 'from neutron.cmd.eventlet import server; server.main_wsgi_pecan()'"

function cleanup() {
  kill $PID
  exit 0
}

if [[ $USE_INOTIFY -eq 1 ]]; then
  trap cleanup INT
  while true; do
    eval "$COMMAND &"
    PID=$!
    inotifywait -e modify -r $DIR/neutron/
    kill $PID
  done
else
  eval $COMMAND
fi
