#!/bin/bash

set -e

echo "Running flake8 ..."
# E711/E712 comparison to False should be 'if cond is False:' or 'if not cond:'
#        query = query.filter(Component.disabled == False)
# E125 continuation line does not distinguish itself from next logical line
# H301 one import per line
# H302 import only modules
# TODO(marun) H404 multi line docstring should start with a summary
# TODO(marun) H901,902 use the not operator inline for clarity
# TODO(markmcclain) H202 assertRaises Exception too broad
PEP8_IGNORE="E711,E712,E125,H301,H302,H404,H901,H902,H202"
PEP8_BUILTINS="_"
PEP8_EXCLUDE=".venv,.git,.tox,dist,doc,*openstack/common*,*lib/python*,*egg,tools"
flake8 --exclude=$PEP8_EXCLUDE --ignore=$PEP8_IGNORE --show-source --builtins=$PEP8_BUILTINS .
