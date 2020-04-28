#!/bin/bash

# For neutron unit tests, you can define git repos containing modules
# that you want to use to override the requirements-based packages.
#
# Why, you ask? Because you made changes to neutron-lib, and you want
# run the unit tests together.  E.g.:
#
#   env TOX_ENV_SRC_MODULES="$HOME/src/neutron-lib" tox -e py38

toxinidir="$1"

if [ -z "$TOX_ENV_SRC_MODULES" ]; then
    exit 0
fi

for repo in $TOX_ENV_SRC_MODULES; do
    d="${toxinidir}/${repo}"
    if [ ! -d "$d" ]; then
        echo "tox_env_src: error: no directory found at $d"
        continue
    fi
    echo "tox_env_src: pip installing from $d"
    pip install -e "$d"
done
