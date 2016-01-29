#!/bin/bash

# Many of neutron's repos suffer from the problem of depending on neutron,
# but it not existing on pypi. -- Well, that's the usual issue, but in
# neutron's case, we want to import tempest directly for the api tests.

# This wrapper for tox's package installer will use the existing package
# if it exists, else use zuul-cloner if that program exists, else grab it
# from neutron master via a hard-coded URL. That last case should only
# happen with devs running unit tests locally.

# From the tox.ini config page:
# install_command=ARGV
# default:
# pip install {opts} {packages}

ZUUL_CLONER=/usr/zuul-env/bin/zuul-cloner
tempest_installed=$(python -c "import tempest" 2>/dev/null ; echo $?)

set -e

if [ $tempest_installed -eq 0 ]; then
    echo "Tempest already installed; using existing package"
elif [ -x "$ZUUL_CLONER" ]; then
    export ZUUL_BRANCH=${ZUUL_BRANCH-$BRANCH}
    pushd /tmp
    $ZUUL_CLONER --cache-dir \
        /opt/git \
        git://git.openstack.org \
        openstack/tempest
    pip install -e openstack/tempest
    popd
else
    pip install -U -egit+https://git.openstack.org/openstack/tempest#egg=tempest
fi

pip install -U $*
