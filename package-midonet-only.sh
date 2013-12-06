# Get version number from command line
pkgver=$1
if [ '$pkgver' == '' ]
then
  echo "Please specify the package version, e.g. 'package-midonet-only.sh havana-v1.0' to package as version havana-v1.0"
  exit
else
    echo "Packaging with version number $pkgver"
fi

# Common args for rpm and deb
FPM_BASE_ARGS=$(cat <<EOF
--name 'python-neutron-plugin-midonet' \
--architecture 'noarch' \
--license '2013, Midokura' \
--vendor 'Midokura' \
--maintainer "Midokura" \
--url 'http://midokura.com' \
--description 'Neutron is a virtual network service for Openstack - Python library
  Neutron MidoNet plugin is a MidoNet virtual network service plugin for Openstack Neutron.' \
-d 'python-neutron' \
--replaces 'python-neutron' \
-s dir \
-C neutron/plugins/midonet/ \
--version $pkgver
EOF
)

RPM_ARGS=$(cat <<EOF
--prefix /usr/lib/python2.6/site-packages/neutron/plugins/midonet \
--provides 'python2.6-neutron-plugin-midonet' \
--epoch 1
EOF
)

DEB_ARGS=$(cat <<EOF
--prefix /usr/lib/python2.7/dist-packages/neutron/plugins/midonet \
--provides 'python2.7-neutron-plugin-midonet' \
--deb-priority 'optional'
EOF
)

# Package rpm
eval fpm $FPM_BASE_ARGS $RPM_ARGS -t rpm .

# Package debian
eval fpm $FPM_BASE_ARGS $DEB_ARGS -t deb .