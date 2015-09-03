LIBDIR=$DEST/neutron/devstack/lib

source $LIBDIR/l2_agent
source $LIBDIR/ml2
source $LIBDIR/qos


if [[ "$1" == "stack" && "$2" == "install" ]]; then
    if is_service_enabled q-qos; then
        configure_qos
    fi
fi

if [[ "$1" == "stack" && "$2" == "post-config" ]]; then
    if is_service_enabled q-agt; then
        configure_l2_agent
    fi
fi
