LIBDIR=$DEST/neutron/devstack/lib

source $LIBDIR/flavors
source $LIBDIR/l2_agent
source $LIBDIR/l2_agent_sriovnicswitch
source $LIBDIR/ml2
source $LIBDIR/qos
source $LIBDIR/ovs
source $LIBDIR/trunk

Q_BUILD_OVS_FROM_GIT=$(trueorfalse False Q_BUILD_OVS_FROM_GIT)

if [ -f $LIBDIR/${Q_AGENT}_agent ]; then
    source $LIBDIR/${Q_AGENT}_agent
fi

if [[ "$1" == "stack" ]]; then
    case "$2" in
        install)
            if is_service_enabled q-flavors; then
                configure_flavors
            fi
            if is_service_enabled q-qos; then
                configure_qos
            fi
            if is_service_enabled q-trunk; then
                configure_trunk_extension
            fi
            if [[ "$Q_AGENT" == "openvswitch" ]] && \
               [[ "$Q_BUILD_OVS_FROM_GIT" == "True" ]]; then
                remove_ovs_packages
                compile_ovs True /usr /var
                start_new_ovs
            fi
            ;;
        post-config)
            if is_service_enabled q-agt; then
                configure_l2_agent
            fi
            #Note: sriov agent should run with OVS or linux bridge agent
            #because they are the mechanisms that bind the DHCP and router ports.
            #Currently devstack lacks the option to run two agents on the same node.
            #Therefore we create new service, q-sriov-agt, and the q-agt should be OVS
            #or linux bridge.
            if is_service_enabled q-sriov-agt; then
                configure_$Q_PLUGIN
                configure_l2_agent
                configure_l2_agent_sriovnicswitch
            fi
            ;;
        extra)
            if is_service_enabled q-sriov-agt; then
                start_l2_agent_sriov
            fi
            ;;
    esac
elif [[ "$1" == "unstack" ]]; then
    if is_service_enabled q-sriov-agt; then
        stop_l2_agent_sriov
    fi
fi
