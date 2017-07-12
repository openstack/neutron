LIBDIR=$DEST/neutron/devstack/lib

source $LIBDIR/dns
source $LIBDIR/flavors
source $LIBDIR/l2_agent
source $LIBDIR/l2_agent_sriovnicswitch
source $LIBDIR/ml2
source $LIBDIR/qos
source $LIBDIR/ovs
source $LIBDIR/segments
source $LIBDIR/trunk

Q_BUILD_OVS_FROM_GIT=$(trueorfalse False Q_BUILD_OVS_FROM_GIT)

if [ -f $LIBDIR/${NEUTRON_AGENT}_agent ]; then
    source $LIBDIR/${NEUTRON_AGENT}_agent
fi

if [[ "$1" == "stack" ]]; then
    case "$2" in
        install)
            if is_service_enabled q-flavors neutron-flavors; then
                configure_flavors
            fi
            if is_service_enabled q-qos neutron-qos; then
                configure_qos
            fi
            if is_service_enabled q-trunk neutron-trunk; then
                configure_trunk_extension
            fi
            if is_service_enabled q-dns neutron-dns; then
                configure_dns_extension
            fi
            if is_service_enabled neutron-segments; then
                configure_segments_extension
            fi
            if [[ "$NEUTRON_AGENT" == "openvswitch" ]] && \
               [[ "$Q_BUILD_OVS_FROM_GIT" == "True" ]]; then
                remove_ovs_packages
                compile_ovs True /usr /var
                start_new_ovs
            fi
            ;;
        post-config)
            if is_service_enabled q-dns neutron-dns; then
                post_config_dns_extension
            fi
            if is_service_enabled q-agt neutron-agent; then
                configure_l2_agent
            fi
            #Note: sriov agent should run with OVS or linux bridge agent
            #because they are the mechanisms that bind the DHCP and router ports.
            #Currently devstack lacks the option to run two agents on the same node.
            #Therefore we create new service, q-sriov-agt, and the
            # q-agt/neutron-agent should be OVS or linux bridge.
            if is_service_enabled q-sriov-agt neutron-sriov-agent; then
                configure_$NEUTRON_CORE_PLUGIN
                configure_l2_agent
                configure_l2_agent_sriovnicswitch
            fi
            ;;
        extra)
            if is_service_enabled q-sriov-agt neutron-sriov-agent; then
                start_l2_agent_sriov
            fi
            ;;
    esac
elif [[ "$1" == "unstack" ]]; then
    if is_service_enabled q-sriov-agt neutron-sriov-agent; then
        stop_l2_agent_sriov
    fi
    if [[ "$NEUTRON_AGENT" == "openvswitch" ]] && \
       [[ "$Q_BUILD_OVS_FROM_GIT" == "True" ]]; then
        stop_new_ovs
    fi
fi
