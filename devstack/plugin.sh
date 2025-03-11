LIBDIR=$DEST/neutron/devstack/lib

source $LIBDIR/distributed_dhcp
source $LIBDIR/dns
source $LIBDIR/flavors
source $LIBDIR/l2_agent
source $LIBDIR/l2_agent_sriovnicswitch
source $LIBDIR/l3_agent
source $LIBDIR/l3_conntrack_helper
source $LIBDIR/l3_ndp_proxy
source $LIBDIR/metadata_path
source $LIBDIR/ml2
source $LIBDIR/network_segment_range
source $LIBDIR/segments
source $LIBDIR/log
source $LIBDIR/fip_port_forwarding
source $LIBDIR/uplink_status_propagation
source $LIBDIR/tag_ports_during_bulk_creation
source $LIBDIR/octavia
source $LIBDIR/loki
source $LIBDIR/local_ip
source $LIBDIR/port_trusted_vif

# source the OVS/OVN compilation helper methods
source $TOP_DIR/lib/neutron_plugins/ovs_source

Q_BUILD_OVS_FROM_GIT=$(trueorfalse False Q_BUILD_OVS_FROM_GIT)

function is_ovn_enabled {
    [[ $NEUTRON_AGENT == "ovn" ]] && return 0
    return 1
}

if [ -f $LIBDIR/${NEUTRON_AGENT}_agent ]; then
    source $LIBDIR/${NEUTRON_AGENT}_agent
fi

if [[ "$1" == "stack" ]]; then
    case "$2" in
        install)
            ;;
        post-config)
            if is_service_enabled neutron-tag-ports-during-bulk-creation; then
                configure_tag_ports_during_bulk_creation_extension
            fi
            if is_service_enabled neutron-uplink-status-propagation; then
                configure_uplink_status_propagation_extension
            fi
            if is_service_enabled q-flavors neutron-flavors; then
                configure_flavors
            fi
            if is_service_enabled q-log neutron-log; then
                configure_log
            fi
            if is_service_enabled q-dns neutron-dns; then
                configure_dns_extension
                post_config_dns_extension
                if is_service_enabled designate; then
                    configure_dns_integration
                fi
            fi
            if is_service_enabled neutron-segments; then
                configure_segments_extension
            fi
            if is_service_enabled neutron-network-segment-range; then
                configure_network_segment_range
            fi
            if is_service_enabled q-distributed-dhcp neutron-distributed-dhcp; then
                if [ $Q_AGENT = openvswitch ]; then
                    configure_ovs_distributed_dhcp
                fi
            fi
            if is_service_enabled q-metadata-path neutron-metadata-path; then
                if [ $Q_AGENT = openvswitch ]; then
                    configure_ovs_metadata_path
                fi
            fi
            if is_service_enabled neutron-local-ip; then
                configure_local_ip
            fi
            if is_service_enabled neutron-local-ip-static; then
                configure_local_ip_static
            fi
            if is_service_enabled q-agt neutron-agent; then
                configure_l2_agent
            fi
            #Note: sriov agent should run with OVS agent
            #because it is the mechanism that binds the DHCP and router ports.
            #Currently devstack lacks the option to run two agents on the same node.
            #Therefore we create new service, q-sriov-agt, and the
            # q-agt/neutron-agent should be OVS.
            if is_service_enabled q-sriov-agt neutron-sriov-agent; then
                configure_l2_agent
                configure_l2_agent_sriovnicswitch
            fi
            if is_service_enabled q-l3 neutron-l3; then
                if is_service_enabled q-port-forwarding neutron-port-forwarding; then
                    configure_port_forwarding
                fi
                if is_service_enabled q-conntrack-helper neutron-conntrack-helper; then
                    configure_l3_conntrack_helper
                fi
                if is_service_enabled q-ndp-proxy neutron-ndp-proxy; then
                    configure_l3_ndp_proxy
                fi
                configure_l3_agent
            fi
            if is_service_enabled q-port-trusted-vif neutron-port-trusted-vif; then
                configure_port_trusted_ml2_extension
            fi
            if [ $NEUTRON_CORE_PLUGIN = ml2 ]; then
                configure_ml2_extension_drivers
            fi
            if is_ovn_enabled; then
                if is_service_enabled q-port-forwarding neutron-port-forwarding; then
                    configure_port_forwarding
                fi
            fi
            if is_service_enabled neutron-loki; then
                configure_loki
            fi
            ;;
        extra)
            if is_service_enabled q-sriov-agt neutron-sriov-agent; then
                start_l2_agent_sriov
            fi
            if is_service_enabled br-ex-tcpdump ; then
                # tcpdump monitor on br-ex for ARP, reverse ARP and ICMP v4 / v6 packets
                sudo ip link set dev $PUBLIC_BRIDGE up
                TCPDUMP=$(which tcpdump)
                if [[ ! $TCPDUMP ]]; then
                    if [[ "$os_CODENAME" == "jammy" ]]; then
                        TCPDUMP=/usr/bin/tcpdump
                    else
                        TCPDUMP=/usr/sbin/tcpdump
                    fi
                fi
                run_process br-ex-tcpdump "$TCPDUMP -i $PUBLIC_BRIDGE arp or rarp or icmp or icmp6 -enlX" "$STACK_GROUP" root
            fi

            if is_service_enabled br-int-flows ; then
                run_process br-int-flows "/bin/sh -c \"set +e; while true; do echo ovs-ofctl dump-flows br-int; ovs-ofctl dump-flows br-int ; sleep 30; done; \"" "$STACK_GROUP" root
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
