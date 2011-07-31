#!/bin/bash
eths=`ifconfig -a | grep eth | cut -f1 -d " "`
for eth in $eths; do
        bdf=`ethtool -i $eth | grep bus-info | cut -f2 -d " "`
        deviceid=`lspci -n -s $bdf | cut -f4 -d ":" | cut -f1 -d " "`
        if [ $deviceid = "0044" ]; then
                used=`/sbin/ip link show $eth | grep "UP"`
                avail=$?
                if [ $avail -eq 1 ]; then
                        echo $eth
                        exit
                fi
        fi
done

