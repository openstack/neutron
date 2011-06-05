#!/bin/sh
VIFLIST=`xe vif-list params=uuid --minimal | sed s/,/" "/g`
for VIF_UUID in $VIFLIST; do
DEVICE_NUM=`xe vif-list params=device uuid=$VIF_UUID --minimal`
  VM_NAME=`xe vif-list params=vm-name-label uuid=$VIF_UUID --minimal`
  NAME="$VM_NAME-eth$DEVICE_NUM"
  echo "Vif: $VIF_UUID is '$NAME'"
  xe vif-param-set uuid=$VIF_UUID other-config:nicira-iface-id="$NAME"
done

ps auxw | grep -v grep | grep ovs-xapi-sync > /dev/null 2>&1
if [ $? -eq 0 ]; then
	killall -HUP ovs-xapi-sync
fi

