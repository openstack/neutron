import groovy.transform.ToString
import groovy.transform.EqualsAndHashCode

import com.radware.alteon.beans.adc.*;
import com.radware.alteon.api.*;
import com.radware.alteon.sdk.*
import com.radware.alteon.sdk.rpm.*
import com.radware.alteon.api.impl.AlteonCliUtils;
import com.radware.alteon.cli.CliSession;


@ToString(includeNames=true)
@EqualsAndHashCode(excludes=["gateway","mask","ips"])
class SubnetInfo {
  String id
  String gateway
  String mask
  String ips
}

@ToString(includeNames=true)
@EqualsAndHashCode(excludes=["subnets"])
class PortInfo {
  String name
  def subnets = [:]
}


def tokenize_key(map_key) {
    def ret_arr = map_key.tokenize(".")
    if (ret_arr.size > 0 && ret_arr[0].startsWith("port")) {
        return ret_arr
    }
    else
        return null;
}


def parse(advanced_props) {
    def ports = [:]
    advanced_props.each {
        key, value ->
        def parsed_key = tokenize_key(key)
        if (parsed_key) {
            def port_name = parsed_key[0]
            def subnet_id = parsed_key[1]
            def property = parsed_key[2]
            def port_info = ports.get(port_name)
            if (port_info) {
                def subnet_info = port_info.subnets.get(subnet_id)
                if (subnet_info) {
                    subnet_info[property] = value
                }
                else {
                    subnet_info = new SubnetInfo(id:subnet_id)
                    subnet_info[property] = value
                    port_info.subnets.put(subnet_id, subnet_info)
                }
            }
            else {
                port_info = new PortInfo(name:port_name)
                subnet_info = new SubnetInfo(id:subnet_id)
                subnet_info[property] = value
                port_info.subnets.put(subnet_id, subnet_info)
                ports.put(port_name, port_info)
            }
        }
    }
    return ports
}

def get_property_per_port (ports, port_name, property_name) {
    port_info = ports[port_name]
    if (port_info) {
        port_subnet = port_info.subnets
        if (port_subnet && !port_subnet.isEmpty()) {
            port_subnet_item = port_subnet.values().iterator().next()
            port_subnet_property = port_subnet_item[property_name]
            if (port_subnet_property) {
                val_array = port_subnet_property.tokenize(",")
                if (!val_array.isEmpty())
                    return val_array[0]
            }
        }
    }
    else {
        return null
    }
}

def cidr_to_mask(cidr) throws NumberFormatException {

    String[] st = cidr.split("\\/");
    if (st.length != 2) {
        throw new NumberFormatException("Invalid CIDR format '"
                + cidr + "', should be: xx.xx.xx.xx/xx");
    }
    String symbolicIP = st[0];
    String symbolicCIDR = st[1];

    Integer numericCIDR = new Integer(symbolicCIDR);
    if (numericCIDR > 32) {
        throw new NumberFormatException("CIDR can not be greater than 32");
    }
    //Get IP
    st = symbolicIP.split("\\.");
    if (st.length != 4) {
        throw new NumberFormatException("Invalid IP address: " + symbolicIP);
    }
    int i = 24;
    baseIPnumeric = 0;
    for (int n = 0; n < st.length; n++) {
        int value = Integer.parseInt(st[n]);
        if (value != (value & 0xff)) {
            throw new NumberFormatException("Invalid IP address: " + symbolicIP);
        }
        baseIPnumeric += value << i;
        i -= 8;
    }
    //Get netmask
    if (numericCIDR < 1)
        throw new NumberFormatException("Netmask CIDR can not be less than 1");
    netmaskNumeric = 0xffffffff;
    netmaskNumeric = netmaskNumeric << (32 - numericCIDR);
    return netmaskNumeric
}


def String convert_numeric_ip_to_symbolic(ip) {
    StringBuffer sb = new StringBuffer(15);
    for (int shift = 24; shift > 0; shift -= 8) {
        // process 3 bytes, from high order byte down.
        def tmp = (ip >>> shift) & 0xff
        sb.append(tmp)
        sb.append('.');
    }
    sb.append(ip & 0xff);
    return sb.toString();
}


primary_adc = sdk.read(service.getPrimaryId())
primary_config = primary_adc.adcInfo.advancedConfiguration
primary_ports = parse(primary_config)
data_ip_address = get_property_per_port(primary_ports, "port1", "ips")
data_ip_mask = convert_numeric_ip_to_symbolic(cidr_to_mask(get_property_per_port(primary_ports, "port1", "mask")))
gateway = get_property_per_port(primary_ports, "port1", "gateway")

if (service.request.ha) {
    secondary_adc = sdk.read(service.getSecondaryId())
    secondary_config = secondary_adc.adcInfo.advancedConfiguration
    secondary_ports = parse(secondary_config)
    ha_ip_address_1 = get_property_per_port(primary_ports, "port2", "ips")
    ha_ip_address_2 = get_property_per_port(secondary_ports, "port2", "ips")
    ha_vrrp_ip_address = ha_ip_address_1
    ha_ip_mask = convert_numeric_ip_to_symbolic(cidr_to_mask(get_property_per_port(primary_ports, "port2", "mask")))
}
else {
    secondary_adc = null
    secondary_config = null
    secondary_ports = null
    ha_ip_address_1 = "1.1.1.1"
    ha_ip_address_2 = "1.1.1.2"
    ha_vrrp_ip_address = "1.1.1.3"
    ha_ip_mask = "255.255.255.255"
    ha_group_vr_id = 2
}

