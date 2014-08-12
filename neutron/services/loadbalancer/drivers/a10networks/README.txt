A10 Networks LBaaS Driver

Installation info:

To use this driver, you must:
- Install the a10-neutron-lbaas module. (E.g.: 'pip install a10-neutron-lbaas')
- Create a driver config file, a sample of which is given below.
- Enable it in neutron.conf
- Restart neutron-server

Third-party CI info:

Contact info for any problems is: a10-openstack-ci at a10networks dot com
Or contact Doug Wiegley directly (IRC: dougwig)

Configuration file:

Create a configuration file with a list of A10 appliances, similar to the
file below, located at:
/etc/neutron/services/loadbalancer/a10networks/config.py

Or you can override that directory by setting the environment
variable A10_CONFIG_DIR.

Example config file:

devices = {
    "ax1": {
        "name": "ax1",
        "host": "10.10.100.20",
        "port": 443,
        "protocol": "https",
        "username": "admin",
        "password": "a10",
        "status": True,
        "autosnat": False,
        "api_version": "2.1",
        "v_method": "LSI",
        "max_instance": 5000,
        "use_float": False,
        "method": "hash"
    },
    "ax4": {
        "host": "10.10.100.23",
        "username": "admin",
        "password": "a10",
    },
}
