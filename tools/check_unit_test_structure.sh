#!/usr/bin/env bash

# This script identifies the unit test modules that do not correspond
# directly with a module in the code tree.  See TESTING.rst for the
# intended structure.

neutron_path=$(cd "$(dirname "$0")/.." && pwd)
base_test_path=neutron/tests/unit
test_path=$neutron_path/$base_test_path

test_files=$(find ${test_path} -iname 'test_*.py')

ignore_regexes=(
    # The following test is required for oslo.versionedobjects
    "^objects/test_objects.py$"
    # The following open source plugin tests are not actually unit
    # tests and are ignored pending their relocation to the functional
    # test tree.
    "^plugins/ml2/drivers/mech_sriov/mech_driver/test_mech_sriov_nic_switch.py$"
    "^plugins/ml2/test_security_group.py$"
    "^plugins/ml2/test_port_binding.py$"
    "^plugins/ml2/test_extension_driver_api.py$"
    "^plugins/ml2/test_ext_portsecurity.py$"
    "^plugins/ml2/test_agent_scheduler.py$"
    "^plugins/ml2/test_tracked_resources.py$"
    "^plugins/ml2/drivers/openvswitch/agent/test_agent_scheduler.py$"
    "^plugins/ml2/drivers/openvswitch/agent/test_ovs_tunnel.py$"
)

error_count=0
ignore_count=0
total_count=0
for test_file in ${test_files[@]}; do
    relative_path=${test_file#$test_path/}
    expected_path=$(dirname $neutron_path/neutron/$relative_path)
    test_filename=$(basename "$test_file")
    expected_filename=${test_filename#test_}
    # Module filename (e.g. foo/bar.py -> foo/test_bar.py)
    filename=$expected_path/$expected_filename
    # Package dir (e.g. foo/ -> test_foo.py)
    package_dir=${filename%.py}
    if [ ! -f "$filename" ] && [ ! -d "$package_dir" ]; then
        for ignore_regex in ${ignore_regexes[@]}; do
            if [[ "$relative_path" =~ $ignore_regex ]]; then
                ignore_count=$((ignore_count + 1))
                continue 2
            fi
        done
        echo "Unexpected test file: $base_test_path/$relative_path"
        error_count=$((error_count + 1))
    fi
    total_count=$((total_count + 1))
done

if [ "$ignore_count" -ne 0 ]; then
    echo "$ignore_count unmatched test modules were ignored"
fi

if [ "$error_count" -eq 0 ]; then
    echo 'Success!  All test modules match targets in the code tree.'
    exit 0
else
    echo "Failure! $error_count of $total_count test modules do not match targets in the code tree."
    exit 1
fi
