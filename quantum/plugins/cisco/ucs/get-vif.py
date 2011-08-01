import sys
import subprocess


def get_next_dynic(argv=[]):
    cmd = ["ifconfig", "-a"]
    f_cmd_output = subprocess.Popen(cmd, stdout=subprocess.PIPE).\
                   communicate()[0]
    eths = [lines.split(' ')[0] for lines in f_cmd_output.splitlines() \
            if "eth" in lines]
    #print eths
    for eth in eths:
        cmd = ["ethtool", "-i", eth]
        f_cmd_output = subprocess.Popen(cmd, stdout=subprocess.PIPE).\
                       communicate()[0]
        bdf = [lines.split(' ')[1] for lines in f_cmd_output.splitlines() \
               if "bus-info" in lines]
        #print bdf
        cmd = ["lspci", "-n", "-s", bdf[0]]
        f_cmd_output = subprocess.Popen(cmd, stdout=subprocess.PIPE).\
                       communicate()[0]
        deviceid = [(lines.split(':')[3]).split(' ')[0] \
                    for lines in f_cmd_output.splitlines()]
        #print deviceid
        if deviceid[0] == "0044":
            cmd = ["/usr/sbin/ip", "link", "show", eth]
            f_cmd_output = subprocess.Popen(cmd, stdout=subprocess.PIPE).\
                           communicate()[0]
            used = [lines for lines in f_cmd_output.splitlines() \
                    if "UP" in lines]
            if not used:
                break
    return eth

if __name__ == '__main__':
    nic = get_next_dynic(sys.argv)
    print nic
