import boto3
import csv
import os.path
import os
from collections import defaultdict
import paramiko
import sys
import csv
from os import listdir
import select
import ast
import re
import json
from pssh.clients import ParallelSSHClient
from pssh.config import HostConfig
from gevent import joinall

"""
Instance Scanner:
    Verify the Listed Instance State.

    1. Read the Instance from Given CSV File.
    2. Proceed with Installation.

"""

# authorship information
__author__      = "Kiran"
__copyright__   = "Copyright 2021"
__license__ = "All rights are Reserved"
__version__ = "1.0.0"
__maintainer__ = "Kiran"
__email__ = ""
__status__ = "Production"


# READ THE INSTANCE FROM CSV FILE AND GENERATE THE JSON.
def read_instance():
    ec2info = {}
    filename = "Package_Detected_Scanned_Hosts_List.csv"
    with open(filename, mode='r') as infile:
        reader = csv.reader(infile)
        next(reader)
        for everyline in reader:
          ec2info[everyline[0]] = {'ID':everyline[0], 'OSType':everyline[1], 'PrivateIP':everyline[2], 'SSHKeyName':everyline[3], 
           'PemFileAvailable':everyline[4], 'ConnectionStatus':everyline[5], 'Amazon-Ssm-Agent_Status':everyline[6], 
           'Amazon-Ssm-Agent_Version':everyline[7], 'Falcon-Sensor_Status':everyline[8], 'Falcon-Sensor_Version':everyline[9], 'OSVersion':everyline[10], 'loginuser':everyline[11]}
    return ec2info


def compose_instance(ec2info):
    host_list = {}
    for key, value in ec2info.items():

        #print(key, value)
        #print(ec2info[key]["PemFileAvailable"])
        #print(ec2info[key]["ConnectionStatus"])
        keyname = str("PEM/"+ec2info[key]['SSHKeyName']+".pem")

        if ec2info[key]["PemFileAvailable"] == str("True") and ec2info[key]["ConnectionStatus"] == "True":
            print("Only Pem, Connection Availables", ec2info[key])
            if ec2info[key]["Amazon-Ssm-Agent_Status"] == "False" or ec2info[key]["Falcon-Sensor_Status"] == "False":
                host_list[key] = {"PrivateIP": ec2info[key]["PrivateIP"], "SSHKeyName": keyname, "loginuser": ec2info[key]['loginuser']}
    
    return host_list


def login_check(composed_instance):

    hosts = []
    host_config = []
    host_result = {}
    # List Generation
    for key, value in composed_instance.items():
        hosts.append(composed_instance[key]['PrivateIP'])
        host_config.append(HostConfig(user=composed_instance[key]['loginuser'], private_key=composed_instance[key]['SSHKeyName']))
    
    if host_config:
        client = ParallelSSHClient(hosts,  host_config=host_config,  timeout=10)
        
        # Data Copy
        outcopy = client.scp_send('os_detect.py','/tmp/os_detect.py')
        joinall(outcopy, raise_error=True)

        # Remote Command Execution
        counter = 0
        host_result = {}
        cmd = 'python3 /tmp/os_detect.py'
        output = client.run_command(cmd, return_list=True)
        client.join(output)
        for host_out in output:
            for line in host_out.stdout:
                t_var = ast.literal_eval(line.encode('utf-8').decode('ascii', 'ignore'))
                host_result[t_var['instance_id']] = t_var
    return host_result


def main():
    # break the execution in micro.
    ec2info = read_instance()
    print(ec2info)
    print("\n")
    composed_instance = compose_instance(ec2info)
    print("Composed_instance", composed_instance)
    host_result = login_check(composed_instance)
    print(host_result)

# Boiler Plate 
if __name__ == '__main__':
    main()
