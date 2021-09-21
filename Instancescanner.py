import csv
import os.path
import os
from collections import defaultdict
import sys
import csv
from os import listdir
import select
import ast
import boto3
import paramiko
import re
import json
from pssh.clients import ParallelSSHClient
from pssh.config import HostConfig
from gevent import joinall

"""
Instance Scanner:
    1. Run the Scan against the active aws account and filter the running Instances
    2. Compose Data Format for every running status detected instances.
    3. Validate PEM file availability and Connection status for login user.
    4. Ignore Windows hosts, PEM file not available hosts.
    5. Copy the pkgdetector.py to the validate Instances
    6. Run the pkgdetector.py on remote hosts where the script was copied
    7. All the instances copy and running pkgdetector will execute parallely
    8. Join all the parallel execution output based on instance_id.
    9. Generate the Report for all instances with available data such as connectivity,
       loginuser, pemfile name, ssm-agent , falcon-sensor pkg availability in csv format.
    Note: This csv report will be used for missing package installation..

"""

# authorship information
__author__      = "Kiran Kumar Suran"
__maintainer__  = "Kiran Kumar Suram"
__email__       = "ksuram30@massmutual.com"

# READ THE INSTANCE FROM CSV FILE AND GENERATE THE JSON.
def read_instance():
    inst_id = []
    with open("inventory.csv", "r") as instid:
        for line in instid:
            cmd = line.strip()
            inst_id.append(cmd)

    return inst_id

#
def aws_running(ec2):

    # Declare local variables
    ec2info = {}
    keystore = {}
    # Get Running Instances
    running_instances = ec2.instances.filter(Filters=[{'Name': 'instance-state-name','Values': ['running']}])

    # running_instances = ec2.instances.filter(InstanceIds=inst_id)

    for instance in running_instances:
        if instance.platform:
            platform = "windows"
        else:
            platform = "linux"

        ec2info[instance.id] = {
            'ID': instance.instance_id,
            'OSType': platform,
            'PrivateIP': instance.private_ip_address,
            'SSHKeyName': instance.key_name,
            'PemFileAvailable': '',
            'ConnectionStatus': '',
            'Amazon-Ssm-Agent_Status': '',
            'Amazon-Ssm-Agent_Version': '',
            'Falcon-Sensor_Status': '',
            'Falcon-Sensor_Version': '',
            'OSVersion': '',
            'loginuser': '',
            }
        if ec2info[instance.id]['SSHKeyName'] == None:
            ec2info[instance.id]['ConnectionStatus']  = False
            ec2info[instance.id]['OSVersion']  = "Instance ID: {} - SSH Key pair is not attached".format(ec2info[instance.id]['ID'])
            ec2info[instance.id]['PemFileAvailable'] = False
        else:
            if str(ec2info[instance.id]['OSType']).lower() != "windows":

                if ec2info[instance.id]['SSHKeyName'].endswith('.pem'):
                    keypath = ec2info[instance.id]['SSHKeyName'].strip('.pem')
                else:
                    keypath = ec2info[instance.id]['SSHKeyName']

                sshkeypath = "../PEM/{}.pem".format(keypath)
                keystore[instance.id] = sshkeypath

                if os.path.isfile(sshkeypath):
                    ec2info[instance.id]['PemFileAvailable'] = True
                else:
                    ec2info[instance.id]['ConnectionStatus'] = False
                    ec2info[instance.id]['OSVersion'] = "PEM Key {} not found locally in the path".format(keypath)
                    ec2info[instance.id]['PemFileAvailable'] = False

            else:
                ec2info[instance.id]['ConnectionStatus'] = False
                ec2info[instance.id]['PemFileAvailable'] = False
                ec2info[instance.id]['OSVersion'] = "Instance {} is Windows Host. Try RDP".format(ec2info[instance.id]['ID'])

    return ec2info, keystore


def login_check(ec2info, keystore):

    hosts = []
    host_config = []
    host_result = {}

    # List Generation
    for connect in ec2info:
        if ec2info[connect]['ConnectionStatus'] == True:
            hosts.append(ec2info[connect]['PrivateIP'])
            host_config.append(HostConfig(user=ec2info[connect]['loginuser'], private_key=keystore[connect]))

    if host_config:
        client = ParallelSSHClient(hosts,  host_config=host_config)

        # Data Copy
        outcopy = client.scp_send('pkgdetector.py','/tmp/pkgdetector.py')
        joinall(outcopy, raise_error=True)

        # Remote Command Execution
        counter = 0
        host_result = {}
        cmd = 'python3 /tmp/pkgdetector.py'
        output = client.run_command(cmd, return_list=True, stop_on_errors=False)
        client.join(output)
        for host_out in output:
            # print(host_out.stdout)
            for line in host_out.stdout:
                t_var = ast.literal_eval(line.encode('utf-8').decode('ascii', 'ignore'))
                host_result[t_var['instance_id']] = t_var
                '''
                counter = counter + 1
                if counter == 1:
                    host_result[line] = ""
                    second_var = line

                elif counter == 2:
                    host_result[second_var] = line
                    counter = 0
                    second_var = ""
                '''

    return host_result


def login(ec2info, keystore):
    for connect in ec2info:
        if ec2info[connect]['PemFileAvailable']:
            hostip = ec2info[connect]['PrivateIP']
            key  = keystore[connect]
            ConnectionStatus = ec2info[connect]['ConnectionStatus']

            print("Connecting to", ec2info[connect]['ID'])
            ConnectionStatus, username = ServerConnection(hostip, key, ConnectionStatus)
            ec2info[connect]['loginuser'] = username
            ec2info[connect]['ConnectionStatus'] = ConnectionStatus

def ServerConnection(hostip, keystore, ConnectionStatus):
    loginuser = {'ubuntu', 'ec2-user', 'admin', 'dbadmin'}
    username = ""

    print("Trying to connect to {}".format(hostip))

    if not ConnectionStatus:
        ConnectionStatus = False

    for user in loginuser:
        try:
            #print(user,keystore, hostip)
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            key = paramiko.RSAKey.from_private_key_file(keystore)
            ssh.connect(hostname=hostip, username=user, pkey=key)

            if ssh.get_transport().is_active() == False:
                continue
            else:
                ConnectionStatus = True
                username = user
                print("Connected using user: ", user)
                break

        except TimeoutError:
            print("Could not SSH to {}. Connection is TimedOut." .format(hostip))
            break

        except paramiko.AuthenticationException:
            print("Authentication failed when connecting to {0} using user {1}".format(hostip, user))

        except Exception as e:
            print(e)

        ssh.close()

    print("SSH connection closed")
    ssh.close()

    return ConnectionStatus, username

# misc
def misc():
    # environment = boto3.client('sts').get_caller_identity().get('Account')
    # Account Details
    #environments = {
    #}
    # Report File
    report_name = 'Package_Detected_Scanned_Hosts_List.csv'

    # Verify the Report and remove if already exists
    if os.path.exists(report_name):
        os.remove(report_name)

    return report_name


# Field Merger
def merger(ec2info, host_result):
    for key, value in ec2info.items():
        if ec2info[key]['ConnectionStatus'] == True:

                if key in host_result.keys():

                    ec2info[key]['OSVersion'] = host_result[key]['os_name']

                    if host_result[key]['amazon-ssm-agent']:
                        ec2info[key]['Amazon-Ssm-Agent_Status'] = True
                        ec2info[key]['Amazon-Ssm-Agent_Version'] = host_result[key]['amazon-ssm-agent']
                    else:
                        ec2info[key]['Amazon-Ssm-Agent_Status'] = False

                    if host_result[key]['falcon-sensor']:
                        ec2info[key]['Falcon-Sensor_Status'] = True
                        ec2info[key]['Falcon-Sensor_Version'] = host_result[key]['falcon-sensor']
                    else:
                        ec2info[key]['Falcon-Sensor_Status'] = False

    return ec2info

# Report Generation
def csvreport(ec2info_final):
    report_name = misc()
    csv_columns = ['ID', 'OSType', 'PrivateIP', 'SSHKeyName', 'PemFileAvailable', 'ConnectionStatus', 'Amazon-Ssm-Agent_Status',
    'Amazon-Ssm-Agent_Version', 'Falcon-Sensor_Status', 'Falcon-Sensor_Version', 'OSVersion', 'loginuser']
    try:
        with open(report_name, 'w') as csvfile:
            csvwriter = csv.DictWriter(csvfile, fieldnames=csv_columns)
            csvwriter.writeheader()
            for key, val in ec2info_final.items():
                csvwriter.writerow(val)

    except Exception as e:
        print(e)

    return report_name


# Main Program
def main():
    ec2 = boto3.resource('ec2')
    ec2info, keystore = aws_running(ec2)

    login(ec2info, keystore)
    #print("ec2info", ec2info)

    host_result = login_check(ec2info, keystore)

    ec2info_final = merger(ec2info, host_result)

    # Report Generation
    print("Generating Report")
    report_name = csvreport(ec2info_final)
    print("Report Generated as {}".format(report_name))


# Boiler Plate
if __name__ == '__main__':
    main()
