import boto3
import csv
import os.path
import os
from collections import defaultdict
import paramiko
from os_detect import install
import sys
import csv
from os import listdir

'''
Task are defined as below.

# 1. Collect all Running EC2 Instances information
# 2. Query all PEM Key file names that are associated with the EC2 Instance Ids that have been collected
# 3. Create a csv report all relevant information `field_names`

# Rules:
1. Ensure to create the PEM folder and .pem files are kept under it
2. Ensure to create the PACKAGES folder and all rpm are kept under it.
3. Ensure to create the MODULES folder and keep the os_detect.py

*** host ip added manually for testing only
'''

def aws_running(ec2):

    # Declare local variables
    ec2info = {}
    keystore = {}
    # Get Running Instances
    running_instances = ec2.instances.filter(Filters=[{'Name': 'instance-state-name','Values': ['running']}])

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
            }

        if ec2info[instance.id]['SSHKeyName'] == None:
            ec2info[instance.id]['ConnectionStatus']  = "Instance ID: {} - SSH Key pair is not attached".format(ec2info[instance.id]['ID'])
            ec2info[instance.id]['PemFileAvailable'] = False
        else:
            if str(ec2info[instance.id]['OSType']).lower() is not "windows":

                if ec2info[instance.id]['SSHKeyName'].endswith('.pem'):
                    keypath = ec2info[instance.id]['SSHKeyName'].strip('.pem')
                else:
                    keypath = ec2info[instance.id]['SSHKeyName']

                sshkeypath = "PEM/{}.pem".format(keypath)
                keystore[instance.id] = sshkeypath

                if os.path.isfile(sshkeypath):
                    ec2info[instance.id]['PemFileAvailable'] = True
                else:
                    ec2info[instance.id]['ConnectionStatus'] = "PEM Key {} not found locally in the path".format(keypath)
                    ec2info[instance.id]['PemFileAvailable'] = False

            else:
                ec2info[instance.id]['ConnectionStatus'] = "Instance {} is Windows Host. Try RDP".format(ec2info[instance.id]['ID'])

    return ec2info, keystore


def login(ec2):
    # aws Running status
    ec2info, keystore = aws_running(ec2)

    for connect in ec2info:
        if ec2info[connect]['PemFileAvailable']:
            hostip = ec2info[connect]['PrivateIP']
            key  = keystore[connect]
            ConnectionStatus = ec2info[connect]['ConnectionStatus']
            ConnectionStatus = ServerConnection("13.232.44.10", key, ConnectionStatus)
            if ConnectionStatus:
                ec2info[connect]['ConnectionStatus'] = ConnectionStatus
            else:
                ec2info[connect]['ConnectionStatus'] = False

    return ec2info

def ServerConnection(hostip, keystore, ConnectionStatus):
    loginuser = {'ubuntu', 'ec2-user', 'admin'}
    print("Trying to connect to {}".format(hostip))

    if not ConnectionStatus:
        ConnectionStatus = False

    for user in loginuser:
        try:
            
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            key = paramiko.RSAKey.from_private_key_file(keystore)
            ssh.connect(hostname=hostip, username=user, pkey=key)

            if ssh.get_transport().is_active() == False:
                continue
            else:
                print("Connected to {}".format(hostip))
                ConnectionStatus = True
                pkg_path = "PACKAGES/"
                module_path = "MODULES/os_detect.py"
                if os.path.isdir(pkg_path):
                    try:
                        sftp_client = ssh.open_sftp()
                        print("sftp connection opened")
                        for pkg in os.listdir(pkg_path):
                            sftp_client.put(pkg_path+pkg, str("/tmp/"+pkg))
                        sftp_client.put(module_path, "/tmp/os_detect.py")
                        print("File Copy Completed.")
                        sftp_client.close()
                        print("sftp connection closed")
                        
                    except Exception as e:
                        print(e)
                        print("Unable to Copy the file.")
                else:
                    print("Packages are not available to copy to target instance.")

                print("ssh connection closed")
                break

        except paramiko.AuthenticationException:
            print("Authentication failed when connecting to {0} using user {1}".format(hostip, user))

        except TimeoutError:
            print("Could not SSH to {}. Connection is TimedOut." .format(hostip))

        except Exception as e:
            #print(str(e))
            print("Could not SSH to {0} using {1}. might be server in stopped status or terminated." .format(hostip, user))
           
    return ConnectionStatus


def misc():
    environment = boto3.client('sts').get_caller_identity().get('Account')
    # Account Details
    environments = {
    '330033715166': 'abcd',
    }
    # Report File 
    report_name = 'ssh_pem_key_information_report-' + environments[environment] + '.csv'

    # Verify the Report and remove if already exists
    if os.path.exists(report_name):
        os.remove(report_name)

    return report_name

def csvreport(ec2info):
    report_name = misc()
    csv_columns = ['ID', 'OSType', 'PrivateIP', 'SSHKeyName', 'PemFileAvailable', 'ConnectionStatus', 'Amazon-Ssm-Agent_Status',
    'Amazon-Ssm-Agent_Version', 'Falcon-Sensor_Status', 'Falcon-Sensor_Version']
    try:
        with open(report_name, 'w') as csvfile: 
            csvwriter = csv.DictWriter(csvfile, fieldnames=csv_columns)
            csvwriter.writeheader()
            for key, val in ec2info.items():
                csvwriter.writerow(val)

    except Exception as e:
        print(e)


def main():
    ec2 = boto3.resource('ec2')
    
    # Method Calling - Generate Report Name 
    #report_name = misc(environment)

    # login method calling
    ec2info = login(ec2)

    # Report Generation
    csvreport(ec2info)


# Boiler Plate 
if __name__ == '__main__':
    main()
