#!/usr/bin/python3

import boto3
import datetime
import re
from datetime import datetime, timedelta
import json

"""

Tasks:
1. Get the EC2 stopped instances list
2. Compare the stopped instance stopped date with no of old threshold days.
2. if the stopped instance is older than thresdhold date then take snapshot of only those instances.
3. Once snapshot completed, terminate the instances.
4. Produce final report as json file.
"""

# authorship information
__author__      = "Kiran"
__copyright__   = "Copyright 2021"
__license__ = "All rights are Reserved"
__version__ = "1.0.0"
__maintainer__ = "Kiran"
__email__ = ""
__status__ = "Production"
#

def get_stopped_instances(ec2_client):
    try:
        stopped_instances = {}
        reservations = ec2_client.describe_instances(Filters=[
            {
                "Name": "instance-state-name",
                "Values": ["stopped"],
            }
        ]).get("Reservations")

        for reservation in reservations:
            #print(reservation)
            for instance in reservation["Instances"]:

                # instance id
                instance_id = instance["InstanceId"]

                # Instance state
                instance_status = instance["State"]["Name"]

                # The private IP address of the instance (multiple IP addresses are listed if there is more than one network interface to the instance).
                private_ip = instance["PrivateIpAddress"]

                # The reason for the change of instance state; if the instance was terminated, for example, \
                # the reason might be User initiated shutdown.
                StateTransitionReasonMessage = instance["StateReason"]["Message"]

                # The reason for the current state of the instance including time of change.
                # 'StateTransitionReason': 'User initiated (2021-07-18 17:46:46 GMT)
                StateTransitionReason = instance["StateTransitionReason"]

                instance_stop_time = str(re.findall(r'\(.*?\)', StateTransitionReason)[0]).strip(")").strip("(")

                # Boot Volume of attached instance.
                VolumeId = instance['BlockDeviceMappings'] [0]['Ebs']['VolumeId']

                # Store the results in dictionary
                stopped_instances[instance_id] = {
                    "StateTransitionReason": StateTransitionReason,
                    "private_ip": private_ip,
                    "StateTransitionReasonMessage": StateTransitionReasonMessage,
                    "instance_status": instance_status,
                    "instance_stop_time": instance_stop_time,
                    "VolumeId": VolumeId

                }

        return stopped_instances

    except Exception as e:
        print(e)


def deltaFinder(stopped_instances, thresh_days ):

    threshold_date = datetime.now() - timedelta(days=thresh_days)
    valid_stopped_instances = []
    invalid_stopped_instances = []

    print("Threshold date for {0} Days older is {1}". format(thresh_days, threshold_date))

    for instance in stopped_instances:

        datetime_object_string = stopped_instances[instance]['instance_stop_time']
        datetime_object = datetime.strptime(datetime_object_string, '%Y-%m-%d %H:%M:%S %Z')

        if datetime_object < threshold_date:
            print(f"{instance} is stopped from {datetime_object} is {thresh_days} days older and good to terminate.")
            valid_stopped_instances.append(instance)

        else:
            print(f"{instance} is stopped from {datetime_object} is not {thresh_days} days older and can't be terminated.")
            invalid_stopped_instances.append(instance)

    return valid_stopped_instances, invalid_stopped_instances


def ec2_snapshot(ec2, vol_id, desc):
    successful_snapshots = dict()

    try:
        response = ec2.create_snapshot(VolumeId=vol_id, Description=desc)

        # response is a dictionary containing ResponseMetadata and SnapshotId
        status_code = response['ResponseMetadata']['HTTPStatusCode']
        snapshot_id = response['SnapshotId']

        # check if status_code was 200 or not to ensure the snapshot was created successfully
        if status_code == 200:
            successful_snapshots[vol_id] = snapshot_id

    except Exception as e:
        exception_message = "There was error in creating snapshot " + vol_id + " with volume id and error is: \n" + str(e)
        print(exception_message)

    # print the snapshots which were created successfully
    return successful_snapshots


def ec2_termination(ec2, stopped_instances, valid_stopped_instances):
    t_instances = {}
    for inst in valid_stopped_instances:
        if "Snapshots" in stopped_instances[inst]:
            print("Snapshot has found and proceeding with termination.")
            stopped_instances[inst].update(({"DestroyStatus": True}))
            response = ec2.terminate_instances(InstanceIds=[inst,],DryRun=False)
            t_instances.update({'inst': response})
            print("Instance Termination Initiated")
    
    return stopped_instances

def action_report(stopped_instances):
    print("Generating Final Report")
    json_report = json.dumps(stopped_instances)

    try:
        with open("final_termination_report.json", "w") as f:
            f.write(json_report)

        print("Report final_termination_report.json file has generated Sucessfully.")

    except Exception as e:
        print(e)

def main():
    #print(datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S %Z"))
    ec2 = boto3.client("ec2")
    stopped_instances = get_stopped_instances(ec2)
    report_snapshots ={}

    # Snapshot Details
    desc = "Cleanup"
    thresh_days = 5

    valid_stopped_instances, invalid_stopped_instances = deltaFinder(stopped_instances, thresh_days)
    count_valid_stopped_inst = len(valid_stopped_instances)
    print(f"{count_valid_stopped_inst} instances considered for backup and termination")

    for v_instances in valid_stopped_instances:
        vol_id = stopped_instances[v_instances]['VolumeId']
        successful_snapshots = ec2_snapshot(ec2, vol_id, desc)
        #report_snapshots[vol_id] =successful_snapshots[vol_id]
        if successful_snapshots:
            stopped_instances[v_instances].update({"Snapshots": successful_snapshots[vol_id]})

    stopped_instances = ec2_termination(ec2, stopped_instances, valid_stopped_instances)
    action_report(stopped_instances)

# Boiler Plate Code
if __name__ == "__main__":
    main()
