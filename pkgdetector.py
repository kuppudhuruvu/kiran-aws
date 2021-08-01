import platform
import os
import urllib.request
import subprocess
import json

"""
This is the script to validate the amazon-ssm-agent package and falcon-sensor
package has installed on servers.
Its a custom script created only for specific use case. Please check with author / maintainer 
before using the script.
"""

# authorship information
__author__      = "Kiran"
__copyright__   = "Copyright 2021"
__license__ = "All rights are Reserved"
__version__ = "1.0.6"
__maintainer__ = "Kiran"
__email__ = ""
__status__ = "Production"

def os_type():

    try:
        f = open('/etc/os-release')
        for line in f.readlines():
            l = line.split('=')
            if l[0] == 'ID':
                os_var = str(l[1].strip())
            
            if l[0] == 'PRETTY_NAME':
                os_name = str(l[1].strip())
        return(os_var.strip('"'), os_name.strip('"'))

    except Exception as e:
        print(e)

def os_arch_ver(ver):
    #detect_arch = platform.architecture()
    if ver == 'rhel':
        try:
            f = open('/etc/os-release')
            for line in f.readlines():
                l = line.split('=')
                if l[0] == 'VERSION_ID':
                    os_ver = str(l[1]).split('.')[0]
            return(os_ver.strip('"'))

        except Exception as e:
            print(e)
    elif ver == 'amzn':
        try:
            f = open('/etc/os-release')
            for line in f.readlines():
                l = line.split('=')
                if l[0] == 'VERSION_ID':
                    os_ver = str(l[1].strip())
            return(os_ver.strip('"'))

        except Exception as e:
            print(e)

def os_machine():
    detect_machine = platform.machine().lower()
    return detect_machine

def os_nodename():
    detect_name = platform.node().lower()
    return detect_name

def os_processor_arch():
    detect_proc_arch = platform.processor().lower()
    return detect_proc_arch

def linux_centos_pkg_status():
    try:
        pkg_status = ""
        child = subprocess.Popen("sudo rpm -qa | grep amazon-ssm-agent", stdout=subprocess.PIPE, shell=True)
        output = child.communicate()[0]

        if output:
            pkg_status = output.decode("utf-8")
            # print("amazon-ssm-agent Package has already installed, ignoring...")

        else:    
            # print("Amazon SSM Package has not installed.")
            pkg_status = ""

        return pkg_status

    except OSError:
        print("Can't change the Current Working Directory")


def linux_centos_falcon_status():
    try:
        pkg_status = ""
        child = subprocess.Popen("sudo rpm -qa | grep falcon-sensor", stdout=subprocess.PIPE, shell=True)
        output = child.communicate()[0]
        if output:
            pkg_status = output.decode("utf-8")
            #print("falcon-sensor Package has already installed, ignoring...")
        else:
            #print("Falcon Sensor Package has not installed.")
            pkg_status = ""

        return pkg_status

    except Exception as e:
        print(e)


def linux_ubuntu_pkg_status():
    try:
        pkg_status = ""
        child = subprocess.Popen("sudo snap list | grep amazon-ssm-agent", stdout=subprocess.PIPE, shell=True)
        output = child.communicate()[0]

        if output:
            pkg_status = output.decode("utf-8") 
            #print("amazon-ssm-agent Package has already installed, ignoring...")

        else:
            #print("Amazon SSM Package has not installed.")
            pkg_status = ""

        return pkg_status

    except OSError:
        print("Can't change the Current Working Directory")


def linux_ubuntu_falcon_status():
    try:
        pkg_status = ""
        error_status = ""
        child = subprocess.Popen("sudo apt list --installed | grep falcon-sensor", stdout=subprocess.PIPE, shell=True)
        output = child.communicate()[0]

        if "installed" in str(output.decode("utf-8")):
            pkg_status = output.decode("utf-8")
            # print("Falcon Sensor Package has already installed, ignoring...")

        else:
            # print("Falcon Sensor Package has not installed.")
            pkg_status = ''

        return pkg_status

    except Exception as e:
        print(e)

def pkg_validate():
    # Call os_type Method to Identify the OS from AWS Instance only.
    inst_id = ""
    os_ver, os_name = os_type()
    child  = subprocess.Popen("wget -q -O - http://169.254.169.254/latest/meta-data/instance-id",stdout=subprocess.PIPE, shell=True)
    output = child.communicate()[0]
    if output:
        inst_id = output.decode("utf-8")

    falcon_status = ""
    ssm_status = ""

    if os_ver == 'ubuntu':
        falcon_status = linux_ubuntu_falcon_status()
        ssm_status = linux_ubuntu_pkg_status()
        
    elif os_ver == 'centos':
        falcon_status = linux_centos_falcon_status()
        ssm_status = linux_centos_pkg_status()
  
    elif os_ver == 'amzn' :
        falcon_status = linux_centos_falcon_status()
        ssm_status = linux_centos_pkg_status()

    elif os_ver == 'rhel':
        falcon_status = linux_centos_falcon_status()
        ssm_status = linux_centos_pkg_status()
        
    else:
        print("unable to determine the os version")
        exit(1)

    # Associate the Result in Dictionary    
    pkgstatus = {
        "amazon-ssm-agent": ssm_status,
        "falcon-sensor": falcon_status,
        "os_name": os_name,
        "instance_id": inst_id
    }
    return pkgstatus

# Boiler Plate Code
if __name__ == "__main__":
    pkgstatus = pkg_validate()
    '''
    #out_path = str("/tmp/pkgdetector.out")
    try:
        if os.path.exists(out_path):
            os.remove(out_path)

        with open(out_path, "w") as fp:
            json.dump(pkgstatus, fp)
            print(pkgstatus)
       
    except Exception as e:
        print(e)
    '''
    print(pkgstatus)
