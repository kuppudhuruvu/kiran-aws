import platform
import os
import urllib.request
import subprocess
import json

"""
This is the script to validate the amazon-ssm-agent package and falcon-sensor
package has installed on servers. if not it will try to install from local and remote reo.
Its a custom script created only for specific use case. Please check with author / maintainer 
before using the script.
"""

# authorship information
__author__      = "Kiran"
__copyright__   = "Copyright 2021"
__license__ = "All rights are Reserved"
__version__ = "1.0.0"
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
        return(os_var.strip('"'))

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

def linux_centos_pkg_install():
    try:
        pkg_status = ""
        child = subprocess.Popen("sudo rpm -qa | grep amazon-ssm-agent", stdout=subprocess.PIPE, shell=True)
        output = child.communicate()[0]

        if output:
            pkg_status = output.decode("utf-8")
            print("amazon-ssm-agent Package has already installed, ignoring...")

        else:    
            cmd = ["sudo", "yum", "install", "-y", "https://s3.amazonaws.com/ec2-downloads-windows/SSMAgent/latest/linux_amd64/amazon-ssm-agent.rpm"]
            p = subprocess.Popen(cmd)
            p.wait()
            if p.returncode == 0:
                print("amazon-ssm-agent Package has installed successfully")
                child = subprocess.Popen("sudo rpm -qa | grep amazon-ssm-agent", stdout=subprocess.PIPE, shell=True)
                output = child.communicate()[0]
                pkg_status = output.decode("utf-8")

                '''
                cmd_enable = ['sudo','systemctl', 'enable','amazon-ssm-agent']
                cmd_start = ['sudo', 'systemctl' ,'start', 'amazon-ssm-agent']
                p = subprocess.Popen(cmd_enable)
                p.wait()
                p = subprocess.Popen(cmd_start)
                p.wait()
                '''
            else:
                print("Something went wrong while installing amazon-ssm-agent")
        
        return pkg_status

    except OSError:
        print("Can't change the Current Working Directory")


def linux_centos_falcon_install(rpm_name):
    try:
        pkg_status = ""
        child = subprocess.Popen("sudo rpm -qa | grep falcon-sensor", stdout=subprocess.PIPE, shell=True)
        output = child.communicate()[0]
        if output:
            pkg_status = output.decode("utf-8")
            print("falcon-sensor Package has already installed, ignoring...")
        else:
            cmd = ["sudo", "rpm", "-ivh", rpm_name]
            p = subprocess.Popen(cmd)
            p.wait()
            if p.returncode == 0:
                print("falcon-sensor Package has installed successfully")
                child = subprocess.Popen("sudo rpm -qa | grep falcon-sensor", stdout=subprocess.PIPE, shell=True)
                output = child.communicate()[0]
                pkg_status = output.decode("utf-8")

                print("Pls wait, bringing up services")
                cmd_register = ['sudo', '/opt/CrowdStrike/falconctl', '-s', '-f', '--cid=EB0EF13C6EE44725BFAB1827AD937C29-8E', '--tags=CLOUD']
                cmd_enable = ['sudo','systemctl', 'enable','falcon-sensor']
                cmd_start = ['sudo', 'systemctl' ,'start', 'falcon-sensor']
                p = subprocess.Popen(cmd_register)
                p.wait()
                p = subprocess.Popen(cmd_enable)
                p.wait()
                p = subprocess.Popen(cmd_start)
                p.wait()
                print("Falcon service registered & started successfully.")
            else:
                print("Something went wrong while installing falcon-sensor")

        return pkg_status

    except Exception as e:
        print(e)


def linux_ubuntu_pkg_install():
    try:
        #os.chdir("/tmp/")
        #url =  "https://s3.amazonaws.com/ec2-downloads-windows/SSMAgent/latest/debian_amd64/amazon-ssm-agent.deb"
        #file_path, _ = urllib.request.urlretrieve(url, 'amazon-ssm-agent.deb')
        # sudo apt list --installed | grep tmux
        pkg_status = ""
        child = subprocess.Popen("sudo snap list | grep amazon-ssm-agent", stdout=subprocess.PIPE, shell=True)
        output = child.communicate()[0]

        if output:
            pkg_status = output.decode("utf-8") 
            print("amazon-ssm-agent Package has already installed, ignoring...")

        else:
            #installation command
            cmd = ["sudo", "snap", "install", "amazon-ssm-agent", "--classic"]
            p = subprocess.Popen(cmd)
            p.wait()
            if p.returncode == 0:
                print("amazon-ssm-agent has Installed Successfully")
                child = subprocess.Popen("sudo snap list | grep amazon-ssm-agent", stdout=subprocess.PIPE, shell=True)
                output = child.communicate()[0]
                pkg_status = output.decode("utf-8") 

            else:
                print("Something went wrong while installing amazon-ssm-agent")

        return pkg_status

    except OSError:
        print("Can't change the Current Working Directory")


def linux_ubuntu_falcon_install():
    try:
        #sudo apt list --installed | grep falcon-sensor
        # falcon-sensor/now 6.24.0-12104 amd64 [installed,local]
        pkg_status = ""
        child = subprocess.Popen("sudo apt list --installed | grep falcon-sensor", stdout=subprocess.PIPE, shell=True)
        output = child.communicate()[0]

        if "installed" in str(output.decode("utf-8")):
            pkg_status = output.decode("utf-8")
            print("Falcon Sensor Package has already installed, ignoring...")

        else:
            cmd  = ["sudo", "dpkg", "-i", "/tmp/falcon-sensor_6.24.0-12104_amd64.deb"]
            p = subprocess.Popen(cmd)
            p.wait()
            if p.returncode == 0:
                print("Falcon Sensor Package Installed Successfully")
                print("Pls wait, bringing up services")
                cmd_register = ['sudo', '/opt/CrowdStrike/falconctl', '-s', '-f', '--cid=EB0EF13C6EE44725BFAB1827AD937C29-8E', '--tags=CLOUD']
                cmd_enable = ['sudo','systemctl', 'enable','falcon-sensor']
                cmd_start = ['sudo', 'systemctl' ,'start', 'falcon-sensor']
                p = subprocess.Popen(cmd_register)
                p.wait()
                p = subprocess.Popen(cmd_enable)
                p.wait()
                p = subprocess.Popen(cmd_start)
                p.wait()
                print("Falcon service registered & started successfully.")
                child = subprocess.Popen("sudo apt list --installed | grep falcon-sensor", stdout=subprocess.PIPE, shell=True)
                output = child.communicate()[0]
                pkg_status = output.decode("utf-8")

            else:
                print("Something went wrong while installing Falcon Sensor")
        
        return pkg_status

    except Exception as e:
        print(e)

def install():
    # Call os_type Method to Identify the OS from AWS Instance only.
    os_ver = os_type()

    if os_ver == 'ubuntu':
        ssm_status = linux_ubuntu_pkg_install()
        falcon_status = linux_ubuntu_falcon_install()

    elif os_ver == 'centos':
        ssm_status = linux_centos_pkg_install()
        # Falcon based on os version
        os_arch = os_arch_ver()
        if os_arch == '8':
            rpm_name = "/tmp/falcon-sensor-6.14.0-11110.el8.x86_64.rpm"
        elif os_arch == '7':
            rpm_name = "/tmp/falcon-sensor-6.14.0-11110.el7.x86_64.rpm"
        elif os_arch == '6':
            rpm_name = "/tmp/falcon-sensor-6.14.0-11110.el6.x86_64.rpm"
        falcon_status = linux_centos_falcon_install()

    elif os_ver == 'amzn' :
        ssm_status = linux_centos_pkg_install()
        # Falcon based on os version
        os_arch = os_arch_ver('amzn')

        if os_arch == '1':
            rpm_name = "/tmp/falcon-sensor-6.14.0-11110.amzn1.x86_64.rpm"
        elif os_arch == '2':
            rpm_name = "/tmp/falcon-sensor-6.14.0-11110.amzn2.x86_64.rpm"

        falcon_status = linux_centos_falcon_install(rpm_name)

    elif os_ver == 'rhel':
        ssm_status = linux_centos_pkg_install()
        # Falcon based on os version
        os_arch = os_arch_ver('rhel')
        if os_arch == '8':
            rpm_name = "/tmp/falcon-sensor-6.14.0-11110.el8.x86_64.rpm"
        elif os_arch == '7':
            rpm_name = "/tmp/falcon-sensor-6.14.0-11110.el7.x86_64.rpm"
        elif os_arch == '6':
            rpm_name = "/tmp/falcon-sensor-6.14.0-11110.el6.x86_64.rpm"

        falcon_status = linux_centos_falcon_install(rpm_name)
        
    else:
        print("unable to determine the os version")
        exit(1)

    # Associate the Result in Dictionary    
    pkgstatus = {
        "amazon-ssm-agent": ssm_status,
        "falcon-sensor": falcon_status
    }
    return pkgstatus

# Boiler Plate Code
if __name__ == "__main__":
    pkgstatus = install()
    out_path = str("/tmp/os_detect.out")
    try:
        if os.path.exists(out_path):
            os.remove(out_path)

        with open(out_path, "w") as fp:
            json.dump(pkgstatus, fp)
            print(pkgstatus)
       
    except Exception as e:
        print(e)
