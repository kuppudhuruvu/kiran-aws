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

def linux_centos_pkg_install():
    try:
        pkg_status = ""
        error_status = ""
        child = subprocess.Popen("sudo rpm -qa | grep amazon-ssm-agent", stdout=subprocess.PIPE, shell=True)
        output = child.communicate()[0]

        if output:
            pkg_status = output.decode("utf-8")
            #print("amazon-ssm-agent Package has already installed, ignoring...")

        else:
            cmd = ["sudo", "yum", "install", "-y", "https://s3.amazonaws.com/ec2-downloads-windows/SSMAgent/latest/linux_amd64/amazon-ssm-agent.rpm"]
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE)
            p.wait()
            if p.returncode == 0:
                #print("amazon-ssm-agent Package has installed successfully")
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
                output, errorcode = p.communicate()
                if errorcode:
                    error_status = errorcode.decode("utf-8")
                #print(error_status)
                #print("Something went wrong while installing amazon-ssm-agent")

        return pkg_status, error_status

    except OSError:
        print("Can't change the Current Working Directory")


def linux_centos_falcon_install(rpm_name):
    try:
        pkg_status = ""
        error_status =""
        child = subprocess.Popen("sudo rpm -qa | grep falcon-sensor", stdout=subprocess.PIPE, shell=True)
        output = child.communicate()[0]
        if output:
            pkg_status = output.decode("utf-8")
            #print("falcon-sensor Package has already installed, ignoring...")
        else:
            cmd = ["sudo", "rpm", "-ivh", rpm_name]
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE)
            p.wait()
            if p.returncode == 0:
                #print("falcon-sensor Package has installed successfully")
                child = subprocess.Popen("sudo rpm -qa | grep falcon-sensor", stdout=subprocess.PIPE, shell=True)
                output = child.communicate()[0]
                pkg_status = output.decode("utf-8")

                #print("Pls wait, bringing up services")
                cmd_register = ['sudo', '/opt/CrowdStrike/falconctl', '-s', '-f', '--cid=EB0EF13C6EE44725BFAB1827AD937C29-8E', '--tags=CLOUD']
                cmd_enable = ['sudo','systemctl', 'enable','falcon-sensor']
                cmd_start = ['sudo', 'systemctl' ,'start', 'falcon-sensor']
                cmd_amz1_start = ['sudo','/etc/init.d/falcon-sensor','start']
                cmd_amz1_enable = ['sudo','chkconfig','falcon-sensor','on']

                p = subprocess.Popen(cmd_register)
                p.wait()
                p = subprocess.Popen(cmd_enable)
                p.wait()
                p = subprocess.Popen(cmd_start)
                p.wait()
                if p.returncode != 0:
                    p = subprocess.Popen(cmd_amz1_start)
                    p.wait()
                    p = subprocess.Popen(cmd_amz1_enable)
                    p.wait()
                #print("Falcon service registered & started successfully.")
            else:
                output,errorcode = p.communicate()
                if errorcode:
                    error_status = errorcode.decode("utf-8")
                #print(error_status)s
                #print("Something went wrong while installing falcon-sensor")

        return pkg_status, error_status

    except Exception as e:
        print(e)


def linux_ubuntu_pkg_install():
    try:
        #os.chdir("/tmp/")
        #url =  "https://s3.amazonaws.com/ec2-downloads-windows/SSMAgent/latest/debian_amd64/amazon-ssm-agent.deb"
        #file_path, _ = urllib.request.urlretrieve(url, 'amazon-ssm-agent.deb')
        # sudo apt list --installed | grep tmux
        pkg_status = ""
        error_status= ""
        child = subprocess.Popen("sudo snap list | grep amazon-ssm-agent", stdout=subprocess.PIPE, shell=True)
        output = child.communicate()[0]


        if output:
            pkg_status = output.decode("utf-8")
            #print("amazon-ssm-agent Package has already installed, ignoring...")

        else:
            snapquery  = ["sudo", "snap", "find", "amazon-ssm-agent"]

            if not snapquery:
                #print("Amazon-ssm-agent manual installation starts.")
                url =  "https://s3.amazonaws.com/ec2-downloads-windows/SSMAgent/latest/debian_amd64/amazon-ssm-agent.deb"
                file_path, _ = urllib.request.urlretrieve(url, 'amazon-ssm-agent.deb')
                cmd  = ["sudo", "dpkg", "-i", file_path]
                p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                p.wait()
                if p.returncode == 0:
                    #print("amazon-ssm-agent package has installed successfully")
                    output = p.communicate()[0]
                    pkg_status = output.decode("utf-8")

                else:
                    output, errorcode = p.communicate()
                    if errorcode:
                        error_status = errorcode.decode("utf-8")
                    #print(error_status)
                    #print("Something went wrong while manually installing amazon-ssm-agent")

            else:
                # installation command
                cmd = ["sudo", "snap", "install", "amazon-ssm-agent", "--classic"]
                p = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)
                p.wait()
                if p.returncode == 0:
                    #print("amazon-ssm-agent has Installed Successfully")
                    child = subprocess.Popen("sudo snap list | grep amazon-ssm-agent", stdout=subprocess.PIPE, shell=True)
                    output = child.communicate()[0]
                    pkg_status = output.decode("utf-8")

                else:
                    output, errorcode = p.communicate()
                    if errorcode:
                        error_status = errorcode.decode("utf-8")
                    #print(error_status)
                    #print("Something went wrong while installing amazon-ssm-agent")

        return pkg_status,error_status

    except OSError:
        print("Can't change the Current Working Directory")


def linux_ubuntu_falcon_install():
    try:
        #sudo apt list --installed | grep falcon-sensor
        # falcon-sensor/now 6.24.0-12104 amd64 [installed,local]
        pkg_status = ""
        error_status = ""
        child = subprocess.Popen("sudo apt list --installed | grep falcon-sensor", stdout=subprocess.PIPE, shell=True)
        output = child.communicate()[0]

        if "installed" in str(output.decode("utf-8")):
            pkg_status = output.decode("utf-8")
            #print("Falcon Sensor Package has already installed, ignoring...")

        else:
            depchild = subprocess.Popen("sudo apt list --installed | grep libnl-genl-3-dev", stdout=subprocess.PIPE, shell=True)
            depoutput = depchild.communicate()[0]
            deppkg_status = depoutput.decode("utf-8")

            if not deppkg_status:
                #print("Dependency package has not found. Installing")
                depcmd = ["sudo", "apt-get", "install", "-y", "libnl-genl-3-dev"]
                dp = subprocess.Popen(depcmd, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE)
                dp.wait()

                #print("Dependency package has installed")
                if dp.returncode == 0:

                    cmd  = ["sudo", "dpkg", "-i", "/tmp/falcon-sensor_6.24.0-12104_amd64.deb"]
                    p = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
                    p.wait()
                    if p.returncode == 0:
                        #print("Falcon Sensor Package Installed Successfully")
                        #print("Pls wait, bringing up services")
                        cmd_register = ['sudo', '/opt/CrowdStrike/falconctl', '-s', '-f', '--cid=EB0EF13C6EE44725BFAB1827AD937C29-8E', '--tags=CLOUD']
                        cmd_enable = ['sudo','systemctl', 'enable','falcon-sensor']
                        cmd_start = ['sudo', 'systemctl' ,'start', 'falcon-sensor']
                        p = subprocess.Popen(cmd_register)
                        p.wait()
                        p = subprocess.Popen(cmd_enable)
                        p.wait()
                        p = subprocess.Popen(cmd_start)
                        p.wait()
                        #print("Falcon service registered & started successfully.")
                        child = subprocess.Popen("sudo apt list --installed | grep falcon-sensor", stdout=subprocess.PIPE, shell=True)
                        output = child.communicate()[0]
                        pkg_status = output.decode("utf-8")

                    else:
                        output, errorcode = p.communicate()
                        if errorcode:
                            error_status = errorcode.decode("utf-8")
                        #print(error_status)
                        #print("Something went wrong while installing Falcon Sensor")
                else:
                    output, errorcode = dp.communicate()
                    if errorcode:
                        error_status = errorcode.decode("utf-8")
                    #print(error_status)
                    #print("Something went wrong while installing dependency libnl-genl-3-dev")

            else:
                output, errorcode = p.communicate()
                if errorcode:
                        error_status = errorcode.decode("utf-8")
                #print(error_status)
                #print("Something went wrong while installing Falcon Sensor")

        return pkg_status, error_status

    except Exception as e:
        print(e)

def install():
    # Call os_type Method to Identify the OS from AWS Instance only.
    os_ver, os_name = os_type()

    child  = subprocess.Popen("wget -q -O - http://169.254.169.254/latest/meta-data/instance-id",stdout=subprocess.PIPE, shell=True)
    output = child.communicate()[0]
    if output:
        inst_id = output.decode("utf-8")

    falcon_status = ""
    ssm_status = ""

    if os_ver == 'ubuntu':
        ssm_status, ssm_error_status = linux_ubuntu_pkg_install()
        falcon_status, falcon_error_status = linux_ubuntu_falcon_install()

    elif os_ver == 'centos':
        ssm_status, ssm_error_status = linux_centos_pkg_install()
        # Falcon based on os version
        os_arch = os_arch_ver()
        if os_arch == '8':
            rpm_name = "/tmp/falcon-sensor-6.14.0-11110.el8.x86_64.rpm"
        elif os_arch == '7':
            rpm_name = "/tmp/falcon-sensor-6.14.0-11110.el7.x86_64.rpm"
        elif os_arch == '6':
            rpm_name = "/tmp/falcon-sensor-6.14.0-11110.el6.x86_64.rpm"
        falcon_status, falcon_error_status = linux_centos_falcon_install(rpm_name)

    elif os_ver == 'amzn' :
        ssm_status, ssm_error_status = linux_centos_pkg_install()
        # Falcon based on os version
        os_arch = os_arch_ver('amzn')

        if os_arch == '1' or os_arch == '2016.09' or os_arch == '2017.09' or os_arch == '2018.03':
            rpm_name = "/tmp/falcon-sensor-6.24.0-12104.amzn1.x86_64.rpm"
            '''
            sudo /opt/CrowdStrike/falconctl -s -f --cid=EB0EF13C6EE44725BFAB1827AD937C29-8E --tags="CLOUD"
            sudo service falcon-sensor start
            '''
        elif os_arch == '2':
            rpm_name = "/tmp/falcon-sensor-6.14.0-11110.amzn2.x86_64.rpm"

        falcon_status, falcon_error_status = linux_centos_falcon_install(rpm_name)

    elif os_ver == 'rhel':
        ssm_status, ssm_error_status = linux_centos_pkg_install()
        # Falcon based on os version
        os_arch = os_arch_ver('rhel')
        if os_arch == '8':
            rpm_name = "/tmp/falcon-sensor-6.14.0-11110.el8.x86_64.rpm"
        elif os_arch == '7':
            rpm_name = "/tmp/falcon-sensor-6.14.0-11110.el7.x86_64.rpm"
        elif os_arch == '6':
            rpm_name = "/tmp/falcon-sensor-6.14.0-11110.el6.x86_64.rpm"

        falcon_status, falcon_error_status = linux_centos_falcon_install(rpm_name)

    else:
        #print("unable to determine the os version")
        exit(1)

    # Associate the Result in Dictionary
    pkgstatus = {
        "amazon-ssm-agent": ssm_status,
        "amazon-ssm-agent-error": ssm_error_status,
        "falcon-sensor": falcon_status,
        "falcon-sensor-error": falcon_error_status,
        "os_name": os_name,
        "instance_id": inst_id
    }
    return pkgstatus

# Boiler Plate Code
if __name__ == "__main__":
    pkgstatus = install()
    print(pkgstatus)
