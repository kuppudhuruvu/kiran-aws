import platform
import os
import urllib.request
import subprocess


def os_type():

    try:
        f = open('/etc/os-release')
        for line in f.readlines():
            l = line.split('=')
            if l[0] == 'ID':
                os_var = str(l[1].strip())
        return(os_var)

    except Exception as e:
        print(e)

def os_arch():
    detect_arch = platform.architecture()
    return detect_arch

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
        cmd = ["sudo", "yum", "install", "-y", "https://s3.amazonaws.com/ec2-downloads-windows/SSMAgent/latest/linux_amd64/amazon-ssm-agent.rpm"]
        p = subprocess.Popen(cmd)
        p.wait()
        if p.returncode == 0:
            print("Package Installed Successfully")
            cmd_enable = ['sudo','systemctl', 'enable','amazon-ssm-agent']
            cmd_start = ['sudo', 'systemctl' ,'start', 'amazon-ssm-agent']
            p = subprocess.Popen(cmd_enable)
            p.wait()
            p = subprocess.Popen(cmd_start)
            p.wait()
        else:
            print("Something went wrong")

    except OSError:
        print("Can't change the Current Working Directory")


def linux_ubuntu_pkg_install():
    try:
        #os.chdir("/tmp/")
        #url =  "https://s3.amazonaws.com/ec2-downloads-windows/SSMAgent/latest/debian_amd64/amazon-ssm-agent.deb"
        #file_path, _ = urllib.request.urlretrieve(url, 'amazon-ssm-agent.deb')
        # sudo apt list --installed | grep tmux

        child = subprocess.Popen("sudo apt list --installed | grep amazon-ssm-agent", stdout=subprocess.PIPE, shell=True)
        output = child.communicate()[0]
        if "installed" in output:
            print("Package has already installed, ignoring...")
        else:
            #installation command
            cmd = ["sudo", "snap", "install", "amazon-ssm-agent", "--classic"]
            p = subprocess.Popen(cmd)
            p.wait()
            if p.returncode == 0:
                print("Package Installed Successfully")
            else:
                print("Something went wrong")

    except OSError:
        print("Can't change the Current Working Directory")


def linux_ubuntu_falcon_install():
    try:
        #sudo apt list --installed | grep falcon-sensor
        # falcon-sensor/now 6.24.0-12104 amd64 [installed,local]

        child = subprocess.Popen("sudo apt list --installed | grep falcon-sensor", stdout=subprocess.PIPE, shell=True)
        output = child.communicate()[0]
        if "installed" in output:
            print("Package has already installed, ignoring...")

        else:
            cmd  = ["sudo", "dpkg", "-i", "./falcon-sensor_6.24.0-12104_amd64.deb"]
            p = subprocess.Popen(cmd)
            p.wait()
            if p.returncode == 0:
                print("Falcon Sensor Package Installed Successfully")
                print("Pls wait, bringing up services")
                cmd_register = ['sudo', '/opt/CrowdStrike/falconctl', '-s', '-f', '--cid=EB0EF13C6EE44725BFAB1827AD937C29-8E', '--tags="CLOUD"']
                cmd_enable = ['sudo','systemctl', 'enable','falcon-sensor']
                cmd_start = ['sudo', 'systemctl' ,'start', 'falcon-sensor']
                p = subprocess.Popen(cmd_enable)
                p.wait()
                p = subprocess.Popen(cmd_start)
                p.wait()
                print("Falcon service registered & started successfully.")
            else:
                print("Something went wrong while installing Falcon Sensor")
        
    except Exception as e:
        print(e)

def main():
    # Call os_type Method to Identify the OS from AWS Instance only.
    os_ver = os_type()

    if os_ver == '"ubuntu"' or os_ver == 'ubuntu':
        linux_ubuntu_pkg_install()
    elif os_ver == '"amzn"' or os_ver == 'amzn':
        linux_centos_pkg_install()
    elif os_ver == '"centos"' or os_ver == 'centos':
        linux_centos_pkg_install()
    elif os_ver == '"amzn"' or os_ver == 'amzn':
        linux_centos_pkg_install()
    elif os_ver == '"rhel"' or os_ver == 'rhel':
        linux_centos_pkg_install()
    else:
        print("unable to determin the os verion")
        exit(1)


# Boiler Plate Code
if __name__ == "__main__":
    main()
