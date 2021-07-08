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
        cmd = ["yum", "install", "-y", "https://s3.amazonaws.com/ec2-downloads-windows/SSMAgent/latest/linux_amd64/amazon-ssm-agent.rpm"]
        p = subprocess.Popen(cmd)
        p.wait()
        if p.returncode == 0:
            print("Package Installed Successfully")
            cmd_enable = ['systemctl', 'enable','amazon-ssm-agent']
            cmd_start = ['systemctl' ,'start', 'amazon-ssm-agent']
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
        os.chdir("/tmp/")
        url =  "https://s3.amazonaws.com/ec2-downloads-windows/SSMAgent/latest/debian_amd64/amazon-ssm-agent.deb"
        file_path, _ = urllib.request.urlretrieve(url, 'amazon-ssm-agent.deb')
        
        #installation command
        cmd = ['dpkg','-i','amazon-ssm-agent.deb']
        p = subprocess.Popen(cmd)
        p.wait()
        if p.returncode == 0:
            print("Package Installed Successfully")
            
        else:
            print("Something went wrong")

    except OSError:
        print("Can't change the Current Working Directory")


def main():
    # Call os_type Method to Identify the OS from AWS Instance only.
    os_ver = os_type()

    if os_ver == '"ubuntu"':
        linux_ubuntu_pkg_install()
    elif os_ver == '"amzn"':
        linux_centos_pkg_install()
    elif os_ver == '"centos"':
        linux_centos_pkg_install()
    else:
        print("unable to determin the os verion")
        exit(1)


# Boiler Plate Code
if __name__ == "__main__":
    main()
