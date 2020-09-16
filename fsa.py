#!/usr/bin/env python3

import os
import sys
import time
import ctypes
import winreg
import shutil
import psutil
from subprocess import PIPE, run
from argparse import ArgumentParser
from configparser import ConfigParser
import win32pipe
import win32file
import win32serviceutil
import pywintypes

process_files = [
    "process\\analysis_tools.txt",
    "process\\antivirus.txt",
    "process\\other_vm.txt",
    "process\\sanboxes.txt",
    "process\\sysinternals.txt",
    "process\\virtualbox.txt",
    "process\\vmware.txt"]
registry_keys_files = [
    "registry\\other_vm.txt",
    "registry\\vmware.txt",
    "registry\\virtualbox.txt",
    "registry\\qemu.txt"]
registry_values_files = [
    "registry\\modify\\vmware.txt",
    "registry\\modify\\virtualbox.txt"]
service_files = [
    "service\\virtualbox.txt",
    "service\\vmware.txt",
    "service\\qemu.txt"]
pipe_files = ["pipe\\virtualbox.txt", "pipe\\vmware.txt", "pipe\\cuckoo.txt"]
apps_files = ["apps\\virtualbox.txt", "apps\\vmware.txt", "apps\\qemu.txt"]

dir_path = os.path.dirname(os.path.realpath(__file__))
system32path = os.environ['WINDIR'] + "\\System32\\"
driverspath = os.environ['WINDIR'] + "\\System32\\drivers\\"
dummy_process = os.environ['WINDIR'] + "\\System32\\choice.exe"
temp_directory = os.path.expanduser('~') + "\\AppData\\Local\\Temp\\"

# This is needed to access C:\windows\system32\ on Win-64 using Python-32 bit
# Otherwise, we are redirected to C:\windows\SysWOW64\
ctypes.windll.kernel32.Wow64DisableWow64FsRedirection(ctypes.byref(ctypes.c_long()))
    
if os.name != "nt":
    exit("This script only supports Windows")
if not os.path.isdir(system32path):
    exit("System32: invalid directory path")
if not os.path.isdir(driverspath):
    exit("System32\Divers: invalid directory path")
if not os.path.isfile(dummy_process):
    exit("Dummy process: file not found")
if not os.path.isdir(temp_directory):
    exit("Temp directory path is invalid")

# Verifies that PS is available
def has_powershell():
    # PS default directory
    powershell = os.environ['WINDIR'] + "\\System32\\WindowsPowerShell\\"
    if os.path.isdir(powershell):
        return

    # If PS hasn't been found, we look at the environment variables
    path_var = os.getenv('PATH')
    if path_var and len(path_var) > 2 and ";" in path_var:
        env_vars = path_var.split(";")
        for paths in env_vars:
            if "powershell" in paths.lower() and os.path.isdir(paths.lower()):
                return

    # If still unfound, we try to invoke it
    process = run(["powershell", "exit"])
    if process.returncode == 0:
        return
    else:
        exit("Is Powershell installed ?")

# Return the name of all running processes
def get_process_names():
    process_names = []
    psutil.process_iter(attrs=None, ad_value=None)
    for proc in psutil.process_iter():
        try:
            processName = proc.name()
            process_names.append(processName)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    return process_names

# Gets the memory usage of all dummy processes
def get_memory_usage(dummy_process_names):
    procs = []
    memory = 0.0
    procs = get_dummy_procs(dummy_process_names)
    for proc in procs:
        memory += float(proc.memory_info()[0]) / float(2 ** 20)
    return memory

# Terminates all dummy processes
def kill_dummy_procs(dummy_process_names):
    procs = []
    procs = get_dummy_procs(dummy_process_names)
    if len(procs) == 0:
        print("No dummy process to kill")
        
    for proc in procs:
        processID = proc.pid
        processName = proc.name()
        print("Killing dummy process '"+processName+"' PID "+str(processID))
        proc.kill()

# Returns a list containing all dummy processes
def get_dummy_procs(dummy_process_names):
    psutil.process_iter(attrs=None, ad_value=None)
    procs = []
    for proc in psutil.process_iter():
        try:
            processName = proc.name()
            absolutePath = proc.exe()
            cmd = proc.cmdline()
            if processName.lower() in map(str.lower, dummy_process_names):
                # To make sure that it is a dummy process, we verify the path
                # of the binary and the command line argument
                if temp_directory in absolutePath and len(cmd) > 1 and cmd[1] == "/N":
                    procs.append(proc)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

    print("Dummy proccesses identified: " + str(len(procs)))
    return procs

# If the current privilege isn't matching what we expect, the script exit
def requiresAdmin(requires):
    isadmin = (ctypes.windll.shell32.IsUserAnAdmin() == 1)
    if requires and not isadmin:
        exit("Must be running with elevated privileges to do this!")
    elif not requires and isadmin:
        exit("Must not be running with elevated privileges to do this!")

# Copies the dummy_process to the temp_directory then,
# Starts it using PowerShell to hide the window and to create an independent process
def create_dummy_proc(processe_names):
    has_powershell()
    running_process_names = get_process_names()
    already_running = 0

    print("Starting dummy processes ...")

    for process in processe_names:
        if not process.lower() in map(str.lower, running_process_names):
            if not os.path.isfile(temp_directory + "\\" + process):
                shutil.copy(dummy_process, temp_directory + "\\" + process)               
            os.system("powershell Start-Process "+temp_directory+"\\"+process+" -WindowStyle Hidden -ArgumentList '/N'")
        else:
            already_running += 1

    print(str(already_running) + " process already started")
    print(str(len(processe_names) - already_running) + " process started")
    print(str(get_memory_usage(processe_names)) + " MB used by all dummy processes")

def read_files(file_name_list):
    lines = []
    for item in file_name_list:
        if not (os.path.isfile(dir_path + "\\" + item)):
            exit("File " + item + " not found ")

        with open(dir_path + "\\" + item) as file:
            for line in file:
                if "#" not in line and len(line) > 0 and len(line) < 300 and line not in lines:
                    lines.append(line.rstrip())
    return lines

# Verifies if a key is already in the registry
def is_entry_in_registry(aReg, key):
    try:
        aKey = winreg.OpenKey(aReg,key,0,winreg.KEY_READ | winreg.KEY_WOW64_64KEY)
        winreg.CloseKey(aKey)
    except FileNotFoundError:
        return False
    except Exception as e:
        exit("Error reading the registry: " + str(e))
    else:
        return True

# Creates the dummy registry values in HKLM
def modify_registry_entry(dummy_registry_values):
    values_created = 0
    values_present = 0

    for value in dummy_registry_values:
        if len(value) > 4 and value[:4] == "HKLM" and value.count(',') > 1:
            key, subkey, value = value.split(",", 2)
            value = value.strip()
            key = '\\'.join(key.split("\\")[1:])
            
            handle = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,key,0,winreg.KEY_ALL_ACCESS | winreg.KEY_WOW64_64KEY)

            # Get information on the current value of the subkey
            try:
                current_values, data_type = winreg.QueryValueEx(handle, subkey)
            except Exception as e:
                # The subkey doesn't exist, we need to create it
                if "[WinError 2]" in str(e):
                    winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,key,0,winreg.KEY_CREATE_SUB_KEY | winreg.KEY_WOW64_64KEY)
                    current_values = ""
                    data_type = winreg.REG_SZ
                else:
                    print("Error querying subkey: " + subkey + " " + str(e))

            # If the current value is already set to the dummy value
            if value in current_values:
                values_present += 1
            else:
                # REG_MULTI_SZ is expected, we need to construct a list with the string
                if data_type == 7:
                    dummy_list = []
                    dummy_list.append(value)
                    value = dummy_list
                try:
                    winreg.SetValueEx(handle, subkey, 0, data_type, value)
                    values_created += 1
                except Exception as e:
                    print("Error modifying registry entry: "+key+" : "+subkey+" "+str(e))
                    
            winreg.CloseKey(handle)
        else:
            exit("Only HKLM registry keys are supported. Invalid registry value in file: "+value)

    print(str(values_created)+" values modified, "+str(values_present)+" values already present")

# Creates the registry keys in HKLM
def create_registry_entry(dummy_registry_keys):
    aReg = winreg.ConnectRegistry(None, winreg.HKEY_LOCAL_MACHINE)
    keys_created = 0
    keys_present = 0

    for entry in dummy_registry_keys:
        if len(entry) < 4 or entry[:4] != "HKLM" or ":" in entry or "\\" not in entry:
            exit("Only HKLM registry keys are supported. Invalid registry keys in file: "+entry)
        else:
            entry = '\\'.join(entry.split("\\")[1:])
            if not is_entry_in_registry(aReg, entry):
                try:
                    # The flag KEY_WOW64_64KEY is needed when using Python-32 bit
                    winreg.CreateKeyEx(aReg,entry,0,access=winreg.KEY_WOW64_64KEY)
                    keys_created += 1
                except Exception as e:
                    print("Failed to create the registry key: "+entry+" "+str(e))
            else:
                keys_present += 1

    print(str(keys_created)+" keys created, "+str(keys_present)+" keys already present")

# Check if a named pipe exist by connecting to it
def is_pipe_running(pipe_name):
    try:
        handle = win32file.CreateFile(
            pipe_name,
            win32file.GENERIC_READ,
            0,
            None,
            win32file.OPEN_EXISTING,
            0,
            None)
    except pywintypes.error as e:
        if e.args[0] == 2:
            return False
        if e.args[0] == 231:
            return True
        else:
            exit("Error validating the status of the pipe: " + str(e))
    return True

# Sends a command to the named pipes server to stop it
def stop_pipes(pipe_names):
    # If the pipes were create few seconds ago, this exception may be raised:
    # 'All pipe instances are busy.'
    time.sleep(2)

    pipes_to_kill = []
    for pipe_name in pipe_names:
        # If the pipe is running
        if is_pipe_running(pipe_name):
            pipes_to_kill.append(pipe_name)

    if len(pipes_to_kill) > 0:
        print("Killing " + str(len(pipes_to_kill)) + " pipes")
        for pipe_name in pipes_to_kill:
            try:
                # Connecting to the pipe
                handle = win32file.CreateFile(
                    pipe_name,
                    win32file.GENERIC_WRITE,
                    0,
                    None,
                    win32file.OPEN_EXISTING,
                    0,
                    None)

                # Sending *STOP*. This is the special keyword expected by the
                # server to break out of the while True loop
                win32file.WriteFile(handle, str.encode("*STOP*"))
                win32file.CloseHandle(handle)

            except pywintypes.error as e:
                exit("Error while killing the pipes, wait few seconds and retry.")

        # Wait for the pipe server to terminate
        time.sleep(2)

        # Confirm that the pipes are no longer running
        still_running = False
        for pipe_name in pipes_to_kill:
            if is_pipe_running(pipe_name):
                print("Error killing a pipe")
                still_running = True
        if not still_running:
            print("Successfully killed " + str(len(pipes_to_kill)) + " pipes")
    else:
        print("No pipes to kill !")

# Starts the pipe server (dummy_pipe.py) using PowerShell to hide the window and to create an independent process
# Each pipes will then run in their thread, in this new Python process
def create_named_pipes(pipe_names):
    if not os.path.isfile(dir_path + "\\dummy_pipe.py"):
        exit("dummy_pipe.py not found !")
        
    has_powershell()
    arguments = ""
    
    for pipe_name in pipe_names:
        if "\\\\.\\pipe\\" not in pipe_name:
            exit("Invalid pipe name: " + pipe_name)
        else:
            if not is_pipe_running(pipe_name):
                arguments += pipe_name + " "

    arguments = arguments.strip()
    if len(arguments) > 0:
        print("Creating " + str(len(arguments.split(" "))) + " pipes")
        os.system("powershell Start-Process "+dir_path +"\\dummy_pipe.py -WindowStyle Hidden -ArgumentList '"+arguments +"'")
    else:
        print("All pipes are already started")
        return

    # Wait for the pipes to be created
    time.sleep(3)

    # Validates the status of the pipes
    for pipe_name in pipe_names:
        if not is_pipe_running(pipe_name):
            exit("Error creating the pipes")

    print(str(len(pipe_names)) + " pipes now running")

# When uninstalling the service, we want to make sure first that it is a dummy service
# To make sure of that, we validate the binary name (dummy-win-service_x64.exe)
def is_dummy_service(service_name):
    try:
        service_path = psutil.win_service_get(service_name).binpath()
        return "dummy-win-service_x64.exe" in service_path
    except Exception as e:
        return False

# Returns True if the Windows service exist
def is_service(service_name):
    try:
        service = psutil.win_service_get(service_name)
        return True
    except Exception as e:
        return False

# Start or Stop a Windows service given its name
def start_stop_service(service_name, action):
    try:
        if action == "start":
            win32serviceutil.StartService(service_name)
            return True
        elif action == "stop":
            win32serviceutil.StopService(service_name)
            return True
    except Exception as e:
        print("Error while trying to "+action+" the service " +service_name+": "+str(e))
        return False

# Creates folders and dummy files
def create_apps_artifact(apps):
    # Artifacts to create
    folders = []
    files = []
    folders_already_created = 0
    files_already_created = 0

    # This is needed to access C:\windows\system32\ on Win-64 using Python-32 bit
    # Otherwise, the files are going to be written in C:\windows\SysWOW64\
    ctypes.windll.kernel32.Wow64DisableWow64FsRedirection(ctypes.byref(ctypes.c_long()))

    for element in apps:
        if element[0] == "%" and "%" in element[1:]:
            # Environment variable used, resolving and replacing it
            try:
                variable = element[0:element.find("%", 1) + 1]
                clean_variable = variable.replace("%", "").replace(" ", "")
                if variable == "%SYSTEM32%":
                    element = element.replace(variable, system32path)
                elif variable == "%DRIVERS%":
                    element = element.replace(variable, driverspath)
                else:
                    element = element.replace(
                        variable, os.environ[clean_variable])
            except Exception as e:
                exit("Couldn't resolve variable: " + variable)

        element = element.replace("\\\\", "\\")

        # This is a directory to create
        if element.endswith("\\"):
            if not os.path.isdir(element):
                folders.append(element)
                os.makedirs(element)
            else:
                folders_already_created += 1
        else:
            # If the path doesn't end with a "\", it must be a file
            if not os.path.isfile(element):
                files.append(element)
            else:
                files_already_created += 1

    # We need to create the files in a second loop because the folder(s) might not have been created before
    for file in files:
        # If the folder for that file hasn't been created, we create it
        folder = file[0:file.rfind("\\")]
        if not os.path.isdir(folder):
            os.makedirs(folder)
        with open(file, 'w') as dummyfile:
            dummyfile.write("inoculate")

    print("Creating "+str(len(folders))+" folders ("+str(folders_already_created)+" already created) and "+
          str(len(files))+" files ("+str(files_already_created)+" already created)")

# This function calls dummy-win-service_x64.exe to install/uninstall dummy services
# The dummy service is a binary compiled in GO from this project: https://github.com/kardianos/service
def manage_services(service_names, action):
    if not os.path.isfile(dir_path + "\\dummy-win-service_x64.exe"):
        exit("dummy-win-service_x64.exe not found !")
    if not action == "install" and not action == "uninstall":
        exit("Arguments error")

    services_to_manage = []
    for dummy_service in service_names:
        if "," not in dummy_service:
            exit("Error reading the service names")
        service_name, service_display_name = dummy_service.split(",")

        if action == "install":
            # We need to install this service, and it hasn't been installed before
            if not is_service(service_name):
                services_to_manage.append(dummy_service)
        else:
            # We need to uninstall this service, and it has been installed
            if is_service(service_name) and is_dummy_service(service_name):
                services_to_manage.append(dummy_service)

    if len(services_to_manage) > 0:
        print(action + "ing " + str(len(services_to_manage)) + " services")
        for service in services_to_manage:
            service_name, service_display_name = service.split(",")
            if action == "uninstall":
                # Stop the service before uninstalling
                if start_stop_service(service_name, "stop"):
                    print("Successfully stopped the service: "+service_display_name)

            # Run the dummy service binary
            # To install/uninstall: dummy-win-service_x64.exe /{install,uninstall} 'service name' 'service display name'
            command = [dir_path + "\\dummy-win-service_x64.exe","/" + action, service_name, service_display_name]
            result = run(command,stdout=PIPE,stderr=PIPE,universal_newlines=True)
          
            if result.returncode != 0:
                exit("Error while executing dummy-win-service_x64.exe : "+str(result.stderr))
            else:
                if "nstall Successful" in result.stdout or "nstall Successful" in result.stderr:
                    if action == "install":
                        # After a successful installation, we confirm the presence of the service and start it
                        if is_service(service_name):
                            print("Successfully installed the service: "+service_display_name)
                            if start_stop_service(service_name, "start"):
                                print("Successfully Started the service: "+service_display_name)
                    else:
                        print("Successfully uninstalled the service: "+service_display_name)
                else:
                    exit("Error during the "+action+" of the service: "+result.stderr+" - "+result.stdout)
    else:
        print("No services to " + action + " !")

def main():
    parser = ArgumentParser(usage="fsa.py [options]:\n",
        description="Fake Sandbox Artifact is a script that helps you create artifacts related to malware analysis lab environment and virtualization systems")
    parser.add_argument("--registry", action="store_true", help="Creates artifacts in the registry. Requires elevated privileges")
    parser.add_argument("--application", action="store_true", help="Creates files and folders specified in the text files. Requires elevated privileges")
    parser.add_argument("--pipe", choices=["start","stop"], help="Starts the dummy pipe server (dummy_pipe.py)")
    parser.add_argument("--process", choices=["start","stop"], help="Start the dummy processes")
    parser.add_argument("--service", choices=["install","uninstall"], help="Install and start dummy services using dummy-win-service_x64.exe. Requires elevated privileges")
    options = parser.parse_args()

    if len(sys.argv) == 1:
        parser.print_help()
        exit(1)

    if options.registry:
        requiresAdmin(True)
        create_registry_entry(read_files(registry_keys_files))
        modify_registry_entry(read_files(registry_values_files))

    if options.application:
        requiresAdmin(True)
        create_apps_artifact(read_files(apps_files))

    if options.pipe:
        requiresAdmin(False)
        if options.pipe == "start":
            create_named_pipes(read_files(pipe_files))
        else:
            stop_pipes(read_files(pipe_files))

    if options.service:
        requiresAdmin(True)
        manage_services(read_files(service_files), options.service)

    if options.process:
        requiresAdmin(False)
        if options.process == "start":
            create_dummy_proc(read_files(process_files))
        else:
            kill_dummy_procs(read_files(process_files))
            
if __name__ == "__main__":
    main()
