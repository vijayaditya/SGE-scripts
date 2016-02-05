#!/usr/bin/env python


# written by Vijayaditya Peddinti

# requires installation of nvidia-ml-py
# e.g. install using pip:
#           pip install nvidia-ml-py

from pynvml import *
import datetime
import os
import pwd
import subprocess
import time
import argparse
import re
import socket 
import signal

def getUserName(pid):
    proc_stat_file = os.stat("/proc/%d" % pid)
    # get UID via stat call
    uid = proc_stat_file.st_uid
    # look up the username from uid
    username = pwd.getpwuid(uid)[0]

    return username

def handleError(err):
    if (err.value == NVML_ERROR_NOT_SUPPORTED):
        return "N/A"
    else:
        return err.__str__()

def getGpuReservationFromQueue():
    proc = subprocess.Popen("qstat -r -q *.q@$HOSTNAME.clsp.jhu.edu|egrep '(^[0-9]|gpu=)'|grep gpu= -B1|grep '^[0-9]'|awk '{print $4}'", shell=True, stdout=subprocess.PIPE)
    stdout_value = proc.communicate()[0]
    usernames = stdout_value.split()
    usage_per_user = {}
    for username in usernames:
        try:
            usage_per_user[username] += 1
        except KeyError:
            usage_per_user[username] = 1
    return usage_per_user


# Example content of /proc/pid/status file
"""
                Name:   nnet3-chain-tra
                State:  R (running)
                Tgid:   10189
                Pid:    10189
                PPid:   10061
                TracerPid:      0
                Uid:    60575   60575   60575   60575
                Gid:    21      21      21      21
                FDSize: 256
                Groups: 21 20072 20870
                VmPeak: 344539448 kB
                VmSize: 344392340 kB
                VmLck:         0 kB
                VmPin:         0 kB
                VmHWM:    414484 kB
                VmRSS:    356508 kB
                VmData: 344290372 kB
                VmStk:       148 kB
                VmExe:     12152 kB
                VmLib:     52856 kB
                VmPTE:       908 kB
                VmSwap:        0 kB
                Threads:        2
                SigQ:   4/2325942
                SigPnd: 0000000000000000
                ShdPnd: 0000000000000000
                SigBlk: 0000000000000000
                SigIgn: 0000000000000000
                SigCgt: 0000000180000000
                CapInh: 0000000000000000
                CapPrm: 0000000000000000
                CapEff: 0000000000000000
                CapBnd: ffffffffffffffff
                Cpus_allowed:   ffff,ffffffff
                Cpus_allowed_list:      0-47
                Mems_allowed:   00000000,00000003
                Mems_allowed_list:      0-1
                voluntary_ctxt_switches:        1301
                nonvoluntary_ctxt_switches:     882
"""

def getProcessInfo(pid):
    info = {}
    info['pid'] = pid
    for ln in open('/proc/{0}/status'.format(pid)):
        if ln.startswith('Name:'):
            info['process_name'] = ln.split()[1]
        if ln.startswith('Uid:'):
            uid = int(ln.split()[1])
            uinfo = pwd.getpwuid(uid)
            #Sample uinfo object:
            #pwd.struct_passwd(pw_name='vpeddinti', pw_passwd='Fc4Ks3watLhcw', pw_uid=60575, pw_gid=21, pw_gecos='Vijayaditya Peddinti,323, Hackerman,p.vijayaditya@gmail.com', pw_dir='/home/vpeddinti', pw_shell='/bin/bash')
            info['user_name'] = uinfo.pw_name
            info['email'] = parseGecosForEmail(uinfo.pw_gecos)

    return info

def parseGecosForEmail(gecos_field):
    #pw_gecos='John Doe,323, Hackerman,pv@gmail.com'
    fields = gecos_field.split(',')
    email = None
    email_pattern = re.compile('[-a-zA-Z_0-9-\.]+@[-a-zA-Z0-9\.]')
    for field in fields:
        match_object = email_pattern.search(field)
        if match_object is not None:
            email = field
            break
    return email 

def killProcess(pid, notify_email):
    process_info = getProcessInfo(pid) 
    message = """Killing process: PID {0},
    name {1},
    username {2},
    user-email {3},
    as it was using a GPU without reserving
    one with the queue-master\n""".format(process_info['pid'],
            process_info['process_name'],
            process_info['user_name'],
            process_info['email'])
    email = process_info['email']
    if email is None:
        email = ''
    
    os.kill(pid, signal.SIGTERM)

    # send an email to user whose process was killed and an additional email_id (e.g. admin)
    subprocess.Popen('echo "{0}" | mail -s "gpu_killer.py triggered on {1} " {2} {3}'.format(message, socket.gethostname(), email, notify_email), shell=True)

def verifyUsage(process_ids, notify_email):
    usage_per_user = getGpuReservationFromQueue()

    for pid in process_ids:
        user_name = getUserName(pid)
        try:
            usage_per_user[user_name] += -1
            if usage_per_user[user_name] < 0:
                # the Qstat command returns lesser number of GPU reservations than being used by the user
                killProcess(pid, notify_email)
        except KeyError:
            # Qstat command returns no GPU reservations for this user
            killProcess(pid, notify_email)

def DeviceQuery(notify_email, query_interval = 2):
    try:
        nvmlInit()
        deviceCount = nvmlDeviceGetCount()
        previous_pids = []
        while True:
            current_pids = []
            for i in range(0, deviceCount):
                handle = nvmlDeviceGetHandleByIndex(i)
                
                try:
                    procs = nvmlDeviceGetComputeRunningProcesses(handle)
                 
                    for p in procs:
                        current_pids.append(p.pid)
                
                except NVMLError as err:
                    raise Exception(handleError(err))

            if current_pids != previous_pids:
                verifyUsage(current_pids, notify_email)
            previous_pids = current_pids
            time.sleep(query_interval)

    except NVMLError as err:
        raise Exception(err.__str__())

    nvmlShutdown()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Monitors GPU usage and kills jobs which use GPUs without reserving one with the SGE master.")
    parser.add_argument("--query-interval", type=int, default=2,
                         help="The time between two queries of GPU state (in seconds)")
    parser.add_argument("notify_email", type=str, help = "Email which will be notified when a process is killed. This is typically the cluster admin email-id")
    
    args = parser.parse_args()
    
    if args.query_interval < 1:
        raise Exception('Please use query interval of at least one second')

    DeviceQuery(args.notify_email, args.query_interval)