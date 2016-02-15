#! /usr/bin/python

# written by Vijayaditya Peddinti

# important note: dont modify the shebang as /usr/bin/env python launches processes
# with the name python which makes killall ineffective

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
import logging
import syslog

from logging.config import fileConfig

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

handler = logging.StreamHandler()
handler.setLevel(logging.INFO)
handler.setFormatter(formatter)
logger.addHandler(handler)

file_handler = logging.FileHandler("/var/log/gpu_killer.log")
file_handler.setLevel(logging.INFO)
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

logger.info('Starting gpu_killer.py')

def getUserName(pid):
    try:
        proc_stat_file = os.stat("/proc/%d" % pid)
        # get UID via stat call
        uid = proc_stat_file.st_uid
        # look up the username from uid
        username = pwd.getpwuid(uid)[0]

        return username
    except OSError:
        return

def handleError(err):
    if (err.value == NVML_ERROR_NOT_SUPPORTED):
        return "N/A"
    else:
        return err.__str__()

def getGpuReservationFromQueue():
    proc = subprocess.Popen("qstat -r -q *.q@$HOSTNAME.clsp.jhu.edu|egrep '(^[0-9]|gpu=)'|grep gpu= -B1|grep '^[0-9]'|awk '{print $4}'",
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE)
    [stdout_value, stderr_value] = proc.communicate()
    if len(stderr_value.strip()) != 0:
        logger.warning("qstat returned an error \n{0}".format(stderr_value))
        return
        # we could have checked proc.returncode, but the return code is reset 
        # by the last command in the pipe so the errorcode of qstat will be reset
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
    try:
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
    except (IOError, OSError):
        # the process file is missing, probably it died before we got to i so lets just return None
        return
        
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

def sendMail(message, notify_email, user_email = None):
    subprocess.Popen('echo "{message}" | mail -s "gpu_killer.py triggered on {hostname} " {user_email} {notify_email}'.format(
	message = message,
	hostname = socket.gethostname(),
        user_email = user_email if user_email is not None else '', 
        notify_email = notify_email), shell=True)

def killProcess(pid, notify_email):
    process_info = getProcessInfo(pid)
    if process_info is None:
        logger.warning("Tried to kill the process with id {0}, but couldn't find its info. So assuming it got killed.".format(pid))
        return

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
    logger.info("Notifications sent to {0}, {1}".format(email, notify_email))
    sendMail(message, notify_email, user_email)

def verifyUsage(process_ids, notify_email):
    usage_per_user = getGpuReservationFromQueue()
    if usage_per_user is None:
        # there was an error while querying SGE using qstat
        return False

    for pid in process_ids:
        user_name = getUserName(pid)
        if user_name is None:
            # the process was done before we looked up the getUserName
            continue

        try:
            usage_per_user[user_name] += -1
            if usage_per_user[user_name] < 0:
                # the Qstat command returns lesser number of GPU reservations than being used by the user
                killProcess(pid, notify_email)
        except KeyError:
            # Qstat command returns no GPU reservations for this user
            killProcess(pid, notify_email)
    return True

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
                is_success = verifyUsage(current_pids, notify_email)
                if not is_success:
                    # there was an error while verifying usage
                    # so sleep and rerun the loop
                    logger.warning("verifyUsage() did not succeed, probably due to qstat failure. So sleeping for 10 seconds before querying again")
                    time.sleep(10)

            previous_pids = current_pids
            time.sleep(query_interval)

    except NVMLError as err:
        raise Exception(err.__str__())

    nvmlShutdown()

def sendDeathMail(notify_email):
	sendMail(' gpu_killer died on {hostname}. Please check /var/log/messages and /var/log/gpu_killer.log for details.'.format(hostname = socket.gethostname()), notify_email)

if __name__ == "__main__":
    notify_email = None
    try:
        parser = argparse.ArgumentParser(description="Monitors GPU usage and kills jobs which use GPUs without reserving one with the SGE master.")
        parser.add_argument("--query-interval", type=int, default=2,
                             help="The time between two queries of GPU state (in seconds)")
        parser.add_argument("--notify-email", type=str, help = "Email which will be notified when a process is killed. This is typically the cluster admin email-id", required=True)
        
        args = parser.parse_args()
        notify_email = args.notify_email
        
        if args.query_interval < 1:
            raise Exception('Please use query interval of at least one second')

        DeviceQuery(args.notify_email, args.query_interval)

    except Exception as e:
        syslog.syslog("Dying due to exception {0}\n".format(str(e)))
	logger.info(str(e))
        if notify_email is not None:
            # this check is necessary as there can be cases where even args might not have been defined before raising the error
    	    sendDeathMail(notify_email)	
	traceback.print_exc()
        raise e
    except BaseException as e :
        # this is the parent class of exception and includes SIG* signals
        syslog.syslog("Dying due to error number '{0}'\n".format(e))
	logger.info(str(e))
        if notify_email is not None:
            # this check is necessary as there can be cases where even args might not have been defined before raising the error
        	sendDeathMail(notify_email)
	traceback.print_exc()
        raise e
