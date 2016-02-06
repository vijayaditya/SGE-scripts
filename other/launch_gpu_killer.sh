#!/bin/bash -u

notification_email=$1 # email id which will receive the email when a process is killed, along the user whose process is killed
# in case there is no email specified in the users gecos field only this email-id will receive the email

query_interval=$2 # interval for checking the GPU status using nvidia-smi, in seconds
# check if the required libraries are present
python -c "from pynvml import *"

if [ $? -ne 0 ]; then 
  echo "Please install nvidia-ml-py available in PYPI."
  echo " This can be done using the following command:"
  echo " pip install nvidia-ml-py"
  exit 1
fi

# run the script
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

#sudo $DIR/gpu_killer.py --query-interval $query_interval $notification_email
$DIR/gpu_killer.py --query-interval $query_interval $notification_email

if [ $? -ne 0 ]; then
  echo "gpu_killer.py died due to an error on $HOSTNAME. If this is a non-GPU message ignore this mail. If not please restart the process." | \
    mail -s "gpu_killer.py died on $HOSTNAME" $notification_email
  exit 1
fi
