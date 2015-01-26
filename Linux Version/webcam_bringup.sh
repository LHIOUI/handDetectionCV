#!/bin/bash

echo -ne "This script is used to reload the kernel module for UVC video webcam, in case it is not detected first time\n"
echo -ne "Run script as root\n"

rmmod uvcvideo
modprobe uvcvideo
echo $?
ls /dev/video*
