#!/bin/bash

if [[ $# < 1 ]]; then
    echo "$0 load|unload|reload|setpid <pid>";
    exit 0;
fi

build_dir="Build/Debug"
kext_name=test.kext
command="$1"

case $command in

"load")
    chown -R root $build_dir/$kext_name
    chgrp -R wheel $build_dir/$kext_name
    kextutil $build_dir/$kext_name
;;

"unload")
    sysctl -w debug.killhook.unhook=1
    kextunload -b acme.test
;;

"reload")
    sysctl -w debug.killhook.unhook=1
    kextunload -b acme.test
    chown -R root $build_dir/$kext_name
    chgrp -R wheel $build_dir/$kext_name
    kextutil $build_dir/$kext_name
;;

"setpid")
    sysctl -w debug.killhook.pid=$2
;;
esac