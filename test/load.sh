#!/bin/bash

sudo sysctl -w debug.killhook.unhook=1
sudo kextunload -b acme.test
sudo chown -R root test.kext
sudo chgrp -R wheel test.kext
sudo kextutil test.kext
