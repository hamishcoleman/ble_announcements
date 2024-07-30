Helpers to allow listening for BLE advertisements and showing the data.


== Quick and dirty start

The current script started as a quick proof of concept and the specific steps
are still being worked on.  So this is more of a suggested guide right now:

On a raspberry PI with built-in bluetooth (tested on a rpi v3)

- sudo apt install python3-bluez
- ./ble_listen.py

If the bluetooth daemon is running, it can conflict with this:
- systemctl stop bluetooth

If the bluetooth daemon is not running, the bluetooth adaptor may need to be
started to allow bluetooth to work properly
- hciconfig hci0 up
