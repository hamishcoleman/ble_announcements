Helpers to allow listening for BLE advertisements and showing the data.


== Quick and dirty start

The current script started as a quick proof of concept and the specific steps
are still being worked on.  So this is more of a suggested guide right now:

On a raspberry PI with built-in bluetooth (tested on a rpi v3)

- sudo apt install python3-bluez
- systemctl stop bluetooth
- hciconfig hci0 up
- btmgmt le on
- ./ble_listen.pl

There may be one other step needed to put the adaptor into the correct mode
but more clean-slate testing is needed to prove this.

The hope is that all the required steps can be folded into the script to make
it more seamless.
