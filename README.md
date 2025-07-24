Helpers to allow listening for BLE advertisements and showing the data.

Tested and known to work on:
- Raspberry PI v3 with its built-in bluetooth
- A random "TP-Link UB500 Adapter"

## Quick and dirty start

The current script started as a quick proof of concept and the specific steps
are still being worked on.  So this is more of a suggested guide right now:

- sudo apt install python3-bluez
- ./ble_listen.py

If the bluetooth daemon is running, it can conflict with this script:
- systemctl stop bluetooth

If the bluetooth daemon is not running, the bluetooth adaptor may need to be
started to allow bluetooth to work properly
- hciconfig hci0 up

## sending data to influx

Simple:

```
./bthome2influx.py --influxdsn influxdb://hostname:port --db example
```

With config:
```
./bthome2influx.py --config mysite.conf
```

See [example config file](bthome2influx.example.conf)

## Compatible hardware

### Xiaomi Mijia

This software should work with any device sending bthome announcements, but
was originally written with the
[Xiaomi Mijia](https://pvvx.github.io/ATC_MiThermometer/) as the test hardware.

Devices with newer firmware from the factory may need an alternate method to
perform the OTA firmware flash:

- Download the [latest bthome firmware](https://github.com/pvvx/ATC_MiThermometer/tree/master/bin)
- Use the atc1441 flasher page https://atc1441.github.io/TelinkFlasher.html

If all else fails, it is also possible to disassemble the device and use a
serial firmware flash tool.
