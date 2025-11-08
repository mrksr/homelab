# Socat

I run Socat on a Raspberry Pi to funnel my Zigbee antenna to Home Assistant running in the basement.
Steps to get things set-up:

1. I installed `socat` and `vlan` on the Raspberry Pi and enabled the required `modules`.
1. I set-up the correct VLAN with `nmtui`.
1. I added the `socat` service to `/etc/systemd/system` and enabled them for the USB device, which is probably `ttyUSB0`.
1. zigbee2mqtt can connect to remote USB dongles via `port: tcp://<RPI-IP>:1234`
1. I enabled the watchdog for zigbee2mqtt since socat sometimes looses connection.
