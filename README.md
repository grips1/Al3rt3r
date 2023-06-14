# Al3rt3r
 A fairly straightforward Loadable Kernel Module that detectes different Nmap scans (SYN, XMAS, FIN & NULL).
 
 # Usage
 You must compile the code yourself with the provided makefile.
Make sure to have the KDIR variable set to your kernel headers directory.
(If you don't have it use `apt install linux-headers-$(uname -r)`. This can vary from different distros, for example on RaspbianOS you'll need to use the package `raspberrypi-kernel-headers)`
After linking the kernel headers directory, enter `make` inside the Al3rt3r's installation directory(where Makefile is).
If all went according to plan, you should be able to insert the LKM like so:
 `sudo insmod Al3rt3r.ko`
 and follow alerts/errors via `sudo dmesg --follow`

# Removal
In order to remove the LKM, input:
`sudo rmmod Al3rt3r`.