# Al3rt3r
 A fairly straightforward Loadable Kernel Module that detectes different Nmap scans (SYN, XMAS, FIN & NULL).
 
 # Usage
 You must compile the code yourself with the provided makefile, make sure to have the KDIR variable set to your kernel source directory.(If you don't have it, apt install linux-source-$(uname -r) or according to your own Distro.
After linking the kernel source directory correctly, enter `make` inside the Al3rt3r directory.
If all went according to plan, you should be able to insert the LKM like so:
 `sudo insmod Al3rt3r.ko`
 Follow alerts/errors via `sudo dmesg --follow`

# Removal
In order to remove the LKM, input:
`sudo rmmod Al3rt3r`.
