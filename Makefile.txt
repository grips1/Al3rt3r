obj-m += Al3rt3r.o

KDIR := /usr/src/linux-headers-$(shell uname -r)
PWD := $(shell pwd)

all:
    $(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
    $(MAKE) -C $(KDIR) M=$(PWD) clean
