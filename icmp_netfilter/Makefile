.PHONY: test

namem = icmp_filter
#namef = 

obj-m += $(namem).o

all:
		make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

rm:
		rmmod -f $(namem).ko

cli:
		make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

clean: rm cli

test:
		insmod $(namem).ko
