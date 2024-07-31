######################################
#
#    RoboPeak USB LCD Display Linux Driver
#    
#    Copyright (C) 2009 - 2013 RoboPeak Team
#    This file is licensed under the GPL. See LICENSE in the package.
#
#    http://www.robopeak.net
#
#    Author Shikai Chen
#
######################################


DRIVER_NAME := usb_disp_drv
KERNEL_SOURCE_DIR ?= /home/taiji/tina-sdk/lichee/linux-5.4

EXTRA_CFLAGS +=-g -I$(PWD)/src -I$(PWD)/../common

obj-m := $(DRIVER_NAME).o
obj-m += f_udisp_drv.o
DRIVER_FILES := udisp_drv.o 

$(DRIVER_NAME)-objs:= $(DRIVER_FILES)
f_udisp_drv-objs := f_udisp.o f_ss.o                    
modules:
	$(MAKE) -C $(KERNEL_SOURCE_DIR) KCPPFLAGS="$(EXTRA_CFLAGS)" M=$(PWD) modules

modules_install:
	$(MAKE) -C $(KERNEL_SOURCE_DIR) M=$(PWD) modules_install

install: modules_install

clean:
	$(MAKE) -C $(KERNEL_SOURCE_DIR) M=$(PWD) clean
