this the kernel driver part for t113 usb display project. 
the lvgl app part is here: https://github.com/chuanjinpang/lv_port_linux_fb_udisp_t113

# how to build
just run ./build.sh
note:you should modify the cross-gcc path or build fault.

# how to run
insmod f_udisp_drv.ko
insmod usb_disp_drv.ko
start lvgl app and click the icon to run usb display demo
