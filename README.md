this the kernel driver part for t113 usb display project. 
the lvgl app part is here: https://github.com/chuanjinpang/lv_port_linux_fb_udisp_t113

# how to build
just run ./build.sh
note:you should modify the cross-gcc path or build fault.

# how to run
insmod f_udisp_drv.ko
insmod usb_disp_drv.ko
start lvgl app and click the icon to run usb display demo

## 怎么在taiji-pi t113上更新ko
背景：几个月没搞了，完全忘记了怎么操作
1. build ko 后
2. screen /dev/ttyUSB0 115200进入tina
3. /etc/rc.d/S98lvgld stop 停止lvgl程序
4. rmmod f_hid f_udisp_drv usb_disp_drv 删除udisp，释放usb otg给adb
5.  ./S80adbd stop start
6. adb devices
7. adb push xx.ko /tmp
8. insmod xx.ko
9. /etc/rc.d/S98lvgld start
