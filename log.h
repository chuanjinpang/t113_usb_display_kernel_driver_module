

#ifndef __LOG_H__
#define __LOG_H__
#include <linux/kernel.h>
#if 0
#define LOGD(fmt,args...) do {}while(0)
//#define LOGD(fmt,args...) do {printk(fmt,##args);}while(0)
#define LOGI(fmt,args...) do {printk(fmt,##args);}while(0)
#else
#define LOGD(fmt,args...) do {}while(0)
#define LOGI(fmt,args...) do {}while(0)
#endif
#define LOGW(fmt,args...) do {printk(fmt,##args);}while(0)
#define LOGE(fmt,args...) do {printk(fmt,##args);}while(0)
#endif
