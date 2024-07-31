// SPDX-License-Identifier: GPL-2.0+
/*
 * f_loopback.c - USB peripheral loopback configuration driver
 *
 * Copyright (C) 2003-2008 David Brownell
 * Copyright (C) 2008 by Nokia Corporation
 */

/* #define VERBOSE_DEBUG */

#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/device.h>
#include <linux/module.h>
#include <linux/err.h>
#include <linux/usb/composite.h>
#include <linux/kfifo.h>
#include <linux/kthread.h>
#include "udisp.h"
#include "u_f.h"
#include "log.h"


long get_os_us(void)
{
    struct timespec64  ts;
    ktime_get_coarse_real_ts64(&ts);
    return ts.tv_sec * 1000000 + ts.tv_nsec / 1000;
}

/*********fps***********/
#define FPS_STAT_MAX 32
typedef struct {
    long tb[FPS_STAT_MAX];
    int cur;
    long last_fps;
} fps_mgr_t;
fps_mgr_t fps_mgr = {
    .cur = 0,
    .last_fps = -1,
};
long get_fps(void)
{
    fps_mgr_t * mgr = &fps_mgr;
    if(mgr->cur < FPS_STAT_MAX)//we ignore first loop and also ignore rollback case due to a long period
        return mgr->last_fps;//if <0 ,please ignore it
   else {
	int i=0;
	long b=0;
        long a = mgr->tb[(mgr->cur-1)%FPS_STAT_MAX];//cur
	for(i=2;i<FPS_STAT_MAX;i++){
	
        b = mgr->tb[(mgr->cur-i)%FPS_STAT_MAX]; //last
	if((a-b) > 1000000)
		break;
	}
        b = mgr->tb[(mgr->cur-i)%FPS_STAT_MAX]; //last
        long fps = (a - b) / (i-1);
        fps = (1000000*10 ) / fps;
        mgr->last_fps = fps;
        return fps;
    }
}
void put_fps_data(long t) //us
{
    fps_mgr_t * mgr = &fps_mgr;
    mgr->tb[mgr->cur%FPS_STAT_MAX] = t;
    mgr->cur++;//cur ptr to next
}

/**********fps end***********/

#define UDISP_BUF_SIZE 480*480*4 // for some data case , 100kB is small
/*
 * LOOPBACK FUNCTION ... a testing vehicle for USB peripherals,
 *
 * This takes messages of various sizes written OUT to a device, and loops
 * them back so they can be read IN from it.  It has been used by certain
 * test applications.  It supports limited testing of data queueing logic.
 */

typedef uint8_t _u8;
typedef uint16_t _u16;
typedef uint32_t _u32;

#define UDISP_TYPE_RGB565  0
#define UDISP_TYPE_RGB888  1
#define UDISP_TYPE_YUV420  2
#define UDISP_TYPE_JPG		3




typedef struct _udisp_frame_header_t {  //16bytes
	_u16 crc16;//payload crc16
    _u8  type; //raw rgb,yuv,jpg,other
    _u8  cmd;    
    _u16 x;  //32bit
    _u16 y;
    _u16 width;//32bit
    _u16 height;
	_u32 frame_id:10;
    _u32 payload_total:22; //payload max 4MB
} __attribute__((packed)) udisp_frame_header_t;

typedef struct  {
	udisp_frame_header_t frame_hd;
    _u16 frame_id;
    _u16 x;
    _u16 y;
    _u16 x2;
    _u16 y2;
    _u16 y_idx;
    int rx_cnt;
    int disp_cnt;
    int done;

} disp_frame_mgr_t;


typedef struct {
struct list_head  list_node;
udisp_frame_header_t  hd;
uint8_t  buf[UDISP_BUF_SIZE];

} udisp_frame_t;

#define JPG_FRAME_MAX  3
struct f_loopback {
	struct usb_function	function;

	struct usb_ep		*in_ep;
	struct usb_ep		*out_ep;
	struct task_struct	*work_thread;
	struct kfifo		con_buf;
	struct kfifo		jpg_buf;
	struct list_head    jpg_free_list;// free jpg list
	struct list_head    jpg_data_list;// data jpg list
	udisp_frame_t   jpg_tb[JPG_FRAME_MAX];
	udisp_frame_t   rgb888x_buf;
	atomic_t  jpg_atom_cnt;
	spinlock_t		con_lock;
	struct file			*filp;
	void __iomem *screen_base;
	unsigned                qlen;
	unsigned                buflen;
	wait_queue_head_t wait_queue;
};

static inline size_t list_count_nodes(struct list_head *head)
{
	struct list_head *pos;
	size_t count = 0;

	list_for_each(pos, head)
		count++;

	return count;
}
#if 0
static void disable_ep(struct usb_composite_dev *cdev, struct usb_ep *ep)
{
	int			value;

	value = usb_ep_disable(ep);
	if (value < 0)
		DBG(cdev, "disable %s --> %d\n", ep->name, value);
}

void disable_endpoints(struct usb_composite_dev *cdev,
		struct usb_ep *in, struct usb_ep *out,
		struct usb_ep *iso_in, struct usb_ep *iso_out)
{
	disable_ep(cdev, in);
	disable_ep(cdev, out);
	if (iso_in)
		disable_ep(cdev, iso_in);
	if (iso_out)
		disable_ep(cdev, iso_out);
}
#endif
static inline struct f_loopback *func_to_loop(struct usb_function *f)
{
	return container_of(f, struct f_loopback, function);
}

/*-------------------------------------------------------------------------*/

static struct usb_interface_descriptor loopback_intf = {
	.bLength =		sizeof(loopback_intf),
	.bDescriptorType =	USB_DT_INTERFACE,

	.bNumEndpoints =	2,
	.bInterfaceClass =	USB_CLASS_VENDOR_SPEC,
	/* .iInterface = DYNAMIC */
};

/* full speed support: */

static struct usb_endpoint_descriptor fs_loop_source_desc = {
	.bLength =		USB_DT_ENDPOINT_SIZE,
	.bDescriptorType =	USB_DT_ENDPOINT,

	.bEndpointAddress =	USB_DIR_IN,
	.bmAttributes =		USB_ENDPOINT_XFER_BULK,
};

static struct usb_endpoint_descriptor fs_loop_sink_desc = {
	.bLength =		USB_DT_ENDPOINT_SIZE,
	.bDescriptorType =	USB_DT_ENDPOINT,

	.bEndpointAddress =	USB_DIR_OUT,
	.bmAttributes =		USB_ENDPOINT_XFER_BULK,
};

static struct usb_descriptor_header *fs_loopback_descs[] = {
	(struct usb_descriptor_header *) &loopback_intf,
	(struct usb_descriptor_header *) &fs_loop_sink_desc,
	(struct usb_descriptor_header *) &fs_loop_source_desc,
	NULL,
};

/* high speed support: */

static struct usb_endpoint_descriptor hs_loop_source_desc = {
	.bLength =		USB_DT_ENDPOINT_SIZE,
	.bDescriptorType =	USB_DT_ENDPOINT,

	.bmAttributes =		USB_ENDPOINT_XFER_BULK,
	.wMaxPacketSize =	cpu_to_le16(512),
};

static struct usb_endpoint_descriptor hs_loop_sink_desc = {
	.bLength =		USB_DT_ENDPOINT_SIZE,
	.bDescriptorType =	USB_DT_ENDPOINT,

	.bmAttributes =		USB_ENDPOINT_XFER_BULK,
	.wMaxPacketSize =	cpu_to_le16(512),
};

static struct usb_descriptor_header *hs_loopback_descs[] = {
	(struct usb_descriptor_header *) &loopback_intf,
	(struct usb_descriptor_header *) &hs_loop_source_desc,
	(struct usb_descriptor_header *) &hs_loop_sink_desc,
	NULL,
};

/* super speed support: */

static struct usb_endpoint_descriptor ss_loop_source_desc = {
	.bLength =		USB_DT_ENDPOINT_SIZE,
	.bDescriptorType =	USB_DT_ENDPOINT,

	.bmAttributes =		USB_ENDPOINT_XFER_BULK,
	.wMaxPacketSize =	cpu_to_le16(1024),
};

static struct usb_ss_ep_comp_descriptor ss_loop_source_comp_desc = {
	.bLength =		USB_DT_SS_EP_COMP_SIZE,
	.bDescriptorType =	USB_DT_SS_ENDPOINT_COMP,
	.bMaxBurst =		0,
	.bmAttributes =		0,
	.wBytesPerInterval =	0,
};

static struct usb_endpoint_descriptor ss_loop_sink_desc = {
	.bLength =		USB_DT_ENDPOINT_SIZE,
	.bDescriptorType =	USB_DT_ENDPOINT,

	.bmAttributes =		USB_ENDPOINT_XFER_BULK,
	.wMaxPacketSize =	cpu_to_le16(1024),
};

static struct usb_ss_ep_comp_descriptor ss_loop_sink_comp_desc = {
	.bLength =		USB_DT_SS_EP_COMP_SIZE,
	.bDescriptorType =	USB_DT_SS_ENDPOINT_COMP,
	.bMaxBurst =		0,
	.bmAttributes =		0,
	.wBytesPerInterval =	0,
};

static struct usb_descriptor_header *ss_loopback_descs[] = {
	(struct usb_descriptor_header *) &loopback_intf,
	(struct usb_descriptor_header *) &ss_loop_source_desc,
	(struct usb_descriptor_header *) &ss_loop_source_comp_desc,
	(struct usb_descriptor_header *) &ss_loop_sink_desc,
	(struct usb_descriptor_header *) &ss_loop_sink_comp_desc,
	NULL,
};

/* function-specific strings: */

static struct usb_string strings_loopback[] = {
	[0].s = "loop input to output",
	{  }			/* end of list */
};

static struct usb_gadget_strings stringtab_loop = {
	.language	= 0x0409,	/* en-us */
	.strings	= strings_loopback,
};

static struct usb_gadget_strings *loopback_strings[] = {
	&stringtab_loop,
	NULL,
};

/*-------------------------------------------------------------------------*/

static int loopback_bind(struct usb_configuration *c, struct usb_function *f)
{
	struct usb_composite_dev *cdev = c->cdev;
	struct f_loopback	*loop = func_to_loop(f);
	int			id;
	int ret;

	/* allocate interface ID(s) */
	id = usb_interface_id(c, f);
	if (id < 0)
		return id;
	loopback_intf.bInterfaceNumber = id;

	id = usb_string_id(cdev);
	if (id < 0)
		return id;
	strings_loopback[0].id = id;
	loopback_intf.iInterface = id;

	/* allocate endpoints */

	loop->in_ep = usb_ep_autoconfig(cdev->gadget, &fs_loop_source_desc);
	if (!loop->in_ep) {
autoconf_fail:
		ERROR(cdev, "%s: can't autoconfigure on %s\n",
			f->name, cdev->gadget->name);
		return -ENODEV;
	}

	loop->out_ep = usb_ep_autoconfig(cdev->gadget, &fs_loop_sink_desc);
	if (!loop->out_ep)
		goto autoconf_fail;

	/* support high speed hardware */
	hs_loop_source_desc.bEndpointAddress =
		fs_loop_source_desc.bEndpointAddress;
	hs_loop_sink_desc.bEndpointAddress = fs_loop_sink_desc.bEndpointAddress;

	/* support super speed hardware */
	ss_loop_source_desc.bEndpointAddress =
		fs_loop_source_desc.bEndpointAddress;
	ss_loop_sink_desc.bEndpointAddress = fs_loop_sink_desc.bEndpointAddress;

	ret = usb_assign_descriptors(f, fs_loopback_descs, hs_loopback_descs,
			ss_loopback_descs, NULL);
	if (ret)
		return ret;

	DBG(cdev, "%s speed %s: IN/%s, OUT/%s\n",
	    (gadget_is_superspeed(c->cdev->gadget) ? "super" :
	     (gadget_is_dualspeed(c->cdev->gadget) ? "dual" : "full")),
			f->name, loop->in_ep->name, loop->out_ep->name);
	return 0;
}

static void lb_free_func(struct usb_function *f)
{
	struct f_lb_opts *opts;

	opts = container_of(f->fi, struct f_lb_opts, func_inst);

	mutex_lock(&opts->lock);
	opts->refcnt--;
	mutex_unlock(&opts->lock);

	usb_free_all_descriptors(f);
	kfree(func_to_loop(f));
}

#define CONFIG_USB_VENDOR_RX_BUFSIZE 512






disp_frame_mgr_t  g_disp_frame_mgr;

uint16_t crc16_calc_multi(uint16_t crc_reg, unsigned char *puchMsg, unsigned int usDataLen ) 
{ 
uint32_t i,j,check; 
	for(i=0;i<usDataLen;i++) 
	{ 
	crc_reg = (crc_reg>>8) ^ puchMsg[i]; 
		for(j=0;j<8;j++) 
		{ 
			check = crc_reg & 0x0001; 
			crc_reg >>= 1; 
			if(check==0x0001){ 
				crc_reg ^= 0xA001; 
			} 
		} 
	} 
return crc_reg; 
}
uint16_t crc16_calc(unsigned char *puchMsg, unsigned int usDataLen ) 
{ 
return crc16_calc_multi(0xFFFF,puchMsg,usDataLen);
}

size_t xStreamBufferSend(void * ctx,uint8_t * buf, int len)
{
unsigned long flags;
struct f_loopback	*loop= ctx;
int xfer;
//LOGD("%s ctx:%p %d\n",__func__, ctx,len);
    spin_lock_irqsave(&loop->con_lock, flags);
	xfer=kfifo_in(&loop->con_buf, buf, len);//put data to fifo
	spin_unlock_irqrestore(&loop->con_lock, flags);
	return xfer;
}

int pop_msg_data(void * ctx,uint8_t * rx_buf, int len)
{
    size_t xTxBytes = 0;


    if(0 == len) {
        return 0;
    }

    xTxBytes = xStreamBufferSend(ctx, rx_buf, len); 

    if(xTxBytes != len) {
        LOGE("!!!send data NG:%d but:%d", len, xTxBytes);
		return -1;
    } 
	//we can't delay in isr

    return 0;
}


void push_a_frame_to_worker(void * ctx){
	unsigned long flags;

	struct f_loopback	*loop= ctx;

	LOGD("%s payload:%d rx:%d",__func__,g_disp_frame_mgr.frame_hd.payload_total,g_disp_frame_mgr.rx_cnt);

	if(g_disp_frame_mgr.rx_cnt && g_disp_frame_mgr.frame_hd.payload_total == g_disp_frame_mgr.rx_cnt ){ //one frame done
	udisp_frame_t * jfr=NULL;
		spin_lock_irqsave(&loop->con_lock, flags);
			LOGD("%s jpg_free_list:%d",__func__,list_count_nodes(&loop->jpg_free_list));
			if(!list_empty(&loop->jpg_free_list)){
				int len;
				push_frame:
				jfr=list_first_entry(&loop->jpg_free_list,udisp_frame_t,list_node);	
				len=kfifo_out(&loop->con_buf, jfr->buf, UDISP_BUF_SIZE);//put data to jpg frame
				jfr->hd= g_disp_frame_mgr.frame_hd;
				//handle over size case
				if(g_disp_frame_mgr.frame_hd.payload_total > UDISP_BUF_SIZE){
					kfifo_reset(&loop->con_buf);
					LOGI("%s drop it too large vf:%d\n",__func__,len);
					goto next;
				}
				if(g_disp_frame_mgr.frame_hd.payload_total < 0x10){ //invalid jpg
					kfifo_reset(&loop->con_buf);
					LOGI("%s drop it too small jpg:%d\n",__func__,len);
					goto next;
				}
				list_del(&jfr->list_node);//remoe it from free list
				list_add_tail(&jfr->list_node,&loop->jpg_data_list); //put it to data list
				LOGD("%s jpg_data_list:%d crc:%x",__func__,list_count_nodes(&loop->jpg_data_list),jfr->hd.crc16);
			}
			else{// no free ,just drop one data node and push it to free list	
			#if 0
				LOGD("%s got data then push to free list\n",__func__);
				jfr=list_first_entry(&loop->jpg_data_list,udisp_frame_t,list_node);
				list_del(&jfr->list_node);//remoe it from data list
				list_add_tail(&jfr->list_node,&loop->jpg_free_list); //put it to data list
				goto push_frame;
				#else
				LOGD("%s no freelist so drop it\n",__func__);
			#endif

			}
		next:
		spin_unlock_irqrestore(&loop->con_lock, flags); 
	}
	kfifo_reset(&loop->con_buf);//frame done, force reset fifo.	

}

void udisp_data_handler(void * ctx,uint8_t *req_buf, size_t len,int start , int end)
{
	struct f_loopback	*loop= ctx;
	unsigned long flags;
  static   uint8_t *rx_buf;
int remain=len,cur=0,read_res=0;

	if(start || end)
		LOGD("%s %d s:%d e:%d\n",__func__,len,start,end);

		do {
            read_res = min(remain, CONFIG_USB_VENDOR_RX_BUFSIZE);
			rx_buf=&req_buf[cur];
            if(0 == read_res)
			    break;
            if(start) {        
				udisp_frame_header_t * pfh = (udisp_frame_header_t *)rx_buf;
				start=0;
			LOGD("rx:%x crc:%x bblt x:%d y:%d w:%d h:%d total:%d",pfh->type,pfh->crc16,pfh->x,pfh->y,pfh->width,pfh->height,pfh->payload_total);
                switch(pfh->type) {
				case UDISP_TYPE_RGB565:
                case UDISP_TYPE_RGB888:
				case UDISP_TYPE_YUV420:
				case UDISP_TYPE_JPG:
                 {
                    
                    //gta = get_system_us();
                    g_disp_frame_mgr.frame_hd = *pfh;
                    g_disp_frame_mgr.x = pfh->x;
                    g_disp_frame_mgr.y = pfh->y;
                    g_disp_frame_mgr.x2 = pfh->x + pfh->width;
                    g_disp_frame_mgr.y2 = pfh->y + pfh->height;
                    g_disp_frame_mgr.y_idx = pfh->y;                   
			        g_disp_frame_mgr.disp_cnt = 0;
                    g_disp_frame_mgr.rx_cnt = read_res - sizeof(udisp_frame_header_t);
                    g_disp_frame_mgr.done = 0;
					spin_lock_irqsave(&loop->con_lock, flags);
					kfifo_reset(&loop->con_buf);
					spin_unlock_irqrestore(&loop->con_lock, flags);
					//g_crc16=0xffff;
                    
                    pop_msg_data(ctx,&rx_buf[sizeof(udisp_frame_header_t)], read_res - sizeof(udisp_frame_header_t));
                    
                }
				break;
                default:
                    LOGI("error cmd");
                    break;
                }

            } else {

                g_disp_frame_mgr.rx_cnt += read_res;
                pop_msg_data(ctx,rx_buf, read_res);

            }
			remain-=read_res;
			cur+=read_res;
			//LOGI("%s rd:%d cur:%d remain:%d len:%d (%d|%d) end:%d\n",__func__,read_res,cur,remain,len,g_disp_frame_mgr.cnt,g_disp_frame_mgr.total,end);


        }while(read_res);
		if(end) {
			push_a_frame_to_worker(ctx);
			wake_up_interruptible(&loop->wait_queue);
			wake_up_process(loop->work_thread);
		}
if(remain){		
LOGI("exit %s rd:%d cur:%d remain:%d len:%d\n",__func__,read_res,cur,remain,len);
}
}

static void loopback_complete(struct usb_ep *ep, struct usb_request *req)
{
	struct f_loopback	*loop = ep->driver_data;
	struct usb_composite_dev *cdev = loop->function.config->cdev;
	int			status = req->status;
	unsigned long flags;
	static int urx_total=0;
	switch (status) {
	case 0:				/* normal completion? */
		if (ep == loop->out_ep) {
			/*
			 * We received some data from the host so let's
			 * queue it so host can read the from our in ep
			 */
			 #if 0
			struct usb_request *in_req = req->context;

			in_req->udisp = (req->actual < req->length);
			in_req->length = req->actual;
			ep = loop->in_ep;
			req = in_req;
			#endif
			#if 0
				{
				uint32_t *ptr=req->buf;
			LOGD("urx:%x %x %x\n",ptr[0],ptr[1],ptr[2]);
				}
			#endif
			udisp_data_handler(loop,req->buf, req->actual,urx_total==0,req->actual < UDISP_BULK_BUFLEN);//means end of file
			if(req->actual < UDISP_BULK_BUFLEN){
				urx_total +=req->actual;
				put_fps_data(get_os_us());
				LOGI("urx:%d|%d(%d)fps:%d\n",req->actual,req->length,urx_total,get_fps());
				urx_total=0;
			} else {
				urx_total +=req->actual;
			}
			
			
		} else {
			/*
			 * We have just looped back a bunch of data
			 * to host. Now let's wait for some more data.
			 */
			req = req->context;
			ep = loop->out_ep;
			LOGD("%s ----send %d %d\n",__func__,req->actual,req->length);

		}
#if 1

		/* queue the buffer back to host or for next bunch of data */
		status = usb_ep_queue(ep, req, GFP_ATOMIC);
		if (status == 0) {
			return;
		} else {
			LOGD("Unable to loop back buffer to %s: %d\n",ep->name, status);
			ERROR(cdev, "Unable to loop back buffer to %s: %d\n",
			      ep->name, status);
			goto free_req;
		}
#else
	return;
#endif
		/* "should never get here" */
	default:
		ERROR(cdev, "%s loop complete --> %d, %d/%d\n", ep->name,
				status, req->actual, req->length);
		/* FALLTHROUGH */

	/* NOTE:  since this driver doesn't maintain an explicit record
	 * of requests it submitted (just maintains qlen count), we
	 * rely on the hardware driver to clean up on disconnect or
	 * endpoint disable.
	 */
	case -ECONNABORTED:		/* hardware forced ep reset */
	case -ECONNRESET:		/* request dequeued */
	case -ESHUTDOWN:		/* disconnect from host */
free_req:
		usb_ep_free_request(ep == loop->in_ep ?
				    loop->out_ep : loop->in_ep,
				    req->context);
		free_ep_req(ep, req);
		return;
	}
}


int  rgb565_decode_rgb888x(uint32_t * framebuffer ,uint16_t * pix_msg ,int x, int y, int right, int bottom, int line_width)
{
int    last_copied_x, last_copied_y;
int pos = 0;

		// locate to the begining...
		framebuffer += (y * line_width + x);


#if 1
		for (last_copied_y = y; last_copied_y <= bottom; ++last_copied_y) {
	
			for (last_copied_x = x; last_copied_x <= right; ++last_copied_x) {
	
				uint16_t pix = *pix_msg;
				uint8_t r, g, b;
				//LOG("fb %p\n",framebuffer);
				r = (pix >> 8) & 0xf8;
				g = (pix >> 3) & 0xfc;
				b = (pix << 3) & 0xf8;
				uint32_t current_pixel_le = r | (g <<8) | (b<<16) | 0xff000000;
				//current_pixel_le = (current_pixel_le >> 8) | (current_pixel_le << 8);
				*framebuffer = current_pixel_le;
				//*framebuffer = 0xff00ff;
				pix_msg++;			
				++framebuffer;
	
			}
			framebuffer += line_width - right - 1 + x;
			//LOGI("%s %x\n",__func__,*pix_msg);
		}
#endif
		return 0;
}


int draw_a_frame(void * ctx ,udisp_frame_t * jf,void * scr){

	struct f_loopback	*loop = ctx;

							
	LOGI("%s %d\n",__func__,jf->hd.type);

	switch (jf->hd.type){
	case UDISP_TYPE_RGB888:
		memcpy(scr,jf->buf,jf->hd.payload_total);
		break;
	case UDISP_TYPE_RGB565:
		
		rgb565_decode_rgb888x((uint32_t *)loop->rgb888x_buf.buf,(uint16_t *)jf->buf,0,0,479,479,480);
		memcpy(scr,loop->rgb888x_buf.buf,jf->hd.payload_total*2);
		break;
	default:
		LOGI("%s no support now\n",__func__);

	}
return 0;

}

void * fb_get_dma_buf(struct file * file);


static int udisp_thread(void *data)
{
struct f_loopback	*loop = data;	
int xfer, ret, count, size;
unsigned long flags;
#define UDISP_RX_BUF_SIZE 1024
uint8_t buf[UDISP_RX_BUF_SIZE];
size=UDISP_RX_BUF_SIZE;
LOGD("%s ctx:%p\n",__func__, loop);

#if 0
loop->filp = filp_open("/dev/fb0", O_RDWR, 0);
	if (IS_ERR(loop->filp)) {
		int ret = PTR_ERR(loop->filp);
		LOGE("unable to open fb0 device file\n");
		loop->filp = NULL;
		return ret;
	}
loop->screen_base= fb_get_dma_buf(loop->filp);
LOGD("%s ctx:%px  screen:%px\n",__func__, loop,loop->screen_base);
#endif
	do {
		set_current_state(TASK_INTERRUPTIBLE);
		udisp_frame_t * jfr=NULL;
		//LOGI("%s count:%d\n",__func__,count);
		if (jfr ) {
			set_current_state(TASK_RUNNING);

				draw_a_frame(loop,jfr,loop->screen_base);
						//LOGI("%s jpg_atomic:%d\n",__func__,atomic_read(&loop->jpg_atom_cnt));
				spin_lock_irqsave(&loop->con_lock,flags);
				list_add_tail(&jfr->list_node,&loop->jpg_free_list); //put it to free list
				spin_unlock_irqrestore(&loop->con_lock, flags);
				//LOGI("%s then jpg_atomic:%d\n",__func__,atomic_read(&loop->jpg_atom_cnt));

		} else {


			if (kthread_should_stop()) {
				set_current_state(TASK_RUNNING);
				break;
			}
			//LOGI("%s sched count:%d\n",__func__,count);
			schedule();
		}
	} while (1);

	return 0;
}

static void disable_loopback(struct f_loopback *loop)
{
	struct usb_composite_dev	*cdev;

	cdev = loop->function.config->cdev;
	disable_endpoints(cdev, loop->in_ep, loop->out_ep, NULL, NULL);
	VDBG(cdev, "%s disabled\n", loop->function.name);
}

static inline struct usb_request *lb_alloc_ep_req(struct usb_ep *ep, int len)
{
	return alloc_ep_req(ep, len);
}

static int alloc_requests(struct usb_composite_dev *cdev,
			  struct f_loopback *loop)
{
	struct usb_request *in_req, *out_req;
	int i;
	int result = 0;

	/*
	 * allocate a bunch of read buffers and queue them all at once.
	 * we buffer at most 'qlen' transfers; We allocate buffers only
	 * for out transfer and reuse them in IN transfers to implement
	 * our loopback functionality
	 */
	for (i = 0; i < loop->qlen && result == 0; i++) {
		result = -ENOMEM;

		in_req = usb_ep_alloc_request(loop->in_ep, GFP_ATOMIC);
		if (!in_req)
			goto fail;

		out_req = lb_alloc_ep_req(loop->out_ep, loop->buflen);
		if (!out_req)
			goto fail_in;

		in_req->complete = loopback_complete;
		out_req->complete = loopback_complete;

		in_req->buf = out_req->buf;
		/* length will be set in complete routine */
		in_req->context = out_req;
		out_req->context = in_req;

		result = usb_ep_queue(loop->out_ep, out_req, GFP_ATOMIC);
		if (result) {
			ERROR(cdev, "%s queue req --> %d\n",
					loop->out_ep->name, result);
			goto fail_out;
		}
	}

	return 0;

fail_out:
	free_ep_req(loop->out_ep, out_req);
fail_in:
	usb_ep_free_request(loop->in_ep, in_req);
fail:
	return result;
}

static int enable_endpoint(struct usb_composite_dev *cdev,
			   struct f_loopback *loop, struct usb_ep *ep)
{
	int					result;

	result = config_ep_by_speed(cdev->gadget, &(loop->function), ep);
	if (result)
		goto out;

	result = usb_ep_enable(ep);
	if (result < 0)
		goto out;
	ep->driver_data = loop;
	result = 0;

out:
	return result;
}

static int
enable_loopback(struct usb_composite_dev *cdev, struct f_loopback *loop)
{
	int					result = 0;

	result = enable_endpoint(cdev, loop, loop->in_ep);
	if (result)
		goto out;

	result = enable_endpoint(cdev, loop, loop->out_ep);
	if (result)
		goto disable_in;

	result = alloc_requests(cdev, loop);
	if (result)
		goto disable_out;

	DBG(cdev, "%s enabled\n", loop->function.name);
	return 0;

disable_out:
	usb_ep_disable(loop->out_ep);
disable_in:
	usb_ep_disable(loop->in_ep);
out:
	return result;
}

static int loopback_set_alt(struct usb_function *f,
		unsigned intf, unsigned alt)
{
	struct f_loopback	*loop = func_to_loop(f);
	struct usb_composite_dev *cdev = f->config->cdev;

	/* we know alt is udisp */
	disable_loopback(loop);
	return enable_loopback(cdev, loop);
}

/*******proc fs*******/
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/proc_fs.h>

/* global variables for procfs folder and file */
static struct proc_dir_entry *proc_folder;
static struct proc_dir_entry *proc_file;
static struct f_loopback * gp_loop;
/**
 * @brief Read data out of the buffer
 */
static ssize_t my_read(struct file *File, char *user_buffer, size_t count, loff_t *offs) {
   
		int cnt=0,err=0;
		unsigned long p=*offs;
        int not_copied=0;
		static udisp_frame_t * g_cur_jfr=NULL;
		struct f_loopback	*loop = gp_loop ;
		unsigned long flags;

   		LOGD("read %d, not_copied:%d offs:%d \n",count,not_copied,p);

#if 1
retry:
		if(g_cur_jfr ==NULL) {
				spin_lock_irqsave(&loop->con_lock,flags);
				LOGD("%s jpg_data_list:%d",__func__,list_count_nodes(&loop->jpg_data_list));
				if(!list_empty(&loop->jpg_data_list)) {
					g_cur_jfr=list_first_entry(&loop->jpg_data_list,udisp_frame_t,list_node);
					list_del(&g_cur_jfr->list_node);//remoe it from data list					
				}else {					
					g_cur_jfr=NULL;
				}		
				spin_unlock_irqrestore(&loop->con_lock, flags);
			}
#endif

		if(g_cur_jfr == NULL){
			LOGD("wait frame data\n");
			unsigned long timeout=msecs_to_jiffies(500);
			if(wait_event_interruptible_timeout(loop->wait_queue,!list_empty(&loop->jpg_data_list),timeout)<=0){
				LOGD("wait frame data timeout or signaled\n");
				return -ERESTARTSYS;
				}
			if(list_empty(&loop->jpg_data_list))
				return -EAGAIN;
			goto retry;// we got a new frame
		}

		if(p >= g_cur_jfr->hd.payload_total){
			LOGD("end of file\n");
			spin_lock_irqsave(&loop->con_lock,flags);
			list_add_tail(&g_cur_jfr->list_node,&loop->jpg_free_list); //put it to free list
			spin_unlock_irqrestore(&loop->con_lock, flags);
			g_cur_jfr = NULL;
			return 0; //end of file
		}
		if(p+count > g_cur_jfr->hd.payload_total)
			count=g_cur_jfr->hd.payload_total - p;
        /* Copy data to user */
        while(count){
			not_copied = copy_to_user(user_buffer, &g_cur_jfr->buf[p], count);
			if(not_copied){
				err=-EFAULT;
				goto exit;
			}
			*offs+=count;
			cnt+=count;
			count-=count;
			LOGD("count:%d not_copied:%d offs:%d cnt:%d\n",count,not_copied,p,cnt);
		}
		

exit:

        return err?err:cnt;
}
/**
 * @brief Write data to buffer
 */
static ssize_t my_write(struct file *File, const char *user_buffer, size_t count, loff_t *offs) {
#if 0
	struct f_loopback * loop=gp_loop;
        u8 * buf;
		unsigned long p=*offs;
        int to_copy=count, not_copied, delta;
		udisp_frame_t * fr=&gjpg_tb[0];
       
		buf=kmalloc(count,GFP_KERNEL);
		if(!buf){
			return -ENOMEM;
		}

        /* Copy data to user */
        not_copied = copy_from_user(buf, user_buffer, to_copy);
        LOGI("written %d to me, not_copied:%d offs:%d\n",to_copy,not_copied,p);

        /* Calculate data */
        delta = to_copy - not_copied;

		if(0 == p){
			fr->len=0;
		}

		if(delta) {
			memcpy(fr->buf+p,buf,delta);
			fr->len+=delta;
			LOGI("fr->len:%d\n",fr->len);
			if(count< PAGE_SIZE) {
				LOGI("draw %d jpg\n",fr->len);
				//jdec_task(fr->buf,fr->len,1024,600,loop->screen_base);	//draw to screen
			}
			
		}
		if(!buf)
			kfree(buf);
        return delta;
#else
	return 0;
#endif
}

static struct file_operations fops = {
        .read = my_read,
        .write = my_write,
};



/**
 * @brief This function is called, when the module is loaded into the kernel
 */
static int  my_procfs_init(void) {
        /* /proc/udisp/xfz1986 */
		LOGI("%s\n",__func__);
        proc_folder = proc_mkdir("udisp", NULL);
        if(proc_folder == NULL) {
                LOGI(" - Error creating /proc/udisp\n");
                return -ENOMEM;
        }

        proc_file = proc_create("xfz1986", 0666, proc_folder, &fops);
        if(proc_file == NULL) {
                LOGI(" - Error creating /proc/udisp/xfz1986\n");
                proc_remove(proc_folder);
                return -ENOMEM;
        }

        LOGI(" - Created /proc/udisp/xfz1986\n");
        return 0;
}

/**
 * @brief This function is called, when the module is removed from the kernel
 */
static void  my_procfs_exit(void) {
        LOGI("Removing /proc/udisp/xfz1986\n");
        proc_remove(proc_file);
        proc_remove(proc_folder);
}


static void loopback_disable(struct usb_function *f)
{
	struct f_loopback	*loop = func_to_loop(f);

	disable_loopback(loop);
}

static struct usb_function *loopback_alloc(struct usb_function_instance *fi)
{
	struct f_loopback	*loop;
	struct f_lb_opts	*lb_opts;
    int status=0;
	loop = kzalloc(sizeof *loop, GFP_KERNEL);
	if (!loop)
		return ERR_PTR(-ENOMEM);

	lb_opts = container_of(fi, struct f_lb_opts, func_inst);

	mutex_lock(&lb_opts->lock);
	lb_opts->refcnt++;
	mutex_unlock(&lb_opts->lock);

	loop->buflen = lb_opts->bulk_buflen;
	loop->qlen = lb_opts->qlen;
	if (!loop->qlen)
		loop->qlen = 32;

	loop->function.name = "loopback";
	loop->function.bind = loopback_bind;
	loop->function.set_alt = loopback_set_alt;
	loop->function.disable = loopback_disable;
	loop->function.strings = loopback_strings;

	loop->function.free_func = lb_free_func;
	
	spin_lock_init(&loop->con_lock);
	status =kfifo_alloc(&loop->con_buf,UDISP_BUF_SIZE, GFP_KERNEL);
	if(status)
	{
		pr_err("%s: cannot create fifo\n", __func__);
	}
	status =kfifo_alloc(&loop->jpg_buf,UDISP_BUF_SIZE, GFP_KERNEL);
	if(status)
	{
		pr_err("%s: cannot create fifo\n", __func__);
	}
	atomic_set(&loop->jpg_atom_cnt,1);
	init_waitqueue_head(&loop->wait_queue);
	loop->work_thread = kthread_create(udisp_thread,loop, "udisp_thread");
	if (IS_ERR(loop->work_thread)) {
		pr_err("%s: cannot create udisp thread\n", __func__);
		return PTR_ERR(loop->work_thread);
	}
	// init jpg input list
	    INIT_LIST_HEAD(&loop->jpg_free_list);
		INIT_LIST_HEAD(&loop->jpg_data_list);
		{
			int i=0;
			for(i=0;i<JPG_FRAME_MAX;i++){
			list_add_tail(&loop->jpg_tb[i].list_node,&loop->jpg_free_list);
			}
		}
	gp_loop=loop;
	my_procfs_init();
	lb_opts->ctx=loop;
		 
	wake_up_process(loop->work_thread);

	return &loop->function;
}

static inline struct f_lb_opts *to_f_lb_opts(struct config_item *item)
{
	return container_of(to_config_group(item), struct f_lb_opts,
			    func_inst.group);
}

static void lb_attr_release(struct config_item *item)
{
	struct f_lb_opts *lb_opts = to_f_lb_opts(item);

	usb_put_function_instance(&lb_opts->func_inst);
}

static struct configfs_item_operations lb_item_ops = {
	.release		= lb_attr_release,
};

static ssize_t f_lb_opts_qlen_show(struct config_item *item, char *page)
{
	struct f_lb_opts *opts = to_f_lb_opts(item);
	int result;

	mutex_lock(&opts->lock);
	result = sprintf(page, "%d\n", opts->qlen);
	mutex_unlock(&opts->lock);

	return result;
}

static ssize_t f_lb_opts_qlen_store(struct config_item *item,
				    const char *page, size_t len)
{
	struct f_lb_opts *opts = to_f_lb_opts(item);
	int ret;
	u32 num;

	mutex_lock(&opts->lock);
	if (opts->refcnt) {
		ret = -EBUSY;
		goto end;
	}

	ret = kstrtou32(page, 0, &num);
	if (ret)
		goto end;

	opts->qlen = num;
	ret = len;
end:
	mutex_unlock(&opts->lock);
	return ret;
}

CONFIGFS_ATTR(f_lb_opts_, qlen);

static ssize_t f_lb_opts_bulk_buflen_show(struct config_item *item, char *page)
{
	struct f_lb_opts *opts = to_f_lb_opts(item);
	int result;

	mutex_lock(&opts->lock);
	result = sprintf(page, "%d\n", opts->bulk_buflen);
	mutex_unlock(&opts->lock);

	return result;
}

static ssize_t f_lb_opts_bulk_buflen_store(struct config_item *item,
				    const char *page, size_t len)
{
	struct f_lb_opts *opts = to_f_lb_opts(item);
	int ret;
	u32 num;

	mutex_lock(&opts->lock);
	if (opts->refcnt) {
		ret = -EBUSY;
		goto end;
	}

	ret = kstrtou32(page, 0, &num);
	if (ret)
		goto end;

	opts->bulk_buflen = num;
	ret = len;
end:
	mutex_unlock(&opts->lock);
	return ret;
}

CONFIGFS_ATTR(f_lb_opts_, bulk_buflen);

static struct configfs_attribute *lb_attrs[] = {
	&f_lb_opts_attr_qlen,
	&f_lb_opts_attr_bulk_buflen,
	NULL,
};

static const struct config_item_type lb_func_type = {
	.ct_item_ops    = &lb_item_ops,
	.ct_attrs	= lb_attrs,
	.ct_owner       = THIS_MODULE,
};

static void lb_free_instance(struct usb_function_instance *fi)
{
	struct f_lb_opts *lb_opts;
  struct f_loopback       *loop ;
	lb_opts = container_of(fi, struct f_lb_opts, func_inst);
	loop=lb_opts->ctx;
	dump_stack();
    if (!IS_ERR_OR_NULL(loop->work_thread))
            kthread_stop(loop->work_thread);
	if(loop->filp){
		LOGI("close fb\n");
		filp_close(loop->filp, NULL);
	}
	my_procfs_exit();
	kfree(lb_opts);
}

static struct usb_function_instance *loopback_alloc_instance(void)
{
	struct f_lb_opts *lb_opts;

	lb_opts = kzalloc(sizeof(*lb_opts), GFP_KERNEL);
	if (!lb_opts)
		return ERR_PTR(-ENOMEM);
	mutex_init(&lb_opts->lock);
	lb_opts->func_inst.free_func_inst = lb_free_instance;
	lb_opts->bulk_buflen = UDISP_BULK_BUFLEN;
	lb_opts->qlen = UDISP_QLEN;

	config_group_init_type_name(&lb_opts->func_inst.group, "",
				    &lb_func_type);

	return  &lb_opts->func_inst;
}
DECLARE_USB_FUNCTION(Loopback, loopback_alloc_instance, loopback_alloc);

int __init lb_modinit(void)
{
	return usb_function_register(&Loopbackusb_func);
}

void __exit lb_modexit(void)
{
	usb_function_unregister(&Loopbackusb_func);
}

MODULE_LICENSE("GPL");
