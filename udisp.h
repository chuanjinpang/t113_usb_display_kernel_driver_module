/* SPDX-License-Identifier: GPL-2.0 */
/*
 * This header declares the utility functions used by "Gadget udisp", plus
 * interfaces to its two single-configuration function drivers.
 */

#ifndef __UDISP_H
#define __UDISP_H

#define UDISP_BULK_BUFLEN	512
#define UDISP_QLEN		8*64
#define UDISP_ISOC_INTERVAL	4
#define UDISP_ISOC_MAXPACKET	1024
#define UDISP_SS_BULK_QLEN	1
#define UDISP_SS_ISO_QLEN	8

struct usb_udisp_options {
	unsigned pattern;
	unsigned isoc_interval;
	unsigned isoc_maxpacket;
	unsigned isoc_mult;
	unsigned isoc_maxburst;
	unsigned bulk_buflen;
	unsigned qlen;
	unsigned ss_bulk_qlen;
	unsigned ss_iso_qlen;
};

struct f_ss_opts {
	struct usb_function_instance func_inst;
	unsigned pattern;
	unsigned isoc_interval;
	unsigned isoc_maxpacket;
	unsigned isoc_mult;
	unsigned isoc_maxburst;
	unsigned bulk_buflen;
	unsigned bulk_qlen;
	unsigned iso_qlen;

	/*
	 * Read/write access to configfs attributes is handled by configfs.
	 *
	 * This is to protect the data from concurrent access by read/write
	 * and create symlink/remove symlink.
	 */
	struct mutex			lock;
	int				refcnt;
};

struct f_lb_opts {
	struct usb_function_instance func_inst;
	unsigned bulk_buflen;
	unsigned qlen;

	/*
	 * Read/write access to configfs attributes is handled by configfs.
	 *
	 * This is to protect the data from concurrent access by read/write
	 * and create symlink/remove symlink.
	 */
	struct mutex			lock;
	int				refcnt;
	void * ctx;
};

void lb_modexit(void);
int lb_modinit(void);

/* common utilities */
void disable_endpoints(struct usb_composite_dev *cdev,
		struct usb_ep *in, struct usb_ep *out,
		struct usb_ep *iso_in, struct usb_ep *iso_out);

#endif /* __UDISP_H */
