#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>
#include <asm/uaccess.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>

#define SEX_IN_DAY 86400
#define MAX_U_SHORT 65535

/* bug with echo -e "...\n" > file - it is refreshing a file*/

/*ks - kernel space, us - user space*/

MODULE_LICENSE("GPL");

static size_t ks_len = 0;
static struct nf_hook_ops hook_ops;
static struct kobject *my_kobj;
static char *end_combo = "end ";
static const char *sys_dir_name = "ant_sys_dir";
static char *ks_buff = NULL, *ks_buff_temp = NULL;
static unsigned short *ports = NULL, *ports_temp = NULL, ports_num = 0;
static unsigned short txt_to_short (const char *, size_t);
static ssize_t sys_show (struct kobject *, struct kobj_attribute *, char *);
static ssize_t sys_store (struct kobject *, struct kobj_attribute *, const char *, size_t);
static unsigned int port_dropper_hook (const struct nf_hook_ops *,
					struct sk_buff *,
					const struct net_device *,
					const struct net_device *,
					int (*okfn)(struct sk_buff *));

//1st arg of __ATTR is stringify
static struct kobj_attribute kobj_attr = __ATTR (block_sys_file, 0644, sys_show, sys_store);

static int __init my_netfilter_init (void) {
	unsigned long res = 0;
	hook_ops.hook = port_dropper_hook;
	hook_ops.owner = THIS_MODULE;
	hook_ops.pf = NFPROTO_IPV4;
	hook_ops.hooknum = NF_INET_LOCAL_OUT;
	hook_ops.priority = NF_IP_PRI_FIRST;
	nf_register_hook(&hook_ops);
	my_kobj = kobject_create_and_add(sys_dir_name, NULL);
	if (!my_kobj) {
	    printk(KERN_WARNING "Can't create sys_dir\n");
	    return -EFAULT;
	}
	res = sysfs_create_file(my_kobj, &kobj_attr.attr);
	if (res) {
	    printk(KERN_WARNING "Can't create sys_file\n");
	    return -EFAULT;
	}
	printk(KERN_INFO "Successfully registered\n");
	return 0;
}

static void __exit my_netfilter_exit (void) {
	if (ks_buff != NULL) {
	    kfree(ks_buff);
	}
	if (ports != NULL) {
	    kfree(ports);
	}
	kobject_put(my_kobj);
	nf_unregister_hook(&hook_ops);
	printk(KERN_INFO "Successfully unregistered\n");
}

static unsigned short txt_to_short (const char *buff, size_t len) {
    int i = len;
    unsigned int digit = 1;
    unsigned int port = 0;
    for (i = len; i >= 0; i--) {
	if (buff[i] >= 48 && buff[i] <= 58) {
	    port += (buff[i] - 48) * digit;
	    if (port > MAX_U_SHORT) {
		return 0;
	    }
	    digit *= 10;
	} else {
	    return 0;
	}
    }
    return port;
}

static ssize_t sys_show (struct kobject *kobj, struct kobj_attribute *kobj_attr, char *us_buf) {
    if (!ks_buff) {
	return 0;
    } else {
	strncpy(us_buf, ks_buff, ks_len);
	return strlen(us_buf);
    }
}

static ssize_t sys_store (struct kobject *kobj, struct kobj_attribute *kobj_attr, const char *us_buff, size_t us_len) {
    int offset = 0;
    unsigned short p_tmp = 0;

    /* refresh file (clean port list and kernel space buffer) */
    if (!strncmp(end_combo, us_buff, us_len - 1)) {
	ks_len = 0;
	ports_num = 0;
	kfree(ks_buff);
	ks_buff_temp = NULL;
	kfree(ports);
	ports_temp = NULL;
	return strlen(end_combo);
    }

    p_tmp = txt_to_short (us_buff, us_len - 2);
    if (p_tmp) {
	ports_num++;
	ks_len = ks_len + us_len;
	offset = ks_len - us_len;
	ks_buff_temp = krealloc(ks_buff, ks_len, GFP_KERNEL);
	if (!ks_buff_temp) {
	    printk(KERN_WARNING "kmalloc can't alloc memory, sys_store fault\n");
	    return -EFAULT;
	}
	ports_temp = krealloc(ports, ports_num, GFP_KERNEL);
	if (!ports_temp) {
	    printk(KERN_WARNING "kmalloc can't alloc memory, sys_store fault\n");
	    return -EFAULT;
	}
	ks_buff = ks_buff_temp;
	ports = ports_temp;
	ports[ports_num - 1] = p_tmp;
	strncpy(ks_buff + offset, us_buff, us_len);
	return us_len;
    }
    return -EFAULT;
}

static unsigned int port_dropper_hook (const struct nf_hook_ops *ops,
					struct sk_buff *skb,
					const struct net_device *in,
					const struct net_device *out,
					int (*okfn)(struct sk_buff *)) {
    int i = 0;
    struct iphdr *ip_hdr;
    unsigned char *bytes = NULL;

    if (skb->protocol == htons(ETH_P_IP)) {
	ip_hdr = (struct iphdr *)skb_network_header(skb);
	if (ip_hdr->protocol == IPPROTO_ICMP) {
	    printk(KERN_INFO "proto#%d\n", ip_hdr->protocol);
	    bytes = skb->head;
	    for (i = 0; i < skb->end; i++) {
		printk("%x ", bytes[i]);
	    }
	    printk(KERN_INFO "%p-%p-%d-%d, sp %d",
			skb->head, skb->data, skb->tail, skb->end, skb->protocol);
	    printk(KERN_INFO "%d-%d-%d\n",skb->mac_header,skb->network_header,skb->transport_header);
	    for (i = 0; i < 14; i++) {
		printk("%x ", bytes[i + skb->mac_header]);
	    }
	}
    }
    return NF_ACCEPT;
}

module_init (my_netfilter_init);
module_exit (my_netfilter_exit);