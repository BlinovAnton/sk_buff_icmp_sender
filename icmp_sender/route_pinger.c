#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>
#include <asm/uaccess.h>
#include <linux/ip.h>
#include <net/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/route.h>
#include <linux/if_ether.h>
#include <net/net_namespace.h>
#include <linux/netdevice.h>
#include <linux/pkt_sched.h>

#define SEX_IN_DAY 86400
#define MAX_U_SHORT 65535

/* bug with echo -e "...\n" > file - it is refreshing a file*/

/*ks - kernel space, us - user space*/

MODULE_LICENSE("GPL");

static size_t ks_len = 0;
static struct sk_buff *skb = NULL;
static struct kobject *my_kobj;
static char *end_combo = "end ";
static const char *sys_dir_name = "ant_pinger";
static char *ks_buff = NULL, *ks_buff_temp = NULL;
static unsigned short *ports = NULL, *ports_temp = NULL, ports_num = 0;
static u_int go_echo_request (void);
static unsigned short txt_to_short (const char *, size_t);
static ssize_t sys_show (struct kobject *, struct kobj_attribute *, char *);
static ssize_t sys_store (struct kobject *, struct kobj_attribute *, const char *, size_t);

//1st arg of __ATTR is stringify
static struct kobj_attribute kobj_attr = __ATTR (my_sys_file, 0644, sys_show, sys_store);

static int __init my_pinger_init (void) {
	unsigned long res = 0;
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
	res = go_echo_request();
	return 0;
}

static void __exit my_pinger_exit (void) {
	if (ks_buff != NULL) {
	    kfree(ks_buff);
	}
	if (!skb) {
	    kfree_skb(skb);
	}
	kobject_put(my_kobj);
	printk(KERN_INFO "Successfully unregistered\n");
}

static u_int my_inet_aton (const char *addr_s) {
    int i = 0, dec = 1;
    u_int addr_d = 0;
    u_char *byte = NULL, num = 0;
    byte = (unsigned char *)&addr_d;
    byte += 3;
    for (i = strlen(addr_s)-1; i >= 0; i--) {
	if (addr_s[i] == '.') {
	    dec = 1;
	    *byte = num;
	    byte--;
	    num = 0;
	} else {
	    num += (addr_s[i] - 48) * dec;
	    dec *= 10;
	}
    }
    *byte = num;
    return addr_d;
}

static u_int go_echo_request () {
    struct icmphdr *icmp_hdr = NULL;
    struct iphdr *ip_hdr = NULL;
    struct net_device *my_dev = NULL;
    struct rtable *rt = NULL;
    struct flowi4 f4;
    const char *my_ip = "192.168.0.2";
    const char *not_my_ip = "192.168.0.3";
    u_char *bytes = NULL;
    int res = 0, seq_num = 1, i = 0;
    int hdr_sizes = sizeof(struct icmphdr) + sizeof(struct iphdr);
    skb = alloc_skb(hdr_sizes, GFP_ATOMIC);
    if (!skb) {
	printk(KERN_INFO "alloc_skb() fault\n");
	return -EFAULT;
    }
    skb_reserve(skb, ETH_ZLEN); //just in case
    skb->len = hdr_sizes;
    skb->protocol = htons(ETH_P_IP);
    skb->priority = 0;
    skb->pkt_type = PACKET_OUTGOING;
    skb_set_network_header(skb, 0);
    skb_set_transport_header(skb, sizeof(struct iphdr));

    printk(KERN_INFO "tail = %d", skb->tail);
    ip_hdr = (struct iphdr *)(skb->head + skb->tail);
    ip_hdr->ihl = sizeof(struct iphdr) / 4;
    ip_hdr->version = 4;
    ip_hdr->tos = 0;
    ip_hdr->tot_len = htons(hdr_sizes);
    ip_hdr->id = htons(1);
    ip_hdr->frag_off = 0;
    ip_hdr->ttl = 255;
    ip_hdr->protocol = IPPROTO_ICMP;
    ip_hdr->check = 0;
    ip_hdr->saddr = my_inet_aton(my_ip);
    ip_hdr->daddr = my_inet_aton(not_my_ip);
    ip_hdr->check = htons(ip_compute_csum(ip_hdr, ip_hdr->ihl * 4));
    skb->tail += ip_hdr->ihl * 4;

    printk(KERN_INFO "tail = %d", skb->tail);
    icmp_hdr = (struct icmphdr *)(skb->head + skb->tail);
    icmp_hdr->type = ICMP_ECHO;
    icmp_hdr->code = 0;
    icmp_hdr->checksum = 0;
    icmp_hdr->un.echo.id = htons(228); 		//trys ping id
    icmp_hdr->un.echo.sequence = htons(seq_num);    //counter of trys
    icmp_hdr->checksum = ip_compute_csum(icmp_hdr, sizeof(struct icmphdr));
    skb->tail += sizeof(struct icmphdr);

    printk(KERN_INFO "tail = %d", skb->tail);
    printk(KERN_INFO "%p-%p-%d-%d (csum = %x & %x)\n",
		skb->head, skb->data, skb->tail, skb->end, ip_hdr->check, icmp_hdr->checksum);

    my_dev = dev_get_by_name(&init_net, "eth1");
    if (my_dev) {
	printk(KERN_INFO "dev->name = %s", my_dev->name);
    } else {
	printk(KERN_WARNING "de_get_by_name() error");
	return -EINVAL;
    }
    skb->dev = my_dev;

    f4.flowi4_oif = my_dev->ifindex;
    f4.daddr = my_inet_aton(not_my_ip);
    f4.saddr = my_inet_aton(my_ip);
    rt = ip_route_output_key(&init_net, &f4);
    skb_dst_set(skb, &rt->dst);

    bytes = skb->head;
    printk("\n%p ", bytes);
    for (i = 0; i < skb->end; i++) {
	printk("%x ", bytes[i]);
    }

    res = ip_local_out(skb);
    printk(KERN_DEBUG "%d-%d-%d (%d)",
	skb->mac_header, skb->network_header, skb->transport_header, res);
    return 0;
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

module_init (my_pinger_init);
module_exit (my_pinger_exit);