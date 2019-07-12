# sk_buff_icmp_sender
kernel module sending echo request. Kernel v3.13.0 (OS Ubuntu 12.04.5 LTS x86_64)

icmp_netfilter is derivative from netfilter (other repo of that profile),
so it consist of some excess data, but it still filtering pretty good

in devq_pinger sk_buff send by dev_queue_xmit()
sk_buff must contain eth, ip and icmp headers + all check sum + net device info

in route_pinger ks_buff send by ip_local_out()
is is enought for sk_buff to contain ip & icmp headers + routing info + net device info

