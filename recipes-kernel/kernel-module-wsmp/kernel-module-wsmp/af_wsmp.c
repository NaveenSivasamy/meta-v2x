/*
 * WAVE Short Message Protocol sockets
 *
 * Copyright (C) 2015 ZENOME Inc. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation version 2 and no later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#ifndef AF_WSMP
	#define AF_WSMP         41
	#define PF_WSMP		AF_WSMP
#endif

#ifndef ETH_P_WSMP
	#define ETH_P_WSMP	0x88DC
#endif

/* version(1) + 1 octet psid(1) + elmid(1) + length(2) */
#define WSMP_MIN_LEN		5

#include <linux/module.h>
#include <linux/kernel.h>

#include <linux/if_arp.h>
#include <linux/init.h>
#include <linux/net.h>
#include <linux/rculist.h>
#include <linux/skbuff.h>
#include <linux/socket.h>
#include <asm/unaligned.h>
#include <net/sock.h>

HLIST_HEAD(sklist);
DEFINE_RWLOCK(sklist_lock);

struct sockaddr_wsmp {
	__kernel_sa_family_t	wsmp_family;
	int			wsmp_ifindex;
	__be32			wsmp_psid; 
	__u8			wsmp_dest_hwaddr[ETH_ALEN]; 
};

struct wsmp_sock {
	/* sk must be the first member. */
	struct sock	sk;
	int		ifindex;
	__be32		psid; 
	char		dest_hwaddr[ETH_ALEN]; 
};

struct wsmphdr {
	__u8	version;
	__be32	psid;
	__u8	chan;
	__u8	rate;
	__s8	txpow;
	__u8	elmid;
	__u8	len;
} __attribute__((packed));

static struct proto wsmp_proto = {
	.name		= "WSMP",
	.owner		= THIS_MODULE,
	.obj_size	= sizeof(struct wsmp_sock),
};

static inline struct wsmp_sock *wsmp_sk(const struct sock *sk)
{
	return (struct wsmp_sock *)sk;
}

static int wsmp_release(struct socket *sock)
{
	struct sock *sk = sock->sk;

	if (!sk) 
		return 0;

	write_lock_bh(&sklist_lock);
	sk_del_node_init(sk);
	write_unlock_bh(&sklist_lock);

	sock_orphan(sk);
	sock->sk = NULL;

	skb_queue_purge(&sk->sk_receive_queue);
	sk_refcnt_debug_release(sk);

	sock_put(sk);
	return 0;
}

static int wsmp_bind(struct socket *sock, struct sockaddr *uaddr, int addr_len)
{
	struct sockaddr_wsmp *addr = (struct sockaddr_wsmp *)uaddr;
	struct sock *sk = sock->sk;
	struct wsmp_sock *wo = wsmp_sk(sk);

	int ifindex = 0;
	unsigned int psid = 0;

	pr_notice("wsmp_bind ifindex: %d psid: %d\n", addr->wsmp_ifindex, addr->wsmp_psid);

	if (addr_len < sizeof(*addr))
		return -EINVAL;

	lock_sock(sk);
	wo->ifindex = ifindex;
	wo->psid = psid;
	release_sock(sk);

	return 0;
}

static int wsmp_getname(struct socket *sock, struct sockaddr *uaddr,
			int *uaddr_len, int peer)
{
	struct sockaddr_wsmp *addr = (struct sockaddr_wsmp *)uaddr;
	struct sock *sk = sock->sk;
	struct wsmp_sock *wo = wsmp_sk(sk);

	if (peer)
		return -EOPNOTSUPP;

	memset(addr, 0, sizeof(*addr));
	addr->wsmp_family  = AF_WSMP;
	addr->wsmp_ifindex = wo->ifindex;
	addr->wsmp_psid = wo->psid;

	*uaddr_len = sizeof(*addr);

	return 0;
}

static int wsmp_recvmsg(struct kiocb *iocb, struct socket *sock,
		        struct msghdr *msg, size_t len, int flags)
{
	struct sock *sk = sock->sk;
	struct sk_buff *skb;
	int copied = 0;
	int rc = -EINVAL;

	if (flags & ~MSG_DONTWAIT)
		goto out;

	skb = skb_recv_datagram(sk, flags, flags & MSG_DONTWAIT, &rc);
	if (!skb)
		goto out;

	copied = skb->len;

        rc = skb_copy_datagram_iovec(skb, 0, msg->msg_iov, copied);
	if (rc)
		goto out_free;

	sock_recv_ts_and_drops(msg, sk, skb);

	/* TODO: Fix ME */
	if (msg->msg_name) {
		msg->msg_namelen = sizeof(struct sockaddr);
		memcpy(msg->msg_name, skb->cb, msg->msg_namelen);
	}

out_free:
	skb_free_datagram(sk, skb);
out:
	return rc ? : copied;
}

static const struct proto_ops wsmp_proto_ops = {
	.family            = PF_WSMP,
	.owner             = THIS_MODULE,
	.release           = wsmp_release,
	.bind              = wsmp_bind,
	.connect           = sock_no_connect,
	.socketpair        = sock_no_socketpair,
	.accept            = sock_no_accept,
	.getname           = wsmp_getname,
	.poll              = datagram_poll,
	.ioctl             = sock_no_ioctl,
	.listen            = sock_no_listen,
	.shutdown          = sock_no_shutdown,
	.setsockopt        = sock_no_setsockopt,
	.getsockopt        = sock_no_getsockopt,
	.sendmsg           = sock_no_sendmsg,
	.recvmsg           = wsmp_recvmsg,
	.mmap              = sock_no_mmap,
	.sendpage	   = sock_no_sendpage,
};

static void wsmp_sock_destruct(struct sock *sk)
{
	skb_queue_purge(&sk->sk_error_queue);

	WARN_ON(atomic_read(&sk->sk_rmem_alloc));
	WARN_ON(atomic_read(&sk->sk_wmem_alloc));

	if (!sock_flag(sk, SOCK_DEAD)) {
		pr_err("Attempt to release alive packet socket: %p\n", sk);
		return;
	}

	sk_refcnt_debug_dec(sk);
}

static int wsmp_create(struct net *net, struct socket *sock,
		       int protocol, int kern)
{
	struct sock *sk;

	pr_notice("wsmp create %d\n", protocol);

	if (!net_eq(net, &init_net))
		return -EAFNOSUPPORT;

        if (sock->type != SOCK_DGRAM)
		return -ESOCKTNOSUPPORT;

        sk = sk_alloc(net, PF_WSMP, GFP_KERNEL, &wsmp_proto);
        if (!sk)
		return -ENOMEM;
                
	sock->ops = &wsmp_proto_ops;
	sock->state = SS_UNCONNECTED;

        sock_init_data(sock, sk);

	sk->sk_destruct = wsmp_sock_destruct;
	sk->sk_family = PF_WSMP;

	sk_refcnt_debug_inc(sk);

	write_lock_bh(&sklist_lock);
	sk_add_node(sk, &sklist);
	write_unlock_bh(&sklist_lock);

	return 0;
}

static const struct net_proto_family wsmp_family_ops = {
	.family		= PF_WSMP,
	.create		= wsmp_create,
	.owner		= THIS_MODULE,
};

static int wsmp_rcv(struct sk_buff *skb, struct net_device *dev,
		    struct packet_type *pt, struct net_device *orig_dev)
{
	struct sock *sk;

	if (skb->pkt_type == PACKET_OTHERHOST)
		goto drop;

	if (skb->len < WSMP_MIN_LEN || skb->data[0] != 2)
		goto drop;

	if (!net_eq(dev_net(dev), &init_net))
		goto drop;

	/* TODO: Fix ME */
	read_lock(&sklist_lock);
	sk_for_each(sk, &sklist) {
		if (sock_queue_rcv_skb(sk, skb) < 0)
			goto drop_unlock;
	}
	read_unlock(&sklist_lock);

	return NET_RX_SUCCESS;

drop_unlock:
	read_unlock(&sklist_lock);
drop:
        kfree_skb(skb);
	return NET_RX_DROP;
}

static struct packet_type wsmp_packet_type __read_mostly = {
	.type = cpu_to_be16(ETH_P_WSMP),
	.func = wsmp_rcv,
}; 

static int __init wsmp_init(void)
{
	int rc = -EINVAL;

	rc = proto_register(&wsmp_proto, 1);
	if (rc)
		goto out;

	rc = sock_register(&wsmp_family_ops);
	if (rc)
		goto out_proto;

	dev_add_pack(&wsmp_packet_type);
	return 0;

out_proto:
	proto_unregister(&wsmp_proto);
out:
	return rc;
}

static void __exit wsmp_exit(void)
{
	dev_remove_pack(&wsmp_packet_type);

	sock_unregister(PF_WSMP);
	proto_unregister(&wsmp_proto);
}

module_init(wsmp_init);
module_exit(wsmp_exit);

MODULE_DESCRIPTION("WAVE Short Message Protocol sockets");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Steve Kwon <steve.kwon@zenome.co.kr>");
MODULE_ALIAS_NETPROTO(PF_WSMP);
