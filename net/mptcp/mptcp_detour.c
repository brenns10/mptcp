/**
 * MPTCP Detour Path Manager
 *
 * Creates paths through detour points in the Internet. Allows for detours to
 * occur through two mechanisms.
 *
 * The first mechanism is via NAT on a detour route. In order to set this up,
 * we must know the end host's IP and port, so we can request that the detour
 * create a tunnel for us. In order to do this, we have a netlink protocol which
 * we use to request detours. A user-space daemon listens to these requests,
 * requests NAT on some of the detour points it is aware of, and then reports
 * them back to the kernel when they are established. The kernel then wakes up
 * the path managers so they can establish new subflows.
 *
 * The second mechanism is via OpenVPN. In this case, the user-space daemon
 * establishes OpenVPN connections to whatever detours it would like, and
 * reports these connections to the kernel. When a MPTCP connection looks for a
 * new subflow, it looks through the OpenVPN connection list and selects one
 * adapter.
 */
#include <linux/module.h>
#include <linux/in.h>
#include <linux/list.h>
#include <linux/mutex.h>

#include <net/mptcp.h>
#include <net/mptcp_v4.h>
#include <net/genetlink.h>

/**
 * Path-manager specific data. Stored within struct mptcp_cb, so it is unique to
 * a specific MPTCP connection.
 * @subflow_work: used to enqueue the worker task
 * @mpcb: theoretically, we could get this with container_of
 * @detour_requesed: have we advertised to user space that we want a detour?
 * @next_id: the id we will use for the next address
 */
struct detour_priv {
	struct work_struct subflow_work;
	struct mptcp_cb *mpcb;
	bool detour_requested;
	int next_id;
};

/**
 * This struct contains a NAT detour record.
 * @entry_list: list head for entry_list
 * @dip, @dpt: detour ip and port (TODO IPv6 support)
 * @rip, @rpt: remote ip and port
 */
struct nat_entry {
	struct list_head entry_list;
	struct in_addr dip;
	__be16 dpt;
	struct in_addr rip;
	__be16 rpt;
};

/**
 * Tests for equality of two NAT entries. There is much double evaluation in
 * this macro, so don't be stupid!
 */
#define nat_entry_eq(e1, e2) (                                          \
	(e1)->dip.s_addr == (e2)->dip.s_addr &&                         \
	(e1)->dpt == (e2)->dpt &&                                       \
	(e1)->rip.s_addr == (e2)->rip.s_addr &&                         \
	(e1)->rpt == (e2)->rpt                                          \
		)

/**
 * This struct contains a VPN record. It's quite simple really.
 * @vpn_list: list head for vpn_list
 * @ifname: name of interface (resolved at runtime)
 */
struct vpn_entry {
	struct list_head vpn_list;
	char ifname[IFNAMSIZ];
};

/**
 * Contains data specific to each network namespace.
 * @priv_list: list of MPTCP pm-priv objects in this namespace
 * @priv_list_lock: protects the above list
 * @entry_list: list of NAT detour entries
 * @entry_list_lock: protects the above list
 * @vpn_list: list of VPN detour entries
 * @vpn_list_lock: protects the above list
 */
struct detour_ns {
	struct list_head entry_list;
	struct mutex entry_list_lock;
	struct list_head vpn_list;
	struct mutex vpn_list_lock;
};


/**
 * Configurable limit for how many subflows we should allow a detoured
 * connection to have.
 */
static int num_subflows __read_mostly = 2;
module_param(num_subflows, int, 0644);
MODULE_PARM_DESC(num_subflows, "choose the number of subflows per MPTCP connection");

/**
 * "Attributes" for our generic netlink protocol.
 */
enum {
	DETOUR_A_UNSPEC,
	DETOUR_A_DETOUR_IP,
	DETOUR_A_DETOUR_PORT,
	DETOUR_A_REMOTE_IP,
	DETOUR_A_REMOTE_PORT,
	DETOUR_A_IFNAME,
	__DETOUR_A_MAX,
};
#define DETOUR_A_MAX (__DETOUR_A_MAX - 1)

static struct nla_policy detour_genl_policy[DETOUR_A_MAX + 1] = {
	[DETOUR_A_DETOUR_IP] = { .type = NLA_U32 },
	[DETOUR_A_DETOUR_PORT] = { .type = NLA_U16 },
	[DETOUR_A_REMOTE_IP] = { .type = NLA_U32 },
	[DETOUR_A_REMOTE_PORT] = { .type = NLA_U16 },
	[DETOUR_A_IFNAME] = { .type = NLA_STRING, .len=IFNAMSIZ },
};

static struct genl_family detour_genl_family = {
	.id = GENL_ID_GENERATE,
	.hdrsize = 0,
	.name = "DETOUR",
	.version = 1,
	.maxattr = DETOUR_A_MAX,
	.netnsok = true,
};

/**
 * Error definitions for our generic netlink family.
 */
enum {
	DETOUR_E_MISSING_ARG = 1,
};

/**
 * This is the multicast group we send our requests to.
 */
static struct genl_multicast_group detour_genl_group[] = {
	{ .name="detour_req" },
};

/**
 * Commands for our generic netlink protocol.
 */
enum {
	DETOUR_C_UNSPEC,
	DETOUR_C_ECHO,   // testing
	DETOUR_C_ADD,    // add detour route
	DETOUR_C_DEL,    // delete detour route
	DETOUR_C_REQ,    // request a detour route
	DETOUR_C_STAT,   // give stats on a detour
	__DETOUR_C_MAX,
};
#define DETOUR_C_MAX (__DETOUR_C_MAX - 1)

static struct detour_ns *detour_get_ns(const struct net *net)
{
	return (struct detour_ns *)net->mptcp.path_managers[MPTCP_PM_DETOUR];
}

/**
 * Search the entry_list for a NAT that matches the given IP address and port.
 */
static struct nat_entry *choose_nat(struct detour_ns *ns, __be32 s_addr,
                                    __be16 port)
{
	struct nat_entry *entry;
	pr_debug("Finding matching detour for %pI4:%u\n", &s_addr, ntohs(port));
	mutex_lock(&ns->entry_list_lock);
	list_for_each_entry(entry, &ns->entry_list, entry_list) {
		pr_debug("Checking detour=%pI4:%u remote=%pI4:%u\n", &entry->dip,
		         ntohs(entry->rpt), &entry->rip, ntohs(entry->rpt));
		if (entry->rip.s_addr == s_addr && entry->rpt == port) {
			mutex_unlock(&ns->entry_list_lock);
			pr_debug("yes\n");
			// TODO move to end of list
			return entry;
		}
		pr_debug("no\n");
	}
	mutex_unlock(&ns->entry_list_lock);
	return NULL;
}

/**
 * Choose a VPN to use. Right now, this simply takes the vpn from the list and
 * moves it to the end, and then returns it. That way we're always rotating
 * through vpns. Returns NULL if we have no vpn.
 */
static struct net_device *choose_vpn(struct detour_ns *ns, struct net *net)
{
	struct vpn_entry *vpn;
	struct net_device *netdev;
	mutex_lock(&ns->vpn_list_lock);
	if (list_empty(&ns->vpn_list)) {
		mutex_unlock(&ns->vpn_list_lock);
		return NULL;
	}
	list_for_each_entry(vpn, &ns->vpn_list, vpn_list) {
		pr_debug("Searching for vpn iface=%s in netns...\n",
		         vpn->ifname);
		netdev = dev_get_by_name(net, vpn->ifname);
		if (netdev) {
			pr_debug("found vpn iface=%s with ifindex=%d\n",
			         vpn->ifname, netdev->ifindex);
			dev_put(netdev);
			return netdev;
		}
	}
	mutex_unlock(&ns->vpn_list_lock);

	return NULL;
}

/**
 * Take an interface name and look up its if_idx.
 */

/**
 * Requests a detour for our new mptcp session. This sends a netlink message
 * to whatever user-space daemons are listening, asking them to create a detour
 * to the given IPv4 address and port.
 */
static void request_detour(struct net *net, __be32 s_addr, __be16 port)
{
	void *head;
	int rc;
	struct sk_buff *buf = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
	pr_debug("request_detour()\n");
	if (!buf)
		goto alloc_failure;
	head = genlmsg_put(buf, 0, 0, &detour_genl_family, 0,
	                   DETOUR_C_REQ);
	if (!head)
		goto failure;
	rc = nla_put_be32(buf, DETOUR_A_REMOTE_IP, s_addr);
	if (rc != 0)
		goto failure;
	rc = nla_put_be16(buf, DETOUR_A_REMOTE_PORT, port);
	if (rc != 0)
		goto failure;
	genlmsg_end(buf, head);
	genlmsg_multicast_netns(&detour_genl_family, net, buf, 0, 0, 0);
	// I don't think we need to free the sk_buff, as the network driver
	// *should* do that for us.
	return;
failure:
	kfree_skb(buf);
alloc_failure:
	pr_alert("mptcp: failed to create detour request\n");
}

/**
 * This function is the *main* routine for the detour worker. It is the task
 * that is enqueued into the MPTCP work queue. *Heavily* based on the ndiffports
 * create_subflow_worker.
 */
static void create_subflow_worker(struct work_struct *work)
{
	struct detour_priv *pm_priv = container_of(
		work, struct detour_priv, subflow_work);
	struct mptcp_cb *mpcb = pm_priv->mpcb;
	struct sock *meta_sk = mpcb->meta_sk;
	struct net *net = sock_net(meta_sk);
	struct detour_ns *detour_ns = detour_get_ns(net);
	int iter = 0;
	pr_debug("detour create_subflow_worker() begins\n");

	if (!pm_priv->detour_requested) {
		request_detour(net, inet_sk(meta_sk)->inet_daddr,
		               inet_sk(meta_sk)->inet_dport);
		pm_priv->detour_requested = true;
	}

next_subflow:
	if (iter) {
		release_sock(meta_sk);
		mutex_unlock(&mpcb->mpcb_mutex);

		cond_resched();
	}
	mutex_lock(&mpcb->mpcb_mutex);
	lock_sock_nested(meta_sk, SINGLE_DEPTH_NESTING);

	iter++;

	if (sock_flag(meta_sk, SOCK_DEAD))
		goto exit;

	if (mpcb->master_sk &&
	    !tcp_sk(mpcb->master_sk)->mptcp->fully_established)
		goto exit;

	if (num_subflows > iter && num_subflows > mpcb->cnt_subflows) {
		if (meta_sk->sk_family == AF_INET ||
		    mptcp_v6_is_v4_mapped(meta_sk)) {
			struct nat_entry *detour;
			struct net_device *dev = choose_vpn(detour_ns, net);
			if (dev) {
				struct mptcp_loc4 loc;
				struct mptcp_rem4 rem;

				// this selects the appropriate source address
				// for our net_device
				loc.addr.s_addr = inet_select_addr(
					dev, inet_sk(meta_sk)->inet_daddr,
					RT_SCOPE_UNIVERSE);
				pr_debug("selected addr=%pI4\n", &loc.addr.s_addr);
				loc.loc4_id = pm_priv->next_id++;
				loc.low_prio = 0;
				loc.if_idx = dev->ifindex;

				rem.addr.s_addr = inet_sk(meta_sk)->inet_daddr;
				rem.port = inet_sk(meta_sk)->inet_dport;
				rem.rem4_id = 0;

				mptcp_init4_subsockets(meta_sk, &loc, &rem);
				goto next_subflow; // skip nat detour
			}

			detour = choose_nat(detour_ns,
			                    inet_sk(meta_sk)->inet_daddr,
			                    inet_sk(meta_sk)->inet_dport);
			if (detour) {
				struct mptcp_loc4 loc;
				struct mptcp_rem4 rem;

				loc.addr.s_addr = inet_sk(meta_sk)->inet_saddr;
				loc.loc4_id = pm_priv->next_id++;
				loc.low_prio = 0;
				loc.if_idx = 0;

				// hack hack hack
				rem.addr.s_addr = detour->dip.s_addr;
				rem.port = detour->dpt;
				rem.rem4_id = 0;

				mptcp_init4_subsockets(meta_sk, &loc, &rem);
			}
		}
		goto next_subflow;
	}

exit:
	release_sock(meta_sk);
	mutex_unlock(&mpcb->mpcb_mutex);
	sock_put(meta_sk);
	pr_debug("detour create_subflow_worker() ends\n");
}

/* Called when MPTCP connection is fully established.
 * NB: called from softirq context (no sleeping)
 */
static void detour_new_session(const struct sock *meta_sk)
{
	struct mptcp_cb *mpcb = tcp_sk(meta_sk)->mpcb;
	struct detour_priv *fmp = (struct detour_priv *)&mpcb->mptcp_pm[0];

	INIT_WORK(&fmp->subflow_work, create_subflow_worker);
	fmp->mpcb = mpcb;
	fmp->detour_requested = false; // we will do this soon
	fmp->next_id = 1;
}

static void detour_create_subflows(struct sock *meta_sk)
{
	const struct mptcp_cb *mpcb = tcp_sk(meta_sk)->mpcb;
	struct detour_priv *pm_priv = (struct detour_priv *)&mpcb->mptcp_pm[0];

	if (mpcb->infinite_mapping_snd || mpcb->infinite_mapping_rcv ||
	    mpcb->send_infinite_mapping || mpcb->server_side ||
	    sock_flag(meta_sk, SOCK_DEAD))
		return;

	if (!work_pending(&pm_priv->subflow_work)) {
		sock_hold(meta_sk);
		queue_work(mptcp_wq, &pm_priv->subflow_work);
	}
}

static int detour_get_local_id(sa_family_t family, union inet_addr *addr,
                               struct net *net, bool *low_prio)
{
	return 0;
	// TODO return an appropriate id for each detour
	// seems important...
}

static struct mptcp_pm_ops detour __read_mostly = {
	.new_session = detour_new_session,
	.fully_established = detour_create_subflows,
	.get_local_id = detour_get_local_id,
	.name = "detour",
	.owner = THIS_MODULE,
};

/* ------------------------------------------------------------
   Netlink address family
   ------------------------------------------------------------ */

/*
 * Callback for the DETOUR_C_ECHO command. Echo the DETOUR_A_MSG attribute to
 * the kernel log.
 * TODO: this would be better represented by a seq file
 */
static int detour_echo(struct sk_buff *skb, struct genl_info *info)
{
	struct nat_entry *entry;
	struct vpn_entry *vpn;
	struct net *net = genl_info_net(info);
	struct detour_ns *ns = detour_get_ns(net);

	pr_debug("mptcp DETOUR_ECHO: begin\n");
	mutex_lock(&ns->entry_list_lock);
	list_for_each_entry(entry, &ns->entry_list, entry_list) {
		pr_debug("mptcp DETOUR_ECHO: detour=%pI4:%u remote=%pI4:%u\n",
		         &entry->dip, ntohs(entry->dpt), &entry->rip,
		         ntohs(entry->rpt));
	}
	mutex_unlock(&ns->entry_list_lock);
	mutex_lock(&ns->vpn_list_lock);
	list_for_each_entry(vpn, &ns->vpn_list, vpn_list) {
		pr_debug("mptcp DETOUR_ECHO: vpn ifname=%s\n",
		         vpn->ifname);
	}
	mutex_unlock(&ns->vpn_list_lock);
	pr_debug("mptcp DETOUR_ECHO: end\n");

	return 0;
}

/*
 * Function which receives netlink messages and adds detour routes to our list
 * of available ones.
 */
static int detour_add(struct sk_buff *skb, struct genl_info *info)
{
	struct nat_entry *entry, *nat_iter;
	struct vpn_entry *vpn, *vpn_iter;
	struct net *net = genl_info_net(info);
	struct detour_ns *ns = detour_get_ns(net);

	if (info->attrs[DETOUR_A_IFNAME]) {
		vpn = kmalloc(sizeof(struct vpn_entry), GFP_KERNEL);
		if (!vpn)
			return -ENOMEM;

		nla_strlcpy(vpn->ifname, info->attrs[DETOUR_A_IFNAME], IFNAMSIZ);

		/* Only add unique VPN entries. */
		mutex_lock(&ns->vpn_list_lock);
		list_for_each_entry(vpn_iter, &ns->vpn_list, vpn_list) {
			if (nla_strcmp(info->attrs[DETOUR_A_IFNAME], vpn_iter->ifname) == 0) {
				kfree(vpn);
				mutex_unlock(&ns->vpn_list_lock);
				pr_debug("mptcp detour: duplicate vpn, ignoring\n");
				return 0;
			}
		}

		pr_debug("Adding \"%s\" to the entry list.\n", vpn->ifname);
		list_add_tail(&vpn->vpn_list, &ns->vpn_list);
		mutex_unlock(&ns->vpn_list_lock);
	} else if (info->attrs[DETOUR_A_DETOUR_IP] &&
	           info->attrs[DETOUR_A_DETOUR_PORT] &&
	           info->attrs[DETOUR_A_REMOTE_IP] &&
	           info->attrs[DETOUR_A_REMOTE_PORT]) {

		entry = kmalloc(sizeof(struct nat_entry), GFP_KERNEL);
		if (!entry)
			return -ENOMEM;

		entry->dip.s_addr = nla_get_in_addr(info->attrs[DETOUR_A_DETOUR_IP]);
		entry->rip.s_addr = nla_get_in_addr(info->attrs[DETOUR_A_REMOTE_IP]);
		entry->dpt = nla_get_be16(info->attrs[DETOUR_A_DETOUR_PORT]);
		entry->rpt = nla_get_be16(info->attrs[DETOUR_A_REMOTE_PORT]);

		/* Only add unique NAT entries. */
		mutex_lock(&ns->entry_list_lock);
		list_for_each_entry(nat_iter, &ns->entry_list, entry_list) {
			if (nat_entry_eq(nat_iter, entry)) {
				kfree(entry);
				mutex_unlock(&ns->entry_list_lock);
				pr_debug("mptcp detour: duplicate nat, ignoring\n");
				return 0;
			}
		}

		pr_debug("Adding a detour to the entry list.\n");
		list_add_tail(&entry->entry_list, &ns->entry_list);
		mutex_unlock(&ns->entry_list_lock);
	} else {
		return -DETOUR_E_MISSING_ARG;
	}

	// TODO: (next commit), rather than wake every queue, simply iterate
	// over every MPTCP socket in the netns and apply it to all that can use
	// it. This is a heavy operation, but in the system call context, the
	// processes should be aware that this could happen.
	return 0;
}

/**
 * Function for deleting detour routes from our list. Called via netlink from
 * userspace. Does not close any subflows over the detour.
 */
static int detour_del(struct sk_buff *skb, struct genl_info *info)
{
	struct net *net = genl_info_net(info);
	struct detour_ns *ns = detour_get_ns(net);

	if (info->attrs[DETOUR_A_IFNAME]) {
		struct vpn_entry *entry, *next;

		mutex_lock(&ns->vpn_list_lock);
		list_for_each_entry_safe(entry, next, &ns->vpn_list, vpn_list) {
			if (nla_strcmp(info->attrs[DETOUR_A_IFNAME], entry->ifname) == 0) {
				list_del(&entry->vpn_list);
			}
		}
		mutex_unlock(&ns->vpn_list_lock);
	} else if (info->attrs[DETOUR_A_DETOUR_IP] &&
	           info->attrs[DETOUR_A_DETOUR_PORT] &&
	           info->attrs[DETOUR_A_REMOTE_IP] &&
	           info->attrs[DETOUR_A_REMOTE_PORT]){
		struct nat_entry *entry, *next;
		struct nat_entry del;

		del.dip.s_addr = nla_get_in_addr(info->attrs[DETOUR_A_DETOUR_IP]);
		del.rip.s_addr = nla_get_in_addr(info->attrs[DETOUR_A_REMOTE_IP]);
		del.dpt = nla_get_be16(info->attrs[DETOUR_A_DETOUR_PORT]);
		del.rpt = nla_get_be16(info->attrs[DETOUR_A_REMOTE_PORT]);

		mutex_lock(&ns->entry_list_lock);
		list_for_each_entry_safe(entry, next, &ns->entry_list, entry_list) {
			if (nat_entry_eq(entry, &del))
				list_del(&entry->entry_list);
		}
		mutex_unlock(&ns->entry_list_lock);


	} else {
		return -DETOUR_E_MISSING_ARG;
	}

	return 0;
}

/* Register functions for operations. */
static struct genl_ops detour_genl_ops[] = {
	{
		.cmd = DETOUR_C_ECHO,
		.flags = 0,
		.policy = detour_genl_policy,
		.doit = detour_echo,
		.dumpit = NULL,
	},
	{
		.cmd = DETOUR_C_ADD,
		.flags = 0,
		.policy = detour_genl_policy,
		.doit = detour_add,
		.dumpit = NULL,
	},
	{
		.cmd = DETOUR_C_DEL,
		.flags = 0,
		.policy = detour_genl_policy,
		.doit = detour_del,
		.dumpit = NULL,
	},
};

/**
 * Called when a new netns is created. This initializes namespace wide data
 * structures, which mainly consists of the detour list.
 */
static int mptcp_detour_init_net(struct net *net)
{
	struct detour_ns *ns;
	ns = kmalloc(sizeof(*ns), GFP_KERNEL);

	if (!ns)
		return -ENOBUFS;

	mutex_init(&ns->entry_list_lock);
	mutex_init(&ns->vpn_list_lock);
	INIT_LIST_HEAD(&ns->entry_list);
	INIT_LIST_HEAD(&ns->vpn_list);

	net->mptcp.path_managers[MPTCP_PM_DETOUR] = ns;

	return 0;
}

/**
 * Called when a netns is being destroyed. My assumption is that all sockets
 * within the netns are now dead, and so we need to clean up all memory used.
 */
static void mptcp_detour_exit_net(struct net *net)
{
	struct nat_entry *nat, *nat_tmp;
	struct vpn_entry *vpn, *vpn_tmp;
	struct detour_ns *ns = detour_get_ns(net);

	// hopefully all subflow workers are gone!

	mutex_lock(&ns->entry_list_lock);
	list_for_each_entry_safe(nat, nat_tmp, &ns->entry_list, entry_list) {
		list_del(&nat->entry_list);
		kfree(nat);
	}
	mutex_unlock(&ns->entry_list_lock);

	mutex_lock(&ns->vpn_list_lock);
	list_for_each_entry_safe(vpn, vpn_tmp, &ns->vpn_list, vpn_list) {
		list_del(&vpn->vpn_list);
		kfree(vpn);
	}
	mutex_unlock(&ns->vpn_list_lock);

	kfree(ns);
}

/**
 * Detour path manager is netns aware. The detour entries created are only used
 * within the namespace they are created, and they only wake matching MPTCP
 * path manager threads within the namespace. This is pretty important for
 * testing with a tool like mininet, but it is also important just for the sake
 * of correctness in the modern kernel.
 */
static struct pernet_operations detour_ops = {
	.init = mptcp_detour_init_net,
	.exit = mptcp_detour_exit_net,
};

/**
 * General initialization of detour path manager. Registers a Generic Netlink
 * family as well as a pernet subsys and finally the MPTCP path manager.
 */
static int __init detour_register(void)
{
	int rc;
	BUILD_BUG_ON(sizeof(struct detour_priv) > MPTCP_PM_SIZE);

	rc = register_pernet_subsys(&detour_ops);
	if (rc)
		goto pernet_subsys_fail;

	rc = genl_register_family_with_ops_groups(&detour_genl_family,
	                                          detour_genl_ops,
	                                          detour_genl_group);
	if (rc)
		goto genl_family_fail;

	rc = mptcp_register_path_manager(&detour);
	if (rc)
		goto path_manager_fail;

	printk(KERN_INFO "mptcp_detour initialized with family=%d\n",
		detour_genl_family.id);

	return 0;

path_manager_fail:
	genl_unregister_family(&detour_genl_family);
genl_family_fail:
	unregister_pernet_subsys(&detour_ops);
pernet_subsys_fail:
	return -1;
}

static void detour_unregister(void)
{
	mptcp_unregister_path_manager(&detour);
	genl_unregister_family(&detour_genl_family);
	unregister_pernet_subsys(&detour_ops);
}

module_init(detour_register);
module_exit(detour_unregister);

MODULE_AUTHOR("Stephen Brennan");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("DETOUR MPTCP");
MODULE_VERSION("0.1");
