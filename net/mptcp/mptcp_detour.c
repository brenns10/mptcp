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
 * The second (upcoming) mechanism is via OpenVPN. In this case, the user-space
 * daemon establishes OpenVPN connections to whatever detours it would like,
 * and reports these connections to the kernel. When a MPTCP connection looks
 * for a new subflow, it looks through the OpenVPN connection list and selects
 * one adapter.
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
 * @priv_list: links all MPTCP connections using detour path_manager into a list
 * @detour_requesed: have we advertised to user space that we want a detour?
 */
struct detour_priv {
	struct work_struct subflow_work;
	struct mptcp_cb *mpcb;
	struct list_head priv_list;
	bool detour_requested;
	int next_id;
};

/**
 * Priv list contains (essentially) each MPTCP connection using this path
 * manager. This is so we can loop through each MPTCP connection and queue work
 * when we receive a new detour advertisement. For better performance, in the
 * future we could use a hash table to identify the affected connections.
 */
static LIST_HEAD(priv_list);
DEFINE_MUTEX(priv_list_lock);

/**
 * This struct contains a detour record.
 * @entry_list: list head for entry_list
 * @dip, @dpt: detour ip and port (TODO IPv6 support)
 * @rip, @rpt: remote ip and port
 */
struct detour_entry {
	struct list_head entry_list;
	struct in_addr dip;
	__be16 dpt;
	struct in_addr rip;
	__be16 rpt;
};

/**
 * Contains every detour entry we've received from userspace. This is a bit of
 * a hack... we probably do not need to keep these around. Will need a mechanism
 * to remove them, otherwise they could clog up memory.
 */
static LIST_HEAD(entry_list);
DEFINE_MUTEX(entry_list_lock);

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
 * Again, this contains every vpn entry we've received from userspace.
 */
static LIST_HEAD(vpn_list);
DEFINE_MUTEX(vpn_list_lock);

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

/**
 * Search the entry_list for a detour that matches the given IP address and
 * port.
 */
static struct detour_entry *get_matching_detour(__be32 s_addr,
                                                __be16 port)
{
	struct detour_entry *entry;
	pr_debug("Finding matching detour for %pI4:%u\n", &s_addr, port);
	mutex_lock(&entry_list_lock);
	list_for_each_entry(entry, &entry_list, entry_list) {
		pr_debug("Checking detour=%pI4:%u remote=%pI4:%u\n", &entry->dip,
		         entry->rpt, &entry->rip, entry->rpt);
		if (entry->rip.s_addr == s_addr && entry->rpt == port) {
			mutex_unlock(&entry_list_lock);
			pr_debug("yes\n");
			// TODO move to end of list
			return entry;
		}
		pr_debug("no\n");
	}
	mutex_unlock(&entry_list_lock);
	return NULL;
}

/**
 * Choose a VPN to use. Right now, this simply takes the vpn from the list and
 * moves it to the end, and then returns it. That way we're always rotating
 * through vpns. Returns NULL if we have no vpn.
 */
static struct net_device *choose_vpn(struct sock *meta_sk)
{
	struct vpn_entry *vpn;
	struct net_device *netdev;
	mutex_lock(&vpn_list_lock);
	if (list_empty(&vpn_list)) {
		mutex_unlock(&vpn_list_lock);
		return NULL;
	}
	list_for_each_entry(vpn, &vpn_list, vpn_list) {
		pr_debug("Searching for vpn iface=%s in netns...\n",
		         vpn->ifname);
		netdev = dev_get_by_name(sock_net(meta_sk), vpn->ifname);
		if (netdev) {
			pr_debug("found vpn iface=%s with ifindex=%d\n",
			         vpn->ifname, netdev->ifindex);
			dev_put(netdev);
			return netdev;
		}
	}
	mutex_unlock(&vpn_list_lock);

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
static void request_detour(__be32 s_addr, __be16 port)
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
	genlmsg_multicast(&detour_genl_family, buf, 0, 0, 0);
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
	int iter = 0;
	pr_debug("detour create_subflow_worker() begins\n");

	if (!pm_priv->detour_requested) {
		request_detour(inet_sk(meta_sk)->inet_daddr,
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

	if (sock_flag(meta_sk, SOCK_DEAD)) {
		list_del(&pm_priv->priv_list);
		goto exit;
	}

	if (mpcb->master_sk &&
	    !tcp_sk(mpcb->master_sk)->mptcp->fully_established)
		goto exit;

	if (num_subflows > iter && num_subflows > mpcb->cnt_subflows) {
		if (meta_sk->sk_family == AF_INET ||
		    mptcp_v6_is_v4_mapped(meta_sk)) {
			struct detour_entry *detour;
			struct net_device *dev = choose_vpn(meta_sk);
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

			detour = get_matching_detour(inet_sk(meta_sk)->inet_daddr,
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
	list_add(&fmp->priv_list, &priv_list);
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
	struct detour_entry *entry;
	struct vpn_entry *vpn;

	printk(KERN_INFO "mptcp DETOUR_ECHO: begin\n");
	mutex_lock(&entry_list_lock);
	list_for_each_entry(entry, &entry_list, entry_list) {
		printk(KERN_INFO "mptcp DETOUR_ECHO: detour=%pI4:%u remote=%pI4:%u\n",
		       &entry->dip, entry->dpt, &entry->rip, entry->rpt);
	}
	mutex_unlock(&entry_list_lock);
	mutex_lock(&vpn_list_lock);
	list_for_each_entry(vpn, &vpn_list, vpn_list) {
		printk(KERN_INFO "mptcp DETOUR_ECHO: vpn ifname=%s\n",
		       vpn->ifname);
	}
	mutex_unlock(&vpn_list_lock);
	printk(KERN_INFO "mptcp DETOUR_ECHO: end\n");

	return 0;
}

/*
 * Function which receives netlink messages and adds detour routes to our list
 * of available ones.
 */
static int detour_add(struct sk_buff *skb, struct genl_info *info)
{
	struct detour_entry *entry;
	struct vpn_entry *vpn;
	struct detour_priv *priv;

	if (info->attrs[DETOUR_A_IFNAME]) {
		vpn = kmalloc(sizeof(struct vpn_entry), GFP_KERNEL);
		if (!vpn)
			return -ENOMEM;

		nla_strlcpy(vpn->ifname, info->attrs[DETOUR_A_IFNAME], IFNAMSIZ);

		pr_debug("Adding \"%s\" to the entry list.\n", vpn->ifname);
		mutex_lock(&vpn_list_lock);
		list_add(&vpn->vpn_list, &vpn_list);
		mutex_unlock(&vpn_list_lock);
	} else if (info->attrs[DETOUR_A_DETOUR_IP] &&
	           info->attrs[DETOUR_A_DETOUR_PORT] &&
	           info->attrs[DETOUR_A_REMOTE_IP] &&
	           info->attrs[DETOUR_A_REMOTE_PORT]) {

		entry = kmalloc(sizeof(struct detour_entry), GFP_KERNEL);
		if (!entry)
			return -ENOMEM;

		entry->dip.s_addr = nla_get_in_addr(info->attrs[DETOUR_A_DETOUR_IP]);
		entry->rip.s_addr = nla_get_in_addr(info->attrs[DETOUR_A_REMOTE_IP]);
		entry->dpt = nla_get_be16(info->attrs[DETOUR_A_DETOUR_PORT]);
		entry->rpt = nla_get_be16(info->attrs[DETOUR_A_REMOTE_PORT]);

		pr_debug("Adding a detour to the entry list.\n");
		mutex_lock(&entry_list_lock);
		list_add(&entry->entry_list, &entry_list);
		mutex_unlock(&entry_list_lock);
	} else {
		return -DETOUR_E_MISSING_ARG;
	}

	mutex_lock(&priv_list_lock);
	list_for_each_entry(priv, &priv_list, priv_list) {
		// TODO check whether detour applies, THEN wake
		if (!work_pending(&priv->subflow_work)) {
			sock_hold(priv->mpcb->meta_sk);
			queue_work(mptcp_wq, &priv->subflow_work);
		}
	}
	mutex_unlock(&priv_list_lock);

	return 0;
}

/*
 * Function for deleting detour routes from our list.
 */
static int detour_del(struct sk_buff *skb, struct genl_info *info)
{
	if (info->attrs[DETOUR_A_IFNAME]) {
		struct vpn_entry *entry, *next;

		mutex_lock(&vpn_list_lock);
		list_for_each_entry_safe(entry, next, &vpn_list, vpn_list) {
			if (nla_strcmp(info->attrs[DETOUR_A_IFNAME], entry->ifname) == 0) {
				list_del(&entry->vpn_list);
			}
		}
		mutex_unlock(&vpn_list_lock);
	} else if (info->attrs[DETOUR_A_DETOUR_IP] &&
	           info->attrs[DETOUR_A_DETOUR_PORT] &&
	           info->attrs[DETOUR_A_REMOTE_IP] &&
	           info->attrs[DETOUR_A_REMOTE_PORT]){
		struct detour_entry *entry, *next;
		struct in_addr detour_ip, remote_ip;
		__be16 detour_port, remote_port;

		detour_ip.s_addr = nla_get_in_addr(info->attrs[DETOUR_A_DETOUR_IP]);
		remote_ip.s_addr = nla_get_in_addr(info->attrs[DETOUR_A_REMOTE_IP]);
		detour_port = nla_get_be16(info->attrs[DETOUR_A_DETOUR_PORT]);
		remote_port = nla_get_be16(info->attrs[DETOUR_A_REMOTE_PORT]);

		mutex_lock(&entry_list_lock);
		list_for_each_entry_safe(entry, next, &entry_list, entry_list) {
			if (entry->dip.s_addr == detour_ip.s_addr &&
			    entry->dpt == detour_port &&
			    entry->rip.s_addr == remote_ip.s_addr &&
			    entry->rpt == remote_port)
				list_del(&entry->entry_list);
		}
		mutex_unlock(&entry_list_lock);


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

/*
 * General initialization of detour path manager.
 * 1. Registers the path manager struct with MPTCP.
 * 2. Registers a General Netlink address family for communicating with a user
 *    space daemon that discovers and requests detours.
 */
static int __init detour_register(void)
{
	int rc;
	BUILD_BUG_ON(sizeof(struct detour_priv) > MPTCP_PM_SIZE);

	printk(KERN_INFO "mptcp_detour initializing...\n");

	if (mptcp_register_path_manager(&detour))
		goto exit;

	rc = genl_register_family_with_ops_groups(&detour_genl_family,
	                                          detour_genl_ops,
	                                          detour_genl_group);
	if (rc != 0)
		goto exit;

	printk(KERN_INFO "mptcp_detour initialized with family=%d\n",
		detour_genl_family.id);

	return 0;

exit:
	return -1;
}

static void detour_unregister(void)
{
	mptcp_unregister_path_manager(&detour);
}

module_init(detour_register);
module_exit(detour_unregister);

MODULE_AUTHOR("Stephen Brennan");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("DETOUR MPTCP");
MODULE_VERSION("0.1");
