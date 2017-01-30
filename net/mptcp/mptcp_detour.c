#include <linux/module.h>
#include <linux/in.h>
#include <linux/list.h>
#include <linux/mutex.h>

#include <net/mptcp.h>
#include <net/mptcp_v4.h>
#include <net/genetlink.h>

struct detour_priv {
	/* Worker struct for subflow establishment */
	struct work_struct subflow_work;
	struct mptcp_cb *mpcb;
};

struct detour_entry {
	struct list_head entry_list;
	struct in_addr dip;
	__be16 dpt;
	struct in_addr rip;
	__be16 rpt;
};

static LIST_HEAD(entry_list);
DEFINE_MUTEX(entry_list_lock);

static int num_subflows __read_mostly = 2;
module_param(num_subflows, int, 0644);
MODULE_PARM_DESC(num_subflows, "choose the number of subflows per MPTCP connection");

/* Create all new subflows, by doing calls to mptcp_init_subsockets
 */
static void create_subflow_worker(struct work_struct *work)
{
	const struct detour_priv *pm_priv = container_of(
		work, struct detour_priv, subflow_work);
	struct mptcp_cb *mpcb = pm_priv->mpcb;
	struct sock *meta_sk = mpcb->meta_sk;
	int iter = 0;

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
			struct mptcp_loc4 loc;
			struct mptcp_rem4 rem;

			loc.addr.s_addr = inet_sk(meta_sk)->inet_saddr;
			loc.loc4_id = 1;
			loc.low_prio = 0;

			// 192.168.0.2
			rem.addr.s_addr = 0x0200a8c0;
			rem.port = inet_sk(meta_sk)->inet_dport;
			rem.rem4_id = 0;

			mptcp_init4_subsockets(meta_sk, &loc, &rem);
		}
		goto next_subflow;
	}

exit:
	release_sock(meta_sk);
	mutex_unlock(&mpcb->mpcb_mutex);
	sock_put(meta_sk);
}

static void detour_new_session(const struct sock *meta_sk)
{
	struct mptcp_cb *mpcb = tcp_sk(meta_sk)->mpcb;
	struct detour_priv *fmp = (struct detour_priv *)&mpcb->mptcp_pm[0];

	INIT_WORK(&fmp->subflow_work, create_subflow_worker);
	fmp->mpcb = mpcb;
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

enum {
	DETOUR_A_UNSPEC,
	DETOUR_A_DETOUR_IP,
	DETOUR_A_DETOUR_PORT,
	DETOUR_A_REMOTE_IP,
	DETOUR_A_REMOTE_PORT,
	__DETOUR_A_MAX,
};
#define DETOUR_A_MAX (__DETOUR_A_MAX - 1)

static struct nla_policy detour_genl_policy[DETOUR_A_MAX + 1] = {
	[DETOUR_A_DETOUR_IP] = { .type = NLA_U32 },
	[DETOUR_A_DETOUR_PORT] = { .type = NLA_U16 },
	[DETOUR_A_REMOTE_IP] = { .type = NLA_U32 },
	[DETOUR_A_REMOTE_PORT] = { .type = NLA_U16 },
};
static struct genl_family detour_genl_family = {
	.id = GENL_ID_GENERATE,
	.hdrsize = 0,
	.name = "DETOUR",
	.version = 1,
	.maxattr = DETOUR_A_MAX,
};

enum {
	DETOUR_E_MISSING_ARG = 1,
};

/* Declarations for command numbers */
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

/*
 * Callback for the DETOUR_C_ECHO command. Echo the DETOUR_A_MSG attribute to
 * the kernel log.
 */
static int detour_echo(struct sk_buff *skb, struct genl_info *info)
{
	struct detour_entry *entry;

	printk(KERN_INFO "mptcp DETOUR_ECHO: begin\n");
	mutex_lock_interruptible(&entry_list_lock);
	list_for_each_entry(entry, &entry_list, entry_list) {
		printk(KERN_INFO "mptcp DETOUR_ECHO: detour=%pI4:%u remote=%pI4:%u\n",
		       &entry->dip, entry->dpt, &entry->rip, entry->rpt);
	}
	mutex_unlock(&entry_list_lock);
	printk(KERN_INFO "mptcp DETOUR_ECHO: end\n");

	return 0;
}

/*
 * Stub for the ADD and DEL commands. Currently all this does is echo the
 * arguments to the kernel log.
 */
static int detour_add_del_stub(struct sk_buff *skb, struct genl_info *info)
{
	struct in_addr *detour_ip, *remote_ip;
	__be16 *detour_port, *remote_port;

	if (!info->attrs[DETOUR_A_DETOUR_IP] ||
	    !info->attrs[DETOUR_A_DETOUR_PORT] ||
	    !info->attrs[DETOUR_A_REMOTE_IP] ||
	    !info->attrs[DETOUR_A_REMOTE_PORT])
		return -DETOUR_E_MISSING_ARG;

	// The attribute data is located directly after the struct.
	detour_ip = (struct in_addr*)(info->attrs[DETOUR_A_DETOUR_IP] + 1);
	remote_ip = (struct in_addr*)(info->attrs[DETOUR_A_REMOTE_IP] + 1);
	detour_port = (__be16*)(info->attrs[DETOUR_A_DETOUR_PORT] + 1);
	remote_port = (__be16*)(info->attrs[DETOUR_A_REMOTE_PORT] + 1);

	printk(KERN_INFO "mptcp DETOUR_C_%s(stub): detour=%pI4:%u remote=%pI4:%u\n",
	       (info->genlhdr->cmd == DETOUR_C_ADD ? "ADD" : "DEL"),
	       detour_ip, *detour_port, remote_ip, *remote_port);
	return 0;
}

/*
 * Function which receives netlink messages and adds detour routes to our list
 * of available ones.
 */
static int detour_add(struct sk_buff *skb, struct genl_info *info)
{
	struct detour_entry *entry;

	if (!info->attrs[DETOUR_A_DETOUR_IP] ||
	    !info->attrs[DETOUR_A_DETOUR_PORT] ||
	    !info->attrs[DETOUR_A_REMOTE_IP] ||
	    !info->attrs[DETOUR_A_REMOTE_PORT])
		return -DETOUR_E_MISSING_ARG;

	entry = kmalloc(sizeof(struct detour_entry), GFP_KERNEL);
	if (!entry)
		return -ENOMEM;

	entry->dip = *(struct in_addr*)(info->attrs[DETOUR_A_DETOUR_IP] + 1);
	entry->rip = *(struct in_addr*)(info->attrs[DETOUR_A_REMOTE_IP] + 1);
	entry->dpt = *(__be16*)(info->attrs[DETOUR_A_DETOUR_PORT] + 1);
	entry->rpt = *(__be16*)(info->attrs[DETOUR_A_REMOTE_PORT] + 1);

	mutex_lock_interruptible(&entry_list_lock);
	list_add(&entry->entry_list, &entry_list);
	mutex_unlock(&entry_list_lock);

	printk(KERN_INFO "mptcp DETOUR_C_ADD: detour=%pI4:%u remote=%pI4:%u\n",
	       &entry->dip, entry->dpt, &entry->rip, entry->rpt);
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
		.doit = detour_add_del_stub,
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

	rc = genl_register_family_with_ops(&detour_genl_family,
	                                   detour_genl_ops);
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
