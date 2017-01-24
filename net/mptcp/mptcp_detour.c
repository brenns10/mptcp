#include <linux/module.h>

#include <net/mptcp.h>
#include <net/mptcp_v4.h>

struct detour_priv {
	/* Worker struct for subflow establishment */
	struct work_struct subflow_work;
	struct mptcp_cb *mpcb;
};

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

/* General initialization of MPTCP_PM */
static int __init detour_register(void)
{
	BUILD_BUG_ON(sizeof(struct detour_priv) > MPTCP_PM_SIZE);

	if (mptcp_register_path_manager(&detour))
		goto exit;

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
