/*
 * libwebsockets-test-server - libwebsockets test implementation
 *
 * Written in 2010-2021 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * The person who associated a work with this deed has dedicated
 * the work to the public domain by waiving all of his or her rights
 * to the work worldwide under copyright law, including all related
 * and neighboring rights, to the extent allowed by law. You can copy,
 * modify, distribute and perform the work, even for commercial purposes,
 * all without asking permission.
 *
 * The test apps are intended to be adapted for use in your code, which
 * may be proprietary.  So unlike the library itself, they are licensed
 * Public Domain.
 *
 * Scrapeable OpenMetrics metrics (compatible with Prometheus)
 */

#define LWS_DLL
#define LWS_INTERNAL
#include <libwebsockets.h>
#include <string.h>
#include <stdlib.h>

struct pss {
	struct lwsac *ac;	/* the translated metrics, one ac per line */
	struct lwsac *walk;	/* iterator for ac when writing */
	size_t tot;		/* content-length computation */
};

static void
prometheus_san(char *nm, size_t nl)
{
	size_t m;

	/* Prometheus has a very restricted token charset */

	for (m = 0; m < nl; m++)
		if ((nm[m] < 'A' || nm[m] > 'Z') &&
		    (nm[m] < 'a' || nm[m] > 'z') &&
		    (nm[m] < '0' || nm[m] > '9') &&
		    nm[m] != '_')
			nm[m] = '_';
}

static int
lws_metrics_om_format_agg(lws_metric_pub_t *pub, const char *nm, lws_usec_t now,
			  int gng, char *buf, size_t len)
{
	const char *_gng = gng ? "_nogo" : "_go";
	char *end = buf + len - 1, *obuf = buf;

	if (pub->flags & LWSMTFL_REPORT_ONLY_GO)
		_gng = "";

	if (!(pub->flags & LWSMTFL_REPORT_MEAN)) {
		/* only the sum is meaningful */
		if (pub->flags & LWSMTFL_REPORT_DUTY_WALLCLOCK_US) {
			buf += lws_snprintf(buf, lws_ptr_diff_size_t(end, buf),
				"%s_count %u\n%s_us_sum %llu\n%s_us_period %llu\n",
				nm, (unsigned int)pub->u.agg.count[gng],
				nm, (unsigned long long)pub->u.agg.sum[gng],
				nm, (unsigned long long)(now - pub->us_first));

			return lws_ptr_diff(buf, obuf);
		}

		/* it's a monotonic ordinal, like total tx */
		buf += lws_snprintf(buf, lws_ptr_diff_size_t(end, buf),
				    "%s%s_count %u\n%s%s_sum %llu\n",
				    nm, _gng,
				    (unsigned int)pub->u.agg.count[gng],
				    nm, _gng,
				    (unsigned long long)pub->u.agg.sum[gng]);

	} else
		buf += lws_snprintf(buf, lws_ptr_diff_size_t(end, buf),
				    "%s%s_count %u\n%s%s_mean %llu\n",
				    nm, _gng,
				    (unsigned int)pub->u.agg.count[gng],
				    nm, _gng, (unsigned long long)
				    (pub->u.agg.count[gng] ?
						pub->u.agg.sum[gng] /
						pub->u.agg.count[gng] : 0));

	return lws_ptr_diff(buf, obuf);
}

static size_t
lws_metrics_om_format(lws_metric_pub_t *pub, const char *nm, char *buf,
		      size_t len)
{
	char *end = buf + len - 1, *obuf = buf, tmp[64];
	lws_usec_t t = lws_now_usecs();

	if (pub->flags & LWSMTFL_REPORT_HIST) {
		lws_metric_bucket_t *buck = pub->u.hist.head;

		buf += lws_snprintf(buf, lws_ptr_diff_size_t(end, buf),
				    "%s_cnt %llu\n", nm, (unsigned long long)
				    pub->u.hist.total_count);

		while (buck) {
			lws_strncpy(tmp, lws_metric_bucket_name(buck),
				    sizeof(tmp));
			//prometheus_san(tmp, strlen(tmp));
			buf += lws_snprintf(buf, lws_ptr_diff_size_t(end, buf),
					    "%s{%s} %llu\n", nm, tmp,
					    (unsigned long long)buck->count);

			buck = buck->next;
		}

		goto happy;
	}

	if (!pub->u.agg.count[METRES_GO] && !pub->u.agg.count[METRES_NOGO])
		return 0;

	if (pub->u.agg.count[METRES_GO])
		buf += lws_metrics_om_format_agg(pub, nm, t, METRES_GO, buf,
						 lws_ptr_diff_size_t(end, buf));

	if (!(pub->flags & LWSMTFL_REPORT_ONLY_GO) &&
	    pub->u.agg.count[METRES_NOGO])
		buf += lws_metrics_om_format_agg(pub, nm, t, METRES_NOGO, buf,
						 lws_ptr_diff_size_t(end, buf));

	if (pub->flags & LWSMTFL_REPORT_MEAN)
		buf += lws_snprintf(buf, lws_ptr_diff_size_t(end, buf),
				    "%s_min %llu\n%s_max %llu\n",
				    nm, (unsigned long long)pub->u.agg.min,
				    nm, (unsigned long long)pub->u.agg.max);

happy:
	buf += lws_snprintf(buf, lws_ptr_diff_size_t(end, buf), "\n");

	return lws_ptr_diff_size_t(buf, obuf);
}

static int
append_om_metric(lws_metric_pub_t *pub, void *user)
{
	struct pss *pss = (struct pss *)user;
	char buf[1180], nm[64];
	size_t m, nl;
	void *q;

	/*
	 * Convert lws_metrics to prometheus metrics data, stashing into an
	 * lwsac without backfill.  Since it's not backfilling, use areas are in
	 * linear sequence simplifying walking them.  Limiting the lwsac alloc
	 * to less than a typical mtu means we can write one per write
	 * efficiently
	 */

	lws_strncpy(nm, pub->name, sizeof(nm));
	nl = strlen(nm);

	prometheus_san(nm, nl);

	m = lws_metrics_om_format(pub, nm, buf + 2, sizeof(buf) - 2);
	if (!m)
		return 0;

	buf[0] = (char)((m >> 8) & 0xff);
	buf[1] = (char)(m & 0xff);

	q = lwsac_use(&pss->ac, LWS_PRE + m + 2, LWS_PRE + m + 2);
	if (!q) {
		lwsac_free(&pss->ac);

		return -1;
	}
	memcpy(q + LWS_PRE, buf, m + 2);
	pss->tot += m;

	return 0;
}

static int
callback_lws_openmetrics_export(struct lws *wsi,
				enum lws_callback_reasons reason,
				void *user, void *in, size_t len)
{
	unsigned char buf[1024], *start = buf + LWS_PRE, *p = start,
		      *end = buf + sizeof(buf) - 1, *ip;
	struct lws_context *ctx = lws_get_context(wsi);
	struct pss *pss = (struct pss *)user;
	unsigned int m, wm;

	switch (reason) {

	case LWS_CALLBACK_HTTP:
		/*
		 * There will usually only be one of these, and not too much
		 * output... for simplicity let's produce the output into an
		 * lwsac all at once and then spool it back to the peer
		 * afterwards
		 */

		pss->tot = 0;
		lws_metrics_foreach(ctx, pss, append_om_metric);
		pss->walk = pss->ac;

		if (lws_add_http_common_headers(wsi, HTTP_STATUS_OK,
						"text/plain", pss->tot,
						&p, end) ||
		    lws_finalize_write_http_header(wsi, start, &p, end))
			return 1;

		lws_callback_on_writable(wsi);

		return 0;

	case LWS_CALLBACK_CLOSED_HTTP:
		lwsac_free(&pss->ac);
		break;

	case LWS_CALLBACK_HTTP_WRITEABLE:
		if (!pss->walk)
			return 0;

		do {

			ip = (uint8_t *)pss->walk +
				lwsac_sizeof(pss->walk == pss->ac) + LWS_PRE;
			m = (unsigned int)((ip[0] << 8) | ip[1]);

			/* coverity */
			if (m > lwsac_get_tail_pos(pss->walk) -
				lwsac_sizeof(pss->walk == pss->ac))
				return -1;

			if (lws_ptr_diff_size_t(end, p) < m)
				break;

			memcpy(p, ip + 2, m);
			p += m;

			pss->walk = lwsac_get_next(pss->walk);
		} while (pss->walk);

		wm = pss->walk ? LWS_WRITE_HTTP : LWS_WRITE_HTTP_FINAL;

		if (lws_write(wsi, start, lws_ptr_diff_size_t(p, start),
				(enum lws_write_protocol)wm) < 0)
			return 1;

		if (!pss->walk) {
			 if (lws_http_transaction_completed(wsi))
				return -1;
		} else
			lws_callback_on_writable(wsi);

		return 0;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static const struct lws_protocols protocols[] = {
	{
		"lws-openmetrics",
		callback_lws_openmetrics_export,
		sizeof(struct pss),
		1024,
	},
};

LWS_VISIBLE const lws_plugin_protocol_t lws_openmetrics_export = {
	.hdr = {
		"lws OpenMetrics export",
		"lws_protocol_plugin",
		LWS_BUILD_HASH,
		LWS_PLUGIN_API_MAGIC
	},

	.protocols = protocols,
	.count_protocols = LWS_ARRAY_SIZE(protocols),
};
