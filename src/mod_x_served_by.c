/*
 * Apache module to add X-Served-By
 *
*/

#define XSB_DISABLED 10
#define XSB_ENABLED 20
#define XSB_UNSET -1

#define XSB_HEADER_NAME "X-Served-By"

#include "httpd.h"
#include "http_config.h"
#include "http_log.h"
#include "apr_network_io.h"
#include "apr_strings.h"
#include "apr_tables.h"

static char *xsb_hostname;

typedef struct xsb_conf_t {
	int enabled;

	char *header_name;
} xsb_conf_t;

module AP_MODULE_DECLARE_DATA x_served_by_module;

static void *xsb_create_server_config (apr_pool_t *p, server_rec *s) {
	xsb_conf_t *conf;

	conf = (xsb_conf_t*) apr_pcalloc(p, sizeof(xsb_conf_t));

	conf->enabled = XSB_UNSET;
	conf->header_name = XSB_HEADER_NAME;

	return conf;
}

static void *xsb_merge_server_config (apr_pool_t *p, void *basev,
		void *overridesv) {
	xsb_conf_t *base = (xsb_conf_t *) basev;
	xsb_conf_t *overrides = (xsb_conf_t *) overridesv;

	xsb_conf_t *conf = apr_pcalloc(p, sizeof(xsb_conf_t));

	switch(overrides->enabled) {
		case XSB_DISABLED:
			conf->enabled = XSB_DISABLED;
			break;
		case XSB_ENABLED:
			conf->enabled = XSB_ENABLED;
			break;
		default:
			conf->enabled = base->enabled;
	}

	conf->header_name = (overrides->header_name != NULL) ?
		overrides->header_name : base->header_name;

	return conf;
}

static const char *xsb_set_enabled (cmd_parms *cmd, void *config, int value) {
	xsb_conf_t *conf = ap_get_module_config(
		cmd->server->module_config, &x_served_by_module);

	conf->enabled = (value == 1) ? XSB_ENABLED : XSB_DISABLED;

	return NULL;
}

static const char *xsb_set_header_name (cmd_parms *cmd, void *config,
		const char *value) {
	xsb_conf_t *conf = ap_get_module_config(
		cmd->server->module_config, &x_served_by_module);

	conf->header_name = (char *) value;

	return NULL;
}

static int xsb_post_config (apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp,
		server_rec *s) {
	/*
	 * This method of determining the hostname and IP was
	 * modelled after mod_unique_id
	 */

	char *ipstr;
	char hostname[APRMAXHOSTLEN + 1];
	apr_status_t rv;
	apr_sockaddr_t *sockaddr;

	xsb_conf_t *conf = ap_get_module_config(s->module_config,
		&x_served_by_module);

	if(conf->enabled != XSB_ENABLED) {
		return DECLINED;
	}

	if((rv = apr_gethostname(hostname, APRMAXHOSTLEN, p)) != APR_SUCCESS) {
		ap_log_error(APLOG_MARK, APLOG_ALERT, rv, s,
			"unable to find hostname of the server");
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	if((rv = apr_sockaddr_info_get(&sockaddr, hostname, APR_UNSPEC, 0,
			APR_IPV4_ADDR_OK, p)) != APR_SUCCESS) {
		ap_log_error(APLOG_MARK, APLOG_ALERT, rv, s,
			"unable to find IP address of \"%s\"", hostname);
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	apr_sockaddr_ip_get(&ipstr, sockaddr);

	xsb_hostname = apr_pstrcat(p, hostname, " (", ipstr, ")", NULL);

	ap_log_error(APLOG_MARK, APLOG_INFO, 0, s,
		"X-Served-By: %s", xsb_hostname);

	return OK;
}

static int xsb_fixups (request_rec *r) {
	xsb_conf_t *conf = ap_get_module_config(
		r->server->module_config, &x_served_by_module);

	if(!ap_is_initial_req(r)) {
		return DECLINED;
	}

	if(conf->enabled == XSB_ENABLED) {
		apr_table_setn(r->err_headers_out, conf->header_name,
			xsb_hostname);
	}

	return DECLINED;
}

static void xsb_register_hooks (apr_pool_t *p) {
	ap_hook_post_config(xsb_post_config, NULL, NULL, APR_HOOK_MIDDLE);
	ap_hook_fixups(xsb_fixups, NULL, NULL, APR_HOOK_MIDDLE);
}

static const command_rec xsb_commands[] = {
	AP_INIT_FLAG("XServedByEnabled", xsb_set_enabled, NULL, RSRC_CONF,
		"Enable/Disable X-Served-By header"),
	AP_INIT_TAKE1("XServedByHeader", xsb_set_header_name, NULL, RSRC_CONF,
		"Set the header name"),
	{ NULL }
};

module AP_MODULE_DECLARE_DATA x_served_by_module = {
	STANDARD20_MODULE_STUFF,
	NULL,				/* create per-dir config */
	NULL,				/* merge per-dir config */
	xsb_create_server_config,	/* create per-server config */
	xsb_merge_server_config,	/* merge per-server config */
	xsb_commands,			/* config file commands */
	xsb_register_hooks		/* register hooks */
};
