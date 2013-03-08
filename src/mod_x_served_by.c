/*
 * Apache module to add X-Served-By
 *
*/

#define XSB_HEADER_NAME "X-Served-By"

#include "httpd.h"
#include "http_config.h"
#include "http_log.h"
#include "apr_network_io.h"
#include "apr_strings.h"
#include "apr_tables.h"

typedef struct xsb_conf_t {
	int enabled;

	char *header_name;
	char *hostname;
} xsb_conf_t;

module AP_MODULE_DECLARE_DATA x_served_by_module;

static void *xsb_create_server_config (apr_pool_t *p, server_rec *s) {
	xsb_conf_t *conf;
	char hostname[APRMAXHOSTLEN + 1];
	apr_status_t rv;

	conf = (xsb_conf_t*) apr_pcalloc(p, sizeof(xsb_conf_t));

	conf->header_name = XSB_HEADER_NAME;

	if((rv = apr_gethostname(hostname, APRMAXHOSTLEN, p)) ==
			APR_SUCCESS) {
		conf->hostname = apr_pstrdup(p, hostname);
		ap_log_error(APLOG_MARK, APLOG_INFO, 0, s,
			"X-Served-By: %s", conf->hostname);
	} else {
		ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
			"Unable to determine hostname, skipping X-Served-By");
	}

	return conf;
}

static void *xsb_merge_server_config (apr_pool_t *p, void *basev,
		void *overridesv) {
	xsb_conf_t *base = (xsb_conf_t *) basev;
	xsb_conf_t *overrides = (xsb_conf_t *) overridesv;

	xsb_conf_t *conf = apr_palloc(p, sizeof(xsb_conf_t));

	conf->enabled = (overrides->enabled == 0) ? base->enabled :
		overrides->enabled;
	conf->header_name = (overrides->header_name != NULL) ?
		overrides->header_name : base->header_name;

	return conf;
}

static const char *xsb_set_enabled (cmd_parms *cmd, void *config, int value) {
	xsb_conf_t *conf = ap_get_module_config(
		cmd->server->module_config, &x_served_by_module);

	conf->enabled = value;

	return NULL;
}

static const char *xsb_set_header_name (cmd_parms *cmd, void *config,
		const char *value) {
	xsb_conf_t *conf = ap_get_module_config(
		cmd->server->module_config, &x_served_by_module);

	conf->header_name = (char *) value;

	return NULL;
}

static int xsb_fixups (request_rec *r) {
	xsb_conf_t *conf = ap_get_module_config(
		r->server->module_config, &x_served_by_module);

	if(conf->enabled == 1) {
		apr_table_setn(r->err_headers_out, conf->header_name,
			conf->hostname);
	}

	return DECLINED;
}

static void xsb_register_hooks (apr_pool_t *p) {
	ap_hook_fixups(xsb_fixups, NULL, NULL, APR_HOOK_FIRST);
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
