#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>

#include <mosquitto.h>
#include <mosquitto_plugin.h>

#include <krb5/krb5.h>

typedef struct udata_t
{
	krb5_context context;
	krb5_keytab keytab;
	char *principal_format;
} udata;

static void report_error(udata *udata, const char *msg, krb5_error_code code)
{
	unsigned char readableCode = code;
	const char *errmsg = krb5_get_error_message(udata->context, code);
	mosquitto_log_printf(MOSQ_LOG_ERR, "%s: %s (%d)", msg, errmsg, readableCode);
	krb5_free_error_message(udata->context, errmsg);
}

int mosquitto_auth_plugin_version(void)
{
	return MOSQ_AUTH_PLUGIN_VERSION;
}

static int valid_format(const char *format)
{
	int inFormat = 0, seenSubst = 0;
	for (const char *c = format; *c; ++c)
		switch(*c)
		{
		case '%':
			inFormat = !inFormat;
			break;
		case 's':
			if (inFormat)
				if (seenSubst++ != 0)
					return 0;
			inFormat = 0;
			break;
		default:
			if (inFormat)
				return 0;
			break;
		}

	if (!seenSubst)
		mosquitto_log_printf(MOSQ_LOG_WARNING, "No substitutions in principal_format!");

	return !inFormat;
}

int mosquitto_auth_plugin_init(void **user_data, struct mosquitto_auth_opt *auth_opts, int auth_opt_count)
{
	krb5_error_code ret;
	udata *udata = *user_data = calloc(1, sizeof(struct udata_t));

	if ((ret = krb5_init_context(&udata->context)))
	{
		report_error(udata, "Failed to create KRB5 context", ret);
		free(udata);
		return 1;
	}

	for (int i = 0; i < auth_opt_count; ++i)
		if (!strcmp(auth_opts[i].key, "principal_format"))
		{
			udata->principal_format = strdup(auth_opts[i].value);
			break;
		}

	if (!udata->principal_format)
		udata->principal_format = strdup("%s");

	if (!valid_format(udata->principal_format))
	{
		mosquitto_log_printf(MOSQ_LOG_ERR, "Invalid principal_format");
		free(udata->principal_format);
		free(udata);
		return 1;
	}

	mosquitto_log_printf(MOSQ_LOG_DEBUG, "Loaded mosquitto krb5 plugin");
	return 0;

	(void) auth_opts;
	(void) auth_opt_count;
}

int mosquitto_auth_plugin_cleanup(void *user_data, struct mosquitto_auth_opt *auth_opts, int auth_opt_count)
{
	udata *udata = user_data;
	krb5_free_context(udata->context);
	if (udata->principal_format)
		free(udata->principal_format);

	free(udata);
	return 0;

	(void) auth_opts;
	(void) auth_opt_count;
}

int mosquitto_auth_security_init(void *user_data, struct mosquitto_auth_opt *auth_opts, int auth_opt_count, bool reload)
{
	krb5_error_code ret;
	udata *udata = user_data;

	const char *keytab = 0;
	for (int i = 0; i < auth_opt_count; ++i)
		if (!strcmp(auth_opts[i].key, "keytab"))
			keytab = auth_opts[i].value;

	if (keytab)
		ret = krb5_kt_resolve(udata->context, keytab, &udata->keytab);
	else
		ret = krb5_kt_default(udata->context, &udata->keytab);

	if (ret)
	{
		report_error(udata, "Failed to create krb5 keytab", ret);
		return MOSQ_ERR_UNKNOWN;
	}

	return 0;

	(void) reload;
}

int mosquitto_auth_security_cleanup(void *user_data, struct mosquitto_auth_opt *auth_opts, int auth_opt_count, bool reload)
{
	udata *udata = user_data;
	krb5_kt_close(udata->context, udata->keytab);
	return 0;

	(void) auth_opts;
	(void) auth_opt_count;
	(void) reload;
}

int mosquitto_auth_acl_check(void *user_data, const char *clientid, const char *username, const char *topic, int access)
{
	return MOSQ_ERR_SUCCESS; // No ACL

	(void) user_data;
	(void) clientid;
	(void) username;
	(void) topic;
	(void) access;
}

static int decode_request(krb5_data *req, const char *encoded)
{
	if (!encoded || strlen(encoded) < 16)
		return 0;

	if (sscanf(encoded, "%08x%08x", &req->magic, &req->length) != 2)
		return 0;

	if (strlen(encoded+16) < req->length)
		return 0;

	char *o = req->data = calloc(1, req->length);
	const char *c = encoded+16;
	for (unsigned int i = 0, wasEscaped = 0; i < strlen(encoded+16); ++i, ++c, ++o)
		switch(*o = *c)
		{
		case 1:
			if ((wasEscaped = !wasEscaped))
				--o;
			break;
		case 2:
			if (wasEscaped)
				*o = wasEscaped = 0;
			break;
		default:
			wasEscaped = 0;
			break;
		}

	return 1;
}

static int check_principal(udata *udata, const char *username, krb5_principal client)
{
	krb5_error_code ret;
	krb5_principal target_principal;
	static char principalbuffer[1000];

	snprintf(principalbuffer, sizeof(principalbuffer), udata->principal_format, username);

	if ((ret = krb5_parse_name(udata->context, principalbuffer, &target_principal)))
	{
		report_error(udata, "Failed to create target principal", ret);
		return 0;
	}

	krb5_boolean success = krb5_principal_compare(udata->context, client, target_principal);
	krb5_free_principal(udata->context, target_principal);

	return success ? 1 : 0;
}

int mosquitto_auth_unpwd_check(void *user_data, const char *username, const char *password)
{
	udata *udata = user_data;

	krb5_data req;
	char *principal;
	krb5_error_code ret;
	krb5_ticket *ticket;
	krb5_auth_context authcon;

	if ((ret = krb5_auth_con_init(udata->context, &authcon)))
	{
		report_error(udata, "Failed to create auth context", ret);
		return MOSQ_ERR_UNKNOWN;
	}

	if (!decode_request(&req, password))
	{
		mosquitto_log_printf(MOSQ_LOG_ERR, "Failed to decode password as serialized krb5 REQ");
		return MOSQ_ERR_UNKNOWN;
	}

	ret = krb5_rd_req(udata->context, &authcon, &req, NULL, udata->keytab, NULL, &ticket);
	free(req.data);
	krb5_auth_con_free(udata->context, authcon);

	if (ret)
	{
		report_error(udata, "Failed to decode krb5 REQ", ret);
		return MOSQ_ERR_UNKNOWN;
	}

	if ((ret = krb5_unparse_name(udata->context, ticket->enc_part2->client, &principal)))
	{
		report_error(udata, "Failed to decode principal in request", ret);
		return MOSQ_ERR_UNKNOWN;
	}

	mosquitto_log_printf(MOSQ_LOG_INFO, "krb5 login attempt for principal: %s", principal);
	krb5_free_string(udata->context, principal);

	return check_principal(udata, username, ticket->enc_part2->client) ?
		MOSQ_ERR_SUCCESS : MOSQ_ERR_AUTH;
}

int mosquitto_auth_psk_key_get(void *user_data, const char *hint, const char *identity, char *key, int max_key_len)
{
	return 1; // No PSK

	(void) user_data;
	(void) hint;
	(void) identity;
	(void) key;
	(void) max_key_len;
}
