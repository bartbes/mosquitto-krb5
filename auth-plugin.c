#include <stdio.h>
#include <string.h>

#include <mosquitto.h>
#include <mosquitto_plugin.h>

#include <krb5/krb5.h>

typedef struct udata_t
{
	krb5_context context;
	krb5_keytab keytab;
} udata;

int mosquitto_auth_plugin_version(void)
{
	return MOSQ_AUTH_PLUGIN_VERSION;
}

int mosquitto_auth_plugin_init(void **user_data, struct mosquitto_auth_opt *auth_opts, int auth_opt_count)
{
	mosquitto_log_printf(MOSQ_LOG_DEBUG, "Loaded mosquitto krb5 plugin");

	udata *udata = *user_data = calloc(1, sizeof(struct udata_t));
	unsigned char ret = krb5_init_context(&udata->context);

	if (ret)
	{
		mosquitto_log_printf(MOSQ_LOG_ERR, "Failed to create krb5 context");
		free(udata);
	}

	return ret;

	(void) auth_opts;
	(void) auth_opt_count;
}

int mosquitto_auth_plugin_cleanup(void *user_data, struct mosquitto_auth_opt *auth_opts, int auth_opt_count)
{
	udata *udata = user_data;
	krb5_free_context(udata->context);
	free(user_data);
	return 0;

	(void) auth_opts;
	(void) auth_opt_count;
}

int mosquitto_auth_security_init(void *user_data, struct mosquitto_auth_opt *auth_opts, int auth_opt_count, bool reload)
{
	udata *udata = user_data;
	unsigned char ret = krb5_kt_resolve(udata->context, "FILE:/tmp/mqtt.keytab", &udata->keytab);

	if (ret)
		mosquitto_log_printf(MOSQ_LOG_ERR, "Failed to create krb5 keytab");

	return ret;

	(void) auth_opts;
	(void) auth_opt_count;
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
	// FIXME
	return MOSQ_ERR_SUCCESS;

	(void) user_data;
	(void) clientid;
	(void) username;
	(void) topic;
	(void) access;
}

static void decode_request(krb5_data *req, const char *encoded)
{
	sscanf(encoded, "%08x%08x", &req->magic, &req->length);
	req->data = calloc(1, req->length);
	const char *c = encoded+16;
	char *o = req->data;
	int wasEscaped = 0;
	for (unsigned int i = 0; i < strlen(encoded+16); ++i, ++c)
		switch(*c)
		{
		case 1:
			if (wasEscaped)
			{
				*o++ = 1;
				wasEscaped = 0;
			}
			else
				wasEscaped = 1;
			break;
		case 2:
			if (wasEscaped)
			{
				*o++ = 0;
				wasEscaped = 0;
			}
			else
				*o++ = 2;
			break;
		default:
			*o++ = *c;
			wasEscaped = 0;
			break;
		}
}

int mosquitto_auth_unpwd_check(void *user_data, const char *username, const char *password)
{
	udata *udata = user_data;
	krb5_ticket *ticket;
	krb5_auth_context authcon;
	krb5_data req;
	char *principal;
	krb5_principal target_principal;

	unsigned char ret = krb5_auth_con_init(udata->context, &authcon);
	if (ret)
	{
		mosquitto_log_printf(MOSQ_LOG_ERR, "Failed to create auth context");
		return MOSQ_ERR_UNKNOWN;
	}

	decode_request(&req, password);

	ret = krb5_rd_req(udata->context, &authcon, &req, NULL, udata->keytab, NULL, &ticket);
	free(req.data);
	krb5_auth_con_free(udata->context, authcon);
	if (ret)
	{
		mosquitto_log_printf(MOSQ_LOG_ERR, "Failed to decode request: %d", (int) ret);
		return MOSQ_ERR_UNKNOWN;
	}

	ret = krb5_unparse_name(udata->context, ticket->enc_part2->client, &principal);
	if (ret)
	{
		mosquitto_log_printf(MOSQ_LOG_ERR, "Failed to decode principal in request");
		return MOSQ_ERR_UNKNOWN;
	}

	mosquitto_log_printf(MOSQ_LOG_INFO, "krb5 login attempt for principal: %s", principal);

	ret = krb5_parse_name(udata->context, username, &target_principal);
	if (ret)
	{
		mosquitto_log_printf(MOSQ_LOG_ERR, "Failed to create target principal");
		krb5_free_string(udata->context, principal);
		return MOSQ_ERR_UNKNOWN;
	}

	krb5_boolean success = krb5_principal_compare(udata->context, ticket->enc_part2->client, target_principal);

	krb5_free_principal(udata->context, target_principal);
	krb5_free_string(udata->context, principal);

	return success ? MOSQ_ERR_SUCCESS : MOSQ_ERR_AUTH;
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
