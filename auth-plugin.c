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
	unsigned char ret;
	udata *udata = *user_data = calloc(1, sizeof(struct udata_t));

	if ((ret = krb5_init_context(&udata->context)))
	{
		mosquitto_log_printf(MOSQ_LOG_ERR, "Failed to create krb5 context: %d", (int) ret);
		free(udata);
	}
	else
		mosquitto_log_printf(MOSQ_LOG_DEBUG, "Loaded mosquitto krb5 plugin");

	return ret;

	(void) auth_opts;
	(void) auth_opt_count;
}

int mosquitto_auth_plugin_cleanup(void *user_data, struct mosquitto_auth_opt *auth_opts, int auth_opt_count)
{
	udata *udata = user_data;
	krb5_free_context(udata->context);
	free(udata);
	return 0;

	(void) auth_opts;
	(void) auth_opt_count;
}

int mosquitto_auth_security_init(void *user_data, struct mosquitto_auth_opt *auth_opts, int auth_opt_count, bool reload)
{
	unsigned char ret;
	udata *udata = user_data;

	if ((ret = krb5_kt_resolve(udata->context, "FILE:/tmp/mqtt.keytab", &udata->keytab)))
		mosquitto_log_printf(MOSQ_LOG_ERR, "Failed to create krb5 keytab: %d", (int) ret);

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

static int check_principal(krb5_context context, const char *username, krb5_principal client)
{
	unsigned char ret;
	krb5_principal target_principal;

	if ((ret = krb5_parse_name(context, username, &target_principal)))
	{
		mosquitto_log_printf(MOSQ_LOG_ERR, "Failed to create target principal: %d", (int) ret);
		return 0;
	}

	krb5_boolean success = krb5_principal_compare(context, client, target_principal);
	krb5_free_principal(context, target_principal);

	return success ? 1 : 0;
}

int mosquitto_auth_unpwd_check(void *user_data, const char *username, const char *password)
{
	udata *udata = user_data;

	krb5_data req;
	char *principal;
	unsigned char ret;
	krb5_ticket *ticket;
	krb5_auth_context authcon;

	if ((ret = krb5_auth_con_init(udata->context, &authcon)))
	{
		mosquitto_log_printf(MOSQ_LOG_ERR, "Failed to create auth context: %d", (int) ret);
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
		mosquitto_log_printf(MOSQ_LOG_ERR, "Failed to decode krb5 REQ: %d", (int) ret);
		return MOSQ_ERR_UNKNOWN;
	}

	if ((ret = krb5_unparse_name(udata->context, ticket->enc_part2->client, &principal)))
	{
		mosquitto_log_printf(MOSQ_LOG_ERR, "Failed to decode principal in request: %d", (int) ret);
		return MOSQ_ERR_UNKNOWN;
	}

	mosquitto_log_printf(MOSQ_LOG_INFO, "krb5 login attempt for principal: %s", principal);
	krb5_free_string(udata->context, principal);

	return check_principal(udata->context, username, ticket->enc_part2->client) ?
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
