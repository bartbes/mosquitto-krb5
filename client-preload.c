#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <dlfcn.h>

#include <mosquitto.h>
#include <krb5/krb5.h>

static krb5_context context;
static krb5_auth_context authcon;
static krb5_ccache ccache;
static char *targetUsername = 0;
static char *targetPassword = 0;

static int (*orig_username_pw_set)(struct mosquitto *mosq, const char *username, const char *password);
static int (*orig_connect)(struct mosquitto *mosq, const char *host, int port, int keepalive);
static int (*orig_connect_bind)(struct mosquitto *mosq, const char *host, int port, int keepalive, const char *bind_address);
static int (*orig_connect_async)(struct mosquitto *mosq, const char *host, int port, int keepalive);
static int (*orig_connect_bind_async)(struct mosquitto *mosq, const char *host, int port, int keepalive, const char *bind_address);
static int (*orig_connect_srv)(struct mosquitto *mosq, const char *host, int keepalive, const char *bind_address);

#define KRB5_FAIL(x) do { unsigned char err = x; if (err) { printf("KRB5 FAILURE %d on line %d\n", (int) err, __LINE__); exit(x); } } while (0)
#define DLSYM(x) orig_ ## x = dlsym(RTLD_NEXT, "mosquitto_" #x)

char *req_encode(krb5_data *request)
{
	unsigned int encodedlen = request->length*2+16+1;
	char *encoded = calloc(1, encodedlen);
	snprintf(encoded, encodedlen, "%08x%08x", (uint32_t) request->magic, (uint32_t) request->length);
	char *o = encoded+16;
	for (unsigned int i = 0; i < request->length; ++i)
		switch (request->data[i])
		{
		case 1:
			*o++ = 1;
			*o++ = 1;
			break;
		case 0:
			*o++ = 1;
			*o++ = 2;
			break;
		default:
			*o++ = request->data[i];
		}
	*o = 0;
	return realloc(encoded, o-encoded+1);
}

static void __attribute__((constructor)) init()
{
	KRB5_FAIL(krb5_init_context(&context));
	KRB5_FAIL(krb5_auth_con_init(context, &authcon));
	KRB5_FAIL(krb5_cc_default(context, &ccache));

	DLSYM(username_pw_set);
	DLSYM(connect);
	DLSYM(connect_bind);
	DLSYM(connect_async);
	DLSYM(connect_bind_async);
	DLSYM(connect_srv);
}

static int calculate_password(const char *host)
{
	printf("Using krb5 authentication for mosquitto\n");

	unsigned char ret;
	krb5_data request;
	char *host_copy = strdup(host);

	if ((ret = krb5_mk_req(context, &authcon, 0, "mqtt", host_copy, NULL, ccache, &request)))
	{
		printf("Failed to create krb5 request: %d\n", (int) ret);
		free(host_copy);
		return 0;
	}

	targetPassword = req_encode(&request);
	krb5_free_data_contents(context, &request);
	free(host_copy);

	return 1;
}

int mosquitto_username_pw_set(struct mosquitto *mosq, const char *username, const char *password)
{
	if (targetUsername)
		free(targetUsername);

	targetUsername = strdup(username);
	// We call the original function so that we fall back to non-krb5 if we can't
	// obtain a ticket
	return orig_username_pw_set(mosq, username, password);
}


int mosquitto_connect(struct mosquitto *mosq, const char *host, int port, int keepalive)
{
	if (targetUsername && calculate_password(host))
		orig_username_pw_set(mosq, targetUsername, targetPassword);

	return orig_connect(mosq, host, port, keepalive);
}

int mosquitto_connect_bind(struct mosquitto *mosq, const char *host, int port, int keepalive, const char *bind_address)
{
	if (targetUsername && calculate_password(host))
		orig_username_pw_set(mosq, targetUsername, targetPassword);

	return orig_connect_bind(mosq, host, port, keepalive, bind_address);
}

int mosquitto_connect_async(struct mosquitto *mosq, const char *host, int port, int keepalive)
{
	if (targetUsername && calculate_password(host))
		orig_username_pw_set(mosq, targetUsername, targetPassword);

	return orig_connect_async(mosq, host, port, keepalive);
}

int mosquitto_connect_bind_async(struct mosquitto *mosq, const char *host, int port, int keepalive, const char *bind_address)
{
	if (targetUsername && calculate_password(host))
		orig_username_pw_set(mosq, targetUsername, targetPassword);

	return orig_connect_bind_async(mosq, host, port, keepalive, bind_address);
}

int mosquitto_connect_srv(struct mosquitto *mosq, const char *host, int keepalive, const char *bind_address)
{
	if (targetUsername && calculate_password(host))
		orig_username_pw_set(mosq, targetUsername, targetPassword);

	return orig_connect_srv(mosq, host, keepalive, bind_address);
}

static void __attribute__((destructor)) fini()
{
	krb5_cc_close(context, ccache);
	krb5_auth_con_free(context, authcon);
	krb5_free_context(context);

	if (targetUsername)
		free(targetUsername);

	if (targetPassword)
		free(targetPassword);
}
