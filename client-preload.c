#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <dlfcn.h>

#include <mosquitto.h>
#include <krb5/krb5.h>

krb5_context context;
krb5_auth_context authcon;
krb5_ccache ccache;
char *password = 0;

int (*orig_username_pw_set)(struct mosquitto *mosq, const char *username, const char *password);

#define KRB5_FAIL(x) do { unsigned char err = x; if (err) { printf("KRB5 FAILURE %d on line %d\n", (int) err, __LINE__); exit(x); } } while (0)

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

	orig_username_pw_set = dlsym(RTLD_NEXT, "mosquitto_username_pw_set");
}

int mosquitto_username_pw_set(struct mosquitto *mosq, const char *username, const char *password)
{
	printf("Intercepted uname/pw call\n");

	krb5_data request;
	KRB5_FAIL(krb5_mk_req(context, &authcon, 0, "mqtt", "localhost.localdomain", NULL, ccache, &request));
	password = req_encode(&request);
	krb5_free_data_contents(context, &request);

	return orig_username_pw_set(mosq, username, password);
}

static void __attribute__((destructor)) fini()
{
	krb5_cc_close(context, ccache);
	krb5_auth_con_free(context, authcon);
	krb5_free_context(context);

	if (password)
		free(password);
}
