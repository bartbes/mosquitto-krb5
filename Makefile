CFLAGS=-std=c99 -Wall -Wextra -fPIC `pkg-config --cflags krb5`
LDADD=`pkg-config --libs krb5`

OUTPUTS=client-preload.so auth-plugin.so

.PHONY: all clean server client

all: $(OUTPUTS)

clean:
	$(RM) $(OUTPUTS)

%.so: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -shared -o $@ $^ $(LDADD)

server: auth-plugin.so
	mosquitto -v -c ./mosquitto.conf

client: client-preload.so
	env LD_PRELOAD=./$< mosquitto_pub -d -h localhost -n -t test -u `whoami`
