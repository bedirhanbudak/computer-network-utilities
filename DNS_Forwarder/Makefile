all: dns_forwarder

dns_forwarder: dns_forwarder.c
	gcc -Wall -g -o dns_forwarder dns_forwarder.c -lcurl

clean:
	rm -f dns_forwarder