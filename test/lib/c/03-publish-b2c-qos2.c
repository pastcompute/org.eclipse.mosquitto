#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <eecloud.h>

static int run = -1;

void on_connect(struct eecloud *ecld, void *obj, int rc)
{
	if(rc){
		exit(1);
	}
}

void on_message(struct eecloud *ecld, void *obj, const struct eecloud_message *msg)
{
	if(msg->mid != 13423){
		printf("Invalid mid (%d)\n", msg->mid);
		exit(1);
	}
	if(msg->qos != 2){
		printf("Invalid qos (%d)\n", msg->qos);
		exit(1);
	}
	if(strcmp(msg->topic, "pub/qos2/receive")){
		printf("Invalid topic (%s)\n", msg->topic);
		exit(1);
	}
	if(strcmp(msg->payload, "message")){
		printf("Invalid payload (%s)\n", (char *)msg->payload);
		exit(1);
	}
	if(msg->payloadlen != 7){
		printf("Invalid payloadlen (%d)\n", msg->payloadlen);
		exit(1);
	}
	if(msg->retain != false){
		printf("Invalid retain (%d)\n", msg->retain);
		exit(1);
	}

	run = 0;
}

int main(int argc, char *argv[])
{
	int rc;
	struct eecloud *ecld;

	eecloud_lib_init();

	ecld = eecloud_new("publish-qos2-test", true, &run);
	eecloud_connect_callback_set(ecld, on_connect);
	eecloud_message_callback_set(ecld, on_message);
	eecloud_message_retry_set(ecld, 5);

	rc = eecloud_connect(ecld, "localhost", 1888, 60);

	while(run == -1){
		eecloud_loop(ecld, 300, 1);
	}

	eecloud_lib_cleanup();
	return run;
}
