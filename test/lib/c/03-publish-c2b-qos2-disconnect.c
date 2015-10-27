#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <eecloud.h>

static int run = -1;
static int first_connection = 1;

void on_connect(struct eecloud *ecld, void *obj, int rc)
{
	if(rc){
		exit(1);
	}else{
		if(first_connection == 1){
			eecloud_publish(ecld, NULL, "pub/qos2/test", strlen("message"), "message", 2, false);
			first_connection = 0;
		}
	}
}

void on_publish(struct eecloud *ecld, void *obj, int mid)
{
	eecloud_disconnect(ecld);
}

void on_disconnect(struct eecloud *ecld, void *obj, int rc)
{
	if(rc){
		eecloud_reconnect(ecld);
	}else{
		run = 0;
	}
}

int main(int argc, char *argv[])
{
	int rc;
	struct eecloud *ecld;

	eecloud_lib_init();

	ecld = eecloud_new("publish-qos2-test", true, NULL);
	eecloud_connect_callback_set(ecld, on_connect);
	eecloud_disconnect_callback_set(ecld, on_disconnect);
	eecloud_publish_callback_set(ecld, on_publish);
	eecloud_message_retry_set(ecld, 3);

	rc = eecloud_connect(ecld, "localhost", 1888, 60);

	while(run == -1){
		eecloud_loop(ecld, 300, 1);
	}

	eecloud_lib_cleanup();
	return run;
}
