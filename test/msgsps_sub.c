/* This provides a crude manner of testing the performance of a broker in messages/s. */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/time.h>
#include <unistd.h>
#include <eecloud.h>

#include <msgsps_common.h>

static bool run = true;
static int message_count = 0;
static struct timeval start, stop;
FILE *fptr = NULL;


void my_connect_callback(struct eecloud *ecld, void *obj, int rc)
{
	printf("rc: %d\n", rc);
}

void my_disconnect_callback(struct eecloud *ecld, void *obj, int result)
{
	run = false;
}

void my_message_callback(struct eecloud *ecld, void *obj, const struct eecloud_message *msg)
{
	if(message_count == 0){
		gettimeofday(&start, NULL);
	}
	fwrite(msg->payload, sizeof(uint8_t), msg->payloadlen, fptr);
	message_count++;
	if(message_count == MESSAGE_COUNT){
		gettimeofday(&stop, NULL);
		eecloud_disconnect((struct eecloud *)obj);
	}
}

int main(int argc, char *argv[])
{
	struct eecloud *ecld;
	double dstart, dstop, diff;
	int mid = 0;
	char id[50];
	int rc;

	start.tv_sec = 0;
	start.tv_usec = 0;
	stop.tv_sec = 0;
	stop.tv_usec = 0;

	fptr = fopen("msgsps_sub.dat", "wb");
	if(!fptr){
		printf("Error: Unable to write to msgsps_sub.dat.\n");
		return 1;
	}
	eecloud_lib_init();

	snprintf(id, 50, "msgps_sub_%d", getpid());
	ecld = eecloud_new(id, true, NULL);
	eecloud_connect_callback_set(ecld, my_connect_callback);
	eecloud_disconnect_callback_set(ecld, my_disconnect_callback);
	eecloud_message_callback_set(ecld, my_message_callback);

	eecloud_connect(ecld, "127.0.0.1", 1884, 600);
	eecloud_subscribe(ecld, &mid, "perf/test", 0);

	do{
		rc = eecloud_loop(ecld, 1, 10);
	}while(rc == MOSQ_ERR_SUCCESS && run);
	printf("rc: %d\n", rc);

	dstart = (double)start.tv_sec*1.0e6 + (double)start.tv_usec;
	dstop = (double)stop.tv_sec*1.0e6 + (double)stop.tv_usec;
	diff = (dstop-dstart)/1.0e6;

	printf("Start: %g\nStop: %g\nDiff: %g\nMessages/s: %g\n", dstart, dstop, diff, (double)MESSAGE_COUNT/diff);

	eecloud_destroy(ecld);
	eecloud_lib_cleanup();
	fclose(fptr);

	return 0;
}
