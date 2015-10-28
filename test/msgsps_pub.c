/* This provides a crude manner of testing the performance of a broker in messages/s. */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <eecloud.h>

#include <msgsps_common.h>

static bool run = true;
static int message_count = 0;
static struct timeval start, stop;

void my_connect_callback(struct eecloud *ecld, void *obj, int rc)
{
	printf("rc: %d\n", rc);
	gettimeofday(&start, NULL);
}

void my_disconnect_callback(struct eecloud *ecld, void *obj, int result)
{
	run = false;
}

void my_publish_callback(struct eecloud *ecld, void *obj, int mid)
{
	message_count++;
	//printf("%d ", message_count);
	if(message_count == MESSAGE_COUNT){
		gettimeofday(&stop, NULL);
		eecloud_disconnect((struct eecloud *)obj);
	}
}

int create_data(void)
{
	int i;
	FILE *fptr, *rnd;
	int rc = 0;
	char buf[MESSAGE_SIZE];

	fptr = fopen("msgsps_pub.dat", "rb");
	if(fptr){
		fseek(fptr, 0, SEEK_END);
		if(ftell(fptr) >= MESSAGE_SIZE*MESSAGE_COUNT){
			fclose(fptr);
			return 0;
		}
		fclose(fptr);
	}

	fptr = fopen("msgsps_pub.dat", "wb");
	if(!fptr) return 1;
	rnd = fopen("/dev/urandom", "rb");
	if(!rnd){
		fclose(fptr);
		return 1;
	}

	for(i=0; i<MESSAGE_COUNT; i++){
		if(fread(buf, sizeof(char), MESSAGE_SIZE, rnd) != MESSAGE_SIZE){
			rc = 1;
			break;
		}
		if(fwrite(buf, sizeof(char), MESSAGE_SIZE, fptr) != MESSAGE_SIZE){
			rc = 1;
			break;
		}
	}
	fclose(rnd);
	fclose(fptr);

	return rc;
}

int main(int argc, char *argv[])
{
	struct eecloud *ecld;
	int i;
	double dstart, dstop, diff;
	FILE *fptr;
	uint8_t *buf;
	
	buf = malloc(MESSAGE_SIZE*MESSAGE_COUNT);
	if(!buf){
		printf("Error: Out of memory.\n");
		return 1;
	}

	start.tv_sec = 0;
	start.tv_usec = 0;
	stop.tv_sec = 0;
	stop.tv_usec = 0;

	if(create_data()){
		printf("Error: Unable to create random input data.\n");
		return 1;
	}
	fptr = fopen("msgsps_pub.dat", "rb");
	if(!fptr){
		printf("Error: Unable to open random input data.\n");
		return 1;
	}
	fread(buf, sizeof(uint8_t), MESSAGE_SIZE*MESSAGE_COUNT, fptr);
	fclose(fptr);

	eecloud_lib_init();

	ecld = eecloud_new("perftest", true, NULL);
	eecloud_connect_callback_set(ecld, my_connect_callback);
	eecloud_disconnect_callback_set(ecld, my_disconnect_callback);
	eecloud_publish_callback_set(ecld, my_publish_callback);

	eecloud_connect(ecld, "127.0.0.1", 1884, 600);

	i=0;
	while(!eecloud_loop(ecld, 1, 10) && run){
		if(i<MESSAGE_COUNT){
			eecloud_publish(ecld, NULL, "perf/test", MESSAGE_SIZE, &buf[i*MESSAGE_SIZE], 0, false);
			i++;
		}
	}
	dstart = (double)start.tv_sec*1.0e6 + (double)start.tv_usec;
	dstop = (double)stop.tv_sec*1.0e6 + (double)stop.tv_usec;
	diff = (dstop-dstart)/1.0e6;

	printf("Start: %g\nStop: %g\nDiff: %g\nMessages/s: %g\n", dstart, dstop, diff, (double)MESSAGE_COUNT/diff);

	eecloud_destroy(ecld);
	eecloud_lib_cleanup();

	return 0;
}
