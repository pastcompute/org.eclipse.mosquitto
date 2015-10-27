/* Fudge a file description into a client instead of a socket connection so
 * that we can write out packets to a file.
 * See http://answers.launchpad.net/eecloud/+question/123594
 * also http://answers.launchpad.net/eecloud/+question/136821
 */
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

#include <eecloud.h>
#include <eecloud_internal.h>
#include <send_ecld.h>

int main(int argc, char *argv[])
{
	struct eecloud *ecld;
	int fd;
	bool clean_session = true;
	int keepalive = 60;

	ecld = eecloud_new("packetgen", NULL);
	if(!ecld){
		fprintf(stderr, "Error: Out of memory.\n");
		return 1;
	}

	/* CONNECT */
	fd = open("mqtt.connect", O_CREAT|O_WRONLY, 00644);
	if(fd<0){
		fprintf(stderr, "Error: Unable to open mqtt.connect for writing.\n");
		return 1;
	}
	ecld->core.sock = fd;
	printf("_eecloud_send_connect(): %d\n", _eecloud_send_connect(ecld, keepalive, clean_session));
	printf("loop: %d\n", eecloud_loop_write(ecld));
	close(fd);

	/* SUBSCRIBE */
	fd = open("mqtt.subscribe", O_CREAT|O_WRONLY, 00644);
	if(fd<0){
		fprintf(stderr, "Error: Unable to open mqtt.subscribe for writing.\n");
		return 1;
	}
	ecld->core.sock = fd;
	printf("_eecloud_send_subscribe(): %d\n", _eecloud_send_subscribe(ecld, NULL, false, "subscribe/topic", 2));
	printf("loop: %d\n", eecloud_loop_write(ecld));
	close(fd);

	eecloud_destroy(ecld);

	return 0;
}

