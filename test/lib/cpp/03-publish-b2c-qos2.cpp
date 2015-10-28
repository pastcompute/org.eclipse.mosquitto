#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <eecloudpp.h>

static int run = -1;

class eecloudpp_test : public ecldpp::eecloudpp
{
	public:
		eecloudpp_test(const char *id);

		void on_connect(int rc);
		void on_message(const struct eecloud_message *msg);
};

eecloudpp_test::eecloudpp_test(const char *id) : ecldpp::eecloudpp(id)
{
}

void eecloudpp_test::on_connect(int rc)
{
	if(rc){
		exit(1);
	}
}

void eecloudpp_test::on_message(const struct eecloud_message *msg)
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
	if(strcmp((char *)msg->payload, "message")){
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
	struct eecloudpp_test *ecld;

	ecldpp::lib_init();

	ecld = new eecloudpp_test("publish-qos2-test");
	ecld->message_retry_set(3);

	ecld->connect("localhost", 1888, 60);

	while(run == -1){
		ecld->loop();
	}

	ecldpp::lib_cleanup();

	return run;
}

