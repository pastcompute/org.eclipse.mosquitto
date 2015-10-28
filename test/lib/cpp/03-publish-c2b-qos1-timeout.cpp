#include <cstdlib>
#include <cstring>

#include <eecloudpp.h>

static int run = -1;

class eecloudpp_test : public ecldpp::eecloudpp
{
	public:
		eecloudpp_test(const char *id);

		void on_connect(int rc);
		void on_disconnect(int rc);
		void on_publish(int mid);
};

eecloudpp_test::eecloudpp_test(const char *id) : ecldpp::eecloudpp(id)
{
}

void eecloudpp_test::on_connect(int rc)
{
	if(rc){
		exit(1);
	}else{
		publish(NULL, "pub/qos1/test", strlen("message"), "message", 1, false);
	}
}

void eecloudpp_test::on_disconnect(int rc)
{
	run = 0;
}

void eecloudpp_test::on_publish(int mid)
{
	disconnect();
}

int main(int argc, char *argv[])
{
	struct eecloudpp_test *ecld;

	ecldpp::lib_init();

	ecld = new eecloudpp_test("publish-qos1-test");
	ecld->message_retry_set(3);

	ecld->connect("localhost", 1888, 60);

	while(run == -1){
		ecld->loop();
	}

	ecldpp::lib_cleanup();

	return run;
}

