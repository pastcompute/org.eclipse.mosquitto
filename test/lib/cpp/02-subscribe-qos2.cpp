#include <eecloudpp.h>

static int run = -1;

class eecloudpp_test : public ecldpp::eecloudpp
{
	public:
		eecloudpp_test(const char *id);

		void on_connect(int rc);
		void on_disconnect(int rc);
		void on_subscribe(int mid, int qos_count, const int *granted_qos);
};

eecloudpp_test::eecloudpp_test(const char *id) : ecldpp::eecloudpp(id)
{
}

void eecloudpp_test::on_connect(int rc)
{
	if(rc){
		exit(1);
	}else{
		subscribe(NULL, "qos2/test", 2);
	}
}

void eecloudpp_test::on_disconnect(int rc)
{
	run = rc;
}

void eecloudpp_test::on_subscribe(int mid, int qos_count, const int *granted_qos)
{
	disconnect();
}


int main(int argc, char *argv[])
{
	struct eecloudpp_test *ecld;

	ecldpp::lib_init();

	ecld = new eecloudpp_test("subscribe-qos2-test");

	ecld->connect("localhost", 1888, 60);

	while(run == -1){
		ecld->loop();
	}

	ecldpp::lib_cleanup();

	return run;
}
