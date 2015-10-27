#include <eecloudpp.h>

static int run = -1;

class eecloudpp_test : public ecldpp::eecloudpp
{
	public:
		eecloudpp_test(const char *id);

		void on_connect(int rc);
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

int main(int argc, char *argv[])
{
	struct eecloudpp_test *ecld;

	ecldpp::lib_init();

	ecld = new eecloudpp_test("01-keepalive-pingreq");

	ecld->connect("localhost", 1888, 4);

	while(run == -1){
		ecld->loop();
	}

	ecldpp::lib_cleanup();

	return run;
}
