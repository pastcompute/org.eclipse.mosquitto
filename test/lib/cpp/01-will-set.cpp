//#include <stdbool.h>
//#include <cstdio>
//#include <stdlib.h>
#include <cstring>
#include <eecloudpp.h>

static int run = -1;

class eecloudpp_test : public ecldpp::eecloudpp
{
	public:
		eecloudpp_test(const char *id);
};

eecloudpp_test::eecloudpp_test(const char *id) : ecldpp::eecloudpp(id)
{
}

int main(int argc, char *argv[])
{
	struct eecloudpp_test *ecld;

	ecldpp::lib_init();

	ecld = new eecloudpp_test("01-will-set");
	ecld->will_set("topic/on/unexpected/disconnect", strlen("will message"), "will message", 1, true);

	ecld->connect("localhost", 1888, 60);

	while(run == -1){
		ecld->loop();
	}

	ecldpp::lib_cleanup();

	return run;
}
