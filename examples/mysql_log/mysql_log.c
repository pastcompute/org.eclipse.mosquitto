#include <signal.h>
#include <stdio.h>
#include <string.h>

#ifndef WIN32
#  include <unistd.h>
#else
#  include <process.h>
#  define snprintf sprintf_s
#endif

#include <eecloud.h>
#include <mysql/mysql.h>

#define db_host "localhost"
#define db_username "mqtt_log"
#define db_password "password"
#define db_database "mqtt_log"
#define db_port 3306

#define db_query "INSERT INTO mqtt_log (topic, payload) VALUES (?,?)"

#define mqtt_host "localhost"
#define mqtt_port 1883

static int run = 1;
static MYSQL_STMT *stmt = NULL;

void handle_signal(int s)
{
	run = 0;
}

void connect_callback(struct eecloud *ecld, void *obj, int result)
{
}

void message_callback(struct eecloud *ecld, void *obj, const struct eecloud_message *message)
{
	MYSQL_BIND bind[2];

	memset(bind, 0, sizeof(bind));

	bind[0].buffer_type = MYSQL_TYPE_STRING;
	bind[0].buffer = message->topic;
	bind[1].buffer_type = MYSQL_TYPE_STRING;
	bind[1].buffer = message->payload;

	mysql_stmt_bind_param(stmt, bind);
	mysql_stmt_execute(stmt);
}

int main(int argc, char *argv[])
{
	MYSQL *connection;
	my_bool reconnect = true;
	char clientid[24];
	struct eecloud *ecld;
	int rc = 0;

	signal(SIGINT, handle_signal);
	signal(SIGTERM, handle_signal);

	mysql_library_init(0, NULL, NULL);
	eecloud_lib_init();

	connection = mysql_init(NULL);

	if(connection){
		mysql_options(connection, MYSQL_OPT_RECONNECT, &reconnect);

		connection = mysql_real_connect(connection, db_host, db_username, db_password, db_database, db_port, NULL, 0);

		if(connection){
			stmt = mysql_stmt_init(connection);

			mysql_stmt_prepare(stmt, db_query, strlen(db_query));

			memset(clientid, 0, 24);
			snprintf(clientid, 23, "mysql_log_%d", getpid());
			ecld = eecloud_new(clientid, true, connection);
			if(ecld){
				eecloud_connect_callback_set(ecld, connect_callback);
				eecloud_message_callback_set(ecld, message_callback);


			    rc = eecloud_connect(ecld, mqtt_host, mqtt_port, 60);

				eecloud_subscribe(ecld, NULL, "#", 0);

				while(run){
					rc = eecloud_loop(ecld, -1, 1);
					if(run && rc){
						sleep(20);
						eecloud_reconnect(ecld);
					}
				}
				eecloud_destroy(ecld);
			}
			mysql_stmt_close(stmt);

			mysql_close(connection);
		}else{
			fprintf(stderr, "Error: Unable to connect to database.\n");
			printf("%s\n", mysql_error(connection));
			rc = 1;
		}
	}else{
		fprintf(stderr, "Error: Unable to start mysql.\n");
		rc = 1;
	}

	mysql_library_end();
	eecloud_lib_cleanup();

	return rc;
}

