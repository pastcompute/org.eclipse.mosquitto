#ifndef TEMPERATURE_CONVERSION_H
#define TEMPERATURE_CONVERSION_H

#include <eecloudpp.h>

class mqtt_tempconv : public ecldpp::eecloudpp
{
	public:
		mqtt_tempconv(const char *id, const char *host, int port);
		~mqtt_tempconv();

		void on_connect(int rc);
		void on_message(const struct eecloud_message *message);
		void on_subscribe(int mid, int qos_count, const int *granted_qos);
};

#endif
