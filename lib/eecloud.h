/*
Copyright (c) 2010-2014 Roger Light <roger@atchoo.org>

All rights reserved. This program and the accompanying materials
are made available under the terms of the Eclipse Public License v1.0
and Eclipse Distribution License v1.0 which accompany this distribution.
 
The Eclipse Public License is available at
   http://www.eclipse.org/legal/epl-v10.html
and the Eclipse Distribution License is available at
  http://www.eclipse.org/org/documents/edl-v10.php.
 
Contributors:
   Roger Light - initial implementation and documentation.
*/

#ifndef _EECLOUD_H_
#define _EECLOUD_H_

#ifdef __cplusplus
extern "C" {
#endif

#if defined(WIN32) && !defined(WITH_BROKER)
#	ifdef libeecloud_EXPORTS
#		define libecld_EXPORT  __declspec(dllexport)
#	else
#		define libecld_EXPORT  __declspec(dllimport)
#	endif
#else
#	define libecld_EXPORT
#endif

#ifdef WIN32
#	ifndef __cplusplus
#		define bool char
#		define true 1
#		define false 0
#	endif
#else
#	ifndef __cplusplus
#		include <stdbool.h>
#	endif
#endif

#define LIBEECLOUD_MAJOR 1
#define LIBEECLOUD_MINOR 4
#define LIBEECLOUD_REVISION 2
/* LIBEECLOUD_VERSION_NUMBER looks like 1002001 for e.g. version 1.2.1. */
#define LIBEECLOUD_VERSION_NUMBER (LIBEECLOUD_MAJOR*1000000+LIBEECLOUD_MINOR*1000+LIBEECLOUD_REVISION)

/* Log types */
#define ECLD_LOG_NONE 0x00
#define ECLD_LOG_INFO 0x01
#define ECLD_LOG_NOTICE 0x02
#define ECLD_LOG_WARNING 0x04
#define ECLD_LOG_ERR 0x08
#define ECLD_LOG_DEBUG 0x10
#define ECLD_LOG_SUBSCRIBE 0x20
#define ECLD_LOG_UNSUBSCRIBE 0x40
#define ECLD_LOG_WEBSOCKETS 0x80
#define ECLD_LOG_ALL 0xFFFF

/* Error values */
enum ecld_err_t {
	ECLD_ERR_CONN_PENDING = -1,
	ECLD_ERR_SUCCESS = 0,
	ECLD_ERR_NOMEM = 1,
	ECLD_ERR_PROTOCOL = 2,
	ECLD_ERR_INVAL = 3,
	ECLD_ERR_NO_CONN = 4,
	ECLD_ERR_CONN_REFUSED = 5,
	ECLD_ERR_NOT_FOUND = 6,
	ECLD_ERR_CONN_LOST = 7,
	ECLD_ERR_TLS = 8,
	ECLD_ERR_PAYLOAD_SIZE = 9,
	ECLD_ERR_NOT_SUPPORTED = 10,
	ECLD_ERR_AUTH = 11,
	ECLD_ERR_ACL_DENIED = 12,
	ECLD_ERR_UNKNOWN = 13,
	ECLD_ERR_ERRNO = 14,
	ECLD_ERR_EAI = 15,
	ECLD_ERR_PROXY = 16
};

/* Error values */
enum ecld_opt_t {
	ECLD_OPT_PROTOCOL_VERSION = 1,
};

/* MQTT specification restricts client ids to a maximum of 23 characters */
#define ECLD_MQTT_ID_MAX_LENGTH 23

#define MQTT_PROTOCOL_V31 3
#define MQTT_PROTOCOL_V311 4

struct eecloud_message{
	int mid;
	char *topic;
	void *payload;
	int payloadlen;
	int qos;
	bool retain;
};

struct eecloud;

/*
 * Topic: Threads
 *	libeecloud provides thread safe operation, with the exception of
 *	<eecloud_lib_init> which is not thread safe.
 *
 *	If your application uses threads you must use <eecloud_threaded_set> to
 *	tell the library this is the case, otherwise it makes some optimisations
 *	for the single threaded case that may result in unexpected behaviour for
 *	the multi threaded case.
 */
/***************************************************
 * Important note
 * 
 * The following functions that deal with network operations will return
 * ECLD_ERR_SUCCESS on success, but this does not mean that the operation has
 * taken place. An attempt will be made to write the network data, but if the
 * socket is not available for writing at that time then the packet will not be
 * sent. To ensure the packet is sent, call eecloud_loop() (which must also
 * be called to process incoming network data).
 * This is especially important when disconnecting a client that has a will. If
 * the broker does not receive the DISCONNECT command, it will assume that the
 * client has disconnected unexpectedly and send the will.
 *
 * eecloud_connect()
 * eecloud_disconnect()
 * eecloud_subscribe()
 * eecloud_unsubscribe()
 * eecloud_publish()
 ***************************************************/

/*
 * Function: eecloud_lib_version
 *
 * Can be used to obtain version information for the eecloud library.
 * This allows the application to compare the library version against the
 * version it was compiled against by using the LIBEECLOUD_MAJOR,
 * LIBEECLOUD_MINOR and LIBEECLOUD_REVISION defines.
 *
 * Parameters:
 *  major -    an integer pointer. If not NULL, the major version of the
 *             library will be returned in this variable.
 *  minor -    an integer pointer. If not NULL, the minor version of the
 *             library will be returned in this variable.
 *  revision - an integer pointer. If not NULL, the revision of the library will
 *             be returned in this variable.
 *
 * Returns:
 *	LIBEECLOUD_VERSION_NUMBER, which is a unique number based on the major,
 *		minor and revision values.
 * See Also:
 * 	<eecloud_lib_cleanup>, <eecloud_lib_init>
 */
libecld_EXPORT int eecloud_lib_version(int *major, int *minor, int *revision);

/*
 * Function: eecloud_lib_init
 *
 * Must be called before any other eecloud functions.
 *
 * This function is *not* thread safe.
 *
 * Returns:
 * 	ECLD_ERR_SUCCESS - always
 *
 * See Also:
 * 	<eecloud_lib_cleanup>, <eecloud_lib_version>
 */
libecld_EXPORT int eecloud_lib_init(void);

/*
 * Function: eecloud_lib_cleanup
 *
 * Call to free resources associated with the library.
 *
 * Returns:
 * 	ECLD_ERR_SUCCESS - always
 *
 * See Also:
 * 	<eecloud_lib_init>, <eecloud_lib_version>
 */
libecld_EXPORT int eecloud_lib_cleanup(void);

/*
 * Function: eecloud_new
 *
 * Create a new eecloud client instance.
 *
 * Parameters:
 * 	id -            String to use as the client id. If NULL, a random client id
 * 	                will be generated. If id is NULL, clean_session must be true.
 * 	clean_session - set to true to instruct the broker to clean all messages
 *                  and subscriptions on disconnect, false to instruct it to
 *                  keep them. See the man page mqtt(7) for more details.
 *                  Note that a client will never discard its own outgoing
 *                  messages on disconnect. Calling <eecloud_connect> or
 *                  <eecloud_reconnect> will cause the messages to be resent.
 *                  Use <eecloud_reinitialise> to reset a client to its
 *                  original state.
 *                  Must be set to true if the id parameter is NULL.
 * 	obj -           A user pointer that will be passed as an argument to any
 *                  callbacks that are specified.
 *
 * Returns:
 * 	Pointer to a struct eecloud on success.
 * 	NULL on failure. Interrogate errno to determine the cause for the failure:
 *      - ENOMEM on out of memory.
 *      - EINVAL on invalid input parameters.
 *
 * See Also:
 * 	<eecloud_reinitialise>, <eecloud_destroy>, <eecloud_user_data_set>
 */
libecld_EXPORT struct eecloud *eecloud_new(const char *id, bool clean_session, void *obj);

/* 
 * Function: eecloud_destroy
 *
 * Use to free memory associated with a eecloud client instance.
 *
 * Parameters:
 * 	ecld - a struct eecloud pointer to free.
 *
 * See Also:
 * 	<eecloud_new>, <eecloud_reinitialise>
 */
libecld_EXPORT void eecloud_destroy(struct eecloud *ecld);

/*
 * Function: eecloud_reinitialise
 *
 * This function allows an existing eecloud client to be reused. Call on a
 * eecloud instance to close any open network connections, free memory
 * and reinitialise the client with the new parameters. The end result is the
 * same as the output of <eecloud_new>.
 *
 * Parameters:
 * 	ecld -          a valid eecloud instance.
 * 	id -            string to use as the client id. If NULL, a random client id
 * 	                will be generated. If id is NULL, clean_session must be true.
 * 	clean_session - set to true to instruct the broker to clean all messages
 *                  and subscriptions on disconnect, false to instruct it to
 *                  keep them. See the man page mqtt(7) for more details.
 *                  Must be set to true if the id parameter is NULL.
 * 	obj -           A user pointer that will be passed as an argument to any
 *                  callbacks that are specified.
 *
 * Returns:
 * 	ECLD_ERR_SUCCESS - on success.
 * 	ECLD_ERR_INVAL -   if the input parameters were invalid.
 * 	ECLD_ERR_NOMEM -   if an out of memory condition occurred.
 *
 * See Also:
 * 	<eecloud_new>, <eecloud_destroy>
 */
libecld_EXPORT int eecloud_reinitialise(struct eecloud *ecld, const char *id, bool clean_session, void *obj);

/* 
 * Function: eecloud_will_set
 *
 * Configure will information for a eecloud instance. By default, clients do
 * not have a will.  This must be called before calling <eecloud_connect>.
 *
 * Parameters:
 * 	ecld -       a valid eecloud instance.
 * 	topic -      the topic on which to publish the will.
 * 	payloadlen - the size of the payload (bytes). Valid values are between 0 and
 *               268,435,455.
 * 	payload -    pointer to the data to send. If payloadlen > 0 this must be a
 *               valid memory location.
 * 	qos -        integer value 0, 1 or 2 indicating the Quality of Service to be
 *               used for the will.
 * 	retain -     set to true to make the will a retained message.
 *
 * Returns:
 * 	ECLD_ERR_SUCCESS -      on success.
 * 	ECLD_ERR_INVAL -        if the input parameters were invalid.
 * 	ECLD_ERR_NOMEM -        if an out of memory condition occurred.
 * 	ECLD_ERR_PAYLOAD_SIZE - if payloadlen is too large.
 */
libecld_EXPORT int eecloud_will_set(struct eecloud *ecld, const char *topic, int payloadlen, const void *payload, int qos, bool retain);

/* 
 * Function: eecloud_will_clear
 *
 * Remove a previously configured will. This must be called before calling
 * <eecloud_connect>.
 *
 * Parameters:
 * 	ecld - a valid eecloud instance.
 *
 * Returns:
 * 	ECLD_ERR_SUCCESS - on success.
 * 	ECLD_ERR_INVAL -   if the input parameters were invalid.
 */
libecld_EXPORT int eecloud_will_clear(struct eecloud *ecld);

/*
 * Function: eecloud_username_pw_set
 *
 * Configure username and password for a eecloudn instance. This is only
 * supported by brokers that implement the MQTT spec v3.1. By default, no
 * username or password will be sent.
 * If username is NULL, the password argument is ignored.
 * This must be called before calling eecloud_connect().
 *
 * This is must be called before calling <eecloud_connect>.
 *
 * Parameters:
 * 	ecld -     a valid eecloud instance.
 * 	username - the username to send as a string, or NULL to disable
 *             authentication.
 * 	password - the password to send as a string. Set to NULL when username is
 * 	           valid in order to send just a username.
 *
 * Returns:
 * 	ECLD_ERR_SUCCESS - on success.
 * 	ECLD_ERR_INVAL -   if the input parameters were invalid.
 * 	ECLD_ERR_NOMEM -   if an out of memory condition occurred.
 */
libecld_EXPORT int eecloud_username_pw_set(struct eecloud *ecld, const char *username, const char *password);

/*
 * Function: eecloud_connect
 *
 * Connect to an MQTT broker.
 *
 * Parameters:
 * 	ecld -      a valid eecloud instance.
 * 	host -      the hostname or ip address of the broker to connect to.
 * 	port -      the network port to connect to. Usually 1883.
 * 	keepalive - the number of seconds after which the broker should send a PING
 *              message to the client if no other messages have been exchanged
 *              in that time.
 *
 * Returns:
 * 	ECLD_ERR_SUCCESS - on success.
 * 	ECLD_ERR_INVAL -   if the input parameters were invalid.
 * 	ECLD_ERR_ERRNO -   if a system call returned an error. The variable errno
 *                     contains the error code, even on Windows.
 *                     Use strerror_r() where available or FormatMessage() on
 *                     Windows.
 *
 * See Also:
 * 	<eecloud_connect_bind>, <eecloud_connect_async>, <eecloud_reconnect>, <eecloud_disconnect>, <eecloud_tls_set>
 */
libecld_EXPORT int eecloud_connect(struct eecloud *ecld, const char *host, int port, int keepalive);

/*
 * Function: eecloud_connect_bind
 *
 * Connect to an MQTT broker. This extends the functionality of
 * <eecloud_connect> by adding the bind_address parameter. Use this function
 * if you need to restrict network communication over a particular interface. 
 *
 * Parameters:
 * 	ecld -         a valid eecloud instance.
 * 	host -         the hostname or ip address of the broker to connect to.
 * 	port -         the network port to connect to. Usually 1883.
 * 	keepalive -    the number of seconds after which the broker should send a PING
 *                 message to the client if no other messages have been exchanged
 *                 in that time.
 *  bind_address - the hostname or ip address of the local network interface to
 *                 bind to.
 *
 * Returns:
 * 	ECLD_ERR_SUCCESS - on success.
 * 	ECLD_ERR_INVAL -   if the input parameters were invalid.
 * 	ECLD_ERR_ERRNO -   if a system call returned an error. The variable errno
 *                     contains the error code, even on Windows.
 *                     Use strerror_r() where available or FormatMessage() on
 *                     Windows.
 *
 * See Also:
 * 	<eecloud_connect>, <eecloud_connect_async>, <eecloud_connect_bind_async>
 */
libecld_EXPORT int eecloud_connect_bind(struct eecloud *ecld, const char *host, int port, int keepalive, const char *bind_address);

/*
 * Function: eecloud_connect_async
 *
 * Connect to an MQTT broker. This is a non-blocking call. If you use
 * <eecloud_connect_async> your client must use the threaded interface
 * <eecloud_loop_start>. If you need to use <eecloud_loop>, you must use
 * <eecloud_connect> to connect the client.
 *
 * May be called before or after <eecloud_loop_start>.
 *
 * Parameters:
 * 	ecld -      a valid eecloud instance.
 * 	host -      the hostname or ip address of the broker to connect to.
 * 	port -      the network port to connect to. Usually 1883.
 * 	keepalive - the number of seconds after which the broker should send a PING
 *              message to the client if no other messages have been exchanged
 *              in that time.
 *
 * Returns:
 * 	ECLD_ERR_SUCCESS - on success.
 * 	ECLD_ERR_INVAL -   if the input parameters were invalid.
 * 	ECLD_ERR_ERRNO -   if a system call returned an error. The variable errno
 *                     contains the error code, even on Windows.
 *                     Use strerror_r() where available or FormatMessage() on
 *                     Windows.
 *
 * See Also:
 * 	<eecloud_connect_bind_async>, <eecloud_connect>, <eecloud_reconnect>, <eecloud_disconnect>, <eecloud_tls_set>
 */
libecld_EXPORT int eecloud_connect_async(struct eecloud *ecld, const char *host, int port, int keepalive);

/*
 * Function: eecloud_connect_bind_async
 *
 * Connect to an MQTT broker. This is a non-blocking call. If you use
 * <eecloud_connect_bind_async> your client must use the threaded interface
 * <eecloud_loop_start>. If you need to use <eecloud_loop>, you must use
 * <eecloud_connect> to connect the client.
 *
 * This extends the functionality of <eecloud_connect_async> by adding the
 * bind_address parameter. Use this function if you need to restrict network
 * communication over a particular interface. 
 *
 * May be called before or after <eecloud_loop_start>.
 *
 * Parameters:
 * 	ecld -         a valid eecloud instance.
 * 	host -         the hostname or ip address of the broker to connect to.
 * 	port -         the network port to connect to. Usually 1883.
 * 	keepalive -    the number of seconds after which the broker should send a PING
 *                 message to the client if no other messages have been exchanged
 *                 in that time.
 *  bind_address - the hostname or ip address of the local network interface to
 *                 bind to.
 *
 * Returns:
 * 	ECLD_ERR_SUCCESS - on success.
 * 	ECLD_ERR_INVAL -   if the input parameters were invalid.
 * 	ECLD_ERR_ERRNO -   if a system call returned an error. The variable errno
 *                     contains the error code, even on Windows.
 *                     Use strerror_r() where available or FormatMessage() on
 *                     Windows.
 *
 * See Also:
 * 	<eecloud_connect_async>, <eecloud_connect>, <eecloud_connect_bind>
 */
libecld_EXPORT int eecloud_connect_bind_async(struct eecloud *ecld, const char *host, int port, int keepalive, const char *bind_address);

/*
 * Function: eecloud_connect_srv
 *
 * Connect to an MQTT broker. This is a non-blocking call. If you use
 * <eecloud_connect_async> your client must use the threaded interface
 * <eecloud_loop_start>. If you need to use <eecloud_loop>, you must use
 * <eecloud_connect> to connect the client.
 *
 * This extends the functionality of <eecloud_connect_async> by adding the
 * bind_address parameter. Use this function if you need to restrict network
 * communication over a particular interface. 
 *
 * May be called before or after <eecloud_loop_start>.
 *
 * Parameters:
 * 	ecld -         a valid eecloud instance.
 * 	host -         the hostname or ip address of the broker to connect to.
 * 	keepalive -    the number of seconds after which the broker should send a PING
 *                 message to the client if no other messages have been exchanged
 *                 in that time.
 *  bind_address - the hostname or ip address of the local network interface to
 *                 bind to.
 *
 * Returns:
 * 	ECLD_ERR_SUCCESS - on success.
 * 	ECLD_ERR_INVAL -   if the input parameters were invalid.
 * 	ECLD_ERR_ERRNO -   if a system call returned an error. The variable errno
 *                     contains the error code, even on Windows.
 *                     Use strerror_r() where available or FormatMessage() on
 *                     Windows.
 *
 * See Also:
 * 	<eecloud_connect_async>, <eecloud_connect>, <eecloud_connect_bind>
 */
libecld_EXPORT int eecloud_connect_srv(struct eecloud *ecld, const char *host, int keepalive, const char *bind_address);

/*
 * Function: eecloud_reconnect
 *
 * Reconnect to a broker.
 *
 * This function provides an easy way of reconnecting to a broker after a
 * connection has been lost. It uses the values that were provided in the
 * <eecloud_connect> call. It must not be called before
 * <eecloud_connect>.
 * 
 * Parameters:
 * 	ecld - a valid eecloud instance.
 *
 * Returns:
 * 	ECLD_ERR_SUCCESS - on success.
 * 	ECLD_ERR_INVAL -   if the input parameters were invalid.
 * 	ECLD_ERR_NOMEM -   if an out of memory condition occurred.
 *
 * Returns:
 * 	ECLD_ERR_SUCCESS - on success.
 * 	ECLD_ERR_INVAL -   if the input parameters were invalid.
 * 	ECLD_ERR_ERRNO -   if a system call returned an error. The variable errno
 *                     contains the error code, even on Windows.
 *                     Use strerror_r() where available or FormatMessage() on
 *                     Windows.
 *
 * See Also:
 * 	<eecloud_connect>, <eecloud_disconnect>, <eecloud_reconnect_async>
 */
libecld_EXPORT int eecloud_reconnect(struct eecloud *ecld);

/*
 * Function: eecloud_reconnect_async
 *
 * Reconnect to a broker. Non blocking version of <eecloud_reconnect>.
 *
 * This function provides an easy way of reconnecting to a broker after a
 * connection has been lost. It uses the values that were provided in the
 * <eecloud_connect> or <eecloud_connect_async> calls. It must not be
 * called before <eecloud_connect>.
 * 
 * Parameters:
 * 	ecld - a valid eecloud instance.
 *
 * Returns:
 * 	ECLD_ERR_SUCCESS - on success.
 * 	ECLD_ERR_INVAL -   if the input parameters were invalid.
 * 	ECLD_ERR_NOMEM -   if an out of memory condition occurred.
 *
 * Returns:
 * 	ECLD_ERR_SUCCESS - on success.
 * 	ECLD_ERR_INVAL -   if the input parameters were invalid.
 * 	ECLD_ERR_ERRNO -   if a system call returned an error. The variable errno
 *                     contains the error code, even on Windows.
 *                     Use strerror_r() where available or FormatMessage() on
 *                     Windows.
 *
 * See Also:
 * 	<eecloud_connect>, <eecloud_disconnect>
 */
libecld_EXPORT int eecloud_reconnect_async(struct eecloud *ecld);

/*
 * Function: eecloud_disconnect
 *
 * Disconnect from the broker.
 *
 * Parameters:
 *	ecld - a valid eecloud instance.
 *
 * Returns:
 *	ECLD_ERR_SUCCESS - on success.
 * 	ECLD_ERR_INVAL -   if the input parameters were invalid.
 * 	ECLD_ERR_NO_CONN -  if the client isn't connected to a broker.
 */
libecld_EXPORT int eecloud_disconnect(struct eecloud *ecld);

/* 
 * Function: eecloud_publish
 *
 * Publish a message on a given topic.
 * 
 * Parameters:
 * 	ecld -       a valid eecloud instance.
 * 	mid -        pointer to an int. If not NULL, the function will set this
 *               to the message id of this particular message. This can be then
 *               used with the publish callback to determine when the message
 *               has been sent.
 *               Note that although the MQTT protocol doesn't use message ids
 *               for messages with QoS=0, libeecloud assigns them message ids
 *               so they can be tracked with this parameter.
 * 	payloadlen - the size of the payload (bytes). Valid values are between 0 and
 *               268,435,455.
 * 	payload -    pointer to the data to send. If payloadlen > 0 this must be a
 *               valid memory location.
 * 	qos -        integer value 0, 1 or 2 indicating the Quality of Service to be
 *               used for the message.
 * 	retain -     set to true to make the message retained.
 *
 * Returns:
 * 	ECLD_ERR_SUCCESS -      on success.
 * 	ECLD_ERR_INVAL -        if the input parameters were invalid.
 * 	ECLD_ERR_NOMEM -        if an out of memory condition occurred.
 * 	ECLD_ERR_NO_CONN -      if the client isn't connected to a broker.
 *	ECLD_ERR_PROTOCOL -     if there is a protocol error communicating with the
 *                          broker.
 * 	ECLD_ERR_PAYLOAD_SIZE - if payloadlen is too large.
 *
 * See Also: 
 *	<eecloud_max_inflight_messages_set>
 */
libecld_EXPORT int eecloud_publish(struct eecloud *ecld, int *mid, const char *topic, int payloadlen, const void *payload, int qos, bool retain);

/*
 * Function: eecloud_subscribe
 *
 * Subscribe to a topic.
 *
 * Parameters:
 *	ecld - a valid eecloud instance.
 *	mid -  a pointer to an int. If not NULL, the function will set this to
 *	       the message id of this particular message. This can be then used
 *	       with the subscribe callback to determine when the message has been
 *	       sent.
 *	sub -  the subscription pattern.
 *	qos -  the requested Quality of Service for this subscription.
 *
 * Returns:
 *	ECLD_ERR_SUCCESS - on success.
 * 	ECLD_ERR_INVAL -   if the input parameters were invalid.
 * 	ECLD_ERR_NOMEM -   if an out of memory condition occurred.
 * 	ECLD_ERR_NO_CONN - if the client isn't connected to a broker.
 */
libecld_EXPORT int eecloud_subscribe(struct eecloud *ecld, int *mid, const char *sub, int qos);

/*
 * Function: eecloud_unsubscribe
 *
 * Unsubscribe from a topic.
 *
 * Parameters:
 *	ecld - a valid eecloud instance.
 *	mid -  a pointer to an int. If not NULL, the function will set this to
 *	       the message id of this particular message. This can be then used
 *	       with the unsubscribe callback to determine when the message has been
 *	       sent.
 *	sub -  the unsubscription pattern.
 *
 * Returns:
 *	ECLD_ERR_SUCCESS - on success.
 * 	ECLD_ERR_INVAL -   if the input parameters were invalid.
 * 	ECLD_ERR_NOMEM -   if an out of memory condition occurred.
 * 	ECLD_ERR_NO_CONN - if the client isn't connected to a broker.
 */
libecld_EXPORT int eecloud_unsubscribe(struct eecloud *ecld, int *mid, const char *sub);

/*
 * Function: eecloud_message_copy
 *
 * Copy the contents of a eecloud message to another message.
 * Useful for preserving a message received in the on_message() callback.
 *
 * Parameters:
 *	dst - a pointer to a valid eecloud_message struct to copy to.
 *	src - a pointer to a valid eecloud_message struct to copy from.
 *
 * Returns:
 *	ECLD_ERR_SUCCESS - on success.
 * 	ECLD_ERR_INVAL -   if the input parameters were invalid.
 * 	ECLD_ERR_NOMEM -   if an out of memory condition occurred.
 *
 * See Also:
 * 	<eecloud_message_free>
 */
libecld_EXPORT int eecloud_message_copy(struct eecloud_message *dst, const struct eecloud_message *src);

/*
 * Function: eecloud_message_free
 * 
 * Completely free a eecloud_message struct.
 *
 * Parameters:
 *	message - pointer to a eecloud_message pointer to free.
 *
 * See Also:
 * 	<eecloud_message_copy>
 */
libecld_EXPORT void eecloud_message_free(struct eecloud_message **message);

/*
 * Function: eecloud_loop
 *
 * The main network loop for the client. You must call this frequently in order
 * to keep communications between the client and broker working. If incoming
 * data is present it will then be processed. Outgoing commands, from e.g.
 * <eecloud_publish>, are normally sent immediately that their function is
 * called, but this is not always possible. <eecloud_loop> will also attempt
 * to send any remaining outgoing messages, which also includes commands that
 * are part of the flow for messages with QoS>0.
 *
 * An alternative approach is to use <eecloud_loop_start> to run the client
 * loop in its own thread.
 *
 * This calls select() to monitor the client network socket. If you want to
 * integrate eecloud client operation with your own select() call, use
 * <eecloud_socket>, <eecloud_loop_read>, <eecloud_loop_write> and
 * <eecloud_loop_misc>.
 *
 * Threads:
 *	
 * Parameters:
 *	ecld -        a valid eecloud instance.
 *	timeout -     Maximum number of milliseconds to wait for network activity
 *	              in the select() call before timing out. Set to 0 for instant
 *	              return.  Set negative to use the default of 1000ms.
 *	max_packets - this parameter is currently unused and should be set to 1 for
 *	              future compatibility.
 * 
 * Returns:
 *	ECLD_ERR_SUCCESS -   on success.
 * 	ECLD_ERR_INVAL -     if the input parameters were invalid.
 * 	ECLD_ERR_NOMEM -     if an out of memory condition occurred.
 * 	ECLD_ERR_NO_CONN -   if the client isn't connected to a broker.
 *  ECLD_ERR_CONN_LOST - if the connection to the broker was lost.
 *	ECLD_ERR_PROTOCOL -  if there is a protocol error communicating with the
 *                       broker.
 * 	ECLD_ERR_ERRNO -     if a system call returned an error. The variable errno
 *                       contains the error code, even on Windows.
 *                       Use strerror_r() where available or FormatMessage() on
 *                       Windows.
 * See Also:
 *	<eecloud_loop_forever>, <eecloud_loop_start>, <eecloud_loop_stop>
 */
libecld_EXPORT int eecloud_loop(struct eecloud *ecld, int timeout, int max_packets);

/*
 * Function: eecloud_loop_forever
 *
 * This function call loop() for you in an infinite blocking loop. It is useful
 * for the case where you only want to run the MQTT client loop in your
 * program.
 *
 * It handles reconnecting in case server connection is lost. If you call
 * eecloud_disconnect() in a callback it will return.
 *
 * Parameters:
 *  ecld - a valid eecloud instance.
 *	timeout -     Maximum number of milliseconds to wait for network activity
 *	              in the select() call before timing out. Set to 0 for instant
 *	              return.  Set negative to use the default of 1000ms.
 *	max_packets - this parameter is currently unused and should be set to 1 for
 *	              future compatibility.
 *
 * Returns:
 *	ECLD_ERR_SUCCESS -   on success.
 * 	ECLD_ERR_INVAL -     if the input parameters were invalid.
 * 	ECLD_ERR_NOMEM -     if an out of memory condition occurred.
 * 	ECLD_ERR_NO_CONN -   if the client isn't connected to a broker.
 *  ECLD_ERR_CONN_LOST - if the connection to the broker was lost.
 *	ECLD_ERR_PROTOCOL -  if there is a protocol error communicating with the
 *                       broker.
 * 	ECLD_ERR_ERRNO -     if a system call returned an error. The variable errno
 *                       contains the error code, even on Windows.
 *                       Use strerror_r() where available or FormatMessage() on
 *                       Windows.
 *
 * See Also:
 *	<eecloud_loop>, <eecloud_loop_start>
 */
libecld_EXPORT int eecloud_loop_forever(struct eecloud *ecld, int timeout, int max_packets);

/*
 * Function: eecloud_loop_start
 *
 * This is part of the threaded client interface. Call this once to start a new
 * thread to process network traffic. This provides an alternative to
 * repeatedly calling <eecloud_loop> yourself.
 *
 * Parameters:
 *  ecld - a valid eecloud instance.
 *
 * Returns:
 *	ECLD_ERR_SUCCESS -       on success.
 * 	ECLD_ERR_INVAL -         if the input parameters were invalid.
 *	ECLD_ERR_NOT_SUPPORTED - if thread support is not available.
 *
 * See Also:
 *	<eecloud_connect_async>, <eecloud_loop>, <eecloud_loop_forever>, <eecloud_loop_stop>
 */
libecld_EXPORT int eecloud_loop_start(struct eecloud *ecld);

/*
 * Function: eecloud_loop_stop
 *
 * This is part of the threaded client interface. Call this once to stop the
 * network thread previously created with <eecloud_loop_start>. This call
 * will block until the network thread finishes. For the network thread to end,
 * you must have previously called <eecloud_disconnect> or have set the force
 * parameter to true.
 *
 * Parameters:
 *  ecld - a valid eecloud instance.
 *	force - set to true to force thread cancellation. If false,
 *	        <eecloud_disconnect> must have already been called.
 *
 * Returns:
 *	ECLD_ERR_SUCCESS -       on success.
 * 	ECLD_ERR_INVAL -         if the input parameters were invalid.
 *	ECLD_ERR_NOT_SUPPORTED - if thread support is not available.
 *
 * See Also:
 *	<eecloud_loop>, <eecloud_loop_start>
 */
libecld_EXPORT int eecloud_loop_stop(struct eecloud *ecld, bool force);

/*
 * Function: eecloud_socket
 *
 * Return the socket handle for a eecloud instance. Useful if you want to
 * include a eecloud client in your own select() calls.
 *
 * Parameters:
 *	ecld - a valid eecloud instance.
 *
 * Returns:
 *	The socket for the eecloud client or -1 on failure.
 */
libecld_EXPORT int eecloud_socket(struct eecloud *ecld);

/*
 * Function: eecloud_loop_read
 *
 * Carry out network read operations.
 * This should only be used if you are not using eecloud_loop() and are
 * monitoring the client network socket for activity yourself.
 *
 * Parameters:
 *	ecld -        a valid eecloud instance.
 *	max_packets - this parameter is currently unused and should be set to 1 for
 *	              future compatibility.
 *
 * Returns:
 *	ECLD_ERR_SUCCESS -   on success.
 * 	ECLD_ERR_INVAL -     if the input parameters were invalid.
 * 	ECLD_ERR_NOMEM -     if an out of memory condition occurred.
 * 	ECLD_ERR_NO_CONN -   if the client isn't connected to a broker.
 *  ECLD_ERR_CONN_LOST - if the connection to the broker was lost.
 *	ECLD_ERR_PROTOCOL -  if there is a protocol error communicating with the
 *                       broker.
 * 	ECLD_ERR_ERRNO -     if a system call returned an error. The variable errno
 *                       contains the error code, even on Windows.
 *                       Use strerror_r() where available or FormatMessage() on
 *                       Windows.
 *
 * See Also:
 *	<eecloud_socket>, <eecloud_loop_write>, <eecloud_loop_misc>
 */
libecld_EXPORT int eecloud_loop_read(struct eecloud *ecld, int max_packets);

/*
 * Function: eecloud_loop_write
 *
 * Carry out network write operations.
 * This should only be used if you are not using eecloud_loop() and are
 * monitoring the client network socket for activity yourself.
 *
 * Parameters:
 *	ecld -        a valid eecloud instance.
 *	max_packets - this parameter is currently unused and should be set to 1 for
 *	              future compatibility.
 *
 * Returns:
 *	ECLD_ERR_SUCCESS -   on success.
 * 	ECLD_ERR_INVAL -     if the input parameters were invalid.
 * 	ECLD_ERR_NOMEM -     if an out of memory condition occurred.
 * 	ECLD_ERR_NO_CONN -   if the client isn't connected to a broker.
 *  ECLD_ERR_CONN_LOST - if the connection to the broker was lost.
 *	ECLD_ERR_PROTOCOL -  if there is a protocol error communicating with the
 *                       broker.
 * 	ECLD_ERR_ERRNO -     if a system call returned an error. The variable errno
 *                       contains the error code, even on Windows.
 *                       Use strerror_r() where available or FormatMessage() on
 *                       Windows.
 *
 * See Also:
 *	<eecloud_socket>, <eecloud_loop_read>, <eecloud_loop_misc>, <eecloud_want_write>
 */
libecld_EXPORT int eecloud_loop_write(struct eecloud *ecld, int max_packets);

/*
 * Function: eecloud_loop_misc
 *
 * Carry out miscellaneous operations required as part of the network loop.
 * This should only be used if you are not using eecloud_loop() and are
 * monitoring the client network socket for activity yourself.
 *
 * This function deals with handling PINGs and checking whether messages need
 * to be retried, so should be called fairly frequently.
 *
 * Parameters:
 *	ecld - a valid eecloud instance.
 *
 * Returns:
 *	ECLD_ERR_SUCCESS -   on success.
 * 	ECLD_ERR_INVAL -     if the input parameters were invalid.
 * 	ECLD_ERR_NO_CONN -   if the client isn't connected to a broker.
 *
 * See Also:
 *	<eecloud_socket>, <eecloud_loop_read>, <eecloud_loop_write>
 */
libecld_EXPORT int eecloud_loop_misc(struct eecloud *ecld);

/*
 * Function: eecloud_want_write
 *
 * Returns true if there is data ready to be written on the socket.
 *
 * Parameters:
 *	ecld - a valid eecloud instance.
 *
 * See Also:
 *	<eecloud_socket>, <eecloud_loop_read>, <eecloud_loop_write>
 */
libecld_EXPORT bool eecloud_want_write(struct eecloud *ecld);

/*
 * Function: eecloud_threaded_set
 *
 * Used to tell the library that your application is using threads, but not
 * using <eecloud_loop_start>. The library operates slightly differently when
 * not in threaded mode in order to simplify its operation. If you are managing
 * your own threads and do not use this function you will experience crashes
 * due to race conditions.
 *
 * When using <eecloud_loop_start>, this is set automatically.
 *
 * Parameters:
 *  ecld -     a valid eecloud instance.
 *  threaded - true if your application is using threads, false otherwise.
 */
libecld_EXPORT int eecloud_threaded_set(struct eecloud *ecld, bool threaded);

/*
 * Function: eecloud_opts_set
 *
 * Used to set options for the client.
 *
 * Parameters:
 *	ecld -   a valid eecloud instance.
 *	option - the option to set.
 *	value -  the option specific value.
 *
 * Options:
 *	ECLD_OPT_PROTOCOL_VERSION - value must be an int, set to either
 *	                            MQTT_PROTOCOL_V31 or MQTT_PROTOCOL_V311. Must
 *	                            be set before the client connects. Defaults to
 *	                            MQTT_PROTOCOL_V31.
 */
libecld_EXPORT int eecloud_opts_set(struct eecloud *ecld, enum ecld_opt_t option, void *value);


/*
 * Function: eecloud_tls_set
 *
 * Configure the client for certificate based SSL/TLS support. Must be called
 * before <eecloud_connect>.
 *
 * Cannot be used in conjunction with <eecloud_tls_psk_set>.
 *
 * Define the Certificate Authority certificates to be trusted (ie. the server
 * certificate must be signed with one of these certificates) using cafile.
 *
 * If the server you are connecting to requires clients to provide a
 * certificate, define certfile and keyfile with your client certificate and
 * private key. If your private key is encrypted, provide a password callback
 * function or you will have to enter the password at the command line.
 *
 * Parameters:
 *  ecld -        a valid eecloud instance.
 *  cafile -      path to a file containing the PEM encoded trusted CA
 *                certificate files. Either cafile or capath must not be NULL.
 *  capath -      path to a directory containing the PEM encoded trusted CA
 *                certificate files. See eecloud.conf for more details on
 *                configuring this directory. Either cafile or capath must not
 *                be NULL.
 *  certfile -    path to a file containing the PEM encoded certificate file
 *                for this client. If NULL, keyfile must also be NULL and no
 *                client certificate will be used.
 *  keyfile -     path to a file containing the PEM encoded private key for
 *                this client. If NULL, certfile must also be NULL and no
 *                client certificate will be used.
 *  pw_callback - if keyfile is encrypted, set pw_callback to allow your client
 *                to pass the correct password for decryption. If set to NULL,
 *                the password must be entered on the command line.
 *                Your callback must write the password into "buf", which is
 *                "size" bytes long. The return value must be the length of the
 *                password. "userdata" will be set to the calling eecloud
 *                instance.
 *
 * Returns:
 *	ECLD_ERR_SUCCESS - on success.
 * 	ECLD_ERR_INVAL -   if the input parameters were invalid.
 * 	ECLD_ERR_NOMEM -   if an out of memory condition occurred.
 *
 * See Also:
 *	<eecloud_tls_opts_set>, <eecloud_tls_psk_set>, <eecloud_tls_insecure_set>
 */
libecld_EXPORT int eecloud_tls_set(struct eecloud *ecld,
		const char *cafile, const char *capath,
		const char *certfile, const char *keyfile,
		int (*pw_callback)(char *buf, int size, int rwflag, void *userdata));

/*
 * Function: eecloud_tls_insecure_set
 *
 * Configure verification of the server hostname in the server certificate. If
 * value is set to true, it is impossible to guarantee that the host you are
 * connecting to is not impersonating your server. This can be useful in
 * initial server testing, but makes it possible for a malicious third party to
 * impersonate your server through DNS spoofing, for example.
 * Do not use this function in a real system. Setting value to true makes the
 * connection encryption pointless.
 * Must be called before <eecloud_connect>.
 *
 * Parameters:
 *  ecld -  a valid eecloud instance.
 *  value - if set to false, the default, certificate hostname checking is
 *          performed. If set to true, no hostname checking is performed and
 *          the connection is insecure.
 *
 * Returns:
 *	ECLD_ERR_SUCCESS - on success.
 * 	ECLD_ERR_INVAL -   if the input parameters were invalid.
 *
 * See Also:
 *	<eecloud_tls_set>
 */
libecld_EXPORT int eecloud_tls_insecure_set(struct eecloud *ecld, bool value);

/*
 * Function: eecloud_tls_opts_set
 *
 * Set advanced SSL/TLS options. Must be called before <eecloud_connect>.
 *
 * Parameters:
 *  ecld -        a valid eecloud instance.
 *	cert_reqs -   an integer defining the verification requirements the client
 *	              will impose on the server. This can be one of:
 *	              * SSL_VERIFY_NONE (0): the server will not be verified in any way.
 *	              * SSL_VERIFY_PEER (1): the server certificate will be verified
 *	                and the connection aborted if the verification fails.
 *	              The default and recommended value is SSL_VERIFY_PEER. Using
 *	              SSL_VERIFY_NONE provides no security.
 *	tls_version - the version of the SSL/TLS protocol to use as a string. If NULL,
 *	              the default value is used. The default value and the
 *	              available values depend on the version of openssl that the
 *	              library was compiled against. For openssl >= 1.0.1, the
 *	              available options are tlsv1.2, tlsv1.1 and tlsv1, with tlv1.2
 *	              as the default. For openssl < 1.0.1, only tlsv1 is available.
 *	ciphers -     a string describing the ciphers available for use. See the
 *	              "openssl ciphers" tool for more information. If NULL, the
 *	              default ciphers will be used.
 *
 * Returns:
 *	ECLD_ERR_SUCCESS - on success.
 * 	ECLD_ERR_INVAL -   if the input parameters were invalid.
 * 	ECLD_ERR_NOMEM -   if an out of memory condition occurred.
 *
 * See Also:
 *	<eecloud_tls_set>
 */
libecld_EXPORT int eecloud_tls_opts_set(struct eecloud *ecld, int cert_reqs, const char *tls_version, const char *ciphers);

/*
 * Function: eecloud_tls_psk_set
 *
 * Configure the client for pre-shared-key based TLS support. Must be called
 * before <eecloud_connect>.
 *
 * Cannot be used in conjunction with <eecloud_tls_set>.
 *
 * Parameters:
 *  ecld -     a valid eecloud instance.
 *  psk -      the pre-shared-key in hex format with no leading "0x".
 *  identity - the identity of this client. May be used as the username
 *             depending on the server settings.
 *	ciphers -  a string describing the PSK ciphers available for use. See the
 *	           "openssl ciphers" tool for more information. If NULL, the
 *	           default ciphers will be used.
 *
 * Returns:
 *	ECLD_ERR_SUCCESS - on success.
 * 	ECLD_ERR_INVAL -   if the input parameters were invalid.
 * 	ECLD_ERR_NOMEM -   if an out of memory condition occurred.
 *
 * See Also:
 *	<eecloud_tls_set>
 */
libecld_EXPORT int eecloud_tls_psk_set(struct eecloud *ecld, const char *psk, const char *identity, const char *ciphers);

/* 
 * Function: eecloud_connect_callback_set
 *
 * Set the connect callback. This is called when the broker sends a CONNACK
 * message in response to a connection.
 *
 * Parameters:
 *  ecld -       a valid eecloud instance.
 *  on_connect - a callback function in the following form:
 *               void callback(struct eecloud *ecld, void *obj, int rc)
 *
 * Callback Parameters:
 *  ecld - the eecloud instance making the callback.
 *  obj - the user data provided in <eecloud_new>
 *  rc -  the return code of the connection response, one of:
 *
 * * 0 - success
 * * 1 - connection refused (unacceptable protocol version)
 * * 2 - connection refused (identifier rejected)
 * * 3 - connection refused (broker unavailable)
 * * 4-255 - reserved for future use
 */
libecld_EXPORT void eecloud_connect_callback_set(struct eecloud *ecld, void (*on_connect)(struct eecloud *, void *, int));
 
/*
 * Function: eecloud_disconnect_callback_set
 *
 * Set the disconnect callback. This is called when the broker has received the
 * DISCONNECT command and has disconnected the client.
 * 
 * Parameters:
 *  ecld -          a valid eecloud instance.
 *  on_disconnect - a callback function in the following form:
 *                  void callback(struct eecloud *ecld, void *obj)
 *
 * Callback Parameters:
 *  ecld - the eecloud instance making the callback.
 *  obj -  the user data provided in <eecloud_new>
 *  rc -   integer value indicating the reason for the disconnect. A value of 0
 *         means the client has called <eecloud_disconnect>. Any other value
 *         indicates that the disconnect is unexpected.
 */
libecld_EXPORT void eecloud_disconnect_callback_set(struct eecloud *ecld, void (*on_disconnect)(struct eecloud *, void *, int));
 
/*
 * Function: eecloud_publish_callback_set
 *
 * Set the publish callback. This is called when a message initiated with
 * <eecloud_publish> has been sent to the broker successfully.
 * 
 * Parameters:
 *  ecld -       a valid eecloud instance.
 *  on_publish - a callback function in the following form:
 *               void callback(struct eecloud *ecld, void *obj, int mid)
 *
 * Callback Parameters:
 *  ecld - the eecloud instance making the callback.
 *  obj -  the user data provided in <eecloud_new>
 *  mid -  the message id of the sent message.
 */
libecld_EXPORT void eecloud_publish_callback_set(struct eecloud *ecld, void (*on_publish)(struct eecloud *, void *, int));

/*
 * Function: eecloud_message_callback_set
 *
 * Set the message callback. This is called when a message is received from the
 * broker.
 * 
 * Parameters:
 *  ecld -       a valid eecloud instance.
 *  on_message - a callback function in the following form:
 *               void callback(struct eecloud *ecld, void *obj, const struct eecloud_message *message)
 *
 * Callback Parameters:
 *  ecld -    the eecloud instance making the callback.
 *  obj -     the user data provided in <eecloud_new>
 *  message - the message data. This variable and associated memory will be
 *            freed by the library after the callback completes. The client
 *            should make copies of any of the data it requires.
 *
 * See Also:
 * 	<eecloud_message_copy>
 */
libecld_EXPORT void eecloud_message_callback_set(struct eecloud *ecld, void (*on_message)(struct eecloud *, void *, const struct eecloud_message *));

/*
 * Function: eecloud_subscribe_callback_set
 *
 * Set the subscribe callback. This is called when the broker responds to a
 * subscription request.
 * 
 * Parameters:
 *  ecld -         a valid eecloud instance.
 *  on_subscribe - a callback function in the following form:
 *                 void callback(struct eecloud *ecld, void *obj, int mid, int qos_count, const int *granted_qos)
 *
 * Callback Parameters:
 *  ecld -        the eecloud instance making the callback.
 *  obj -         the user data provided in <eecloud_new>
 *  mid -         the message id of the subscribe message.
 *  qos_count -   the number of granted subscriptions (size of granted_qos).
 *  granted_qos - an array of integers indicating the granted QoS for each of
 *                the subscriptions.
 */
libecld_EXPORT void eecloud_subscribe_callback_set(struct eecloud *ecld, void (*on_subscribe)(struct eecloud *, void *, int, int, const int *));

/*
 * Function: eecloud_unsubscribe_callback_set
 *
 * Set the unsubscribe callback. This is called when the broker responds to a
 * unsubscription request.
 * 
 * Parameters:
 *  ecld -           a valid eecloud instance.
 *  on_unsubscribe - a callback function in the following form:
 *                   void callback(struct eecloud *ecld, void *obj, int mid)
 *
 * Callback Parameters:
 *  ecld - the eecloud instance making the callback.
 *  obj -  the user data provided in <eecloud_new>
 *  mid -  the message id of the unsubscribe message.
 */
libecld_EXPORT void eecloud_unsubscribe_callback_set(struct eecloud *ecld, void (*on_unsubscribe)(struct eecloud *, void *, int));

/*
 * Function: eecloud_log_callback_set
 *
 * Set the logging callback. This should be used if you want event logging
 * information from the client library.
 *
 *  ecld -   a valid eecloud instance.
 *  on_log - a callback function in the following form:
 *           void callback(struct eecloud *ecld, void *obj, int level, const char *str)
 *
 * Callback Parameters:
 *  ecld -  the eecloud instance making the callback.
 *  obj -   the user data provided in <eecloud_new>
 *  level - the log message level from the values:
 *	        ECLD_LOG_INFO
 *	        ECLD_LOG_NOTICE
 *	        ECLD_LOG_WARNING
 *	        ECLD_LOG_ERR
 *	        ECLD_LOG_DEBUG
 *	str -   the message string.
 */
libecld_EXPORT void eecloud_log_callback_set(struct eecloud *ecld, void (*on_log)(struct eecloud *, void *, int, const char *));

/*
 * Function: eecloud_reconnect_delay_set
 *
 * Control the behaviour of the client when it has unexpectedly disconnected in
 * <eecloud_loop_forever> or after <eecloud_loop_start>. The default
 * behaviour if this function is not used is to repeatedly attempt to reconnect
 * with a delay of 1 second until the connection succeeds.
 *
 * Use reconnect_delay parameter to change the delay between successive
 * reconnection attempts. You may also enable exponential backoff of the time
 * between reconnections by setting reconnect_exponential_backoff to true and
 * set an upper bound on the delay with reconnect_delay_max.
 *
 * Example 1:
 *	delay=2, delay_max=10, exponential_backoff=False
 *	Delays would be: 2, 4, 6, 8, 10, 10, ...
 *
 * Example 2:
 *	delay=3, delay_max=30, exponential_backoff=True
 *	Delays would be: 3, 6, 12, 24, 30, 30, ...
 *
 * Parameters:
 *  ecld -                          a valid eecloud instance.
 *  reconnect_delay -               the number of seconds to wait between
 *                                  reconnects.
 *  reconnect_delay_max -           the maximum number of seconds to wait
 *                                  between reconnects.
 *  reconnect_exponential_backoff - use exponential backoff between
 *                                  reconnect attempts. Set to true to enable
 *                                  exponential backoff.
 *
 * Returns:
 *	ECLD_ERR_SUCCESS - on success.
 * 	ECLD_ERR_INVAL -   if the input parameters were invalid.
 */
libecld_EXPORT int eecloud_reconnect_delay_set(struct eecloud *ecld, unsigned int reconnect_delay, unsigned int reconnect_delay_max, bool reconnect_exponential_backoff);

/*
 * Function: eecloud_max_inflight_messages_set
 *
 * Set the number of QoS 1 and 2 messages that can be "in flight" at one time.
 * An in flight message is part way through its delivery flow. Attempts to send
 * further messages with <eecloud_publish> will result in the messages being
 * queued until the number of in flight messages reduces.
 *
 * A higher number here results in greater message throughput, but if set
 * higher than the maximum in flight messages on the broker may lead to
 * delays in the messages being acknowledged.
 *
 * Set to 0 for no maximum.
 *
 * Parameters:
 *  ecld -                  a valid eecloud instance.
 *  max_inflight_messages - the maximum number of inflight messages. Defaults
 *                          to 20.
 *
 * Returns:
 *	ECLD_ERR_SUCCESS - on success.
 * 	ECLD_ERR_INVAL -   if the input parameters were invalid.
 */
libecld_EXPORT int eecloud_max_inflight_messages_set(struct eecloud *ecld, unsigned int max_inflight_messages);

/*
 * Function: eecloud_message_retry_set
 *
 * Set the number of seconds to wait before retrying messages. This applies to
 * publish messages with QoS>0. May be called at any time.
 * 
 * Parameters:
 *  ecld -          a valid eecloud instance.
 *  message_retry - the number of seconds to wait for a response before
 *                  retrying. Defaults to 20.
 */
libecld_EXPORT void eecloud_message_retry_set(struct eecloud *ecld, unsigned int message_retry);

/*
 * Function: eecloud_user_data_set
 *
 * When <eecloud_new> is called, the pointer given as the "obj" parameter
 * will be passed to the callbacks as user data. The <eecloud_user_data_set>
 * function allows this obj parameter to be updated at any time. This function
 * will not modify the memory pointed to by the current user data pointer. If
 * it is dynamically allocated memory you must free it yourself.
 *
 * Parameters:
 *  ecld - a valid eecloud instance.
 * 	obj -  A user pointer that will be passed as an argument to any callbacks
 * 	       that are specified.
 */
libecld_EXPORT void eecloud_user_data_set(struct eecloud *ecld, void *obj);

/* =============================================================================
 *
 * Section: SOCKS5 proxy functions
 *
 * =============================================================================
 */

/*
 * Function: eecloud_socks5_set
 *
 * Configure the client to use a SOCKS5 proxy when connecting. Must be called
 * before connecting. "None" and "username/password" authentication is
 * supported.
 *
 * Parameters:
 *   ecld - a valid eecloud instance.
 *   host - the SOCKS5 proxy host to connect to.
 *   port - the SOCKS5 proxy port to use.
 *   username - if not NULL, use this username when authenticating with the proxy.
 *   password - if not NULL and username is not NULL, use this password when
 *              authenticating with the proxy.
 */
libecld_EXPORT int eecloud_socks5_set(struct eecloud *ecld, const char *host, int port, const char *username, const char *password);

/* =============================================================================
 *
 * Section: Utility functions
 *
 * =============================================================================
 */

/*
 * Function: eecloud_strerror
 *
 * Call to obtain a const string description of a eecloud error number.
 *
 * Parameters:
 *	ecld_errno - a eecloud error number.
 *
 * Returns:
 *	A constant string describing the error.
 */
libecld_EXPORT const char *eecloud_strerror(int ecld_errno);

/*
 * Function: eecloud_connack_string
 *
 * Call to obtain a const string description of an MQTT connection result.
 *
 * Parameters:
 *	connack_code - an MQTT connection result.
 *
 * Returns:
 *	A constant string describing the result.
 */
libecld_EXPORT const char *eecloud_connack_string(int connack_code);

/*
 * Function: eecloud_sub_topic_tokenise
 *
 * Tokenise a topic or subscription string into an array of strings
 * representing the topic hierarchy.
 *
 * For example:
 *
 * subtopic: "a/deep/topic/hierarchy"
 *
 * Would result in:
 *
 * topics[0] = "a"
 * topics[1] = "deep"
 * topics[2] = "topic"
 * topics[3] = "hierarchy"
 *
 * and:
 *
 * subtopic: "/a/deep/topic/hierarchy/"
 *
 * Would result in:
 *
 * topics[0] = NULL
 * topics[1] = "a"
 * topics[2] = "deep"
 * topics[3] = "topic"
 * topics[4] = "hierarchy"
 *
 * Parameters:
 *	subtopic - the subscription/topic to tokenise
 *	topics -   a pointer to store the array of strings
 *	count -    an int pointer to store the number of items in the topics array.
 *
 * Returns:
 *	ECLD_ERR_SUCCESS - on success
 * 	ECLD_ERR_NOMEM -   if an out of memory condition occurred.
 *
 * Example:
 *
 * > char **topics;
 * > int topic_count;
 * > int i;
 * > 
 * > eecloud_sub_topic_tokenise("$SYS/broker/uptime", &topics, &topic_count);
 * >
 * > for(i=0; i<token_count; i++){
 * >     printf("%d: %s\n", i, topics[i]);
 * > }
 *
 * See Also:
 *	<eecloud_sub_topic_tokens_free>
 */
libecld_EXPORT int eecloud_sub_topic_tokenise(const char *subtopic, char ***topics, int *count);

/*
 * Function: eecloud_sub_topic_tokens_free
 *
 * Free memory that was allocated in <eecloud_sub_topic_tokenise>.
 *
 * Parameters:
 *	topics - pointer to string array.
 *	count - count of items in string array.
 *
 * Returns:
 *	ECLD_ERR_SUCCESS - on success
 * 	ECLD_ERR_INVAL -   if the input parameters were invalid.
 *
 * See Also:
 *	<eecloud_sub_topic_tokenise>
 */
libecld_EXPORT int eecloud_sub_topic_tokens_free(char ***topics, int count);

/*
 * Function: eecloud_topic_matches_sub
 *
 * Check whether a topic matches a subscription.
 *
 * For example:
 *
 * foo/bar would match the subscription foo/# or +/bar
 * non/matching would not match the subscription non/+/+
 *
 * Parameters:
 *	sub - subscription string to check topic against.
 *	topic - topic to check.
 *	result - bool pointer to hold result. Will be set to true if the topic
 *	         matches the subscription.
 *
 * Returns:
 *	ECLD_ERR_SUCCESS - on success
 * 	ECLD_ERR_INVAL -   if the input parameters were invalid.
 * 	ECLD_ERR_NOMEM -   if an out of memory condition occurred.
 */
libecld_EXPORT int eecloud_topic_matches_sub(const char *sub, const char *topic, bool *result);

/*
 * Function: eecloud_pub_topic_check
 *
 * Check whether a topic to be used for publishing is valid.
 *
 * This searches for + or # in a topic and checks its length.
 *
 * This check is already carried out in <eecloud_publish> and
 * <eecloud_will_set>, there is no need to call it directly before them. It
 * may be useful if you wish to check the validity of a topic in advance of
 * making a connection for example.
 *
 * Parameters:
 *   topic - the topic to check
 *
 * Returns:
 *   ECLD_ERR_SUCCESS - for a valid topic
 *   ECLD_ERR_INVAL - if the topic contains a + or a #, or if it is too long.
 *
 * See Also:
 *   <eecloud_sub_topic_check>
 */
libecld_EXPORT int eecloud_pub_topic_check(const char *topic);

/*
 * Function: eecloud_sub_topic_check
 *
 * Check whether a topic to be used for subscribing is valid.
 *
 * This searches for + or # in a topic and checks that they aren't in invalid
 * positions, such as with foo/#/bar, foo/+bar or foo/bar#, and checks its
 * length.
 *
 * This check is already carried out in <eecloud_subscribe> and
 * <eecloud_unsubscribe>, there is no need to call it directly before them.
 * It may be useful if you wish to check the validity of a topic in advance of
 * making a connection for example.
 *
 * Parameters:
 *   topic - the topic to check
 *
 * Returns:
 *   ECLD_ERR_SUCCESS - for a valid topic
 *   ECLD_ERR_INVAL - if the topic contains a + or a # that is in an invalid
 *                    position, or if it is too long.
 *
 * See Also:
 *   <eecloud_sub_topic_check>
 */
libecld_EXPORT int eecloud_sub_topic_check(const char *topic);

#ifdef __cplusplus
}
#endif

#endif
