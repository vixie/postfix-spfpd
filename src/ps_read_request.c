#include <stdbool.h>
#include "ps_read_request.h"

SPF_client_request_t* ReadRequest ( void )
{
	const char* const module = "readrequest";

	const char req_client_address[] = "client_address=";
	const char req_sender[]         = "sender=";
	const char req_helo_name[]      = "helo_name=";
	const char req_recipient[]      = "recipient=";

	SPF_client_request_t* req = (SPF_client_request_t *)malloc ( sizeof *req );
	if ( req == NULL )
		return NULL;
	memset ( req, 0, sizeof *req );

	char* line = NULL;
	bool args = false;
	bool err = false;

	while ( getline ( &line, NULL, stdin ) != -1 )
	{
		char* nl = strchr ( line, '\n' );
		if ( nl == NULL ) err = true;
		if ( err ) break;
		*nl = '\0';

		if ( ga.m_debug == 2 ) syslog ( LOG_DEBUG, "%s: line: %s", module, line );

		switch ( line[0] )
		{
		case '\0':
			break;
		case 'c':
			if ( strncasecmp (	line,
				req_client_address,
				sizeof ( req_client_address ) / sizeof ( *req_client_address ) - 1 ) == 0 )
			{
				req->ip = strdup ( &line[sizeof ( req_client_address ) / sizeof ( *req_client_address ) - 1] );
				if ( req->ip == NULL ) { err = true; continue; }
				if ( ga.m_debug != 0 ) syslog ( LOG_DEBUG, "%s: %s%s", module, req_client_address, req->ip );
				args = true;
				continue;
			}
			break;
		case 's':
			if ( strncasecmp (	line,
				req_sender,
				sizeof ( req_sender ) / sizeof ( *req_sender ) - 1 ) == 0 )
			{
				req->sender = strdup ( &line[sizeof ( req_sender ) / sizeof ( *req_sender ) - 1] );
				if ( req->sender == NULL ) { err = true; continue; }
				if ( ga.m_debug != 0 ) syslog ( LOG_DEBUG, "%s: %s%s", module, req_sender, req->sender );
				args = true;
				continue;
			}
			break;
		case 'h':
			if ( strncasecmp (	line,
				req_helo_name,
				sizeof ( req_helo_name ) / sizeof ( *req_helo_name ) - 1 ) == 0 )
			{
				req->helo = strdup ( &line[sizeof ( req_helo_name ) / sizeof ( *req_helo_name ) - 1] );
				if ( req->helo == NULL ) { err = true; continue; }
				if ( ga.m_debug != 0 ) syslog ( LOG_DEBUG, "%s: %s%s", module, req_helo_name, req->helo );
				args = true;
				continue;
			}
			break;
		case 'r':
			if ( strncasecmp (	line,
				req_recipient,
				sizeof ( req_recipient ) / sizeof ( *req_recipient ) - 1 ) == 0 )
			{
				req->rcpt_to = strdup ( &line[sizeof ( req_recipient ) / sizeof ( *req_recipient ) - 1] );
				if ( req->rcpt_to == NULL ) { err = true; continue; }
				if ( ga.m_debug != 0 ) syslog ( LOG_DEBUG, "%s: %s%s", module, req_recipient, req->rcpt_to );
				args = true;
				continue;
			}
			break;
		}
	}
	FREE ( line, free );

	if ( (!args) || feof ( stdin ) )
		err = true;
	if ( err )
		RequestFree ( &req );
	return req;
}
