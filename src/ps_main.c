#include "ps_main.h"

int main ( int argc, char* argv[] )
{
	const char* const module = "main";

	GetOpt ( argc, argv );

	SPF_client_request_t* req = NULL;
	SPF_server_t* spf_server = NULL;
	SPF_request_t* spf_request = NULL;
	SPF_response_t* spf_response = NULL;
	SPF_errcode_t err;

	int request_number = 0;
	int res = 0;

	const char *partial_result;
	char *result = NULL;
	int result_len = 0;

	int logopts = LOG_PID | LOG_CONS | LOG_NDELAY | LOG_NOWAIT;
	if ( ga.m_debug == 2 ) logopts |= LOG_PERROR;
	openlog ( progname, logopts, LOG_MAIL );
	if ( ga.m_debug == 2 ) syslog ( LOG_INFO, "%s: startup", module );

	SPF_error_handler = SPF_error_syslog;
	SPF_warning_handler = SPF_warning_syslog;
	SPF_info_handler = SPF_info_syslog;
	SPF_debug_handler = SPF_debug_syslog;

	if ( ga.m_debug > 1 )
		spf_server = SPF_server_new ( SPF_DNS_CACHE, 1 );
	else
		spf_server = SPF_server_new ( SPF_DNS_CACHE, 0 );
	if ( spf_server == NULL ) abort ( );

	err = SPF_server_set_explanation ( spf_server, DEFAULT_EXPLANATION, &spf_response );
	if ( err )
	{
		ResponseLogErrors ( "Error setting default explanation",
				    spf_response, err );
		res = 255;
	}
	ResponseFree ( &spf_response );

	if ( ga.m_white != 0 )
		ReadWhiteFromFile ( ga.m_white );

	while ( request_number < REQUEST_LIMIT )
	{
		req = ReadRequest ( );
		if ( req == NULL )
		{
			syslog ( LOG_WARNING, "%s: %s: exiting", module,
				 feof ( stdin ) ? "io closed while reading"
					: "badly formatted policy request" );
			res = 0;
			break;
		}

		request_number ++;
		if ( ga.m_debug != 0 ) syslog ( LOG_DEBUG, "%s: request %d",
					        module, request_number );

		FREE_REQUEST ( spf_request );

		ResponseFree ( &spf_response );

		spf_request = SPF_request_new ( spf_server );

		if ( SPF_request_set_ipv4_str ( spf_request, req->ip ) && SPF_request_set_ipv6_str ( spf_request, req->ip ) )
		{
			syslog ( LOG_WARNING, "%s: Invalid IP address", module );

			res = 255;

			if ( ga.m_test == 0 )
				PostfixAccessReject ( req );
			else
				PostfixAccessOk ( "test mode", req );

			continue;
		}

		if ( strchr ( req->sender, '@' ) != NULL )
		{
			if ( SPF_request_set_env_from ( spf_request, req->sender ) )
			{
				syslog ( LOG_WARNING, "Invalid envelope from address" );

				res = 255;

				if ( ga.m_test == 0 )
					PostfixAccessReject ( req );
				else
					PostfixAccessOk ( "TM: Reject", req );

				continue;
			}
		}
		else
		{
			res = 255;

			if ( ga.m_test == 0 )
				PostfixAccessDunno ( "no valid email address found", req );
			else
				PostfixAccessOk ( "TM: Dunno: no valid email address found", req );

			continue;
		}

		if ( ThisIsIpAddressInWhitelist ( req->ip ) )
		{
			res = 255;
			PostfixAccessOk ( "whitelisted", req );
			continue;
		}

		err = SPF_request_query_mailfrom ( spf_request, &spf_response );

		if ( ga.m_debug != 0 ) ResponseLog ( "Main query", spf_response );

		if ( err )
		{
			if ( ga.m_debug != 0 ) ResponseLogErrors ( "Failed to query MAIL-FROM", spf_response, err );

			res = 255;

			if ( ga.m_test == 0 )
				PostfixAccessDunno ( "no SPF record found", req );
			else
				PostfixAccessOk ( "TM: Dunno: no SPF record found", req );

			continue;
		}

		if ( result != NULL )
			result[0] = '\0';

		APPEND_RESULT ( SPF_response_result ( spf_response ) );

		ResponsePrint ( spf_response, req );

		res = SPF_response_result ( spf_response );

		fflush ( stdout );

		RequestFree ( &req );
	}

	RequestFree ( &req );
	FREE ( result, free );
	ResponseFree ( &spf_response );
	FREE_REQUEST ( spf_request );
	FREE ( spf_server, SPF_server_free );

	syslog ( LOG_INFO, "%s: exit(%d), requests: %d",
		module, res, request_number );

	return res;
}
