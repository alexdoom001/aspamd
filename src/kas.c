/* 
 * aspamd - advanced spam daemon 
 *
 */

#include <stdio.h>
#include <glib.h>
#include <pairs.h>
#include <errors.h>
#include <server.h>
#include <session.h>
#include <kas.h>
#include <string.h>
#include <config.h>

/*-----------------------------------------------------------------------------*/

static const gchar
	*default_work_path = ASPAMD_DEFAULT_KAS_WORK_PATH,
	*default_lic_path = ASPAMD_DEFAULT_KAS_LIC_PATH,
	*default_update_path = ASPAMD_DEFAULT_KAS_UPDATE_PATH;

/* I did not find function to convert error codes to string
 * description in KAS API so I wrote one */

aspamd_pair_t kas_errors[] = {
	{KASSDK_E_FAILED, "operation has failed"},
	{KASSDK_E_NOT_IMPLEMENTED, "method is not implemented"},
	{KASSDK_E_INVALID_ARGUMENT, "invalid argument is provided"},
	{KASSDK_E_NOT_INITIALIZED, "SDK has not been initialized"},
	{KASSDK_E_SCANNING_QUEUE_FULL, "scanning queue reached its maximum length"},
	{KASSDK_E_SERVICE_DISABLED, "required service is disabled"},
	{KASSDK_E_ALREADY_INITIALIZED, "SDK has been initialized already"},
	{KASSDK_E_NO_MEMORY, "no enough of RAM"},
	{KASSDK_E_IO, "I/O error occurred"},
	{KASSDK_E_BASE, "Anti-Spam bases related error occurred"},
	{KASSDK_E_CANCELED, "operation has been canceled"},
	{KASSDK_E_MESSAGE_FORMAT, "message format is invalid"},
	{KASSDK_E_LICENSE_EXPIRED, "license expired"},
	{KASSDK_E_INVALID_LICENSE_KEY, "license key is invalid"},
	{KASSDK_E_CANNOT_LOAD_APP_INFO, "cannot load application info file"},
	{KASSDK_E_BAD_SIGNATURE, "digital signature verification failed"},
	{KASSDK_E_TIMEDOUT, "operation timed out"},
	{KASSDK_E_ALREADY_STARTED, "operation already started"},
	{KASSDK_E_NO_LICENSE_KEY, "license key file is missing"}};

aspamd_pair_t kas_stats[] = {
	{KASSDK_STATUS_FAILED, "an error occurred while processing the message"},
	{KASSDK_STATUS_MORE_DATA_NEEDED, "checking was not completed because lack of data"},
	{KASSDK_STATUS_NOT_DETECTED, "no spam signs detected"},
	{KASSDK_STATUS_SPAM, "the message is considered to be spam"},
	{KASSDK_STATUS_PROBABLE_SPAM, "the message is considered to be probable spam"},
	{KASSDK_STATUS_AUTO_RESPONDER, "the message is an auto generated reply"},
	{KASSDK_STATUS_BLACK_LISTED, "the message is considered to be spam because it "
	 "came from a blacklisted source"},
	{KASSDK_STATUS_TRUSTED_SOURCE, "the message is not considered to be spam because "
	 "it came from a trusted source"},
	{KASSDK_STATUS_QUARANTIFIED, "the message has been filtered out by"
	 "Reputation Filtering technology and stored to the backup storage"}};

/*-----------------------------------------------------------------------------*/

static void __cdecl
aspamd_kas_callback (KasSdkScanId scanId, void *user_context,
		     KasSdkCheckResult* check_result)
{
	gint ret = ASPAMD_ERR_OK;
	aspamd_session_t *session = NULL;
	kas_data_t *kas = NULL;
	assassin_message_t *reply = NULL;
	gboolean spam = FALSE;
	aspamd_pair_t *pair = NULL;

	g_assert (user_context);
	session = (aspamd_session_t *) user_context;

	if (session->cleaned)
	{
		session_free (session);
		return;
	}

	kas = session->parent->kas;
	g_assert (kas);

	ret = assassin_msg_allocate (&reply, assassin_msg_reply, NULL);
	ASPAMD_ERR_CHECK (ret);
	reply->command = session->request->command;
	reply->version_minor = session->request->version_minor;
	reply->version_major = session->request->version_major;

	g_debug ("kas %p: callback initiated: id - %i", kas, scanId.handle);

	pair = code_to_str (kas_stats, check_result->status);
	g_debug ("kas %p: status - `%s', rating - %i", kas, pair->string, check_result->rating);

	reply->error = assassin_ex_ok;
	switch (check_result->status)
	{
	case KASSDK_STATUS_SPAM:
	case KASSDK_STATUS_PROBABLE_SPAM:
	case KASSDK_STATUS_BLACK_LISTED:
		spam = TRUE;
		break;
	case KASSDK_STATUS_NOT_DETECTED:
	case KASSDK_STATUS_TRUSTED_SOURCE:
	case KASSDK_STATUS_AUTO_RESPONDER:
		spam = FALSE;
		break;
	case KASSDK_STATUS_QUARANTIFIED:
		session->quarantine = 1;
		break;
	default:
		reply->error = assassin_ex_software;
	}

	if (session->quarantine)
	{
		ret = assassin_msg_add_header (reply, assassin_hdr_spam,
				g_variant_new ("(bii)", TRUE, 100, ASPAMD_KAS_MAX_RATING));
		ASPAMD_ERR_CHECK (ret);
		ret = assassin_msg_add_header (reply, assassin_hdr_quarantine, g_variant_new_boolean (TRUE));
		ASPAMD_ERR_CHECK (ret);
	}
	else
	{
		ret = assassin_msg_add_header (reply, assassin_hdr_spam,
				g_variant_new ("(bii)", spam, check_result->rating, ASPAMD_KAS_MAX_RATING));
		ASPAMD_ERR_CHECK (ret);
	}

	ret = aspamd_session_reply (session, reply, scanId.handle);
	ASPAMD_ERR_CHECK (ret);
at_exit:
	aspamd_session_unref (session);
}

static gint aspamd_kas_check_settings(kas_data_t *kas)
{
	gint ret = ASPAMD_ERR_OK;
	KasSdkError kas_error = KASSDK_S_SUCCESS;
	aspamd_pair_t *pair = NULL;

	g_assert (kas);
	
	kas->check_settings.checkFlags =
		KASSDK_USE_GSG |
		/* enables the use of image recognition technology
		 * (GSG) */
		KASSDK_USE_CONTENT_FILTRATION |
		/* enables content filtration technologies */
		KASSDK_USE_SURBL_DEFAULT_LIST |
		/* enables filtration based on the default SURBL lists
		 * received with updates. */
		KASSDK_USE_DNSBL_DEFAULT_LIST |
		/* enables filtration based on the default DNSBL lists
		 * which are delivered with updates */
		KASSDK_CHECK_PLAIN_TEXT | 
		/* enables processing message plain text */
		KASSDK_CHECK_HTML
		/* enables parsing HTML documents */;

	if (kas->parse_bin)
		kas->check_settings.checkFlags |=
			KASSDK_CHECK_PDF |
			KASSDK_CHECK_MS_OFFICE |
			KASSDK_CHECK_RTF;
	else
		g_debug ("kas %p: binary formats parsing is disabled", kas);

	if (kas->use_uds)
		kas->check_settings.checkFlags |= KASSDK_USE_UDS;
			/* enables using real time Urgent Detection
			 * System (UDS) requests */

	if (kas->ext_net)
		kas->check_settings.checkFlags |=
			KASSDK_USE_SPF |
			/* enables using the Sender Policy Framework
			 * (SPF) technology for checking sender IP
			 * addresses */
			KASSDK_USE_DNS |
			/* enables the use of DNS queries */
			KASSDK_USE_SURBL |
			/* enables filtration based on custom SURBL
			 * lists. The specified SURBL service(s) will
			 * perform DNS requests and check if any URLs
			 * found in the message body are present in
			 * their spam lists.  */
			KASSDK_USE_DNSBL;
			/* enables filtration based on custom DNSBL
			 * lists (DNS-based Blackhole Lists). The
			 * specified DNSBL service(s) will perform DNS
			 * request and check if the sender IP address
			 * is found in their black lists.  */
	else
		g_debug ("kas %p: external network services usage is disabled", kas);

	g_debug ("kas %p: check flags: 0x%x", kas, (unsigned) kas->check_settings.checkFlags);

	kas->check_settings.filterOptions.checkOptions = NULL;
	kas->check_settings.filterOptions.checkOptionsCount = 0;

	kas->check_settings.blackDnsList.handle = KASSDK_DNS_LIST_INVALID_HANDLE;
	kas->check_settings.blackSurList.handle = KASSDK_DNS_LIST_INVALID_HANDLE;
	kas->check_settings.blackIpList.handle = KASSDK_IP_LIST_INVALID_HANDLE;
	kas->check_settings.whiteIpList.handle = KASSDK_IP_LIST_INVALID_HANDLE;
	kas->check_settings.blackEmailList.handle = KASSDK_EMAIL_LIST_INVALID_HANDLE;
	kas->check_settings.whiteEmailList.handle = KASSDK_EMAIL_LIST_INVALID_HANDLE;
	kas->check_settings.blackPhraseList.handle = KASSDK_PHRASE_LIST_INVALID_HANDLE;
	kas->check_settings.whitePhraseList.handle = KASSDK_PHRASE_LIST_INVALID_HANDLE;
	
	kas_error = KasSdkSetDefaultCheckSettings (&kas->check_settings);
	if (kas_error != KASSDK_S_SUCCESS)
	{
		pair = code_to_str (kas_errors, kas_error);
		ASPAMD_ERR (ASPAMD_ERR_KAS,
			    "kas %p: failed to set default check settings: %s", kas,
			    pair->string);
	}
	g_debug ("kas %p: default check settings is set successfully", kas);

at_exit:
	return ret;
}

/*-----------------------------------------------------------------------------*/

/** @brief allocates new KAS wrapper
 *
 * @param new_kas pointer to return allocated object
 * @return an error code
 */

gint aspamd_kas_allocate (kas_data_t **new_kas)
{
	gint ret = ASPAMD_ERR_OK;
	kas_data_t *kas = NULL;

	kas = g_slice_new(kas_data_t);
	ASPAMD_ERR_IF (!kas, ASPAMD_ERR_MEM, "new kas wrapper allocation failed");

	kas->work_path = (gchar *) default_work_path;
	kas->license_path = (gchar *) default_lic_path;
	kas->update_path = (gchar *) default_update_path;
	kas->initialized = FALSE;
	kas->queue_size = ASPAMD_DEFAULT_KAS_QUEUE_SIZE;
	kas->threads_count = ASPAMD_DEFAULT_KAS_THREADS_COUNT;
	kas->use_uds = 0;
	kas->ext_net = 0;
	kas->parse_bin = 0;

	memset (&kas->check_settings, 0, sizeof(kas->check_settings));
	memset (&kas->filtering, 0, sizeof(kas->filtering));

	g_debug ("kas at %p is allocated, work directory - %s, licenses directory - %s, \
update directory - %s, queue size - %i, threads count - %i", kas, kas->work_path,
		 kas->license_path, kas->update_path, kas->queue_size, kas->threads_count);
	
at_exit:
	if (ret == ASPAMD_ERR_OK)
		*new_kas = kas;
	else
	{
		if (kas)
			aspamd_kas_free (kas);
		*new_kas = NULL;
	}
	return ret;
}

/** @brief initializes KAS engine
 *
 * @param kas kas wrapper
 * @return an error code
 */

gint aspamd_kas_initialize (kas_data_t *kas)
{
	gint ret = ASPAMD_ERR_OK;
	KasSdkError kas_error = KASSDK_S_SUCCESS;
	aspamd_pair_t *pair;

	KasSdkInitializer init;
	memset(&init, 0, sizeof(init));

	init.environment.workBasesPath = kas->work_path;
	init.environment.newBasesPath = kas->update_path;
	init.operationOptions.licensingOptions.licenseMode = KasSdkLicenseModeSimple;
	init.operationOptions.licensingOptions.licensePath = kas->license_path;
	init.operationOptions.scannerOptions.queueLength = kas->queue_size;
	init.operationOptions.scannerOptions.threadCount = kas->threads_count;
	init.operationOptions.scannerOptions.utf8Mode = 1;
	init.operationOptions.networkTimeouts.timeoutDNS = 10;
	init.operationOptions.networkTimeouts.timeoutUDS = 10;
	init.loggingOptions.loggingLevel = KasSdkLoggingMinimum;

	if (kas->filtering.enable) {
		init.operationOptions.filteringOptions.enable = 1;
		init.operationOptions.filteringOptions.messageTTL = 40;
		init.operationOptions.filteringOptions.storageSize = kas->filtering.storage_size;
		init.operationOptions.filteringOptions.storagePath = kas->filtering.storage_path;
	}

	g_assert (kas);

	if (!kas->initialized)
	{
		kas_error = KasSdkInitializeInprocMode (&init);

		if (kas_error == KASSDK_E_LICENSE_EXPIRED)
		{
			ret = ASPAMD_ERR_LIC_EXP;
			goto at_exit;
		}
		if (kas_error != KASSDK_S_SUCCESS)
		{
			pair = code_to_str (kas_errors, kas_error);
			ASPAMD_ERR (ASPAMD_ERR_KAS, "kas %p: initialization failed: %s", kas,
				    pair->string);
		}
		kas->initialized = TRUE;
		g_message ("KAS engine initialized and ready to run");
		aspamd_kas_check_settings (kas);
	}
	else
		ASPAMD_ERR (ASPAMD_ERR_KAS, "kas %p: engine is already initialized", kas);

at_exit:
	return ret;
}

gint aspamd_kas_check (kas_data_t *kas, aspamd_session_t *session,
		       assassin_message_t *message, guint *id)
{
	gint ret = ASPAMD_ERR_OK;
	KasSdkError kas_error = KASSDK_S_SUCCESS;
	gchar *mime_data = NULL;
	gint mime_size = 0;
	aspamd_pair_t *pair = NULL;
	const gchar *hdr_data;
	guint a1, a2, a3, a4, i, rcpt_count = 0;
	assassin_header_t *header = NULL;
	GSList *iter;
	
	KasSdkScanId scanId;
	KasSdkMessage sdkMessage;
	memset(&sdkMessage, 0, sizeof(sdkMessage));

	for (iter = message->headers; iter; iter = g_slist_next (iter))
	{
		header = (assassin_header_t*)iter->data;
		switch (header->type)
		{
		case assassin_hdr_client_address:
		{
			hdr_data = g_variant_get_string (header->value, NULL);
			if ((sscanf(hdr_data, "%u.%u.%u.%u", &a1, &a2, &a3, &a4)) < 4)
			{
				g_message ("kas failed to set client-address: %s", hdr_data);
				break;
			}
			sdkMessage.header.address.address.a1 = (unsigned char) a1;
			sdkMessage.header.address.address.a2 = (unsigned char) a2;
			sdkMessage.header.address.address.a3 = (unsigned char) a3;
			sdkMessage.header.address.address.a4 = (unsigned char) a4;
			sdkMessage.header.address.mask = 32;
			break;
		}
		case assassin_hdr_helo_name:
		{
			sdkMessage.header.heloName = g_variant_get_string (header->value, NULL);
			break;
		}
		case assassin_hdr_mail_from:
		{
			sdkMessage.header.mailFrom = g_variant_get_string (header->value, NULL);
			break;
		}
		case assassin_hdr_rcpt_to:
		{
			rcpt_count++;
			break;
		}
		}
	}

	if (rcpt_count)
	{
		message->recipients = g_malloc (sizeof(gchar*) * rcpt_count);
		ASPAMD_ERR_IF (!message->recipients, ASPAMD_ERR_MEM, "kas %p: failed to allocate recipients buffer", kas);

		i = 0;
		for (iter = message->headers; iter; iter = g_slist_next (iter))
		{
			header = (assassin_header_t*)iter->data;
			if (header->type == assassin_hdr_rcpt_to)
				message->recipients[i++] = g_variant_get_string (header->value, NULL);
		}
	}

	sdkMessage.header.recipients = message->recipients;
	sdkMessage.header.recipientCount = rcpt_count;

	assassin_buffer_get_data (message->content, (gpointer *)&mime_data,
				  (gint *)&mime_size);

	sdkMessage.body.mimeData = mime_data;
	sdkMessage.body.mimeSize = (size_t) mime_size;

	kas_error = KasSdkCheckMessageAsync (&sdkMessage, NULL, aspamd_kas_callback, session, &scanId);

	if (id)
		*id = (guint) scanId.handle;

	if (kas_error != KASSDK_S_SUCCESS)
	{
		pair = code_to_str (kas_errors, kas_error);
		ASPAMD_ERR (ASPAMD_ERR_KAS,"kas %p: failed to start asynchronous "
			    "message check: %s", kas, pair->string);
	}
	g_debug ("kas %p: asynchronous message %p check is started, id - %i",
		 kas, message, scanId.handle);

at_exit:
	return ret;
}

gint aspamd_kas_get_license_info (KasSdkLicenseInfo *info)
{
	gint ret = ASPAMD_ERR_OK;
	KasSdkError kas_error = KASSDK_S_SUCCESS;
	aspamd_pair_t *pair = NULL;

	g_assert (info);

	kas_error = KasSdkGetLicenseInfo (info);

	if (kas_error != KASSDK_S_SUCCESS)
	{
		pair = code_to_str (kas_errors, kas_error);
		ASPAMD_ERR (ASPAMD_ERR_KAS, 
			    "failed to get license info: %s", pair->string);
	}

at_exit:
	return ret;
}

/** @brief stops KAS engine and terminates all message processing
 *
 * @param kas kas wrapper
 * @return an error code
 */

gint aspamd_kas_stop (kas_data_t *kas)
{
	gint ret = ASPAMD_ERR_OK;
	KasSdkError kas_error = KASSDK_S_SUCCESS;
	aspamd_pair_t *pair = NULL;

	if (!kas->initialized)
	{
		ret = ASPAMD_ERR_KAS;
		goto at_exit;
	}

	kas_error = KasSdkCancelAllMessageChecks ();
	switch(kas_error)
	{
	case KASSDK_S_SUCCESS:
		break;
	default:
		pair = code_to_str (kas_errors, kas_error);
		ASPAMD_ERR (ASPAMD_ERR_KAS, "kas %p: failed to cancel messages processing: "
			    "%s", kas, pair->string);
	}

at_exit:
	return ret;
}


/** @brief deinitializes KAS engine
 *
 * @param kas kas wrapper
 * @return an error code
 */

gint aspamd_kas_deinitialize (kas_data_t *kas)
{
	gint ret = ASPAMD_ERR_OK;
	KasSdkError kas_error = KASSDK_S_SUCCESS;
	aspamd_pair_t *pair = NULL;

	g_assert (kas);

	if (kas->initialized)
	{
		kas_error = KasSdkUninitialize ();

		kas->initialized = FALSE;

		if (kas_error != KASSDK_S_SUCCESS)
		{
			pair = code_to_str (kas_errors, kas_error);
			ASPAMD_ERR (ASPAMD_ERR_KAS, 
				    "kas %p: engine deinitialization failed: %s",
				    kas, pair->string);
		}
		g_debug ("kas %p: engine is deinitialized", kas);
	}

at_exit:
	return ret;
}

/** @brief releases resources allocated by wrapper and KAS engine
 *
 * @param kas kas wrapper
 */

void aspamd_kas_free (kas_data_t *kas)
{
	g_assert (kas);

	g_debug ("kas at %p is about to be released", kas);

	if (kas->initialized)
		aspamd_kas_deinitialize (kas);

	if (kas->work_path && kas->work_path != default_work_path)
	{
		g_free (kas->work_path);
		kas->work_path = NULL;
	}

	if (kas->license_path && kas->license_path != default_lic_path)
	{
		g_free (kas->license_path);
		kas->license_path = NULL;
	}

	if (kas->update_path && kas->update_path != default_update_path)
	{
		g_free (kas->update_path);
		kas->update_path = NULL;
	}

	if (kas->filtering.storage_path)
	{
		g_free (kas->filtering.storage_path);
		kas->filtering.storage_path = NULL;
	}

	g_slice_free1 (sizeof (kas_data_t), kas);
}

void aspamd_kas_reload_database (kas_data_t *kas)
{
	KasSdkError kas_error = KASSDK_S_SUCCESS;

	kas_error = KasSdkReloadDatabase ();

	if (kas_error != KASSDK_S_SUCCESS)
		g_message ("KAS databases reload failed");
	else
		g_message ("KAS databases reloaded successfully");
}
