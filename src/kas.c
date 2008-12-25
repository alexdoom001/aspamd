/* 
 * aspamd - advanced spam daemon 
 *
 */

#include <stdio.h>
#include <glib.h>
#include <errors.h>
#include <kas.h>
#include <kas_sdk.h>

/*-----------------------------------------------------------------------------*/

static const gchar
	*default_work_path = ASPAMD_DEFAULT_KAS_WORK_PATH,
	*default_lic_path = ASPAMD_DEFAULT_KAS_LIC_PATH,
	*default_update_path = ASPAMD_DEFAULT_KAS_UPDATE_PATH;

/* I did not find function to convert error codes to string
 * description in KAS API so I wrote one */

static const struct
{
	gint code;
	gchar *str;
} error_to_str[] = {
	{KASSDK_E_INVALID_ARGUMENT, "function parameter is incorrect"},
	{KASSDK_E_INVALID_DATA, "data of object is incorrect"},
	{KASSDK_E_NO_MEMORY, "no enough of RAM"},
	{KASSDK_E_READ, "reading error"},
	{KASSDK_E_WRITE, "writing error"},
	{KASSDK_E_BASE_CREATE, "storage creating error"},
	{KASSDK_E_BASE_READ, "storage reading error"},
	{KASSDK_E_BASE_WRITE, "storage writing error"},
	{KASSDK_E_BASE_SAVE, "storage saving error"},
	{KASSDK_E_DNS_RESOLVER, "DNS-resolving error"},
	{KASSDK_E_CF, "Content Filtration error"},
	{KASSDK_E_GSG, "Image processor error"},
	{KASSDK_E_PDB_COMPILER, "Profiles compiler error"},
	{KASSDK_E_PDB_INTERPRETER, "Profiles interpreter error"},
	{KASSDK_E_INTERNAL, "Unexpected error"},
	{KASSDK_E_DB_COMPILER, "Unite compiler error"},
	{KASSDK_E_LIB_ARCHIVE, "LibArchive error"},
	{KASSDK_E_GSG_INIT, "error on initialization gsg"},
	{KASSDK_E_UDS_INIT, "error on initialization uds"},
	{KASSDK_E_CF_INIT, " Error on initialization cf"},
	{KASSDK_E_UDS, "UDS error"},
	{KASSDK_E_DNS_INIT, "error on initialization dns shared"},
	{KASSDK_E_FILE_DELETE, "error on deleting file"},
	{KASSDK_E_SHARED_LOADER, "KAS Shared loader error"},
	{KASSDK_E_PROFILES_INIT, "error on initialization profiles"},
	{KASSDK_E_MESSAGE_FORMAT, "format of message data is invalid"},
	{KASSDK_E_ENGINE_INIT, "error on library initialization"},
	{KASSDK_E_FILTER_BUSY, "cannot uninitialize due to active filters"},
	{KASSDK_E_NOT_INITIALIZED, "SDK is not initialized"},
	{KASSDK_E_ALREADY_INITIALIZED, "SDK is already initialized"},
	{KASSDK_E_DATABASE_NOT_LOADED, "Database is not loaded"},
	{KASSDK_E_INSUFFICIENT_RESOURCES, "System is low on resources to continue the \
operation"},
	{KASSDK_E_BUFFER_TOO_SMALL, "Buffer is too small to hold the requested data"},
	{KASSDK_E_LICENSE_EXPIRED, "License has has expired"},
	{KASSDK_E_INVALID_LICENSE_KEY, "License key is invalid"},
	{KASSDK_E_CANNOT_LOAD_APP_INFO, "Cannot load application info file"},
	{KASSDK_E_BAD_SIGNATURE, "Signed binary signature does not match license key's \
signature or is invalid"},
	{KASSDK_E_CANNOT_LOAD_ENGINE, "Cannot load AS engine"},
	{KASSDK_E_NO_DEFAULT_SETTINGS, "No default settings"},
	{KASSDK_E_NO_IMPLEMENTED, "No default settings"},
	{KASSDK_E_FAILED, "operation failed"},
	{KASSDK_E_UNEXPECTED, "unexpected error"}};

static gchar *kas_error_to_str (gint code)
{
	gint i;
	static char buf[16];

	for (i = 0; i < sizeof (error_to_str)/sizeof(error_to_str[0]); i++)
	{
		if (error_to_str[i].code == code)
			return (gchar *) error_to_str[i].str;
	}
	snprintf (buf, 16, "%i", code);
	return buf;
}

/*-----------------------------------------------------------------------------*/

static KASSDK_CALLBACK_RESULT __cdecl 
aspamd_kas_callback(KASSDK_EVENTS eventType, unsigned long param, const void *additionalData,
		     unsigned int scanId, const void *userContext)
{
	g_debug ("---");
	return 0;
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
	if (!kas)
	{
		g_critical ("new kas wrapper allocation failed");
		ret = ASPAMD_ERR_MEM;
		goto at_exit;
	}

	kas->work_path = (gchar *) default_work_path;
	kas->license_path = (gchar *) default_lic_path;
	kas->update_path = (gchar *) default_update_path;
	kas->initialized = FALSE;
	kas->queue_size = ASPAMD_DEFAULT_KAS_QUEUE_SIZE;
	kas->threads_count = ASPAMD_DEFAULT_KAS_THREADS_COUNT;

	g_debug ("kas at %p is allocated, work directory - %s, licences directory - %s, \
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
	KASSDK_ERROR kas_error = KASSDK_SUCCESS;

	g_assert (kas);

	if (!kas->initialized)
	{
		kas_error = KasSdkInitialize (KASSDK_SHT_INPROC,
					      kas->work_path,
					      kas->license_path,
					      KASSDK_LICENSE_FULL,
					      kas->update_path,
					      1, /* try to load old DB*/
					      0, /* UTF8 support */
					      kas->queue_size,
					      kas->threads_count,
					      NULL,
					      aspamd_kas_callback);
		if (kas_error != KASSDK_SUCCESS)
		{
			g_critical ("kas %p initialization failed: %s", kas,
				    kas_error_to_str (kas_error));
			ret = ASPAMD_ERR_KAS;
			goto at_exit;
		}
		kas->initialized = TRUE;
		g_debug ("kas %p is initialized", kas);
	}
	else
	{
		g_critical ("KAS engine is already initialized");
		ret = ASPAMD_ERR_KAS;
		goto at_exit;
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
	return ASPAMD_ERR_OK;
}


/** @brief deinitializes KAS engine
 *
 * @param kas kas wrapper
 * @return an error code
 */

gint aspamd_kas_deinitialize (kas_data_t *kas)
{
	gint ret = ASPAMD_ERR_OK;
	KASSDK_ERROR kas_error = KASSDK_SUCCESS;

	g_assert (kas);

	if (kas->initialized)
	{
		kas_error = KasSdkUninitialize ();

		kas->initialized = FALSE;

		if (kas_error != KASSDK_SUCCESS)
		{
			g_critical ("kas %p deinitialization failed: %s", kas,
				    kas_error_to_str (kas_error));
			ret = ASPAMD_ERR_KAS;
			goto at_exit;
		}
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

	g_debug ("kas %p is about to be released", kas);

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

	g_slice_free1 (sizeof (kas_data_t), kas);
}
