/* 
 * aspamd - advanced spam daemon 
 *
 */

/*! \file kas.h
 *  \brief KAS connector */

#ifndef _ASPAMD_KAS_
#define _ASPAMD_KAS_

#include <assassin.h>
#include <session.h>
#include <kassdk/kassdk_inproc.h>

/* it is not clarified clearly in documentation but rating seems to be
 * in range from 0 to 100 */
#define ASPAMD_KAS_MAX_RATING			(100)

struct reputation_filtering
{
	guint enable;
	guint storage_size;
	gchar* storage_path;
};

typedef struct reputation_filtering reputation_filtering_t;

struct kas_data
{
	gchar *work_path;
	gchar *license_path;
	gchar *update_path;
	gint queue_size;
	gint threads_count;
	gboolean initialized;
	KasSdkCheckSettings check_settings;
	gint use_uds;
	gint ext_net;
	gint parse_bin;
	reputation_filtering_t filtering;
};

typedef struct kas_data kas_data_t;

gint aspamd_kas_allocate (kas_data_t **new_kas);
gint aspamd_kas_initialize (kas_data_t *kas);
gint aspamd_kas_check (kas_data_t *kas, aspamd_session_t *session,
		       assassin_message_t *message, guint *id);
gint aspamd_kas_get_license_info (KasSdkLicenseInfo *info);
gint aspamd_kas_stop (kas_data_t *kas);
gint aspamd_kas_deinitialize (kas_data_t *kas);
void aspamd_kas_free (kas_data_t *kas);
void aspamd_kas_reload_database (kas_data_t *kas);

#endif
