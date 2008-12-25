/* 
 * aspamd - advanced spam daemon 
 *
 */

/*! \file kas.h
 *  \brief KAS connector */

#ifndef _ASPAMD_KAS_
#define _ASPAMD_KAS_

#define ASPAMD_DEFAULT_KAS_WORK_PATH		"/var/lib/aspamd/temp"
#define ASPAMD_DEFAULT_KAS_LIC_PATH		"/var/lib/aspamd/license"
#define ASPAMD_DEFAULT_KAS_UPDATE_PATH		"/var/lib/aspamd/update"
#define ASPAMD_DEFAULT_KAS_QUEUE_SIZE		256
#define ASPAMD_DEFAULT_KAS_THREADS_COUNT	16

struct kas_data
{
	gchar *work_path;
	gchar *license_path;
	gchar *update_path;
	gint queue_size;
	gint threads_count;
	gboolean initialized;
};

typedef struct kas_data kas_data_t;

gint aspamd_kas_allocate (kas_data_t **new_kas);
gint aspamd_kas_initialize (kas_data_t *kas);
gint aspamd_kas_stop (kas_data_t *kas);
gint aspamd_kas_deinitialize (kas_data_t *kas);
void aspamd_kas_free (kas_data_t *kas);

#endif
