/* 
 * aspamd - advanced spam daemon 
 *
 */

#ifndef _ASPAMD_PAIRS_
#define _ASPAMD_PAIRS_

struct aspamd_pair
{
	gint code;
	const gchar *string;
};

typedef struct aspamd_pair aspamd_pair_t;

aspamd_pair_t *code_to_str (aspamd_pair_t *pairs, gint code);
aspamd_pair_t *str_to_code (aspamd_pair_t *pairs, const gchar *string);
aspamd_pair_t *strn_to_code (aspamd_pair_t *pairs, const gchar *string, gint n);

extern aspamd_pair_t assassin_cmds[];
extern aspamd_pair_t assassin_hdrs[];
extern aspamd_pair_t assassin_errs[];
extern aspamd_pair_t assassin_msgs[];

#endif
