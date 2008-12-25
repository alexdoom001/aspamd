/* 
 * aspamd - advanced spam daemon 
 *
 */

/*! \file errors.h
 *  \brief error code definitions */

#ifndef _ASPAMD_ERRORS_
#define _ASPAMD_ERRORS_

#define ASPAMD_ERR_BASE         (0)

/** error codes  */
enum aspamd_error_code
{
	ASPAMD_ERR_OK =		(0 << ASPAMD_ERR_BASE), 
	/*!< no error */
	ASPAMD_ERR_ERR =	(1 << ASPAMD_ERR_BASE),
	/*!< general or unspecified error */
	ASPAMD_ERR_MEM =	(3 << ASPAMD_ERR_BASE),
	/*!< memory allocation error */
	ASPAMD_ERR_CM_LINE =	(4 << ASPAMD_ERR_BASE),
	/*!< command line parsing error */
	ASPAMD_ERR_CFG =	(5 << ASPAMD_ERR_BASE),
	/*!< configuration file parsing error */
	ASPAMD_ERR_DAEMONIZE =	(6 << ASPAMD_ERR_BASE),
	/*!< daemonization error */
	ASPAMD_ERR_NET =	(7 << ASPAMD_ERR_BASE),
	/*!< network error */
	ASPAMD_ERR_MSG =	(8 << ASPAMD_ERR_BASE),
	/*!< message error */
	ASPAMD_ERR_PARSER =	(9 << ASPAMD_ERR_BASE),
	/*!< parser error */
	ASPAMD_ERR_IO	=	(10 << ASPAMD_ERR_BASE)
	/*!< IO error */
};

typedef enum aspamd_error_code aspamd_error_code_t;

#define ASPAMD_ERR_CHECK(err)			\
	if (err != ASPAMD_ERR_OK)		\
		goto at_exit;

#endif
