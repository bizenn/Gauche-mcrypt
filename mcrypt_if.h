/*
 * mcrypt_if.h: libmcrypt API I/F header
 *
 * Copyright (c) 2005-2008 Tatsuya BIZENN, All rights reserved.
 */

#ifndef _MCRYPT_IF_H
#define _MCRYPT_IF_H
#include <mcrypt.h>
#include <gauche/extend.h>
#include <gauche/uvector.h>

typedef struct {
    SCM_HEADER;
    MCRYPT mcrypt;
} ScmMcrypt;
SCM_CLASS_DECL(Scm_McryptClass);
#define SCM_CLASS_MCRYPT (&Scm_McryptClass)
#define SCM_MCRYPT(obj) ((ScmMcrypt*)(obj))
#define SCM_MCRYPTP(obj) (SCM_XTYPEP(obj, SCM_CLASS_MCRYPT))
#define SCM_MCRYPT_MCRYPT(obj) ((MCRYPT)((ScmMcrypt*)(obj))->mcrypt)

ScmObj Scm_mcrypt_module_open(ScmString *algo, ScmObj algo_dir,
			      ScmString *mode, ScmObj mode_dir);
void Scm_mcrypt_generic_init(ScmMcrypt *mcrypt, ScmString *key, ScmU8Vector *iv);
void Scm_mcrypt_generic_deinit(ScmMcrypt *mcrypt);
void Scm_mcrypt_generic(ScmMcrypt *mcrypt, ScmU8Vector *buf, int buf_start, int buf_end);
void Scm_mdecrypt_generic(ScmMcrypt *mcrypt, ScmU8Vector *buf, int buf_start, int buf_end);
int Scm_mcrypt_enc_is_block_algorithm_mode(ScmMcrypt *mcrypt);
int Scm_mcrypt_enc_is_block_algorithm(ScmMcrypt *mcrypt);
ScmObj Scm_mcrypt_enc_get_block_size(ScmMcrypt *mcrypt);
ScmObj Scm_mcrypt_enc_get_key_size(ScmMcrypt *mcrypt);
ScmObj Scm_mcrypt_enc_get_supported_key_sizes(ScmMcrypt *mcrypt);
ScmObj Scm_mcrypt_enc_get_iv_size(ScmMcrypt *mcrypt);
int Scm_mcrypt_enc_mode_has_iv(ScmMcrypt *mcrypt);

#define PADDING_UNKNOWN 0
#define PADDING_STD	1
#define PADDING_1_0s	2
#define PADDING_SPACE	3
#define PADDING_NULL	4

ScmObj Scm_MakeInputDecryptionPort(ScmPort *toPort,
				   ScmMcrypt *mcrypt,
				   int padding_mode,
				   int bufsize, int ownerp);
ScmObj Scm_MakeOutputEncryptionPort(ScmPort *toPort,
				    ScmMcrypt *mcrypt,
				    int padding_mode,
				    int bufsize, int ownerp);
#endif	/* _MCRYPT_IF_H */

/*
  Local Variables:
  mode: c++
  tab-width: 8
  End:
*/
