/*
 * mcrypt_if.c: libmcrypt API I/F
 *
 * Copyright (c) 2005-2008 Tatsuya BIZENN, All rights reserved.
 */

#include <stdlib.h>
#include "mcrypt_if.h"

static void mcrypt_finalize(ScmObj obj, void *data)
{
    MCRYPT m = SCM_MCRYPT_MCRYPT(SCM_MCRYPT(obj));
    mcrypt_module_close(m);
}

ScmObj Scm_mcrypt_module_open(ScmString *algo, ScmObj algo_dir,
			      ScmString *mode, ScmObj mode_dir)
{
    char *algo_cstr, *algo_dir_cstr = NULL;
    char *mode_cstr, *mode_dir_cstr = NULL;
    MCRYPT mcrypt;
    ScmMcrypt *m;

    algo_cstr = Scm_GetString(SCM_STRING(algo));
    if (!SCM_FALSEP(algo_dir))
	algo_dir_cstr = Scm_GetString(SCM_STRING(algo_dir));
    mode_cstr = Scm_GetString(SCM_STRING(mode));
    if (!SCM_FALSEP(mode_dir))
	mode_dir_cstr = Scm_GetString(SCM_STRING(mode_dir));

    if ((mcrypt = mcrypt_module_open(algo_cstr, algo_dir_cstr, mode_cstr, mode_dir_cstr)) == MCRYPT_FAILED)
	Scm_Error("mcrypt_module_open() failed:"
		  " algo=%S, algo_dir=%S, mode=%S, mode_dir=%S", algo, algo_dir, mode, mode_dir);

    m = SCM_NEW(ScmMcrypt);
    SCM_SET_CLASS(m, SCM_CLASS_MCRYPT);
    ((ScmMcrypt*)(m))->mcrypt = mcrypt;
    Scm_RegisterFinalizer(SCM_OBJ(m), mcrypt_finalize, NULL);
    SCM_RETURN(SCM_OBJ(m));
}

void Scm_mcrypt_generic_init(ScmMcrypt *mcrypt, ScmString *key, ScmU8Vector *iv)
{
    int iv_size = mcrypt_enc_get_iv_size(SCM_MCRYPT_MCRYPT(mcrypt));
    if (SCM_U8VECTOR_SIZE(iv) < iv_size)
	Scm_Error("mcrypt_generic_init(): iv too short: %S", iv);
    if (mcrypt_generic_init(SCM_MCRYPT_MCRYPT(mcrypt), (void*)SCM_STRING_START(key),
			    SCM_STRING_SIZE(key), (void*)SCM_U8VECTOR_ELEMENTS(iv)) < 0)
	Scm_Error("mcrypt_generic_init(): unknown error");
}

void Scm_mcrypt_generic_deinit(ScmMcrypt *mcrypt)
{
    mcrypt_generic_deinit(SCM_MCRYPT_MCRYPT(mcrypt));
}

void Scm_mcrypt_generic(ScmMcrypt *mcrypt, ScmU8Vector *buf, int buf_start, int buf_end)
{
    if ((buf_start<0)||(buf_end>SCM_U8VECTOR_SIZE(buf)))
	Scm_Error("mcrypt_generic(): buf is %dbytes, but buf_start=%d, buf_end=%d",
		  SCM_U8VECTOR_SIZE(buf), buf_start, buf_end);
    if (mcrypt_generic(SCM_MCRYPT_MCRYPT(mcrypt), (void*)&SCM_U8VECTOR_ELEMENTS(buf)[buf_start], buf_end - buf_start))
	Scm_Error("mcrypt_generic(): unknown error");
}

void Scm_mdecrypt_generic(ScmMcrypt *mcrypt, ScmU8Vector *buf, int buf_start, int buf_end)
{
    if ((buf_start<0)||(buf_end>SCM_U8VECTOR_SIZE(buf)))
	Scm_Error("mdecrypt_generic(): buf is %dbytes, but buf_start=%d, buf_end=%d",
		  SCM_U8VECTOR_SIZE(buf), buf_start, buf_end);
    if (mdecrypt_generic(SCM_MCRYPT_MCRYPT(mcrypt), (void*)&SCM_U8VECTOR_ELEMENTS(buf)[buf_start], buf_end - buf_start))
	Scm_Error("mdecrypt_generic(): unknown error");
}

int Scm_mcrypt_enc_is_block_algorithm_mode(ScmMcrypt *mcrypt)
{
    return mcrypt_enc_is_block_algorithm_mode(SCM_MCRYPT_MCRYPT(mcrypt));
}

int Scm_mcrypt_enc_is_block_algorithm(ScmMcrypt *mcrypt)
{
    return mcrypt_enc_is_block_algorithm(SCM_MCRYPT_MCRYPT(mcrypt));
}

ScmObj Scm_mcrypt_enc_get_block_size(ScmMcrypt *mcrypt)
{
    SCM_RETURN(SCM_OBJ(Scm_MakeInteger(mcrypt_enc_get_block_size(SCM_MCRYPT_MCRYPT(mcrypt)))));
}

ScmObj Scm_mcrypt_enc_get_key_size(ScmMcrypt *mcrypt)
{
    SCM_RETURN(SCM_OBJ(Scm_MakeInteger(mcrypt_enc_get_key_size(SCM_MCRYPT_MCRYPT(mcrypt)))));
}

ScmObj Scm_mcrypt_enc_get_supported_key_sizes(ScmMcrypt *mcrypt)
{
    int sizes;
    int *ret;
    ScmObj p = SCM_NIL;

    ret = mcrypt_enc_get_supported_key_sizes(SCM_MCRYPT_MCRYPT(mcrypt), &sizes);
    if (sizes == 0)
	SCM_RETURN(p);
    else if (sizes == 1)
	SCM_RETURN(Scm_Cons(Scm_MakeInteger(ret[0]), p));
    while (sizes)
	p = Scm_Cons(Scm_MakeInteger(ret[--sizes]), p);
    free(ret);
    SCM_RETURN(p);
}

ScmObj Scm_mcrypt_enc_get_iv_size(ScmMcrypt *mcrypt)
{
    SCM_RETURN(SCM_OBJ(Scm_MakeInteger(mcrypt_enc_get_iv_size(SCM_MCRYPT_MCRYPT(mcrypt)))));
}

int Scm_mcrypt_enc_mode_has_iv(ScmMcrypt *mcrypt)
{
    return mcrypt_enc_mode_has_iv(SCM_MCRYPT_MCRYPT(mcrypt));
}

/*
  Local Variables:
  mode: c++
  tab-width: 8
  End:
*/
