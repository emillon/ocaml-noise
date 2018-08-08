#include "caml/memory.h"
#include "caml/bigarray.h"

#include "tweetnacl.h"

void randombytes(unsigned char *buf, unsigned int n)
{
	abort();
}

CAMLprim value caml_tweetnacl_scalar_mult(value into, value priv, value pub)
{
	CAMLparam3 (pub, priv, into);

	crypto_scalarmult_curve25519_tweet(
		Caml_ba_data_val(into),
		Caml_ba_data_val(priv),
		Caml_ba_data_val(pub)
	);

	CAMLreturn(Val_unit);
}
