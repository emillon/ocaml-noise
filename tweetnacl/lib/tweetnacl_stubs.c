#include "caml/memory.h"
#include "caml/bigarray.h"

#include "tweetnacl.h"

void randombytes(unsigned char *buf, unsigned int n)
{
	abort();
}

CAMLprim value caml_tweetnacl_poly1305(value into, value m, value n, value k)
{
	CAMLparam4(into, m, n, k);

	crypto_onetimeauth_poly1305(
		Caml_ba_data_val(into),
		Caml_ba_data_val(m),
		Int64_val(n),
		Caml_ba_data_val(k)
	);

	CAMLreturn(Val_unit);
}
