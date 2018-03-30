-module(tpke_privkey).

-record(privkey, {
          pubkey :: tpke_pubkey(),
          secret_key,
          secret_key_index
         }).

-type privkey() :: #privkey{}.

-export_type([privkey/0]).

decrypt_share({U, _V, _W}=CipherText, SecretKey) ->
    pbc:element_pow(U, SecretKey).
