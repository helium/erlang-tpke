-record(privkey, {
          pubkey :: tpke_pubkey:pubkey(),
          secret_key :: erlang_pbc:element(),
          secret_key_index :: non_neg_integer()
         }).

-record(privkey_serialized, {
          pubkey :: tpke_pubkey:pubkey_serialized(),
          secret_key :: binary(),
          secret_key_index :: non_neg_integer()
         }).
