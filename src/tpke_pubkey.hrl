-record(pubkey, {
          players :: pos_integer(),
          k :: non_neg_integer(),
          curve :: curve(),
          g1 :: erlang_pbc:element(),
          g2 :: erlang_pbc:element(),
          verification_key :: erlang_pbc:element(),
          verification_keys :: [erlang_pbc:element(), ...]
         }).

-record(pubkey_serialized, {
          players :: pos_integer(),
          k :: non_neg_integer(),
          curve :: curve(),
          g1 :: binary(),
          g2 :: binary(),
          verification_key :: binary(),
          verification_keys :: [binary(), ...]
         }).
