-module(tpke_privkey).

-record(privkey, {
          pubkey :: tpke_pubkey:pubkey(),
          secret_key,
          secret_key_index
         }).

-type privkey() :: #privkey{}.

-export_type([privkey/0]).

-export([init/3]).

init(PubKey, SecretKey, SecretKeyIndex) ->
    #privkey{pubkey=PubKey, secret_key=SecretKey, secret_key_index=SecretKeyIndex}.
