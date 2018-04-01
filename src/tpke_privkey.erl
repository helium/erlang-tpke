-module(tpke_privkey).

-record(privkey, {
          pubkey :: tpke_pubkey:pubkey(),
          secret_key,
          secret_key_index
         }).

-type privkey() :: #privkey{}.

-export_type([privkey/0]).

-export([init/3, decrypt_share/2, sign/2]).

init(PubKey, SecretKey, SecretKeyIndex) ->
    #privkey{pubkey=PubKey, secret_key=SecretKey, secret_key_index=SecretKeyIndex}.

decrypt_share(PrivKey, {U, _V, _W}) ->
    Share = erlang_pbc:element_pow(U, PrivKey#privkey.secret_key),
    {PrivKey#privkey.secret_key_index, Share}.

sign(PrivKey, H) ->
    {PrivKey#privkey.secret_key_index, erlang_pbc:element_pow(H, PrivKey#privkey.secret_key)}.
