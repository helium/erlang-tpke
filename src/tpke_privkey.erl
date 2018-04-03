-module(tpke_privkey).

-record(privkey, {
          pubkey :: tpke_pubkey:pubkey(),
          secret_key,
          secret_key_index
         }).

-type privkey() :: #privkey{}.

-export_type([privkey/0]).

-export([init/3, decrypt_share/3, sign/2]).

init(PubKey, SecretKey, SecretKeyIndex) ->
    #privkey{pubkey=PubKey, secret_key=SecretKey, secret_key_index=SecretKeyIndex}.

decrypt_share(PrivKey, G1, {U, V, W}) ->
    H = tpke_pubkey:hashH(U, V),
    Share = case  erlang_pbc:element_cmp(erlang_pbc:element_pairing(G1, W), erlang_pbc:element_pairing(U, H)) of
                true ->
                    erlang_pbc:element_mul(PrivKey#privkey.secret_key, U);
                false ->
                    '?'
            end,
    {PrivKey#privkey.secret_key_index, Share}.


sign(PrivKey, H) ->
    {PrivKey#privkey.secret_key_index, erlang_pbc:element_pow(H, PrivKey#privkey.secret_key)}.
