-module(tpke_privkey).

-record(privkey, {
          pubkey :: tpke_pubkey:pubkey(),
          secret_key,
          secret_key_index
         }).

-type privkey() :: #privkey{}.

-export_type([privkey/0]).

-export([init/3, decrypt_share/3, sign/2, public_key/1]).

init(PubKey, SecretKey, SecretKeyIndex) ->
    #privkey{pubkey=PubKey, secret_key=SecretKey, secret_key_index=SecretKeyIndex}.


%% Section 3.2.2 Baek and Zheng
%% Dski(C):
decrypt_share(PrivKey, G1, {U, V, W}) ->
    Share = case tpke_pubkey:verify_ciphertext(PrivKey#privkey.pubkey, G1, {U, V, W}) of
                true ->
                    %% computes Ui = xiU
                    erlang_pbc:element_mul(PrivKey#privkey.secret_key, U);
                false ->
                    '?'
            end,
    %% output Di = (i, Ui)
    {PrivKey#privkey.secret_key_index, Share}.


%% Section 5.2 Boldyrevya
%% MS
sign(PrivKey, H) ->
    %% σj←H(M)^xj
    %% Note that H(M) has already been computed here
    {PrivKey#privkey.secret_key_index, erlang_pbc:element_pow(H, PrivKey#privkey.secret_key)}.

-spec public_key(privkey()) -> tpke_pubkey:pubkey().
public_key(PrivKey) ->
    PrivKey#privkey.pubkey.
