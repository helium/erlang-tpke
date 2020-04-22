-module(decrypt_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").

-export([all/0, init_per_testcase/2, end_per_testcase/2]).
-export([threshold_decrypt_test/1]).

all() ->
    [threshold_decrypt_test].

init_per_testcase(_, Config) ->
    D1 = dealer:new(10, 5, 'SS512'),
    D2 = dealer:new(100, 30, 'SS512'),
    [ {dealers, [D1, D2]} | Config ].

end_per_testcase(_, _Config) ->
    ok.

threshold_decrypt_test(Config) ->
    Dealers = proplists:get_value(dealers, Config),
    lists:foreach(fun({ok, Dealer}) ->
                          {ok, _Group} = dealer:group(Dealer),
                          {ok, {PubKey, PrivateKeys}} = dealer:deal(Dealer),
                          {ok, {OtherPubKey, OtherPrivateKeys}} = dealer:deal(Dealer),
                          {ok, K} = dealer:threshold(Dealer),
                          Message = crypto:hash(sha256, <<"my hovercraft is full of eels">>),
                          CipherText = tpke_pubkey:encrypt(PubKey, Message),
                          %% verify ciphertext
                          ?assertError(unverified_ciphertext, [ tpke_privkey:decrypt_share(SK, CipherText) || SK <- PrivateKeys ]),
                          {ok, VerifiedCipherText} = tpke_pubkey:verify_ciphertext(PubKey, CipherText),
                          ?assertError(inconsistent_ciphertext, [ tpke_privkey:decrypt_share(SK, VerifiedCipherText) || SK <- OtherPrivateKeys ]),
                          Shares = [ tpke_privkey:decrypt_share(SK, VerifiedCipherText) || SK <- PrivateKeys ],
                          %% verify share
                          ?assertError(unverified_ciphertext, lists:all(fun(X) -> X end, [tpke_pubkey:verify_share(PubKey, Share, CipherText) || Share <- Shares])),
                          ?assertError(inconsistent_ciphertext, lists:all(fun(X) -> X end, [tpke_pubkey:verify_share(OtherPubKey, Share, VerifiedCipherText) || Share <- Shares])),
                          ?assert(lists:all(fun(X) -> X end, [tpke_pubkey:verify_share(PubKey, Share, VerifiedCipherText) || Share <- Shares])),
                          %% verify combine_shares
                          ?assertError(unverified_ciphertext, tpke_pubkey:combine_shares(PubKey, CipherText, dealer:random_n(K, Shares))),
                          ?assertError(inconsistent_ciphertext, tpke_pubkey:combine_shares(OtherPubKey, VerifiedCipherText, dealer:random_n(K, Shares))),
                          ?assertEqual(Message, tpke_pubkey:combine_shares(PubKey, VerifiedCipherText, dealer:random_n(K, Shares))),
                          %% test serialization/deserialization
                          SerializedCipherText = tpke_pubkey:ciphertext_to_binary(CipherText),
                          %% we don't encode validation status
                          ?assertEqual(SerializedCipherText, tpke_pubkey:ciphertext_to_binary(CipherText)),
                          DeserializedCipherText = tpke_pubkey:binary_to_ciphertext(SerializedCipherText, PubKey),
                          ?assertError(inconsistent_ciphertext, tpke_pubkey:binary_to_ciphertext(SerializedCipherText, OtherPubKey)),
                          ?assertEqual(Message, tpke_pubkey:combine_shares(PubKey, DeserializedCipherText, dealer:random_n(K, Shares))),

                          %% test serialization/deserialization
                          VerifiedSerializedCipherText = tpke_pubkey:ciphertext_to_binary(VerifiedCipherText),
                          %% we don't encode validation status
                          ?assertEqual(VerifiedSerializedCipherText, tpke_pubkey:ciphertext_to_binary(VerifiedCipherText)),
                          VerifiedDeserializedCipherText = tpke_pubkey:binary_to_ciphertext(SerializedCipherText, PubKey),
                          ?assertError(inconsistent_ciphertext, tpke_pubkey:binary_to_ciphertext(VerifiedSerializedCipherText, OtherPubKey)),
                          ?assertEqual(Message, tpke_pubkey:combine_shares(PubKey, VerifiedDeserializedCipherText, dealer:random_n(K, Shares))),

                          ok
                  end, Dealers).
