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
                          {ok, K} = dealer:threshold(Dealer),
                          Message = crypto:hash(sha256, <<"my hovercraft is full of eels">>),
                          CipherText = tpke_pubkey:encrypt(PubKey, Message),
                          %% verify ciphertext
                          ?assert(tpke_pubkey:verify_ciphertext(PubKey, CipherText)),
                          Shares = [ tpke_privkey:decrypt_share(SK, CipherText) || SK <- PrivateKeys ],
                          %% verify share
                          ?assert(lists:all(fun(X) -> X end, [tpke_pubkey:verify_share(PubKey, Share, CipherText) || Share <- Shares])),
                          %% verify combine_shares
                          ?assertEqual(Message, tpke_pubkey:combine_shares(PubKey, CipherText, dealer:random_n(K, Shares)))
                  end, Dealers).
