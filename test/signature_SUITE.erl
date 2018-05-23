-module(signature_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").

-export([all/0, init_per_testcase/2, end_per_testcase/2]).
-export([threshold_signatures_test/1]).

all() ->
    [threshold_signatures_test].

init_per_testcase(_, Config) ->
    Curves = [ 'SS512', 'MNT224', 'MNT159'],
    LowDealers = [ dealer:start_link(10, 5, Curve) || Curve <- Curves ],
    HighDealers = [ dealer:start_link(100, 30, Curve) || Curve <- Curves ],
    [ {dealers, LowDealers ++ HighDealers} | Config ].

end_per_testcase(_, Config) ->
    Dealers = proplists:get_value(dealers, Config),
    lists:foreach(fun({ok, Dealer}) -> gen_server:stop(Dealer) end, Dealers),
    ok.

threshold_signatures_test(Config) ->
    Dealers = proplists:get_value(dealers, Config),
    lists:foreach(fun({ok, Dealer}) ->
                          {ok, K} = dealer:adversaries(Dealer),
                          {ok, _Group} = dealer:group(Dealer),
                          {ok, PubKey, PrivateKeys} = dealer:deal(Dealer),
                          Msg = crypto:hash(sha256, crypto:strong_rand_bytes(12)),
                          MessageToSign = tpke_pubkey:hash_message(PubKey, Msg),
                          Signatures = [ tpke_privkey:sign(PrivKey, MessageToSign) || PrivKey <- PrivateKeys],
                          io:format("Signatures ~p~n", [[ erlang_pbc:element_to_string(S) || {_, S} <- Signatures]]),
                          ?assert(lists:all(fun(X) -> X end, [tpke_pubkey:verify_signature_share(PubKey, Share, MessageToSign) || Share <- Signatures])),
                          {ok, Sig} = tpke_pubkey:combine_signature_shares(PubKey, dealer:random_n(K, Signatures), MessageToSign),
                          ?assert(tpke_pubkey:verify_signature(PubKey, Sig, MessageToSign))
                  end, Dealers).
