-module(dealer_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").

-export([all/0, init_per_testcase/2, end_per_testcase/2]).
-export([first_secret_equality_test/1, zero_reconstruction_test/1]).

all() ->
    [first_secret_equality_test, zero_reconstruction_test].

init_per_testcase(_, Config) ->
    {ok, Dealer} = dealer:start_link(),
    {ok, Group} = dealer:group(Dealer),
    {ok, PubKey, PrivateKeys} = dealer:deal(Dealer),
    Element = erlang_pbc:element_new('Zr', Group),
    K = 5,
    Coefficients = [erlang_pbc:element_random(Element) || _ <- lists:seq(1, K)],
    [ {dealer, Dealer}, {group, Group}, {pubkey, PubKey}, {privkeys, PrivateKeys}, {element, Element}, {k, K}, {coefficients, Coefficients} | Config ].

end_per_testcase(_, Config) ->
    Dealer = proplists:get_value(dealer, Config),
    gen_server:stop(Dealer),
    ok.

zero_reconstruction_test(Config) ->
    K = proplists:get_value(k, Config),
    Coefficients = proplists:get_value(coefficients, Config),
    PubKey = proplists:get_value(pubkey, Config),
    FirstSecret = dealer:share_secret(0, Coefficients),
    Set = ordsets:from_list(lists:seq(0, K-1)),
    Bits = [ erlang_pbc:element_mul(tpke_pubkey:lagrange(PubKey, Set, J), dealer:share_secret(J+1, Coefficients)) || J <- ordsets:to_list(Set)],
    SumBits = lists:foldl(fun erlang_pbc:element_add/2, hd(Bits), tl(Bits)),
    ?assert(erlang_pbc:element_cmp(FirstSecret, SumBits)).

first_secret_equality_test(Config) ->
    Coefficients = proplists:get_value(coefficients, Config),
    Secret = hd(Coefficients),
    FirstSecret = dealer:share_secret(0, Coefficients),
    ?assert(erlang_pbc:element_cmp(Secret, FirstSecret)).
