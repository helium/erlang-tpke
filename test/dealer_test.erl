-module(dealer_test).

-include_lib("eunit/include/eunit.hrl").

-define(GROUP, erlang_pbc:group_new('SS512')).
-define(ELEMENT, erlang_pbc:element_new('Zr', ?GROUP)).

first_secret_equality_test() ->
	%% change later
	_Players = 10,
	K = 5,
	Coefficients = [erlang_pbc:element_random(?ELEMENT) || _ <- lists:seq(1, K)],
	%% io:format("Coefficients: ~p~n", [Coefficients]),
	Secret = hd(Coefficients),
	%% io:format("Secret: ~p~n", [erlang_pbc:element_to_string(Secret)]),
	FirstSecret = tpke_pubkey:f(0, Coefficients),
	%% io:format("Foo: ~p", [erlang_pbc:element_to_string(Foo)]),
	?assertEqual(erlang_pbc:element_to_string(Secret), erlang_pbc:element_to_string(FirstSecret)),
	ok.

