-module(dealer_test).

-include_lib("eunit/include/eunit.hrl").

-define(GROUP, erlang_pbc:group_new('SS512')).
-define(ELEMENT, erlang_pbc:element_new('Zr', ?GROUP)).

basic_test() ->

	%% change later
	_Players = 10,
	K = 5,
	Coefficients = [erlang_pbc:element_random(?ELEMENT) || _ <- lists:seq(1, K)],
	%% io:format("Coefficients: ~p~n", [Coefficients]),
	Secret = hd(Coefficients),
	io:format("Secret: ~p~n", [erlang_pbc:element_to_string(Secret)]),

	Foo = f(0, Coefficients),
	io:format("Foo: ~p", [erlang_pbc:element_to_string(Foo)]),

	?assert(false),
	ok.

f(Xval, Coefficients) ->
	Zero = erlang_pbc:element_mul(erlang_pbc:element_random(?ELEMENT), 0),
	io:format("Zero: ~p~n", [erlang_pbc:element_to_string(Zero)]),
	One = erlang_pbc:element_add(erlang_pbc:element_mul(erlang_pbc:element_random(?ELEMENT), 0), 1),
	io:format("One: ~p~n", [erlang_pbc:element_to_string(One)]),
	f(Xval, Coefficients, Zero, One).

f(_Xval, [] = _Coefficients, NewY, _InitX) -> NewY;
f(Xval, [Head | Tail] = _Coefficients, Y, X) ->
	NewY = erlang_pbc:element_add(Y, erlang_pbc:element_mul(Head, X)),
	NewX = erlang_pbc:element_mul(X, Xval),
	f(Xval, Tail, NewY, NewX).
