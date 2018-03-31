-module(tpke_pubkey).

-record(pubkey, {
          players,
          k,
          verification_key,
          verification_keys
         }).

-type pubkey() :: #pubkey{}.

-export_type([pubkey/0]).
-export([f/2]).

f(Xval, Coefficients) ->
	Zero = erlang_pbc:element_set(hd(Coefficients), 0),
	%% io:format("Zero: ~p~n", [erlang_pbc:element_to_string(Zero)]),
	One = erlang_pbc:element_set(hd(Coefficients), 1),
	%% io:format("One: ~p~n", [erlang_pbc:element_to_string(One)]),
	f(Xval, Coefficients, Zero, One).

f(_Xval, [] = _Coefficients, NewY, _InitX) -> NewY;
f(Xval, [Head | Tail] = _Coefficients, Y, X) ->
	NewY = erlang_pbc:element_add(Y, erlang_pbc:element_mul(Head, X)),
	NewX = erlang_pbc:element_mul(X, Xval),
	f(Xval, Tail, NewY, NewX).
