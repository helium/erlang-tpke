-module(secret_key_match_eqc).

-include_lib("eqc/include/eqc.hrl").

-define(GROUP, erlang_pbc:group_new('SS512')).
-define(ELEMENT, erlang_pbc:element_new('Zr', ?GROUP)).

-export([prop_secret_key_match/0]).

prop_secret_key_match() ->
    ?FORALL(Coefficients, gen_coefficients(),
            begin
                Secret = hd(Coefficients),
                FirstSecret = tpke_pubkey:f(0, Coefficients),
                ?WHENFAIL(begin
                              io:format("Secret ~p~n", [erlang_pbc:element_to_string(Secret)]),
                              io:format("FirstSecret ~p~n", [erlang_pbc:element_to_string(FirstSecret)])
                          end,
                          conjunction([
                                       {secret_equality, eqc:equals(erlang_pbc:element_to_string(Secret), erlang_pbc:element_to_string(FirstSecret))}
                                      ]))
            end).

gen_coefficients() ->
    ?SUCHTHAT(L, list(erlang_pbc:element_random(?ELEMENT)), length(L) > 0).
