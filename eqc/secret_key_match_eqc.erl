-module(secret_key_match_eqc).

-include_lib("eqc/include/eqc.hrl").


-export([prop_secret_key_match/0]).

prop_secret_key_match() ->
    ?FORALL(N, gen_coefficients(),
            begin
                Group =erlang_pbc:group_new('SS512'),
                Element = erlang_pbc:element_new('Zr', Group),
                Coefficients = [ erlang_pbc:element_random(Element) || _ <- lists:seq(1, N)],
                Secret = hd(Coefficients),
                FirstSecret = dealer:share_secret(0, Coefficients),
                ?WHENFAIL(begin
                              io:format("Secret ~p~n", [erlang_pbc:element_to_string(Secret)]),
                              io:format("FirstSecret ~p~n", [erlang_pbc:element_to_string(FirstSecret)])
                          end,
                          conjunction([
                                       {secret_equality, eqc:equals(erlang_pbc:element_to_string(Secret), erlang_pbc:element_to_string(FirstSecret))}
                                      ]))
            end).

gen_coefficients() ->
    ?SUCHTHAT(L, int(), L > 0).
