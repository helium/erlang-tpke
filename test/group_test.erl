-module(group_test).

-include_lib("eunit/include/eunit.hrl").

basic_test() ->
    Group = erlang_pbc:group_new('SS512'),
    Element = erlang_pbc:element_new('G1', Group),
    ?assertEqual(erlang_pbc:element_to_string(Element), "O"),
    ok.
