-module(tpke_pubkey).

-record(pubkey, {
          players,
          k,
          verification_key,
          verification_keys
         }).

-type pubkey() :: #pubkey{}.

-export_type([pubkey/0]).
-export([f/2, init/4, lagrange/4]).

init(Players, K, VK, VKs) ->
    #pubkey{players=Players, k=K, verification_key=VK, verification_keys=VKs}.

lagrange(PubKey, One, Set, Index) ->
    true = ordsets:is_set(Set),
    true = PubKey#pubkey.k == ordsets:size(Set),
    MySet = ordsets:from_list(lists:seq(0, PubKey#pubkey.players - 1)),
    true = ordsets:is_subset(Set, MySet),

    true = ordsets:is_element(Index, Set),
    true = 0 =< Index andalso Index < PubKey#pubkey.players,

    Num = lists:foldl(fun(E, Acc) ->
                              erlang_pbc:element_mul(Acc, E)
                      end, One, [ 0 - JJ  - 1 || JJ <- ordsets:to_list(Set), JJ /= Index]),

    Den = lists:foldl(fun(E, Acc) ->
                              erlang_pbc:element_mul(Acc, E)
                      end, One, [ Index - JJ  || JJ <- ordsets:to_list(Set), JJ /= Index]),

    erlang_pbc:element_div(Num, Den).

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
