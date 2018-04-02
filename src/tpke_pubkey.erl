-module(tpke_pubkey).

-record(pubkey, {
          players,
          k,
          verification_key,
          verification_keys
         }).

-type pubkey() :: #pubkey{}.

-export_type([pubkey/0]).
-export([init/4, lagrange/4, encrypt/3, verify_ciphertext/3, verify_share/4, combine_shares/3, hash_message/2, verify_signature/4, combine_signature_shares/2, verify_signature_share/4]).

init(Players, K, VK, VKs) ->
    #pubkey{players=Players, k=K, verification_key=VK, verification_keys=VKs}.

encrypt(PubKey, G1, Message) when is_binary(Message) ->
    32 = byte_size(Message),
    R = erlang_pbc:element_new('Zr', PubKey#pubkey.verification_key),
    U = erlang_pbc:element_pow(G1, R),
    V = xor_bin(Message, hashG(erlang_pbc:element_pow(PubKey#pubkey.verification_key, R))),
    W = erlang_pbc:element_pow(hashH(U, V), R),
    {U, V, W}.

verify_ciphertext(_PubKey, G1, {U, V, W}) ->
    H = hashH(U, V),
    erlang_pbc:element_cmp(erlang_pbc:element_pairing(G1, W), erlang_pbc:element_pairing(U, H)).

verify_share(PubKey, G2, {Index, Share}, {U, _V, _W}) ->
    true = 0 =< Index andalso Index < PubKey#pubkey.players,
    Y_i = lists:nth(Index+1, PubKey#pubkey.verification_keys),
    erlang_pbc:element_cmp(erlang_pbc:element_pairing(Share, G2), erlang_pbc:element_pairing(U, Y_i)).

verify_signature_share(PubKey, G2, {Index, Share}, H) ->
    true = 0 =< Index andalso Index < PubKey#pubkey.players,
    B = lists:nth(Index+1, PubKey#pubkey.verification_keys),
    erlang_pbc:element_cmp(erlang_pbc:element_pairing(Share, G2), erlang_pbc:element_pairing(H, B)).

verify_signature(PubKey, G2, Signature, H) ->
    A = erlang_pbc:element_pairing(Signature, G2),
    B = erlang_pbc:element_pairing(H, PubKey#pubkey.verification_key),
    io:format("Signature ~p~n", [erlang_pbc:element_to_string(Signature)]),
    io:format("A ~p~n", [erlang_pbc:element_to_string(A)]),
    io:format("B ~p~n", [erlang_pbc:element_to_string(B)]),
    erlang_pbc:element_cmp(A, B).

combine_shares(PubKey, {U, V, _W}, Shares) ->
    {Indices, _} = lists:unzip(Shares),
    Set = ordsets:from_list(Indices),
    MySet = ordsets:from_list(lists:seq(0, PubKey#pubkey.players - 1)),
    true = ordsets:is_subset(Set, MySet),

    One = erlang_pbc:element_set(erlang_pbc:element_new('Zr', U), 1),
    io:format("ONE ~p~n", [erlang_pbc:element_to_string(One)]),

    Bleh = [ erlang_pbc:element_pow(Share, lagrange(PubKey, One, Set, Index)) || {Index, Share} <- Shares],
    Res = lists:foldl(fun(E, Acc) ->
                              erlang_pbc:element_mul(E, Acc)
                      end, 1, Bleh),
    xor_bin(hashG(Res), V).

combine_signature_shares(PubKey, Shares) ->
    {Indices, _} = lists:unzip(Shares),
    Set = ordsets:from_list(Indices),
    MySet = ordsets:from_list(lists:seq(0, PubKey#pubkey.players - 1)),
    true = ordsets:is_subset(Set, MySet),

    One = erlang_pbc:element_set(erlang_pbc:element_new('Zr', PubKey#pubkey.verification_key), 1),
    io:format("ONE ~p~n", [erlang_pbc:element_to_string(One)]),

    Bleh = [ erlang_pbc:element_pow(Share, lagrange(PubKey, One, Set, Index)) || {Index, Share} <- Shares],
    io:format("Bleh ~p~n", [[ erlang_pbc:element_to_string(S) || S <- Bleh]]),
    lists:foldl(fun(E, Acc) ->
                              Next = erlang_pbc:element_mul(E, Acc),
                              io:format("Next ~p~n", [erlang_pbc:element_to_string(Next)]),
                              Next
                      end, 1, Bleh).

hash_message(PubKey, Msg) ->
    Res = erlang_pbc:element_from_hash(erlang_pbc:element_new('G1', PubKey#pubkey.verification_key), Msg),
    erlang_pbc:element_pp_init(Res),
    Res.

lagrange(PubKey, One, Set, Index) ->
    true = ordsets:is_set(Set),
    %true = PubKey#pubkey.k == ordsets:size(Set),
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

    io:format("Num ~p~n", [erlang_pbc:element_to_string(Num)]),
    io:format("Den ~p~n", [erlang_pbc:element_to_string(Den)]),
    Res = erlang_pbc:element_div(Num, Den),
    io:format("Res ~p~n", [erlang_pbc:element_to_string(Res)]),
    Res.

hashG(G) ->
    crypto:hash(sha256, erlang_pbc:element_to_binary(G)).

hashH(G, X) ->
    32 = byte_size(X),
    erlang_pbc:element_from_hash(erlang_pbc:element_new('G2', G), list_to_binary([erlang_pbc:element_to_binary(G), X])).

xor_bin(A, B) ->
    32 = byte_size(A),
    32 = byte_size(B),
    xor_bin(A, B, []).

xor_bin(<<>>, <<>>, Acc) ->
    list_to_binary(lists:reverse(Acc));
xor_bin(<<A:8/integer-unsigned, T1/binary>>, <<B:8/integer-unsigned, T2/binary>>, Acc) ->
    xor_bin(T1, T2, [A bxor B | Acc]).
