-module(tpke_pubkey).

-record(pubkey, {
          players,
          k,
          verification_key,
          verification_keys
         }).

-type pubkey() :: #pubkey{}.

-export_type([pubkey/0]).
-export([f/2, init/4, lagrange/4, encrypt/3, verify_ciphertext/3, verify_share/4, combine_shares/3]).

init(Players, K, VK, VKs) ->
    #pubkey{players=Players, k=K, verification_key=VK, verification_keys=VKs}.

encrypt(PubKey, G1, Message) when is_binary(Message) ->
    32 = byte_size(Message),
    R = erlang_pbc:element_new('Zr', PubKey#pubkey.verification_key),
    U = erlang_pbc:element_pow(G1, R),
    V = xor_bin(Message, hashG(erlang_pbc:element_pow(PubKey#pubkey.verification_key, R))),
    W = erlang_pbc:element_pow(hashH(U, V), R),
    {U, V, W}.

verify_ciphertext(PubKey, G1, {U, V, W}) ->
    H = hashH(U, V),
    erlang_pbc:element_cmp(erlang_pbc:element_pairing(G1, W), erlang_pbc:element_pairing(U, H)).

verify_share(PubKey, G2, {Index, Share}, {U, V, W}) ->
    true = 0 =< Index andalso Index < PubKey#pubkey.players,
    Y_i = lists:nth(Index+1, PubKey#pubkey.verification_keys),
    erlang_pbc:element_cmp(erlang_pbc:element_pairing(Share, G2), erlang_pbc:element_pairing(U, Y_i)).

combine_shares(PubKey, {U, V, W}, Shares) ->
    {Indices, _} = lists:unzip(Shares),
    Set = ordsets:from_list(Indices),
    MySet = ordsets:from_list(lists:seq(0, PubKey#pubkey.players - 1)),
    true = ordsets:is_subset(Set, MySet),

    One = erlang_pbc:element_set(erlang_pbc:element_new('G1', U), 1),

    Bleh = [ erlang_pbc:element_pow(Share, lagrange(PubKey, One, Set, Index)) || {Index, Share} <- Shares],
    Res = lists:foldl(fun(E, Acc) ->
                              erlang_pbc:element_mul(Acc, E)
                      end, One, Bleh),
    xor_bin(hashG(Res), V).

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
    One = erlang_pbc:element_set(hd(Coefficients), 1),
    f(Xval, Coefficients, Zero, One).

f(_Xval, [] = _Coefficients, NewY, _InitX) -> NewY;
f(Xval, [Head | Tail] = _Coefficients, Y, X) ->
    NewY = erlang_pbc:element_add(Y, erlang_pbc:element_mul(Head, X)),
    NewX = erlang_pbc:element_mul(X, Xval),
    f(Xval, Tail, NewY, NewX).

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
