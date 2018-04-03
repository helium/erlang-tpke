-module(tpke_pubkey).

-record(pubkey, {
          players,
          k,
          verification_key,
          verification_keys
         }).

-type pubkey() :: #pubkey{}.

-export_type([pubkey/0]).
-export([init/4, lagrange/3, encrypt/3, verify_ciphertext/3, verify_share/4, combine_shares/4, hash_message/2, verify_signature/4, combine_signature_shares/2, verify_signature_share/4]).

-export([hashH/2]).

init(Players, K, VK, VKs) ->
    #pubkey{players=Players, k=K, verification_key=VK, verification_keys=VKs}.

%% Section 3.2.2 Baek and Zheng
%% Epk(m):
encrypt(PubKey, G1, Message) when is_binary(Message) ->
    32 = byte_size(Message),
    %% r is randomly chosen from ZZ∗q
    R = erlang_pbc:element_random(erlang_pbc:element_new('Zr', PubKey#pubkey.verification_key)),
    %% U = rP
    U = erlang_pbc:element_mul(R, G1),
    %% V = G(rY)⊕m
    V = xor_bin(hashG(erlang_pbc:element_mul(R, PubKey#pubkey.verification_key)), Message),
    %% W = rH(U, V)
    W = erlang_pbc:element_mul(R, hashH(U, V)),
    %% ciphertext C = (U, V, W)
    {U, V, W}.

%% Section 3.2.2 Baek and Zheng
%% common code to verify ciphertext is valid
verify_ciphertext(_PubKey, G1, {U, V, W}) ->
    %% H = H(U, V)
    H = hashH(U, V),
    %% check if ˆe(P, W) = ˆe(U, H)
    erlang_pbc:element_cmp(erlang_pbc:element_pairing(G1, W), erlang_pbc:element_pairing(U, H)).

%% Section 3.2.2 Baek and Zheng
%% Vvk(C, Di):
verify_share(PubKey, G2, {Index, Share}, {U, V, W}) ->
    true = 0 =< Index andalso Index < PubKey#pubkey.players,
    case verify_ciphertext(PubKey, G2, {U, V, W}) of
        true when Share == '?' ->
            false;
        true ->
            %% check if ˆe(P, Ui) = ˆe(U, Yi).
            Yi = lists:nth(Index+1, PubKey#pubkey.verification_keys),
            erlang_pbc:element_cmp(erlang_pbc:element_pairing(G2, Share), erlang_pbc:element_pairing(U, Yi));
        false when Share == '?' ->
            true;
        false ->
            false
    end.

%% Section 3.2.2 Baek and Zheng
%% SCvk(C,{Di}i∈Φ):
combine_shares(PubKey, G2, {U, V, W}, Shares) ->
    {Indices, _} = lists:unzip(Shares),
    Set = ordsets:from_list(Indices),
    MySet = ordsets:from_list(lists:seq(0, PubKey#pubkey.players - 1)),
    true = ordsets:is_subset(Set, MySet),

    case verify_ciphertext(PubKey, G2, {U, V, W}) of
        true ->
            %% m=G(∑i∈ΦλΦ0iUi)⊕V
            Bleh = [ erlang_pbc:element_pow(Share, lagrange(PubKey, Set, Index)) || {Index, Share} <- Shares],
            Res = lists:foldl(fun(E, Acc) ->
                              erlang_pbc:element_mul(Acc, E)
                      end, hd(Bleh), tl(Bleh)),
            xor_bin(hashG(Res), V);
        false ->
            undefined
    end.


%% Section 3.1 Boldyreva
%% Decisional Diffie-Hellman (DDH) problem.
verify_signature_share(PubKey, G2, {Index, Share}, HM) ->
    true = 0 =< Index andalso Index < PubKey#pubkey.players,
    Y = lists:nth(Index+1, PubKey#pubkey.verification_keys),
    %% In order to verify the validity of a candidate signature σ of a messageM,
    %% a verifier simply checks whether (g,y,H(M),σ) is a valid Diffie-Hellman tuple.
    %% Given (g,g^x,g^y,g^z) it is possible to check z=xy if e(g,g^z) == e(g^x,g^y)
    erlang_pbc:element_cmp(erlang_pbc:element_pairing(G2, Share), erlang_pbc:element_pairing(Y, HM)).

%% Section 3.2 Boldyrevya
%% V(pk,M,σ) :
verify_signature(PubKey, G2, Signature, H) ->
    %% VDDH(g,y,H(M),σ)
    %% VDDH(g,pkL,H(M),σ)
    A = erlang_pbc:element_pairing(Signature, G2),
    B = erlang_pbc:element_pairing(H, PubKey#pubkey.verification_key),
    erlang_pbc:element_cmp(A, B).

combine_signature_shares(PubKey, Shares) ->
    {Indices, _} = lists:unzip(Shares),
    Set = ordsets:from_list(Indices),
    MySet = ordsets:from_list(lists:seq(0, PubKey#pubkey.players - 1)),
    true = ordsets:is_subset(Set, MySet),

    %% TODO for robustness we should verify each share before combining them

    %% pkL= Πj∈J(pkj) =Πj∈J(gxj)
    Bleh = [ erlang_pbc:element_pow(Share, lagrange(PubKey, Set, Index)) || {Index, Share} <- Shares],
    lists:foldl(fun(E, Acc) ->
                              erlang_pbc:element_mul(E, Acc)
                      end, hd(Bleh), tl(Bleh)).

%% H(M)
hash_message(PubKey, Msg) ->
    Res = erlang_pbc:element_from_hash(erlang_pbc:element_new('G1', PubKey#pubkey.verification_key), Msg),
    erlang_pbc:element_pp_init(Res),
    Res.

lagrange(PubKey, Set, Index) ->
    true = ordsets:is_set(Set),
    %true = PubKey#pubkey.k == ordsets:size(Set),
    MySet = ordsets:from_list(lists:seq(0, PubKey#pubkey.players - 1)),
    true = ordsets:is_subset(Set, MySet),

    true = ordsets:is_element(Index, Set),
    true = 0 =< Index andalso Index < PubKey#pubkey.players,

    One = erlang_pbc:element_set(erlang_pbc:element_new('Zr', PubKey#pubkey.verification_key), 1),

    Num = lists:foldl(fun(E, Acc) ->
                              erlang_pbc:element_mul(Acc, E)
                      end, One, [ 0 - JJ  - 1 || JJ <- ordsets:to_list(Set), JJ /= Index]),

    Den = lists:foldl(fun(E, Acc) ->
                              erlang_pbc:element_mul(Acc, E)
                      end, One, [ Index - JJ  || JJ <- ordsets:to_list(Set), JJ /= Index]),

    erlang_pbc:element_div(Num, Den).

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
