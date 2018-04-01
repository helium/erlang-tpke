-module(dealer_test).

-include_lib("eunit/include/eunit.hrl").

first_secret_equality_test() ->
    Group = erlang_pbc:group_new('SS512'),
    Element = erlang_pbc:element_new('Zr', Group),
    %% change later
    Players = 10,
    K = 5,
    Coefficients = [erlang_pbc:element_random(Element) || _ <- lists:seq(1, K)],
    Secret = hd(Coefficients),
    FirstSecret = tpke_pubkey:f(0, Coefficients),
    SKs = [ tpke_pubkey:f(N, Coefficients) || N <- lists:seq(1, Players)],
    ?assert(erlang_pbc:element_cmp(Secret, FirstSecret)),

    G1 = erlang_pbc:element_new('G1', Group),
    Hash = erlang_pbc:element_from_hash(G1, <<"geng1">>),
    io:format("Hash: ~p~n", [erlang_pbc:element_to_string(Hash)]),

    VK = erlang_pbc:element_pow(Hash, Secret),
    io:format("VK: ~p~n", [erlang_pbc:element_to_string(VK)]),
    VKs = [ erlang_pbc:element_pow(Hash, XX) || XX <- SKs],

    PublicKey = tpke_pubkey:init(Players, K, VK, VKs),
    PrivateKeys = [tpke_privkey:init(PublicKey, SK, I) || {I, SK} <- enumerate(SKs)],

    One = erlang_pbc:element_set(erlang_pbc:element_new('Zr', Group), 1),

    Set = ordsets:from_list(lists:seq(0, K-1)),
    Bits = [ erlang_pbc:element_mul(tpke_pubkey:lagrange(PublicKey, One, Set, J), tpke_pubkey:f(J+1, Coefficients)) || J <- ordsets:to_list(Set)],
    SumBits = lists:foldl(fun erlang_pbc:element_add/2, hd(Bits), tl(Bits)),
    io:format("Sum: ~p~n", [erlang_pbc:element_to_string(SumBits)]),
    io:format("FirstSecret: ~p~n", [erlang_pbc:element_to_string(FirstSecret)]),
    ?assert(erlang_pbc:element_cmp(FirstSecret, SumBits)),

    Message = crypto:hash(sha256, <<"my hovercraft is full of eels">>),
    CipherText = tpke_pubkey:encrypt(PublicKey, G1, Message),

    io:format("Ciphertext is ~p~n", [CipherText]),
    ?assert(tpke_pubkey:verify_ciphertext(PublicKey, G1, CipherText)),

    Shares = [ tpke_privkey:decrypt_share(SK, CipherText) || SK <- PrivateKeys ],
    ?assert(lists:all(fun(X) -> X end, [tpke_pubkey:verify_share(PublicKey, G1, Share, CipherText) || Share <- Shares])),
    ?assertEqual(Message, tpke_pubkey:combine_shares(PublicKey, CipherText, random_n(K, Shares))),
    ok.

enumerate(List) ->
    lists:zip(lists:seq(0, length(List) - 1), List).

random_n(N, List) ->
    lists:sublist(shuffle(List), N).

shuffle(List) ->
    [X || {_,X} <- lists:sort([{random:uniform(), N} || N <- List])].
