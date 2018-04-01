-module(dealer_test).

-include_lib("eunit/include/eunit.hrl").

first_secret_equality_test() ->
    dealer:start_link(),
    {ok, Group} = dealer:group(),
    %% TODO make this work over the MNT224 curve
    %Group = erlang_pbc:group_new('MNT224'),
    Element = erlang_pbc:element_new('Zr', Group),
    K = 5,
    Coefficients = [erlang_pbc:element_random(Element) || _ <- lists:seq(1, K)],
    Secret = hd(Coefficients),
    FirstSecret = tpke_pubkey:f(0, Coefficients),
    ?assert(erlang_pbc:element_cmp(Secret, FirstSecret)).

zero_reconstruction_test() ->
    dealer:start_link(),
    {ok, Group} = dealer:group(),
    {ok, PubKey, _PrivateKeys} = dealer:deal(),
    Element = erlang_pbc:element_new('Zr', Group),
    K = 5,
    Coefficients = [erlang_pbc:element_random(Element) || _ <- lists:seq(1, K)],
    FirstSecret = tpke_pubkey:f(0, Coefficients),
    One = erlang_pbc:element_set(erlang_pbc:element_new('Zr', Group), 1),
    Set = ordsets:from_list(lists:seq(0, K-1)),
    Bits = [ erlang_pbc:element_mul(tpke_pubkey:lagrange(PubKey, One, Set, J), tpke_pubkey:f(J+1, Coefficients)) || J <- ordsets:to_list(Set)],
    SumBits = lists:foldl(fun erlang_pbc:element_add/2, hd(Bits), tl(Bits)),
    ?assert(erlang_pbc:element_cmp(FirstSecret, SumBits)).

dealer_test() ->
    dealer:start_link(),
    {ok, Group} = dealer:group(),
    {ok, PubKey, _PrivateKeys} = dealer:deal(),
    G1 = erlang_pbc:element_new('G1', Group),
    Message = crypto:hash(sha256, <<"my hovercraft is full of eels">>),
    CipherText = tpke_pubkey:encrypt(PubKey, G1, Message),
    ?assert(tpke_pubkey:verify_ciphertext(PubKey, G1, CipherText)).

%% threshold_signatures_test() ->
%%     dealer:start_link(),
%%     {ok, K} = dealer:adversaries(),
%%     {ok, Group} = dealer:group(),
%%     {ok, PubKey, PrivateKeys} = dealer:deal(),
%%     G1 = erlang_pbc:element_new('G1', Group),
%%     G2 = erlang_pbc:element_from_hash(erlang_pbc:element_new('G2', Group), <<"geng2">>),
%% 
%%     Message = crypto:hash(sha256, crypto:strong_rand_bytes(12)),
%%     CipherText = tpke_pubkey:encrypt(PubKey, G1, Message),
%%     ?assertNotEqual(Message, CipherText),
%% 
%%     io:format("Message is ~p~n", [Message]),
%%     io:format("Ciphertext is ~p~n", [CipherText]),
%%     ?assert(tpke_pubkey:verify_ciphertext(PubKey, G1, CipherText)),
%% 
%%     Shares = [ tpke_privkey:decrypt_share(SK, CipherText) || SK <- PrivateKeys ],
%%     ?assert(lists:all(fun(X) -> X end, [tpke_pubkey:verify_share(PubKey, G1, Share, CipherText) || Share <- Shares])),
%%     ?assertEqual(Message, tpke_pubkey:combine_shares(PubKey, CipherText, random_n(K, Shares))),
%% 
%%     %% Test threshold signatures, too
%%     MessageToSign = tpke_pubkey:hash_message(PubKey, crypto:hash(sha256, crypto:strong_rand_bytes(12))),
%%     Signatures = [ tpke_privkey:sign(PrivKey, MessageToSign) || PrivKey <- PrivateKeys],
%%     io:format("Signatures ~p~n", [[ erlang_pbc:element_to_string(S) || {_, S} <- Signatures]]),
%%     Sig = tpke_pubkey:combine_signature_shares(PubKey, random_n(K, Signatures)),
%%     ?assert(tpke_pubkey:verify_signature(PubKey, G2, Sig, MessageToSign)),
%%     ok.
%% 
%% random_n(N, List) ->
%%     lists:sublist(shuffle(List), N).
%% 
%% shuffle(List) ->
%%     [X || {_,X} <- lists:sort([{rand:uniform(), N} || N <- List])].
