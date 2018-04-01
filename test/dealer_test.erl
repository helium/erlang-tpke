-module(dealer_test).

-include_lib("eunit/include/eunit.hrl").

first_secret_equality_test() ->
    dealer:start_link(),
    {ok, Group} = dealer:group(),
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
