-module(dealer_test).

-include_lib("eunit/include/eunit.hrl").

first_secret_equality_test() ->
    {ok, Dealer} = dealer:new(),
    {ok, Group} = dealer:group(Dealer),
    %% TODO make this work over the MNT224 curve
    %Group = erlang_pbc:group_new('MNT224'),
    Element = erlang_pbc:element_new('Zr', Group),
    K = 5,
    Coefficients = [erlang_pbc:element_random(Element) || _ <- lists:seq(1, K)],
    Secret = hd(Coefficients),
    FirstSecret = dealer:share_secret(0, Coefficients),
    ?assert(erlang_pbc:element_cmp(Secret, FirstSecret)).

zero_reconstruction_test() ->
    {ok, Dealer} = dealer:new(),
    {ok, Group} = dealer:group(Dealer),
    {ok, {PubKey, _PrivateKeys}} = dealer:deal(Dealer),
    Element = erlang_pbc:element_new('Zr', Group),
    K = 5,
    Coefficients = [erlang_pbc:element_random(Element) || _ <- lists:seq(1, K)],
    FirstSecret = dealer:share_secret(0, Coefficients),
    Set = ordsets:from_list(lists:seq(0, K-1)),
    Bits = [ erlang_pbc:element_mul(tpke_pubkey:lagrange(PubKey, Set, J), dealer:share_secret(J+1, Coefficients)) || J <- ordsets:to_list(Set)],
    SumBits = lists:foldl(fun erlang_pbc:element_add/2, hd(Bits), tl(Bits)),
    ?assert(erlang_pbc:element_cmp(FirstSecret, SumBits)).
