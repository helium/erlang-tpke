-module(dealer).

-export([new/0,
         new/3,
         share_secret/2,
         threshold/1,
         group/1,
         deal/1,
         random_n/2,
         shuffle/1]).

-record(dealer, {
          pubkey :: undefined | tpke_pubkey:pubkey(),
          privkeys :: undefined | [tpke_privkey:privkey(), ...],
          group :: erlang_pbc:group(),
          players :: non_neg_integer(),
          curve :: tpke_pubkey:curve(),
          threshold :: non_neg_integer()
         }).

new() ->
    new(10, 5, 'SS512').

new(Players, Threshold, Curve) ->
    {ok, #dealer{players=Players, curve=Curve, threshold=Threshold, group=erlang_pbc:group_new(Curve)}}.

deal(_Dealer=#dealer{group=Group, threshold=Threshold, players=Players, curve=Curve}) ->
    Element = erlang_pbc:element_new('Zr', Group),
    Coefficients = [erlang_pbc:element_random(Element) || _ <- lists:seq(1, Threshold)],
    MasterSecret = hd(Coefficients),
    MasterSecretKeyShares = [share_secret(N, Coefficients) || N <- lists:seq(1, Players)],
    G1 = erlang_pbc:element_from_hash(erlang_pbc:element_new('G1', Group), crypto:strong_rand_bytes(32)),
    G2 = case erlang_pbc:pairing_is_symmetric(Group) of
             true -> G1;
             false -> erlang_pbc:element_from_hash(erlang_pbc:element_new('G2', Group), crypto:strong_rand_bytes(32))
         end,
    %% pre-process them for faster exponents later
    erlang_pbc:element_pp_init(G1),
    erlang_pbc:element_pp_init(G2),
    VerificationKey = erlang_pbc:element_pow(G2, MasterSecret),
    VerificationKeys = [erlang_pbc:element_pow(G2, SecretKeyShare) || SecretKeyShare <- MasterSecretKeyShares],
    PublicKey = tpke_pubkey:init(Players, Threshold, G1, G2, VerificationKey, VerificationKeys, Curve),
    PrivateKeys = [tpke_privkey:init(PublicKey, SKShare, Index) || {Index, SKShare} <- enumerate(MasterSecretKeyShares)],
    {ok, {PublicKey, PrivateKeys}}.

group(Dealer) ->
    {ok, Dealer#dealer.group}.

threshold(Dealer) ->
    {ok, Dealer#dealer.threshold}.

share_secret(Xval, Coefficients) ->
    Zero = erlang_pbc:element_set(hd(Coefficients), 0),
    One = erlang_pbc:element_set(hd(Coefficients), 1),
    share_secret(Xval, Coefficients, Zero, One).

share_secret(_Xval, [] = _Coefficients, NewY, _InitX) -> NewY;
share_secret(Xval, [Head | Tail] = _Coefficients, Y, X) ->
    NewY = erlang_pbc:element_add(Y, erlang_pbc:element_mul(Head, X)),
    NewX = erlang_pbc:element_mul(X, Xval),
    share_secret(Xval, Tail, NewY, NewX).

%% helper functions

enumerate(List) ->
    lists:zip(lists:seq(0, length(List) - 1), List).

random_n(N, List) ->
    lists:sublist(shuffle(List), N).

shuffle(List) ->
    [X || {_,X} <- lists:sort([{rand:uniform(), N} || N <- List])].
