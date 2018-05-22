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
    FirstSecret = dealer:share_secret(0, Coefficients),
    ?assert(erlang_pbc:element_cmp(Secret, FirstSecret)),
    gen_server:stop(dealer).

zero_reconstruction_test() ->
    dealer:start_link(),
    {ok, Group} = dealer:group(),
    {ok, PubKey, _PrivateKeys} = dealer:deal(),
    Element = erlang_pbc:element_new('Zr', Group),
    K = 5,
    Coefficients = [erlang_pbc:element_random(Element) || _ <- lists:seq(1, K)],
    FirstSecret = dealer:share_secret(0, Coefficients),
    Set = ordsets:from_list(lists:seq(0, K-1)),
    Bits = [ erlang_pbc:element_mul(tpke_pubkey:lagrange(PubKey, Set, J), dealer:share_secret(J+1, Coefficients)) || J <- ordsets:to_list(Set)],
    SumBits = lists:foldl(fun erlang_pbc:element_add/2, hd(Bits), tl(Bits)),
    ?assert(erlang_pbc:element_cmp(FirstSecret, SumBits)),
    gen_server:stop(dealer).

threshold_decrypt_test_() ->
    Fun = fun(Players, Threshold, Curve) ->
                  fun() ->
                          dealer:start_link(Players, Threshold, Curve),
                          {ok, _Group} = dealer:group(),
                          {ok, PubKey, PrivateKeys} = dealer:deal(),
                          {ok, K} = dealer:adversaries(),
                          Message = crypto:hash(sha256, <<"my hovercraft is full of eels">>),
                          CipherText = tpke_pubkey:encrypt(PubKey, Message),
                          %% verify ciphertext
                          ?assert(tpke_pubkey:verify_ciphertext(PubKey, CipherText)),
                          Shares = [ tpke_privkey:decrypt_share(SK, CipherText) || SK <- PrivateKeys ],
                          %% verify share
                          ?assert(lists:all(fun(X) -> X end, [tpke_pubkey:verify_share(PubKey, Share, CipherText) || Share <- Shares])),
                          %% verify combine_shares
                          ?assertEqual(Message, tpke_pubkey:combine_shares(PubKey, CipherText, dealer:random_n(K, Shares)))
                  end
    end,
    {foreach, fun() -> ok end, fun(_) -> gen_server:stop(dealer) end, [
     {"Players: 10, Threshold: 5, Curve: SS512", Fun(10, 5, 'SS512')},
     %{"Players: 10, Threshold: 5, Curve: MNT224", Fun(10, 5, 'MNT224')},
     %{"Players: 10, Threshold: 5, Curve: MNT159", Fun(10, 5, 'MNT159')},
     {"Players: 100, Threshold: 30, Curve: SS512", Fun(100, 30, 'SS512')}
     %{"Players: 100, Threshold: 30, Curve: MNT224", Fun(100, 30, 'MNT224')},
     %{"Players: 100, Threshold: 30, Curve: MNT159", Fun(100, 30, 'MNT159')}
    ]}.

threshold_signatures_test_() ->
    Fun = fun(Players, Threshold, Curve) ->
                  fun() ->
                          dealer:start_link(Players, Threshold, Curve),
                          %dealer:start_link(10, 5, 'SS512'),
                          {ok, K} = dealer:adversaries(),
                          {ok, _Group} = dealer:group(),
                          {ok, PubKey, PrivateKeys} = dealer:deal(),

                          %% Test threshold signatures, too
                          Msg = crypto:hash(sha256, crypto:strong_rand_bytes(12)),
                          MessageToSign = tpke_pubkey:hash_message(PubKey, Msg),
                          CipherText = tpke_pubkey:encrypt(PubKey, Msg),
                          Signatures = [ tpke_privkey:sign(PrivKey, MessageToSign) || PrivKey <- PrivateKeys],
                          io:format("Signatures ~p~n", [[ erlang_pbc:element_to_string(S) || {_, S} <- Signatures]]),
                          ?assert(lists:all(fun(X) -> X end, [tpke_pubkey:verify_signature_share(PubKey, Share, MessageToSign) || Share <- Signatures])),
                          Sig = tpke_pubkey:combine_signature_shares(PubKey, dealer:random_n(K, Signatures), CipherText),
                          ?assert(tpke_pubkey:verify_signature(PubKey, Sig, MessageToSign)),
                          ok
                  end
          end,
    {foreach, fun() -> ok end, fun(_) -> gen_server:stop(dealer) end, [
     {"Players: 10, Threshold: 5, Curve: SS512", Fun(10, 5, 'SS512')},
     {"Players: 10, Threshold: 5, Curve: MNT224", Fun(10, 5, 'MNT224')},
     {"Players: 10, Threshold: 5, Curve: MNT159", Fun(10, 5, 'MNT159')},
     {"Players: 100, Threshold: 30, Curve: SS512", Fun(100, 30, 'SS512')},
     {"Players: 100, Threshold: 30, Curve: MNT224", Fun(100, 30, 'MNT224')},
     {"Players: 100, Threshold: 30, Curve: MNT159", Fun(100, 30, 'MNT159')}
    ]}.
