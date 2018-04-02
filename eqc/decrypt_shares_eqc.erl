-module(decrypt_shares_eqc).

-include_lib("eqc/include/eqc.hrl").

-export([prop_decrypt_shares/0]).

prop_decrypt_shares() ->
    ?FORALL({{Players, Threshold}, Curve}, {gen_players_threshold(), gen_curve()},
            begin
                {ok, _} = dealer:start_link(Players, Threshold, Curve),
                {ok, K} = dealer:adversaries(),
                {ok, _Group} = dealer:group(),
                {ok, G1, G2, PubKey, PrivateKeys} = dealer:deal(),

                Message = crypto:hash(sha256, crypto:strong_rand_bytes(12)),
                CipherText = tpke_pubkey:encrypt(PubKey, G1, Message),
                Shares = [ tpke_privkey:decrypt_share(SK, CipherText) || SK <- PrivateKeys ],
                gen_server:stop(dealer),

                ?WHENFAIL(begin
                              io:format("Shares ~p~n", [Shares])
                          end,
                          conjunction([
                                       {verify_ciphertext, eqc:equals(true, tpke_pubkey:verify_ciphertext(PubKey, G1, CipherText))},
                                       {verify_share, eqc:equals(true, lists:all(fun(X) -> X end, [tpke_pubkey:verify_share(PubKey, G2, Share, CipherText) || Share <- Shares]))},
                                       {verify_combine_shares, eqc:equals(Message, tpke_pubkey:combine_shares(PubKey, CipherText, dealer:random_n(K, Shares)))}
                                      ]))
            end).

gen_players_threshold() ->
    ?SUCHTHAT({Players, Threshold},
              ?LET({X, Y},
                   ?SUCHTHAT({A, B}, {int(), int()}, A > 0 andalso B >= 0 andalso A > B),
                   {X*3, X - Y}),
              Players > 3*Threshold+1 andalso Threshold > 1).

gen_curve() ->
    elements(['SS512']).
