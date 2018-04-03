-module(decrypt_shares_eqc).

-include_lib("eqc/include/eqc.hrl").

-export([prop_decrypt_shares/0]).

prop_decrypt_shares() ->
    ?FORALL({{Players, Threshold}, Curve, Fail}, {gen_players_threshold(), gen_curve(), gen_failure_mode()},
            begin
                {ok, _} = dealer:start_link(Players, Threshold, Curve),
                {ok, K} = dealer:adversaries(),
                {ok, _Group} = dealer:group(),
                {ok, G1, G2, PubKey, PrivateKeys} = dealer:deal(),

                FailPKeys = case Fail of
                    wrong_key ->
                        {ok, _, _, _, PKs} = dealer:deal(),
                        PKs;
                    _ ->
                        PrivateKeys
                end,

                Message = crypto:hash(sha256, crypto:strong_rand_bytes(12)),
                FailMessage = case Fail of
                                  wrong_message ->
                                      crypto:hash(sha256, crypto:strong_rand_bytes(12));
                                  _ ->
                                      Message
                              end,

                CipherText = tpke_pubkey:encrypt(PubKey, G1, Message),
                FailCipherText = tpke_pubkey:encrypt(PubKey, G1, FailMessage),

                Shares = [ tpke_privkey:decrypt_share(SK, CipherText) || SK <- PrivateKeys ],
                FailShares = [ tpke_privkey:decrypt_share(SK, FailCipherText) || SK <- FailPKeys ],

                gen_server:stop(dealer),

                VerifiedCipherText = tpke_pubkey:verify_ciphertext(PubKey, G1, CipherText),
                VerifiedShares = lists:all(fun(X) -> X end, [tpke_pubkey:verify_share(PubKey, G2, Share, CipherText) || Share <- Shares]),
                VerifiedCombinedShares = tpke_pubkey:combine_shares(PubKey, CipherText, dealer:random_n(K, Shares)),

                ?WHENFAIL(begin
                              io:format("Shares ~p~n", [Shares])
                          end,
                          conjunction([
                                       {verify_ciphertext, eqc:equals(true, (Fail /= wrong_message andalso Fail /= wrong_key) /= VerifiedCipherText)},
                                       {verify_share, eqc:equals(true, (Fail /= wrong_message andalso Fail /= wrong_key) /= VerifiedShares)},
                                       {verify_combine_shares, eqc:equals(Message, (Fail /= wrong_message andalso Fail /= wrong_key) /= VerifiedCombinedShares)}
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

gen_failure_mode() ->
    elements([wrong_message, wrong_key]).
