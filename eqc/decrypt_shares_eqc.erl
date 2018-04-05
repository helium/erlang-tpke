-module(decrypt_shares_eqc).

-include_lib("eqc/include/eqc.hrl").

-export([prop_decrypt_shares/0]).

prop_decrypt_shares() ->
    ?FORALL({{Players, Threshold}, Curve, Fail}, {gen_players_threshold(), gen_curve(), gen_failure_mode()},
            begin
                {ok, _} = dealer:start_link(Players, Threshold, Curve),
                {ok, K} = dealer:adversaries(),
                {ok, _Group} = dealer:group(),
                {ok, PubKey, PrivateKeys} = dealer:deal(),

                {FailPubKey, FailPKeys} = case Fail of
                                              wrong_key ->
                                                  {ok, FPk, PKs} = dealer:deal(),
                                                  {FPk, PKs};
                                              _ ->
                                                  {PubKey, PrivateKeys}
                                          end,

                Message = crypto:hash(sha256, crypto:strong_rand_bytes(12)),
                FailMessage = case Fail of
                                  wrong_message ->
                                      crypto:hash(sha256, crypto:strong_rand_bytes(12));
                                  _ ->
                                      Message
                              end,

                CipherText = tpke_pubkey:encrypt(PubKey, Message),
                FailCipherText = tpke_pubkey:encrypt(FailPubKey, FailMessage),

                GoodShares = [ tpke_privkey:decrypt_share(SK, CipherText) || SK <- PrivateKeys ],

                FailShares = case Fail of
                                 wrong_message ->
                                     [ tpke_privkey:decrypt_share(SK, FailCipherText) || SK <- FailPKeys ];
                                 _ ->
                                     [ tpke_privkey:decrypt_share(SK, CipherText) || SK <- FailPKeys ]
                             end,

                Shares = case Fail of
                             duplicate_shares ->
                                 %% provide K shares, but with a duplicate
                                 [S|Ss] = dealer:random_n(K, GoodShares),
                                 [S, S | tl(Ss)];
                             none -> dealer:random_n(K, GoodShares);
                             _ ->
                                 %% either wrong_message or wrong_key
                                 dealer:random_n(K-1, GoodShares) ++ dealer:random_n(1, FailShares)
                         end,


                gen_server:stop(dealer),

                VerifiedCipherText = tpke_pubkey:verify_ciphertext(PubKey, CipherText),
                FailVerifiedCipherText = tpke_pubkey:verify_ciphertext(PubKey, FailCipherText),
                VerifiedShares = lists:all(fun(X) -> X end, [tpke_pubkey:verify_share(PubKey, Share, CipherText) || Share <- Shares]),
                VerifiedCombinedShares = tpke_pubkey:combine_shares(PubKey, CipherText, Shares),

                ?WHENFAIL(begin
                              io:format("Shares ~p~n", [Shares])
                          end,
                          conjunction([
                                       {verify_ciphertext, VerifiedCipherText},
                                       {dont_verify_wrong_ciphertext, eqc:equals((Fail /= wrong_key), FailVerifiedCipherText)},
                                       {verify_share, eqc:equals((Fail == none orelse Fail == duplicate_shares),  VerifiedShares)},
                                       {verify_combine_shares, eqc:equals((Fail == none),  Message == VerifiedCombinedShares)}
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
    elements([none, wrong_key, wrong_message, duplicate_shares]).
