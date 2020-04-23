-module(decrypt_shares_eqc).

-include_lib("eqc/include/eqc.hrl").

-export([prop_decrypt_shares/0]).

prop_decrypt_shares() ->
    ?FORALL({{Players, Threshold}, Curve, Fail}, {gen_players_threshold(), gen_curve(), gen_failure_mode()},
            begin
                {ok, Dealer} = dealer:new(Players, Threshold, Curve),
                {ok, K} = dealer:threshold(Dealer),
                {ok, _Group} = dealer:group(Dealer),
                {ok, {PubKey, PrivateKeys}} = dealer:deal(Dealer),

                {FailPubKey, FailPKeys} = case Fail of
                                              wrong_key ->
                                                  {ok, {FPk, PKs}} = dealer:deal(Dealer),
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
                {ok, VerifiedCipherText} = tpke_pubkey:verify_ciphertext(PubKey, CipherText),
                FailCipherText = tpke_pubkey:encrypt(FailPubKey, FailMessage),
                FailVerifiedCipherText = case tpke_pubkey:verify_ciphertext(PubKey, FailCipherText) of
                                             {ok, _} -> true;
                                             _ -> false
                                         end,

                GoodShares = [ tpke_privkey:decrypt_share(SK, VerifiedCipherText) || SK <- PrivateKeys ],

                FailShares = case Fail of
                                 wrong_message ->
                                     {ok, FCS} = tpke_pubkey:verify_ciphertext(PubKey, FailCipherText),
                                     [ tpke_privkey:decrypt_share(SK, FCS) || SK <- PrivateKeys ];
                                 _ ->
                                     {ok, FCS} = tpke_pubkey:verify_ciphertext(FailPubKey, FailCipherText),
                                     [ tpke_privkey:decrypt_share(SK, FCS) || SK <- FailPKeys ]
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

                VerifiedShares = lists:all(fun(X) -> X end, [tpke_pubkey:verify_share(PubKey, Share, VerifiedCipherText) || Share <- Shares]),
                ValidShares = lists:usort([ Share || Share <- Shares, tpke_pubkey:verify_share(PubKey, Share, VerifiedCipherText) ]),
                VerifiedCombinedShares = tpke_pubkey:combine_shares(PubKey, VerifiedCipherText, Shares),

                ?WHENFAIL(begin
                              io:format("K ~p~n", [K]),
                              io:format("Shares ~p~n", [Shares]),
                              io:format("FailShares ~p~n", [FailShares])
                          end,
                          conjunction([
                                       {dont_verify_wrong_ciphertext, eqc:equals((Fail /= wrong_key), FailVerifiedCipherText)},
                                       {verify_share, eqc:equals((Fail == none orelse Fail == duplicate_shares),  VerifiedShares)},
                                       {verify_combine_shares, eqc:equals((Fail == none),  Message == VerifiedCombinedShares)},
                                       {all_shares_validate, eqc:equals((Fail == none), length(Shares) == length(ValidShares))}
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
