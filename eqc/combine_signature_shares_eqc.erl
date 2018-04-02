-module(combine_signature_shares_eqc).

-include_lib("eqc/include/eqc.hrl").

-export([prop_combine_signature_shares/0]).

prop_combine_signature_shares() ->
    ?FORALL({{Players, Threshold}, Curve, Fail}, {gen_players_threshold(), gen_curve(), bool()},
            begin
                {ok, _} = dealer:start_link(Players, Threshold, Curve),
                {ok, K} = dealer:adversaries(),
                {ok, _Group} = dealer:group(),
                {ok, _G1, G2, PubKey, PrivateKeys} = dealer:deal(),
                {ok, _G1_2, _G2, _PubKey, PrivateKeys2} = dealer:deal(),
                MessageToSign = tpke_pubkey:hash_message(PubKey, crypto:hash(sha256, crypto:strong_rand_bytes(12))),
                MessageToSign2 = tpke_pubkey:hash_message(PubKey, crypto:hash(sha256, crypto:strong_rand_bytes(12))),
                Signatures = [ tpke_privkey:sign(PrivKey, MessageToSign) || PrivKey <- PrivateKeys],
                Signatures2 = [ tpke_privkey:sign(PrivKey, MessageToSign2) || PrivKey <- PrivateKeys2],
                Shares = case Fail of
                             true -> dealer:random_n(K-1, Signatures) ++ dealer:random_n(1, Signatures2);
                             false -> dealer:random_n(K, Signatures)
                         end,
                Sig = tpke_pubkey:combine_signature_shares(PubKey, Shares),
                gen_server:stop(dealer),
                SharesVerified = lists:all(fun(X) -> X end, [tpke_pubkey:verify_signature_share(PubKey, G2, Share, MessageToSign) || Share <- Signatures]),
                SignatureVerified = tpke_pubkey:verify_signature(PubKey, G2, Sig, MessageToSign),
                ?WHENFAIL(begin
                              io:format("Signatures ~p~n", [[ erlang_pbc:element_to_string(S) || {_, S} <- Signatures]]),
                              io:format("Shares ~p~n", [[ erlang_pbc:element_to_string(S) || {_, S} <- Shares]])
                          end,
                          conjunction([
                                       {verify_signature_share, eqc:equals(true, Fail /= SharesVerified)},
                                       {verify_combine_signature_shares, eqc:equals(true, Fail /= SignatureVerified)}
                                      ]))
            end).

gen_players_threshold() ->
    ?SUCHTHAT({Players, Threshold},
              ?LET({X, Y},
                   ?SUCHTHAT({A, B}, {int(), int()}, A > 0 andalso B >= 0 andalso A > B),
                   {X*3, X - Y}),
              Players > 3*Threshold+1).

gen_curve() ->
    %elements(['SS512', 'MNT224']).
    elements(['SS512']).
