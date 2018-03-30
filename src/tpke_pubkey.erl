-module(tpke_pubkey).

-record(pubkey, {
          players,
          k,
          verification_key,
          verification_keys
         }).

-define(Group, pbc:group_new('SS512')).
-define(G1, pbc:element_from_hash('geng1', ?Group)).
-define(G2, ?G1).

-type pubkey() :: #pubkey{}.

-export_type([pubkey/0]).

hash_h(SerialzedGroup, X) ->
    pbc:element_from_hash(SerialzedGroup + X, ?G2).

encrypt(#{verification_key=VK}PubKey, M) ->
    Random = pbc:element_random('ZR')
    U = pbc:element_pow(?G1, Random),
    Serialized = pbc:serialize(pbc:element_pow(VK, Random)),
    V = util:xor(M, crypto:hash(sha256, Serialized)),
    W = pbc:element_pow(hash_h(U, V), Random),
    {U, V, W}.
