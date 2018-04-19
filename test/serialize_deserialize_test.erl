-module(serialize_deserialize_test).

-include_lib("eunit/include/eunit.hrl").
-include("../src/tpke_privkey.hrl").

simple_test() ->
    dealer:start_link(),
    {ok, _Group} = dealer:group(),
    {ok, PubKey, PrivateKeys} = dealer:deal(),

    SerializedPubKey = tpke_pubkey:serialize(PubKey),
    SerializedPvtKeys = [tpke_privkey:serialize(PK) || PK <- PrivateKeys],
    Foo = hd(SerializedPvtKeys),
    ?assertEqual(SerializedPubKey, Foo#privkey_serialized.pubkey),
    ok.
