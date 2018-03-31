-module(dealer_test).

-include_lib("eunit/include/eunit.hrl").

first_secret_equality_test() ->
	Group = erlang_pbc:group_new('SS512'),
	Element = erlang_pbc:element_new('Zr', Group),
	%% change later
	Players = 10,
	K = 5,
	Coefficients = [erlang_pbc:element_random(Element) || _ <- lists:seq(1, K)],
	%% io:format("Coefficients: ~p~n", [Coefficients]),
	Secret = hd(Coefficients),
	%% io:format("Secret: ~p~n", [erlang_pbc:element_to_string(Secret)]),
	FirstSecret = tpke_pubkey:f(0, Coefficients),
	SKs = [ tpke_pubkey:f(N, Coefficients) || N <- lists:seq(1, Players)],
	%% io:format("Foo: ~p", [erlang_pbc:element_to_string(Foo)]),
	?assert(erlang_pbc:element_cmp(Secret, FirstSecret)),

	G1 = erlang_pbc:element_new('G1', Group),
	Hash = erlang_pbc:element_from_hash(G1, <<"geng1">>),
	io:format("Hash: ~p~n", [erlang_pbc:element_to_string(Hash)]),

	VK = erlang_pbc:element_pow(Hash, Secret),
	io:format("VK: ~p~n", [erlang_pbc:element_to_string(VK)]),
	VKs = [ erlang_pbc:element_pow(Hash, XX) || XX <- SKs],

	PublicKey = tpke_pubkey:init(Players, K, VK, VKs),
	PrivateKeys = [tpke_privkey:init(PublicKey, SK, I) || {I, SK} <- enumerate(SKs)],

	%% TODO this is a hack
	One = erlang_pbc:element_set(hd(Coefficients), 1),

	Set = ordsets:from_list(lists:seq(0, K-1)),
	Bits = [ erlang_pbc:element_mul(tpke_pubkey:lagrange(PublicKey, One, Set, J), tpke_pubkey:f(J+1, Coefficients)) || J <- ordsets:to_list(Set)],
	SumBits = lists:foldl(fun erlang_pbc:element_add/2, hd(Bits), tl(Bits)),
	io:format("Sum: ~p~n", [erlang_pbc:element_to_string(SumBits)]),
	io:format("FirstSecret: ~p~n", [erlang_pbc:element_to_string(FirstSecret)]),
	?assert(erlang_pbc:element_cmp(FirstSecret, SumBits)),
	ok.

enumerate(List) ->
		lists:zip(lists:seq(0, length(List) - 1), List).
