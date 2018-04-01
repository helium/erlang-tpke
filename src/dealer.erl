-module(dealer).

-behavior(gen_server).

-export([start_link/0, group/0, deal/0]).
-export([init/1, handle_call/3, handle_cast/2]).

-record(state, {
          pubkey :: tpke_pubkey:pubkey(),
          privkeys :: [tpke_privkey:privkeys(), ...],
          group, %% Group type?
          players :: non_neg_integer(),
          adversaries :: non_neg_integer()
         }).

start_link() ->
    start_link(10, 5).

start_link(Players, Adversaries) ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [Players, Adversaries], []).

init([Players, Adversaries]) ->
    Group = erlang_pbc:group_new('SS512'),
    {ok, #state{players=Players, adversaries=Adversaries, group=Group}}.

deal() ->
    gen_server:call(?MODULE, deal).

group() ->
    gen_server:call(?MODULE, group).

handle_call(group, _From, #state{group=Group}=State) -> {reply, {ok, Group}, State};
handle_call(deal, _From, #state{group=Group, adversaries=Adversaries, players=Players}=State) ->
    Element = erlang_pbc:element_new('Zr', Group),
    Coefficients = [erlang_pbc:element_random(Element) || _ <- lists:seq(1, Adversaries)],
    MasterSecret = hd(Coefficients),
    MasterSecretKeyShares = [tpke_pubkey:f(N, Coefficients) || N <- lists:seq(1, Players)],
    G1 = erlang_pbc:element_new('G1', Group),
    Hash = erlang_pbc:element_from_hash(G1, <<"geng1">>),
    VerificationKey = erlang_pbc:element_pow(Hash, MasterSecret),
    VerificationKeys = [erlang_pbc:element_pow(Hash, SecretKeyShare) || SecretKeyShare <- MasterSecretKeyShares],
    PublicKey = tpke_pubkey:init(Players, Adversaries, VerificationKey, VerificationKeys),
    PrivateKeys = [tpke_privkey:init(PublicKey, SKShare, Index) || {Index, SKShare} <- enumerate(MasterSecretKeyShares)],
    {reply, {ok, PublicKey, PrivateKeys}, State#state{pubkey=PublicKey, privkeys=PrivateKeys}}.

handle_cast(_Msg, State) ->
    {noreply, State}.

enumerate(List) ->
    lists:zip(lists:seq(0, length(List) - 1), List).
