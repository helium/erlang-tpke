-module(dealer).

-behavior(gen_server).

-export([start_link/0, start_link/3, adversaries/0, group/0, deal/0]).
-export([init/1, handle_call/3, handle_cast/2]).

-record(state, {
          pubkey :: tpke_pubkey:pubkey(),
          privkeys :: [tpke_privkey:privkeys(), ...],
          group, %% Group type?
          players :: non_neg_integer(),
          adversaries :: non_neg_integer()
         }).

start_link() ->
    start_link(10, 5, 'SS512').

start_link(Players, Adversaries, Curve) ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [Players, Adversaries, Curve], []).

init([Players, Adversaries, Curve]) ->
    Group = erlang_pbc:group_new(Curve),
    {ok, #state{players=Players, adversaries=Adversaries, group=Group}}.

deal() ->
    gen_server:call(?MODULE, deal).

group() ->
    gen_server:call(?MODULE, group).

adversaries() ->
    gen_server:call(?MODULE, adversaries).

handle_call(adversaries, _From, #state{adversaries=Adversaries}=State) -> {reply, {ok, Adversaries}, State};
handle_call(group, _From, #state{group=Group}=State) -> {reply, {ok, Group}, State};
handle_call(deal, _From, #state{group=Group, adversaries=Adversaries, players=Players}=State) ->
    Element = erlang_pbc:element_new('Zr', Group),
    Coefficients = [erlang_pbc:element_random(Element) || _ <- lists:seq(1, Adversaries)],
    MasterSecret = hd(Coefficients),
    MasterSecretKeyShares = [tpke_pubkey:f(N, Coefficients) || N <- lists:seq(1, Players)],
    G1 = erlang_pbc:element_from_hash(erlang_pbc:element_new('G1', Group), <<"geng1">>),
    case erlang_pbc:pairing_is_symmetric(Group) of
        true ->
            G2 = G1;
        false ->
            G2 = erlang_pbc:element_from_hash(erlang_pbc:element_new('G2', Group), <<"geng2">>)
    end,
    %% pre-process them for faster exponents later
    erlang_pbc:element_pp_init(G1),
    erlang_pbc:element_pp_init(G2),
    VerificationKey = erlang_pbc:element_pow(G2, MasterSecret),
    VerificationKeys = [erlang_pbc:element_pow(G2, SecretKeyShare) || SecretKeyShare <- MasterSecretKeyShares],
    PublicKey = tpke_pubkey:init(Players, Adversaries, VerificationKey, VerificationKeys),
    PrivateKeys = [tpke_privkey:init(PublicKey, SKShare, Index) || {Index, SKShare} <- enumerate(MasterSecretKeyShares)],
    {reply, {ok, G1, G2, PublicKey, PrivateKeys}, State#state{pubkey=PublicKey, privkeys=PrivateKeys}}.

handle_cast(_Msg, State) ->
    {noreply, State}.

enumerate(List) ->
    lists:zip(lists:seq(0, length(List) - 1), List).
