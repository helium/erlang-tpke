.PHONY: compile rel test typecheck

REBAR=./rebar3

compile:
	$(REBAR) compile

clean:
	$(REBAR) clean

test:
	$(REBAR) as test do eunit,ct

typecheck:
	$(REBAR) dialyzer

ci:
ifdef NIGHTLY
	$(REBAR) as test do eunit,ct,eqc -t 600,cover
else
	$(REBAR) do dialyzer && $(REBAR) as test do eunit,ct,cover
endif
	$(REBAR) covertool generate
	codecov --required -f _build/test/covertool/erlang_tpke.covertool.xml
