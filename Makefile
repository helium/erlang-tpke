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
	$(REBAR) do dialyzer && $(REBAR) as test do eunit,ct,cover
	$(REBAR) covertool generate
	codecov --required -f _build/test/covertool/erlang_tpke.covertool.xml

ci-nightly:
	$(REBAR) as test do eunit,ct,eqc -t 1800,cover
	cp _build/eqc/cover/eqc.coverdata _build/test/cover/
	$(REBAR) covertool generate
	codecov --required -f _build/test/covertool/erlang_tpke.covertool.xml
