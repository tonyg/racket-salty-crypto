INPUTS=oneway-patterns.txt interactive-patterns.txt deferred-patterns.txt

all: patterns.rktd patterns.ts

patterns.rktd: $(INPUTS) pattern-compiler.rkt
	cat $(INPUTS) | OUTPUT=racket racket pattern-compiler.rkt | tee $@.tmp
	sort < $@.tmp > $@
	rm -f $@.tmp

patterns.ts: $(INPUTS) pattern-compiler.rkt
	cat $(INPUTS) | OUTPUT=typescript racket pattern-compiler.rkt | tee $@.tmp
	sort < $@.tmp > $@
	rm -f $@.tmp

clean:
	rm -f patterns.rktd patterns.ts
	rm -f patterns.rktd.tmp patterns.ts.tmp
