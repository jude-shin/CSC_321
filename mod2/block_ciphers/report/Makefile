SHELL = /bin/sh

MAIN  = labreport

TEXFILES = labreport.tex 

PDFLATEX   = pdflatex

.PHONY: all ps pdf pre pspre clean

pdf: $(MAIN).pdf

%.pdf: %.tex $(TEXFILES)
	$(PDFLATEX) $<

clean:
	rm -f $(MAIN).pdf $(MAIN).log $(MAIN).aux

