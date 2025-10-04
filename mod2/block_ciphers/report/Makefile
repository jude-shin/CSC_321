SHELL = /bin/sh
MAIN = labreport
TEXFILES = labreport.tex 
PDFLATEX = pdflatex
IMGS = ./plts/aes.png ./plts/rsa.png

.PHONY: pdf

pdf: $(MAIN).pdf $(IMGS)

%.pdf: %.tex $(TEXFILES)
	$(PDFLATEX) $<

clean:
	rm -f $(MAIN).pdf $(MAIN).log $(MAIN).aux

