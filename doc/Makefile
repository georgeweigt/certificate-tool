.PHONY: default clean

%.pdf: %.tex
	pdflatex $<
	pdflatex $<

default:
	make certificate-tool.pdf

clean:
	rm -f *.aux *.log *.synctex.gz *.toc
