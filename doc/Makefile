.PHONY: clean

# pdflatex twice for table of contents

certificate-tool.pdf: certificate-tool.tex
	pdflatex certificate-tool.tex
	pdflatex certificate-tool.tex

clean:
	rm -f *.aux *.log *.pdf *.synctex.gz *.toc
