.PHONY: clean

# pdflatex twice for table of contents

certificate-tool.pdf: certificate-tool.tex
	pdflatex certificate-tool.tex
	pdflatex certificate-tool.tex

clean:
	rm -f $(shell ls certificate-tool.* | sed "s/certificate-tool\.tex//")
