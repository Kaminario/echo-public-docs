# Makefile for generating readme.pdf from README.md

# The input and output files
TEMP = temp.md
INPUT = README.md
OUTPUT = readme.pdf

# The Pandoc command
PANDOC = pandoc

# The Pandoc options
PANDOC_OPTS = --from=markdown --to=pdf

# Declare phony targets
.PHONY: pdf clean $(OUTPUT)

# The default target
pdf: $(OUTPUT)

# Rule for generating the PDF
$(OUTPUT): $(INPUT)
	@echo "---" > $(TEMP)
	@echo "header-includes:" >> $(TEMP)
	@echo "  - \usepackage[margin=1in]{geometry}" >> $(TEMP)
	@echo "---" >> $(TEMP)
	@cat $(INPUT) >> $(TEMP)
	$(PANDOC) $(PANDOC_OPTS) $(TEMP) -o $(OUTPUT)
	@rm -f $(TEMP)

# Clean up generated files
clean:
	rm -f $(OUTPUT)
