all: total/total.yara test
force: clean all
clean:
	rm -f total/total.yara
test: total/total.yara
	yara total/total.yara test
total/total.yara:
	./bin/create-total.sh

.PHONY: clean force total
