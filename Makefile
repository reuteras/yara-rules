all: update-git total test
force: clean all
clean:
	rm -f total/total.yara
test:
	yara total/total.yara test
total:
	./bin/create-total.sh
update-git:
	git submodule foreach git pull origin master
yara: total test

.PHONY: clean force test total update-git yara
