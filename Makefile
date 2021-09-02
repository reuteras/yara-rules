all: update-git update-capa2yara total test
force: clean all
clean:
	rm -f total/total.yara
init:
	git submodule update --init
test:
	yara total/total.yara test
total:
	./bin/create-total.sh
update-git:
	git pull
	git submodule foreach git pull origin master
update-capa2yara:
	wget -O misc/capa.yar https://raw.githubusercontent.com/ruppde/yara_rules/main/capa2yara/capa.yar
yara: total test

.PHONY: clean force test total update-git update-capa2yara yara
