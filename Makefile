all: update-git update-capa2yara total sig test
force: clean all
clean:
	rm -f total/total.yara
init:
	git submodule update --init
sig:
	mkdir tmp || exit
	cp -r sub/signature-base/yara/* tmp
	cd tmp && rm generic_anomalies.yar general_cloaking.yar gen_webshells_ext_vars.yar thor_inverse_matches.yar yara_mixed_ext_vars.yar configured_vulns_ext_vars.yar
	find tmp -type f -name "*.yar" -exec cat {} \; > signature.yara
	cp -r sub/signature-base .
	rm -rf signature-base/.git* signature-base/.travis.yml signature-base/.yara-ci.yml
	7z a -pinfected signature.7z signature.yara signature-base
	mv signature.7z signature/
	rm -rf tmp signature.yara signature-base
test:
	yara total/total.yara test
total:
	./bin/create-total.sh
	cat total/total.yara capa/capa.yar > total/total_inc_capa.yar
	cd total && 7z a -pinfected total.7z total.yara
update-git:
	cd sub && git submodule update --remote
	# git submodule foreach git pull origin master
update-capa2yara:
	wget -O capa/capa.yar https://raw.githubusercontent.com/ruppde/yara_rules/main/capa2yara/capa.yar
yara: total test

.PHONY: clean force test total update-git update-capa2yara yara
