# Makefile :^)

# handle depsss
include pip.mk

# the basicsss...
PREFIX=/usr/local
PRJFIX=`pwd`
BIN_DIR=${PREFIX}/bin
PRBIN_DIR=${PRJFIX}/bin

# COMMANDS TO INVOKE
CMD_PIP=pip3
CMD_INSTALL=/usr/bin/install
CMD_INSTDATA=${CMD_INSTALL} -m 644 -o root -g root
CMD_INSTEXEC=${CMD_INSTALL} -m 755 -o root -g root

# FILES TO mcHANDLE
FILES_BIN = bin/quickCA.py \
	    bin/launcher.sh

FILES_RT  = quickCA.py \
	    launcher.sh

####-NOTES 4 ME ####
# 1st -> output
# 2nd -> pre-output
# ./bin/*.* COPIED O'ER TO /usr/local/bin

### ALL ### 

.PHONY: deps-pip deps-wx create-prbin quick-ca all clean locally \
	install uninstall

all: ${PRETARGETS} create-prbin quick-ca

.SUFFIXES: .py .sh

### BIN/*.* ###
$(FILES_BIN):
	cd bin; \
	for f in $(FILES_RT) ; do \
		cp ../$$f ./$$f ; \
	done

### ./BIN ###
create-prbin:
	mkdir -p $(PRBIN_DIR); chmod -R a+x $(PRBIN_DIR); cd bin

### QUICK-CA ###
quick-ca: $(FILES_BIN) bin/quick-ca.sh

### BIN/QUICK-CA.SH <--- from LAUNCHER.SH ###
bin/quick-ca.sh :
	cd bin; mv ./launcher.sh ../bin/quick-ca.sh

### CLEAN ###
clean:
	rm -rf ./bin ; \
	rm -rf ./.yaynay

### INSTALL ###
install: all
	cd ./bin; \
	$(CMD_INSTEXEC) quick-ca.sh $(BIN_DIR) ; \
	$(CMD_INSTEXEC) quickCA.py $(BIN_DIR)

### UNINSTALL ###
uninstall:
	rm -f $(BIN_DIR)/quick-ca.sh && \
	rm -f $(BIN_DIR)/quickCA.py

### PIP DEPENDS ###
#### FOR WX'S b**** a** ####

deps-pip: deps-wx
	$(CMD_PIP) install -r requirements.txt; \
	touch ./.PIP-DEPENDS

deps-wx:
	sudo apt-get build-dep wx-common || \
	echo -e "\nBUILD-DEP FAILED... OH WELL...\n"

locally:
	touch ./.yaynay


