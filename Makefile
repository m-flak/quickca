# Makefile :^)

# the basicsss...
PREFIX=/usr/local
PRJFIX=`pwd`
BIN_DIR=${PREFIX}/bin
PRBIN_DIR=${PRJFIX}/bin

# COMMANDS TO INVOKE
CMD_PIP=pip3

# FILES TO mcHANDLE
FILES_BIN = bin/quickCA.py \
	    bin/launcher.sh

FILES_RT  = quickCA.py \
	    launcher.sh

####-NOTES 4 ME ####
# 1st -> output
# 2nd -> pre-output
# ./bin/*.* COPIED O'ER TO /usr/local/bin
#### TODO: ADD PIP DEP CHECK, INSTALL
### ALL ### 

.PHONY: create-prbin quick-ca all clean 

all: create-prbin quick-ca

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
	rm -rf ./bin


