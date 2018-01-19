# for pip stuffs

PRETARGETS=

ifneq ($(shell stat ./.PIP-DEPENDS 1>/dev/null || echo Z),)
    PRETARGETS+=deps-pip
endif

