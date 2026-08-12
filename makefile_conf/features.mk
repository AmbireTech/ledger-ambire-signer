# Activate requested features
# ---------------------------
# Bypass the signature verification for setExternalPlugin, setPlugin, provideERC20TokenInfo and provideNFTInfo calls
BYPASS_SIGNATURES ?= 0
ifneq ($(BYPASS_SIGNATURES),0)
    DEFINES += HAVE_BYPASS_SIGNATURES
endif

# Enable the SET_PLUGIN test key
SET_PLUGIN_TEST_KEY ?= 0
ifneq ($(SET_PLUGIN_TEST_KEY),0)
    DEFINES += HAVE_SET_PLUGIN_TEST_KEY
endif

# CryptoAssetsList key
CAL_TEST_KEY ?= 0
ifneq ($(CAL_TEST_KEY),0)
    # Key used in our test framework
    DEFINES += HAVE_CAL_TEST_KEY
endif
CAL_STAGING_KEY ?= 0
ifneq ($(CAL_STAGING_KEY),0)
    # Key used by the staging CAL
    DEFINES += HAVE_CAL_STAGING_KEY
endif

# CryptoAssetsList key
ifneq (,$(filter $(DEFINES),HAVE_CAL_TEST_KEY))
    ifneq (, $(filter $(DEFINES),HAVE_CAL_STAGING_KEY))
        # Can't use both the staging and testing keys
        $(error Multiple alternative CAL keys set at once)
    endif
endif
