UNAME = $(shell uname)
CYGW  = $(findstring CYGWIN, $(UNAME))
ifeq ($(CYGW), CYGWIN)
	GO      = /cygdrive/c/Go/bin/go.exe
	EXTEND  = .exe
else
	GO      = go
	PERMS   = set_perms
endif

EXTENTION = $(EXTEND)

SRC_DIR  = .
BIN_DIR  = .
GO_BUILD = $(GO) build

GPING_SRC = $(SRC_DIR)/gping.go
GPING     = $(BIN_DIR)/gping$(EXTENTION)

compile: $(GPING)

$(GPING): $(GPING_SRC)
	$(GO_BUILD) -o $(GPING) $(GPING_SRC)
	sudo chown root $(GPING)
	sudo chmod 4555 $(GPING)


clean:
	rm -f $(GPING)
