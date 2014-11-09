UNAME = $(shell uname)
CYGW  = $(findstring CYGWIN, $(UNAME))
ifeq ($(CYGW), CYGWIN)
	GO        = /cygdrive/c/Go/bin/go.exe
	EXTENTION = .exe
else
	GO      = go
endif


SRC_DIR  = .
BIN_DIR  = .
GO_BUILD = $(GO) build

PPING_SRC = $(SRC_DIR)/pping.go
PPING     = $(BIN_DIR)/pping$(EXTENTION)

$(PPING): $(PPING_SRC)
	$(GO_BUILD) -o $(PPING) $(PPING_SRC)
	sudo chown root $(PPING)
	sudo chmod 4555 $(PPING)

start: $(PPING)
	$(PPING) --host=192.168.0.5 --timeout=5

start1: $(PPING)
	$(PPING) --host=192.168.0.6 --timeout=5

clean:
	rm -f $(PPING)
