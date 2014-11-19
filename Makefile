UNAME = $(shell uname)
CYGW  = $(findstring CYGWIN, $(UNAME))
ifeq ($(CYGW), CYGWIN)
	GO = /cygdrive/c/Go/bin/go.exe
	EXTENTION = .exe
else
	GO = go
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
	$(PPING) --host=192.168.0.5 --timeout=5000 --number=6 --interval=50
	$(PPING) --host=fe80::200:24ff:fecc:2a9c --timeout=5000 --number=2 --interval=50 --ipv6=true --ipv6-if=eth0 --size=5000
	$(PPING) --host=www.google.fr --timeout=5000 --number=6 --interval=50
	$(PPING) --host=10.1.1.1 --timeout=5000 --number=6 --interval=50

start1: $(PPING)
	$(PPING) --host=192.168.0.6 --timeout=5000

clean:
	rm -f $(PPING)
