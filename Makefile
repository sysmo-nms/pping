
.PHONY: all clean_all

all:
	make -C build all

clean_all:
	rm -rf build; rm Makefile

%: 
	make -C build $@

