prefix = ${HOME}/ipv6gw
DEST = ${prefix}
BINFILE = ipv6gw
CONFFILE = ipv6gw.conf
KEYFILE = ipv6gw.key
CERTFILE = ipv6gw.cer
REQFILE = ipv6gw.req

INSTALL = /usr/bin/install -c
INSTALL_PROGRAM = ${INSTALL}

all: ipv6

ipv6:
	g++ -O3 -ggdb -Wall -lssl -o $(BINFILE) ipv6gw.cpp
clean:
	rm -f $(BINFILE) *.orig;

install:
	@if test ! -f $(BINFILE); then \
		echo ""; \
		echo "You haven't compiled ipv6gw yet."; \
		echo "To compile ipv6gw, use:"; \
		echo ""; \
		echo "  make [target]"; \
		echo ""; \
		echo "Valid targets: 'ipv6gw'."; \
		echo "Default target: 'ipv6gw'."; \
		echo ""; \
		exit 1; \
	fi
	@if test "x$(DEST)" = "x"; then \
		echo "You must specify a destination directory."; \
		echo "Example:"; \
		echo ""; \
		echo "  make install DEST=\"/home/wcc/mybot\""; \
		echo ""; \
		exit 1; \
	fi
	@echo ""
	@echo "Installing in directory: '$(DEST)'."
	@echo ""
	@if test ! -d $(DEST); then \
		echo "Creating directory '$(DEST)'."; \
		mkdir $(DEST) >/dev/null; \
	fi
	@if test -f $(DEST)/$(BINFILE); then \
		rm -f $(DEST)/$(BINFILE); \
	fi
	@$(INSTALL_PROGRAM) $(BINFILE) $(DEST)/$(BINFILE)
	@if test ! -f $(DEST)/$(CONFFILE); then \
		$(INSTALL_PROGRAM) -m 0600 $(CONFFILE) $(DEST)/$(CONFFILE); \
	fi
	@if test ! -f $(DEST)/$(CERTFILE); then \
		echo "SSL key and certificate not found."; \
		echo "Generating SSL key and certificate."; \
		openssl genrsa -out $(DEST)/$(KEYFILE) 1024; \
		openssl req -new -key $(DEST)/$(KEYFILE) -out $(DEST)/$(REQFILE); \
		openssl x509 -req -days 365 -in $(DEST)/$(REQFILE) -signkey $(DEST)/$(KEYFILE) -out $(DEST)/$(CERTFILE); \
                chmod 0600 $(DEST)/$(REQFILE) $(DEST)/$(KEYFILE) $(DEST)/$(CERTFILE); \
	fi

