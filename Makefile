CXX      ?= g++
CXXFLAGS  = -std=c++17 -Wall -Wextra
LDFLAGS   =

SRCDIR    = src
SRCS      = $(SRCDIR)/main.cpp $(SRCDIR)/config.cpp $(SRCDIR)/fanotify.cpp
TARGET    = dirblock

PREFIX    ?= $(HOME)/.local

.PHONY: all release debug clean install

all: release

release: CXXFLAGS += -Os -DNDEBUG -ffunction-sections -fdata-sections
release: LDFLAGS  += -s -Wl,--gc-sections
release: $(TARGET)

debug: CXXFLAGS += -g -O0 -fsanitize=address
debug: LDFLAGS  += -fsanitize=address
debug: $(TARGET)

$(TARGET): $(SRCS) $(wildcard $(SRCDIR)/*.hpp)
	$(CXX) $(CXXFLAGS) -o $@ $(SRCS) $(LDFLAGS)

clean:
	rm -f $(TARGET)

install: release
	mkdir -p $(PREFIX)/bin $(HOME)/.config/dirblock
	@if [ -x $(PREFIX)/bin/$(TARGET) ] && getcap $(PREFIX)/bin/$(TARGET) | grep -q cap_sys_admin; then \
		echo "Preserving existing capabilities..."; \
		cp $(TARGET) $(PREFIX)/bin/$(TARGET); \
		chmod 755 $(PREFIX)/bin/$(TARGET); \
		sudo setcap cap_sys_admin,cap_sys_ptrace+ep $(PREFIX)/bin/$(TARGET); \
		echo "Capabilities restored."; \
	else \
		cp $(TARGET) $(PREFIX)/bin/$(TARGET); \
		chmod 755 $(PREFIX)/bin/$(TARGET); \
		echo ""; \
		echo "Installed. To grant capabilities (required):"; \
		echo "  sudo setcap cap_sys_admin,cap_sys_ptrace+ep $(PREFIX)/bin/$(TARGET)"; \
	fi
	cp config/dirblock.toml $(HOME)/.config/dirblock/dirblock.toml
	@if ! getcap $(PREFIX)/bin/$(TARGET) 2>/dev/null | grep -q cap_sys_admin; then \
		echo ""; \
		echo "  sudo setcap cap_sys_admin,cap_sys_ptrace+ep $(PREFIX)/bin/$(TARGET)"; \
		echo ""; \
	fi
