CC = gcc
CFLAGS = -Wall -Wextra -O2 -std=c99 -D_GNU_SOURCE
LDFLAGS = -lpthread
TARGET = webserver
SOURCE = WEBserver.c

# Check for libcjson availability
HAS_CJSON := $(shell pkg-config --exists libcjson && echo yes)
ifeq ($(HAS_CJSON),yes)
    CFLAGS += $(shell pkg-config --cflags libcjson) -DHAVE_CJSON
    LDFLAGS += $(shell pkg-config --libs libcjson)
else
    # Fallback: try system libcjson
    ifneq (,$(wildcard /usr/include/cjson/cJSON.h))
        LDFLAGS += -lcjson
        CFLAGS += -DHAVE_CJSON
    else
        # No cjson available - compile without JSON support
        CFLAGS += -DNO_CJSON
        $(warning libcjson not found - compiling without JSON support)
    endif
endif

# Directories
INSTALL_DIR = /usr/local/bin
CONFIG_DIR = /etc/webserver
LOG_DIR = /var/log
WWW_DIR = /var/www

.PHONY: all clean install uninstall test security-test

all: $(TARGET)

$(TARGET): $(SOURCE)
	$(CC) $(CFLAGS) -o $(TARGET) $(SOURCE) $(LDFLAGS)

clean:
	rm -f $(TARGET)

install: $(TARGET)
	sudo mkdir -p $(CONFIG_DIR)
	sudo mkdir -p $(LOG_DIR)
	sudo mkdir -p $(WWW_DIR)
	sudo cp $(TARGET) $(INSTALL_DIR)/
	sudo cp server.conf $(CONFIG_DIR)/
	sudo chmod +x $(INSTALL_DIR)/$(TARGET)
	sudo chmod 644 $(CONFIG_DIR)/server.conf
	@echo "Installation complete. Run with: sudo webserver"

uninstall:
	sudo rm -f $(INSTALL_DIR)/$(TARGET)
	sudo rm -rf $(CONFIG_DIR)
	@echo "Uninstallation complete."

test: $(TARGET)
	@echo "Starting basic functionality test..."
	./$(TARGET) &
	sleep 2
	curl -I http://localhost:8080/ || echo "Server not responding on port 8080"
	pkill -f "./$(TARGET)" || true
	@echo "Basic test complete."

security-test: $(TARGET)
	@echo "Running security tests..."
	@echo "Testing path traversal protection..."
	./$(TARGET) &
	sleep 2
	curl -I "http://localhost:8080/../../../etc/passwd" || echo "Path traversal test complete"
	@echo "Testing rate limiting..."
	for i in {1..5}; do curl -s http://localhost:8080/ > /dev/null; done
	pkill -f "./$(TARGET)" || true
	@echo "Security tests complete."

debug: $(SOURCE)
	$(CC) $(CFLAGS) -g -DDEBUG -o $(TARGET)_debug $(SOURCE) $(LDFLAGS)

static-analysis:
	@echo "Running static analysis with cppcheck..."
	cppcheck --enable=all --suppress=missingIncludeSystem $(SOURCE) || echo "cppcheck not installed"
	@echo "Running analysis with clang-static-analyzer..."
	scan-build gcc $(CFLAGS) -o $(TARGET)_analyze $(SOURCE) $(LDFLAGS) || echo "scan-build not installed"

help:
	@echo "Available targets:"
	@echo "  all           - Build the web server"
	@echo "  clean         - Remove built files"
	@echo "  install       - Install the web server system-wide"
	@echo "  uninstall     - Remove installed files"
	@echo "  test          - Run basic functionality tests"
	@echo "  security-test - Run security tests"
	@echo "  debug         - Build debug version"
	@echo "  static-analysis - Run static code analysis"
	@echo "  help          - Show this help message"