CC = g++
# OSに応じてパスを変更
ifeq ($(shell uname), Darwin)
  # macOS
  CFLAGS = -Wall -std=c++17 -I./src -I/usr/local/opt/libpcap/include -D_GLIBCXX_USE_CXX11_ABI=0
  LDFLAGS = -L/usr/local/opt/libpcap/lib -lpcap
else
  # Linux (Raspberry Pi)
  CFLAGS = -Wall -std=c++17 -I./src -D_GLIBCXX_USE_CXX11_ABI=0
  LDFLAGS = -lpcap
endif
TARGET_DIR = bin
OBJDIR = obj
SRCDIR = src
TESTDIR = tests

# For Linux
# CFLAGS = -Wall -std=c++17 -I./src
# LDFLAGS = -lpcap

# Source files (excluding test files)
SRC_FILES = $(wildcard $(SRCDIR)/device/*.cpp) $(wildcard $(SRCDIR)/ethernet/*.cpp) $(wildcard $(SRCDIR)/arp/*.cpp) $(wildcard $(SRCDIR)/ip/*.cpp) $(wildcard $(SRCDIR)/icmp/*.cpp) $(wildcard $(SRCDIR)/tcp/*.cpp) $(wildcard $(SRCDIR)/common/*.cpp)
SRC_OBJS = $(patsubst $(SRCDIR)/%.cpp,$(OBJDIR)/%.o,$(SRC_FILES))

# Test targets
TEST_SRCS = $(wildcard $(TESTDIR)/*.cpp)
TEST_TARGETS = $(patsubst $(TESTDIR)/%.cpp,$(TARGET_DIR)/%,$(TEST_SRCS))

all: directories $(SRC_OBJS) $(TEST_TARGETS)

directories:
	mkdir -p $(TARGET_DIR) $(OBJDIR)/device $(OBJDIR)/ethernet $(OBJDIR)/arp $(OBJDIR)/ip $(OBJDIR)/icmp $(OBJDIR)/tcp $(OBJDIR)/common

# Build rule: test executables
$(TARGET_DIR)/%: $(TESTDIR)/%.cpp $(SRC_OBJS)
	$(CC) $(CFLAGS) -o $@ $< $(SRC_OBJS) $(LDFLAGS)

# Build rule: source object files
$(OBJDIR)/%.o: $(SRCDIR)/%.cpp
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -c $< -o $@

# Build specific test
build-%: directories $(SRC_OBJS)
	$(CC) $(CFLAGS) -o $(TARGET_DIR)/$* $(TESTDIR)/$*.cpp $(SRC_OBJS) $(LDFLAGS) -pthread

# Run specific test
run-%: $(TARGET_DIR)/%
	sudo $<

clean:
	rm -rf $(OBJDIR)/*/*.o $(TEST_TARGETS)

list-tests:
	@echo "Available tests:"
	@for test in $(TEST_TARGETS); do \
		basename $$test; \
	done

.PHONY: all directories clean run-% build-% list-tests