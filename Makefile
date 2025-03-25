CC = g++
CFLAGS = -Wall -std=c++17 -I./src -I/usr/local/opt/libpcap/include
LDFLAGS = -L/usr/local/opt/libpcap/lib -lpcap
TARGET_DIR = bin
OBJDIR = obj
SRCDIR = src
TESTDIR = tests

# Source files (ただしテストファイルは除く)
SRC_FILES = $(wildcard $(SRCDIR)/*.cpp)
SRC_OBJS = $(patsubst $(SRCDIR)/%.cpp,$(OBJDIR)/%.o,$(SRC_FILES))

# Test targets
TEST_SRCS = $(wildcard $(TESTDIR)/*.cpp)
TEST_TARGETS = $(patsubst $(TESTDIR)/%.cpp,$(TARGET_DIR)/%,$(TEST_SRCS))

all: directories $(SRC_OBJS) $(TEST_TARGETS)

directories:
	mkdir -p $(TARGET_DIR) $(OBJDIR)

# ビルドルール: テスト実行ファイル
$(TARGET_DIR)/%: $(TESTDIR)/%.cpp $(SRC_OBJS)
	$(CC) $(CFLAGS) -o $@ $< $(SRC_OBJS) $(LDFLAGS)

# ビルドルール: ソースファイルのオブジェクトファイル
$(OBJDIR)/%.o: $(SRCDIR)/%.cpp
	$(CC) $(CFLAGS) -c $< -o $@

# 特定のテストをビルド
build-%: directories $(SRC_OBJS)
	$(CC) $(CFLAGS) -o $(TARGET_DIR)/$* $(TESTDIR)/$*.cpp $(SRC_OBJS) $(LDFLAGS)

# 特定のテストを実行
run-%: $(TARGET_DIR)/%
	sudo $<

clean:
	rm -rf $(OBJDIR)/*.o $(TEST_TARGETS)

list-tests:
	@echo "利用可能なテスト:"
	@for test in $(TEST_TARGETS); do \
		basename $$test; \
	done

.PHONY: all directories clean run-% build-% list-tests