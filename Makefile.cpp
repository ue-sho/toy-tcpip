CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -I/usr/local/opt/libpcap/include
LDFLAGS = -L/usr/local/opt/libpcap/lib -lpcap
TARGET = bin/toy-tcpip-cpp
SRCDIR = src/cpp
OBJDIR = obj_cpp

# Source files
SRCS = $(wildcard $(SRCDIR)/*.cpp)
OBJS = $(patsubst $(SRCDIR)/%.cpp,$(OBJDIR)/%.o,$(SRCS))

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $(OBJS) $(LDFLAGS)

$(OBJDIR)/%.o: $(SRCDIR)/%.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

run: $(TARGET)
	sudo $(TARGET)

clean:
	rm -rf $(TARGET) $(OBJS)

.PHONY: all run clean