CXX      := g++
CXXFLAGS := -std=c++17 -O3 -Wall -Wextra -pthread
LDLIBS   := -lcrypt

TARGET   := bcryptCompute
SRC      := bcryptCompute.cpp

all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDLIBS)

run: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(TARGET)

.PHONY: all clean
