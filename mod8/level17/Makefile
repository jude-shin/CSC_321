CXX      := g++
CXXFLAGS := -std=c++17 -Wall -O2

TARGET := client
SRC    := main.cpp

all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) $(CURL_CFLAGS) -o $@ $^ $(CURL_LIBS)

run: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(TARGET)

