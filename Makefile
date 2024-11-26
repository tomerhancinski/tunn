# Compiler and flags
CXX = g++
CXXFLAGS = -Wall -Wextra -O2 -std=c++17

# Directories
SRC_DIR = src
OBJ_DIR = build
BIN_DIR = .

# Source files (explicitly list or use wildcard to include all .cpp files in the src directory)
SRCS = $(wildcard $(SRC_DIR)/*.cpp)

# Object files (in the build directory)
OBJS = $(SRCS:$(SRC_DIR)/%.cpp=$(OBJ_DIR)/%.o)

# Target executable
TARGET = $(BIN_DIR)/tun_program

# Default target
all: $(TARGET)

# Rule to build the target executable
$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^

# Rule to build object files
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.cpp
	@mkdir -p $(OBJ_DIR)  # Create the build directory if it doesn't exist
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Clean rule to remove compiled files
clean:
	rm -rf $(OBJ_DIR) $(TARGET)

# PHONY targets
.PHONY: all clean
