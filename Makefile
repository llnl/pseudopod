# Tools and flags
CXX      := g++
CC       := gcc
AR       := ar
CFLAGS   := -Wall -Wextra -O3 -fPIC -DUSE_LIBCAP
CXXFLAGS := $(CFLAGS) -std=c++17
CPPFLAGS := -I./include
LDFLAGS  := -static-libstdc++ -static-libgcc
LIBS     := -lcap

# Directories
SRCDIR   := src
LIBDIR   := lib
BINDIR   := bin

# Library sources
LIB_C_SRCS   := \
  $(SRCDIR)/libpseudo/pseudo.c \
  $(SRCDIR)/libpseudo/seccomp.c \
  $(SRCDIR)/libpseudo/log.c \
  $(SRCDIR)/libpseudo/syscall.c \
  $(SRCDIR)/libpseudo/emulation.c \
  $(SRCDIR)/libpseudo/virtid.c

LIB_CXX_SRCS := \
  $(SRCDIR)/libpseudo/containers.cpp

# App sources
PSEUDO_SRCS := \
  $(SRCDIR)/pseudo/pseudo-cli.c

POD_SRCS := \
  $(SRCDIR)/pseudopod/pseudopod-cli.cpp \
  $(SRCDIR)/pseudopod/userns.c

# Objects (in-place, next to sources)
LIB_C_OBJS    := $(LIB_C_SRCS:.c=.o)
LIB_CXX_OBJS  := $(LIB_CXX_SRCS:.cpp=.o)
PSEUDO_OBJS   := $(PSEUDO_SRCS:.c=.o)
POD_OBJS      := $(filter %.o, $(POD_SRCS:.c=.o) $(POD_SRCS:.cpp=.o))

# Dependency files, 1:1 with objects
DEPS := $(LIB_C_OBJS:.o=.d) \
        $(LIB_CXX_OBJS:.o=.d) \
        $(PSEUDO_OBJS:.o=.d) \
        $(POD_OBJS:.o=.d)

# Artifacts
STATIC_LIB := $(LIBDIR)/libpseudo.a
PSEUDO_BIN := $(BINDIR)/pseudo
POD_BIN    := $(BINDIR)/pseudopod

.PHONY: all clean dirs
all: dirs $(PSEUDO_BIN) $(POD_BIN)

dirs:
	@mkdir -p $(LIBDIR) $(BINDIR)

# Static-only library
$(STATIC_LIB): $(LIB_C_OBJS) $(LIB_CXX_OBJS)
	$(AR) crs $@ $^

# Binaries
$(PSEUDO_BIN): $(PSEUDO_OBJS) $(STATIC_LIB)
	$(CXX) $(CXXFLAGS) -o $@ $(PSEUDO_OBJS) $(STATIC_LIB) $(LDFLAGS)

$(POD_BIN): $(POD_OBJS) $(STATIC_LIB)
	$(CXX) $(CXXFLAGS) -o $@ $(POD_OBJS) $(STATIC_LIB) $(LDFLAGS) $(LIBS)

# Compile rules (objects produced next to sources)
$(SRCDIR)/libpseudo/%.o: $(SRCDIR)/libpseudo/%.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

$(SRCDIR)/libpseudo/%.o: $(SRCDIR)/libpseudo/%.cpp
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) -c $< -o $@

$(SRCDIR)/pseudo/%.o: $(SRCDIR)/pseudo/%.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

$(SRCDIR)/pseudopod/%.o: $(SRCDIR)/pseudopod/%.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

$(SRCDIR)/pseudopod/%.o: $(SRCDIR)/pseudopod/%.cpp
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) -c $< -o $@

clean:
	rm -f \
	  $(LIBDIR)/libpseudo.a \
	  $(BINDIR)/pseudo $(BINDIR)/pseudopod \
	  $(LIB_C_OBJS) $(LIB_CXX_OBJS) $(PSEUDO_OBJS) $(POD_OBJS) \
	  $(DEPS)

# Include auto-generated dependency files if they exist
# Use '-' prefix to ignore missing files without treating other files as makefiles.
-include $(DEPS)
