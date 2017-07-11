# Micro Snake Makefile
# Remember to update the VERSION before a new release.
# -- " --  to set the DESTDIR env. variable when installing.
#
# Set CC and CFGLAGS in your local environment for a suitable
# compiler (tcc?) and CFLAGS (-Os -W -Wall -Werror).

VERSION   = 1.0.1
CC       ?= gcc
CFLAGS   += -W -Wall -Werror -DVERSION=\"$(VERSION)\"

BUILD = build/

all: directory $(BUILD)snake

.PHONY: directory
directory:
	@mkdir -p $(BUILD)

$(BUILD)snake: snake.c
	$(CC) $(CFLAGS) -o $@ $^

clean:
	-@$(RM) $(BUILD)snake $(BUILD)snake.o
