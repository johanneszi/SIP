CLANG=clang-3.9
LINK=llvm-link-3.9

.PHONY: all
all: c-snake micro-snake tetris zopfli

c-snake.bc:
	$(CLANG) -c -emit-llvm -o $@ src/c-snake/snake.c

c-snake: c-snake.bc
	$(CLANG) -lncurses $^ -o $@

micro-snake.bc:
	$(CLANG) -c -emit-llvm -W -Wall -Werror -DVERSION=\"1.0.1\" -o $@ src/micro-snake/snake.c

micro-snake: micro-snake.bc
	$(CLANG) $^ -o $@

tetris.bc:
	$(CLANG) -c -emit-llvm -DENABLE_SCORE -DENABLE_PREVIEW -DENABLE_HIGH_SCORE -o $@ src/tetris/tetris.c

tetris: tetris.bc
	$(CLANG) $^ -o $@

zopfli.bc:
	$(CLANG) -c -emit-llvm src/zopfli/src/zopfli/blocksplitter.c src/zopfli/src/zopfli/cache.c src/zopfli/src/zopfli/deflate.c src/zopfli/src/zopfli/gzip_container.c src/zopfli/src/zopfli/hash.c src/zopfli/src/zopfli/katajainen.c src/zopfli/src/zopfli/lz77.c src/zopfli/src/zopfli/squeeze.c src/zopfli/src/zopfli/tree.c src/zopfli/src/zopfli/util.c src/zopfli/src/zopfli/zlib_container.c src/zopfli/src/zopfli/zopfli_lib.c src/zopfli/src/zopfli/zopfli_bin.c -W -Wall -Wextra -ansi -pedantic -O2 -Wno-unused-function
	$(LINK) blocksplitter.bc deflate.bc hash.bc lz77.bc squeeze.bc util.bc zopfli_lib.bc cache.bc gzip_container.bc katajainen.bc tree.bc zlib_container.bc zopfli_bin.bc -o $@
	@ rm -f blocksplitter.bc deflate.bc hash.bc lz77.bc squeeze.bc util.bc zopfli_lib.bc cache.bc gzip_container.bc katajainen.bc tree.bc zlib_container.bc zopfli_bin.bc

zopfli: zopfli.bc
	$(CLANG) $^ -lm -o $@

clean:
	@ rm -f c-snake c-snake.bc micro-snake micro-snake.bc tetris tetris.bc zopfli zopfli.bc
