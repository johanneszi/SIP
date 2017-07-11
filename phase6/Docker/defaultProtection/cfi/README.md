# control flow integrity #

## Building ##
To build the program, do the following:
```
#!
cd build
cmake ..
make
```

## Usage ##
To run the program, use the following commands:
```
#!
cd build
./compile <llvm bc file> <desired path to new binary> <sensitive function list>
```
The list of sensitive functions is given in a text file with exactly one function name in each line. E.g.
```
#!
foo
bar
foobar
```
