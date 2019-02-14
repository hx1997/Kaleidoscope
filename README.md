# Kaleidoscope

A simple x86 (32 bit) disassembler written in C 

## Features

- decode common one-byte and two-byte x86-32 opcode
- support 0x66 (operand-size override) prefix
- parse PE files and calculate virtual addresses (used in JMP, etc.) automatically

## Building

Kaleidoscope has been tested to compile and run on:

- Windows 10, CLion, MinGW w64 3.4, CMake 3.13.2

## Usage

```
klp -s SIZE [-a ADDR] [-b BASE] [-h] FILE
```

`-s SIZE`: disassemble `SIZE` bytes (in decimal) starting from `ADDR`

`-a ADDR`: start disassembling from file offset `ADDR` (in hex)

`-b BASE`: specify the image base in hex (i.e. the address an executable is loaded to in memory); the disassember will add `BASE` to file offsets to form virtual addresses (VA). Note: this `BASE` is calculated automatically if `FILE` is a PE; you don't need to specify it manually.

`-h`: display this help message

## License

MIT License