//
// Created by hx1997 on 2019/2/9.
//

#ifndef KALEIDOSCOPE_PEPARSER_H
#define KALEIDOSCOPE_PEPARSER_H

#include <stdio.h>
#include <windows.h>

int parse_pe(FILE *fp, PIMAGE_OPTIONAL_HEADER32 ptr_opt_header, PIMAGE_SECTION_HEADER ptr_code_sect_header);
long int raw_to_rva(long int raw_addr, PIMAGE_OPTIONAL_HEADER32 ptr_opt_header, PIMAGE_SECTION_HEADER ptr_sect_header);
unsigned long int get_pe_ep_addr(FILE *fp, long int *rva);

#endif //KALEIDOSCOPE_PEPARSER_H
