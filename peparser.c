//
// Created by hx1997 on 2019/2/9.
//

#include <stdio.h>
#include <windows.h>

int parse_pe(FILE *fp, PIMAGE_OPTIONAL_HEADER32 ptr_opt_header, PIMAGE_SECTION_HEADER ptr_code_sect_header) {
    // read and check DOS header
    IMAGE_DOS_HEADER dos_header = {0};
    fseek(fp, 0, SEEK_SET);
    fread(&dos_header, sizeof(dos_header), 1, fp);

    if (dos_header.e_magic != IMAGE_DOS_SIGNATURE) {
        fprintf(stderr, "parse_pe(): input file not a valid PE!");
        return -1;
    }

    // check NT signature
    DWORD nt_signature = 0;
    fseek(fp, dos_header.e_lfanew, SEEK_SET);
    fread(&nt_signature, sizeof(DWORD), 1, fp);

    if (nt_signature != IMAGE_NT_SIGNATURE) {
        fprintf(stderr, "parse_pe(): input file not a valid PE!");
        return -1;
    }

    // read NT headers
    IMAGE_FILE_HEADER file_header = {0};
    fread(&file_header, sizeof(file_header), 1, fp);
    fread(ptr_opt_header, sizeof(IMAGE_OPTIONAL_HEADER32), 1, fp);

    // find and read code section header
    for (int i = 0; i < file_header.NumberOfSections; i++) {
        fseek(fp, dos_header.e_lfanew + sizeof(IMAGE_NT_HEADERS32) + i * sizeof(IMAGE_SECTION_HEADER), SEEK_SET);
        fread(ptr_code_sect_header, sizeof(IMAGE_SECTION_HEADER), 1, fp);

        // is it the code section?
        if ((ptr_code_sect_header->Characteristics & IMAGE_SCN_CNT_CODE)
            && (ptr_code_sect_header->VirtualAddress == ptr_opt_header->BaseOfCode)) {
            return 0;
        }
    }

    fprintf(stderr, "parse_pe(): code section not found! Maybe the input file is not a valid PE!");
    return -1;
}

long int raw_to_rva(long int raw_addr, PIMAGE_OPTIONAL_HEADER32 ptr_opt_header, PIMAGE_SECTION_HEADER ptr_sect_header) {
    return ptr_sect_header->VirtualAddress + ptr_opt_header->ImageBase + (raw_addr - ptr_sect_header->PointerToRawData);
}

unsigned long int get_pe_ep_addr(FILE *fp, long int *rva) {
    IMAGE_OPTIONAL_HEADER32 opt_header = {0};
    IMAGE_SECTION_HEADER code_sect_header = {0};

    if (parse_pe(fp, &opt_header, &code_sect_header) < 0) {
        return 0;
    }

    DWORD ep = code_sect_header.PointerToRawData + (opt_header.AddressOfEntryPoint - opt_header.BaseOfCode);
    *rva = raw_to_rva(ep, &opt_header, &code_sect_header);

    return ep;
}