#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <elf.h>

char *getFileContent(const char *path, unsigned int offset, unsigned int size);

char *type(Elf64_Half e_type)
{
    if (e_type == ET_REL) {
        return "Rel (Relocatable file)" ;
    }
    if (e_type == ET_EXEC) {
        return "Exec (Executable file)" ;
    }
    if (e_type == ET_DYN) {
        return "Dyn (Shared object file)" ;
    }
    if (e_type == ET_CORE) {
        return "Core (Core file)" ;
    }
}

void print_header(const char *path)
{
    Elf64_Ehdr *header = (Elf64_Ehdr*)getFileContent(path, 0, sizeof(Elf64_Ehdr));

    printf("ELF Header:\n");
    printf("    Magic:   %x %x %x %x 02 01 01 00 00 00 00 00 00 00 00 00 :\n", header->e_ident[EI_MAG0], header->e_ident[EI_MAG1], header->e_ident[EI_MAG2], header->e_ident[EI_MAG3]);
    printf("    Class:                             ELF64:\n");
    printf("    Data:                              2's complement, little endian:\n");
    printf("    Version:                           1 (current):\n");
    printf("    OS/ABI:                            UNIX - System V:\n");
    printf("    ABI Version:                       0:\n");
    printf("    Type:                              %s:\n", type(header->e_type));
    printf("    Machine:                           Advanced Micro Devices X86-64:\n");
    printf("    Version:                           0x%x:\n", header->e_version);
    printf("    Entry point address:               0x%x:\n", header->e_entry);
    printf("    Start of program headers:          %d (bytes into file):\n", header->e_phoff);
    printf("    Start of section headers:          %d (bytes into file):\n", header->e_shoff);
    printf("    Flags:                             0x%x:\n", header->e_flags);
    printf("    Size of this header:               %d (bytes):\n", header->e_ehsize);
    printf("    Size of program headers:           %d (bytes):\n", header->e_phentsize);
    printf("    Number of program headers:         %d:\n", header->e_phnum);
    printf("    Size of section headers:           %d (bytes):\n", header->e_shentsize);
    printf("    Number of section headers:         %d:\n", header->e_shnum);
    printf("    Section header string table index: %d:\n", header->e_shstrndx);
}

char *section_type(Elf64_Word sh_type)
{
    switch (sh_type) {
        case SHT_NULL: return "NULL";
        case SHT_PROGBITS: return "PROGBITS";
        case SHT_SYMTAB: return "SYMTAB";
        case SHT_DYNSYM: return "DYNSYM";
        case SHT_STRTAB: return "STRTAB";
        case SHT_REL: return "REL";
        case SHT_RELA: return "RELA";
        case SHT_HASH: return "HASH";
        case SHT_GNU_HASH: return "GNU_HASH";
        case SHT_DYNAMIC: return "DYNAMIC";
        case SHT_NOTE: return "NOTE";
        case SHT_NOBITS: return "NOBITES";
        case SHT_INIT_ARRAY: return "INIT_ARRAY";
        case SHT_FINI_ARRAY: return "FINI_ARRAY";
        case SHT_SYMTAB_SHNDX: return "SYMTAB_SHNDX";

        default: return "Unknow";
    } 
}

char * section_flags(Elf64_Xword sh_flags)
{
    char *buf = (char *)malloc(6);
    char *pos = buf;

    if (sh_flags & SHF_WRITE) {
        *pos++ = 'W';
    }
    if (sh_flags & SHF_ALLOC) {
        *pos++ = 'A';
    }
    if (sh_flags & SHF_EXECINSTR) {
        *pos++ = 'X';
    }
    if (sh_flags & SHF_MERGE) {
        *pos++ = 'M';
    }
    if (sh_flags & SHF_STRINGS) {
        *pos++ = 'S';
    }
    if (sh_flags & SHF_INFO_LINK) {
        *pos++ = 'I';
    }
    return buf;
}

void print_sections(const char *path)
{
    Elf64_Ehdr *header = (Elf64_Ehdr*)getFileContent(path, 0, sizeof(Elf64_Ehdr));
    Elf64_Shdr *sections = (Elf64_Shdr*)getFileContent(path, header->e_shoff, header->e_shnum * sizeof(Elf64_Shdr));

    unsigned int string_offset = sections[header->e_shstrndx].sh_offset;
    unsigned int string_size = sections[header->e_shstrndx].sh_size;
    //printf("offset:0x%x, size:0x%x\n", string_offset, string_size);

    char *stringBuffer = getFileContent(path, string_offset, string_size);


    printf("Section Headers:\n");
    printf("[Nr] %-20s %-15s %-16s %-6s %-6s %-2s %-3s %-2s %-3s %-2s\n", "Name", "Type", "Address", "Off", "Size", "ES", "Flg", "Lk", "Inf", "Al");
    int i;
    for (i = 0; i < header->e_shnum; ++i) {
        printf("[%2d] %-20s %-15s %-16x %-6x %-6x %-2x %-3s %-2d %-3d %-2d\n",
                i, 
                stringBuffer + sections[i].sh_name,
                section_type(sections[i].sh_type),
                sections[i].sh_addr,
                sections[i].sh_offset,
                sections[i].sh_size,
                sections[i].sh_entsize,
                section_flags(sections[i].sh_flags),
                sections[i].sh_link,
                sections[i].sh_info,
                sections[i].sh_addralign
        );
    }

    printf("\nKey to Flags:\n");
    printf("    W (write), A (alloc), X (execute), M (merge), S (strings), l (large)\n");
    printf("    I (info), L (link order), G (group), T (TLS), E (exclude), x (unknown)\n");
    printf("    O (extra OS processing required) o (OS specific), p (processor specific)\n");
}


char *symbol_type(unsigned char st_info)
{
    unsigned char type = ELF32_ST_TYPE(st_info);
    switch (type) {
        case STT_NOTYPE: return "NOTYPE";
        case STT_OBJECT: return "OBJECT";
        case STT_FUNC: return "FUNC"; 
        case STT_SECTION: return "SECTION"; 
        case STT_FILE : return "FILE"; 
        case STT_COMMON: return "COMMON"; 
        case STT_TLS: return "TLS"; 
        case STT_NUM: return "NUM"; 
        defaut: return "Unknow";
    }
}

char *symbol_bind(unsigned char st_info)
{
    unsigned char bind = ELF32_ST_BIND(st_info);
    switch (bind) {
        case STB_LOCAL: return "LOCAL";
        case STB_GLOBAL: return "GLOBAL";
        case STB_WEAK: return "WEAK";
        case STB_NUM: return "NUM";
        default: return "Unknow";
    }
}

char *symbol_visibility(unsigned char st_other)
{
    switch (ELF64_ST_VISIBILITY(st_other)) {
        case STV_DEFAULT: return "DEFAULT";
        case STV_INTERNAL: return "INTERNAL";
        case STV_HIDDEN: return "HIDDEN";
        case STV_PROTECTED: return "PROTECTED";
    }
}

void print_symbols(const char *path)
{
    Elf64_Ehdr *header = (Elf64_Ehdr*)getFileContent(path, 0, sizeof(Elf64_Ehdr));
    Elf64_Shdr *sections = (Elf64_Shdr*)getFileContent(path, header->e_shoff, header->e_shnum * sizeof(Elf64_Shdr));

    unsigned int string_offset = sections[header->e_shstrndx].sh_offset;
    unsigned int string_size = sections[header->e_shstrndx].sh_size;
    char *stringBuffer = getFileContent(path, string_offset, string_size);


    Elf64_Sym *dynsymTable = NULL;
    Elf64_Sym *symTable = NULL;
    char *dynBuffer = NULL;
    char *symBuffer = NULL;
    int dynNum = 0;
    int strNum = 0;

    int i;
    char *sName = NULL;
    for (i = 0; i < header->e_shnum; ++i) {
        sName = stringBuffer + sections[i].sh_name;
        if (strcmp(sName, ".dynsym") == 0) {
            dynsymTable = (Elf64_Sym*)getFileContent(path, sections[i].sh_offset, sections[i].sh_size);
            dynNum = sections[i].sh_size / sizeof(Elf64_Sym);
        }
        if (strcmp(sName, ".dynstr") == 0) {
            dynBuffer = (char*)getFileContent(path, sections[i].sh_offset, sections[i].sh_size);
        }
        if (strcmp(sName, ".symtab") == 0) {
            symTable = (Elf64_Sym*)getFileContent(path, sections[i].sh_offset, sections[i].sh_size);
            strNum = sections[i].sh_size / sizeof(Elf64_Sym);
        }
        if (strcmp(sName, ".strtab") == 0) {
            symBuffer = (char*)getFileContent(path, sections[i].sh_offset, sections[i].sh_size);
        }
    }

    printf("Symbol table '.dynsym' contains %d entries:\n", dynNum);
    printf("%5s: %-16s %-4s %-10s %-10s %-10s %-3s %s\n", "Num", "Value", "Size", "Type", "Bind", "Vis", "Ndx", "Name");

    for (i = 0; i < dynNum; ++i) {
        printf("%5d: 0x%-16x %-4d %-10s %-10s %-10s %-3d %s\n", 
                i,
                (dynsymTable + i)->st_value,
                (dynsymTable + i)->st_size,
                symbol_type((dynsymTable + i)->st_info),
                symbol_bind((dynsymTable + i)->st_info),
                symbol_visibility((dynsymTable + i)->st_other),
                ((dynsymTable + i)->st_shndx),
                dynBuffer + (dynsymTable + i)->st_name
            );
    }
    // st_shndx如果是0就代表UND，未定义符号, 如果是65521就是ABS

    printf("\n");
    printf("Symbol table '.symtab' contains %d entries:\n", strNum);
    printf("%5s: %-16s %-4s %-10s %-10s %-10s %-3s %s\n", "Num", "Value", "Size", "Type", "Bind", "Vis", "Ndx", "Name");

    for (i = 0; i < strNum; ++i) {
        printf("%5d: 0x%-16x %-4d %-10s %-10s %-10s %-3d %s\n", 
                i,
                (symTable + i)->st_value,
                (symTable + i)->st_size,
                symbol_type((symTable + i)->st_info),
                symbol_bind((symTable + i)->st_info),
                symbol_visibility((symTable + i)->st_other),
                ((symTable + i)->st_shndx),
                symBuffer + (symTable + i)->st_name
            );
    }
}

char *rel_type(unsigned int r_info)
{
    switch (r_info) {
        case R_X86_64_64: return "R_X86_64_64";
        case R_X86_64_PC32: return "R_X86_64_PC32";
        case R_X86_64_GOT32: return "R_X86_64_GOT32";
        case R_X86_64_PLT32: return "R_X86_64_PLT32";
        case R_X86_64_COPY: return "R_X86_64_COPY";
        case R_X86_64_GLOB_DAT: return "R_X86_64_GLOB_DAT";
        case R_X86_64_JUMP_SLOT: return "R_X86_64_JUMP_SLOT";
        case R_X86_64_RELATIVE: return "R_X86_64_RELATIVE";
        default: return "Unknow";
    }
}

void handle_rel_table(const char *name, unsigned int offset, unsigned int num, Elf64_Rel *relTable)
{
    printf("\n");
    printf("Relocation section '%s' at offset 0x%x contains %d entries:\n", name, offset, num);
    printf("    Offset             Info             Type               Symbol's Value  Symbol's Name + Addend\n");

    int i = 0;
    for (; i < num; ++i) {
        printf("0x%-16x 0x%016llx %-20s 0x%-16x %s\n",
                relTable[i].r_offset,
                relTable[i].r_info,
                rel_type(ELF64_R_TYPE(relTable[i].r_info)),
                ELF64_R_SYM(relTable[i].r_info),
                "unknow" //ELF64_R_SYM(relTable[i].r_info)
            );
    }
}

void handle_rela_table(const char *name, unsigned int offset, unsigned int num, Elf64_Rela *relaTable)
{
    printf("\n");
    printf("Relocation section '%s' at offset 0x%x contains %d entries:\n", name, offset, num);
    printf("    Offset             Info             Type               Symbol's Value  Symbol's Name + Addend\n");

    int i;
    for (i = 0; i < num; ++i) {
        printf("0x%-16x 0x%-16llx %-20s 0x%-16x %s\n",
                relaTable[i].r_offset,
                relaTable[i].r_info,
                rel_type(ELF64_R_TYPE(relaTable[i].r_info)),
                ELF64_R_SYM(relaTable[i].r_info),
                "unknow", //ELF64_R_SYM(relaTable[i].r_info),
                relaTable[i].r_addend
            );
    }
}

void print_relocations(const char *path)
{
    Elf64_Ehdr *header = (Elf64_Ehdr*)getFileContent(path, 0, sizeof(Elf64_Ehdr));
    Elf64_Shdr *sections = (Elf64_Shdr*)getFileContent(path, header->e_shoff, header->e_shnum * sizeof(Elf64_Shdr));

    char *secNameBuffer = getFileContent(path, sections[header->e_shstrndx].sh_offset, sections[header->e_shstrndx].sh_size);

    Elf64_Rel *relTable = NULL;
    Elf64_Rela *relaTable = NULL;

    int i;
    char *sName = NULL;
    for (i = 0; i < header->e_shnum; ++i) {
        
        if (sections[i].sh_type == SHT_REL) {
            relTable = (Elf64_Rel*)getFileContent(path, sections[i].sh_offset, sections[i].sh_size);
            handle_rel_table(secNameBuffer + sections[i].sh_name, sections[i].sh_offset, (sections[i].sh_size / sizeof(Elf64_Rel)), relTable);
        }

        if (sections[i].sh_type == SHT_RELA) {
            relaTable = (Elf64_Rela*)getFileContent(path, sections[i].sh_offset, sections[i].sh_size);
            handle_rela_table(secNameBuffer + sections[i].sh_name, sections[i].sh_offset, (sections[i].sh_size / sizeof(Elf64_Rela)), relaTable);
        }
    }
}


char *dynamic_type(unsigned int d_tag)
{
    switch (d_tag) {
        case DT_NULL: return "NULL"; 
        case DT_NEEDED: return "NEEDED"; 
        case DT_PLTRELSZ: return "PLTRELSZ"; 
        case DT_PLTGOT: return "PLTGOT"; 
        case DT_HASH: return "HASH"; 
        case DT_STRTAB: return "SRTTAB"; 
        case DT_SYMTAB: return "SYMTAB"; 
        case DT_RELA: return "RELA"; 
        case DT_RELASZ: return "RELASZ"; 
        case DT_RELAENT: return "RELAENT"; 
        case DT_STRSZ: return "STRSZ"; 
        case DT_SYMENT: return "SYMENT"; 
        case DT_INIT: return "INIT"; 
        case DT_FINI: return "FINI"; 
        case DT_SONAME: return "SONAME"; 
        case DT_RPATH: return "RPATH"; 
        case DT_SYMBOLIC: return "SYMBOLIC"; 
        case DT_REL: return "REL"; 
        case DT_RELSZ: return "RELSZ"; 
        case DT_RELENT: return "RELENT"; 
        case DT_PLTREL: return "PLTREL"; 
        case DT_DEBUG: return "DEBUG"; 
        case DT_TEXTREL: return "TEXTREL"; 
        case DT_JMPREL: return "JMPREL"; 
        case DT_BIND_NOW: return "BIND_NOW"; 
        case DT_INIT_ARRAY: return "INIT_ARRAY"; 
        case DT_FINI_ARRAY: return "FINI_ARRAY"; 
        case DT_INIT_ARRAYSZ: return "INIT_ARRAYSZ"; 
        case DT_FINI_ARRAYSZ: return "FINI_ARRAYSZ"; 
        case DT_RUNPATH: return "RUNPATH"; 
        case DT_FLAGS: return "FLAGS"; 
        case DT_PREINIT_ARRAY: return "PREINIT_ARRAY";
        case DT_PREINIT_ARRAYSZ: return "PREINIT_ARRAYSZ"; 
        case DT_NUM: return "NUM"; 
        case DT_LOOS: return "LOOS"; 
        case DT_HIOS: return "HIOS"; 
        case DT_LOPROC: return "LOPROC"; 
        case DT_HIPROC: return "HIPROC"; 
        default: return "Unknow";
    }
}

void print_dynamic(const char *path)
{
    Elf64_Ehdr *header = (Elf64_Ehdr*)getFileContent(path, 0, sizeof(Elf64_Ehdr));
    Elf64_Shdr *sections = (Elf64_Shdr*)getFileContent(path, header->e_shoff, header->e_shnum * sizeof(Elf64_Shdr));

    char *stringBuffer = getFileContent(path, sections[header->e_shstrndx].sh_offset, sections[header->e_shstrndx].sh_size);

    Elf64_Dyn *dyn = NULL;
    char *dynstrBuffer = NULL;
    char *sName = NULL;
    int dynNum = 0;
    int i;
    for (i = 0; i < header->e_shnum; ++i) {
        sName = stringBuffer + sections[i].sh_name;
        if (sections[i].sh_type == 0x06) { // SHT_DYNAMIC  /usr/include/elf.h
            dyn = (Elf64_Dyn*)getFileContent(path, sections[i].sh_offset, sections[i].sh_size);
            dynNum = sections[i].sh_size / sizeof(Elf64_Dyn);
            printf("Dynamic section at offset 0x%x contains %d entries:\n", sections[i].sh_offset, dynNum);
            printf("  Tag              Type                 Name/Value\n");
        }
        if (strncmp(sName, ".dynstr", 7) == 0) {
            dynstrBuffer =  (char*)getFileContent(path, sections[i].sh_offset, sections[i].sh_size);
        }
    }

    for (i = 0; i < dynNum; ++i) {
        printf("0x%-16x %-20s ", dyn[i].d_tag, dynamic_type(dyn[i].d_tag));
        switch (dyn[i].d_tag) {
            case DT_NEEDED: 
                printf("Shared library: [%s]", dynstrBuffer + dyn[i].d_un.d_val); break;

            case DT_PLTRELSZ: 
            case DT_RELASZ: 
            case DT_STRSZ: 
            case DT_RELSZ: 
            case DT_RELAENT: 
            case DT_SYMENT: 
            case DT_RELENT: 
            case DT_INIT_ARRAYSZ: 
            case DT_FINI_ARRAYSZ: 
            case DT_PREINIT_ARRAYSZ: 
                printf("%d (bytes)", dyn[i].d_un.d_val); break;

            case DT_INIT: 
            case DT_FINI: 
            case DT_INIT_ARRAY: 
            case DT_FINI_ARRAY: 
            case DT_PREINIT_ARRAY: 
            case DT_PLTGOT: 
            case DT_PLTREL: 
            case DT_HASH: 
            case DT_STRTAB: 
            case DT_SYMTAB: 
            case DT_RELA: 
            case DT_REL: 
            case DT_DEBUG: 
            case DT_TEXTREL: 
            case DT_JMPREL: 
                printf("0x%-16x", dyn[i].d_un.d_ptr); break;

            case DT_NULL: 
            case DT_SONAME: 
            case DT_RPATH: 
            case DT_RUNPATH: 
            case DT_SYMBOLIC: 
            case DT_BIND_NOW: 
            case DT_FLAGS: 
            case DT_NUM: 
            case DT_LOOS: 
            case DT_HIOS: 
            case DT_LOPROC: 
            case DT_HIPROC: 
            default: 
                printf("0x%-16x", dyn[i].d_un.d_ptr); break;
        }
        printf("\n");
    }
}

char *phdr_type(unsigned int p_type) {
    switch (p_type) {
        case PT_NULL: return "NULL";
        case PT_LOAD: return "LOAD";
        case PT_DYNAMIC: return "DYNAMIC";
        case PT_INTERP: return "INTERP";
        case PT_NOTE: return "NOTE";
        case PT_SHLIB: return "SHLIB";
        case PT_PHDR: return "PHDR";
        case PT_TLS: return "TLS";
        case PT_NUM: return "NUM";
        case PT_LOOS: return "LOOS";
        case PT_GNU_EH_FRAME: return "GNU_EH_FRAME";
        case PT_GNU_STACK: return "GNU_STACK";
        case PT_GNU_RELRO: return "GNU_RELRO";
        case PT_SUNWSTACK: return "SUNWSTACK";
        case PT_LOPROC: return "LOPROC";
        case PT_HIPROC: return "HIPROC";
        default: return "Unknow";
    }
}

char *phdr_flags(unsigned int p_flags) {
    static char buf[5];
    memset(buf, '\0', 5);
    char *pos = buf;

    *pos++ = (p_flags & PF_R) ? 'R' : ' '; 
    *pos++ = (p_flags & PF_W) ? 'W' : ' '; 
    *pos++ = (p_flags & PF_X) ? 'X' : ' '; 
    return buf;
}

void print_segments(const char *path)
{
    Elf64_Ehdr *header = (Elf64_Ehdr*)getFileContent(path, 0, sizeof(Elf64_Ehdr));
    if (header->e_type != ET_EXEC) {
        printf("File Format Is't Exec\n", header->e_entry);
        return;
    }

    Elf64_Shdr *sections = (Elf64_Shdr*)getFileContent(path, header->e_shoff, header->e_shnum * sizeof(Elf64_Shdr));
    char *sectionBuffer = getFileContent(path, sections[header->e_shstrndx].sh_offset, sections[header->e_shstrndx].sh_size);

    printf("Entry point 0x%x\n", header->e_entry);
    printf("    There are %d program headers, starting at offset %d\n", header->e_phnum, header->e_phoff);

    Elf64_Phdr *phdr = (Elf64_Phdr*)getFileContent(path, header->e_phoff, header->e_phnum * sizeof(Elf64_Phdr));

    printf("Program Headers:\n");
    printf("  Type           file Offset        VirtAddr           PhysAddr           FileSiz  MemSiz   Flg  Align\n");
    printf("------------------------------------------------------------------------------------------------------\n");

    int i;
    for (i = 0; i < header->e_phnum; ++i) {
        printf("%-16s 0x%-16x 0x%-16x 0x%-16x 0x%-6x 0x%-6x %-4s 0x%-6x\n",
                phdr_type(phdr[i].p_type),
                phdr[i].p_offset,
                phdr[i].p_vaddr,
                phdr[i].p_paddr,
                phdr[i].p_filesz,
                phdr[i].p_memsz,
                phdr_flags(phdr[i].p_flags),
                phdr[i].p_align
        );
    }
}


int main(int argc, char *argv[])
{
    if (argc < 2) {
        printf("./%s filepath\n", argv[0]);
        return -1;
    }

    //print_header(argv[1]);
    //print_sections(argv[1]);
    //print_symbols(argv[1]);
    print_relocations(argv[1]);
    //print_dynamic(argv[1]);
    //print_segments(argv[1]);

    return 0;
}

