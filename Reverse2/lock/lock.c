#include <stdio.h>
#include <stdlib.h>

#define MAX_LEN 1024
#define SECTOR_SIZE 0x200
typedef unsigned char byte;
typedef unsigned short word;
typedef unsigned int dword;

typedef struct _IMAGE_DOS_HEADER{
    char e_magic[2]; // Magic DOS signature MZ(4Dh 5Ah) DOS��ִ���ļ����
    word e_cblp; // Bytes on last page of file
    word e_cp; // Pages in file
    word e_crlc; // Relocations
    word e_cparhdr; // Size of header in paragraphs
    word e_minalloc; // Minimun extra paragraphs needs
    word e_maxalloc; // Maximun extra paragraphs needs
    word e_ss; // intial(relative)SS value DOS����ĳ�ʼ����ջSS
    word e_sp; // intial SP value DOS����ĳ�ʼ����ջָ��SP
    word e_csum; // Checksum
    word e_ip; // intial IP value DOS����ĳ�ʼ��ָ�����[ָ��IP]
    word e_cs; // intial(relative)CS value DOS����ĳ�ʼ��ջ���
    word e_lfarlc; // File Address of relocation table
    word e_ovno; // Overlay number
    word e_res[4]; // Reserved words   helloc�ļ�ͷ�͵�����
    word e_oemid; // OEM identifier(for e_oeminfo)
    word e_oeminfo; // OEM information;e_oemid specific
    word e_res2[10]; // Reserved words
    dword e_lfanew; // Offset to start of PE header ָ��PE�ļ�ͷ
    byte extra[0x200];
} IMAGE_DOS_HEADER;

typedef struct _SHELL_END {
    word e_crlc;
    word e_ss;
    word e_sp;
    word e_ip;
    word e_cs;
} SHELL_END;

void print_image_head(IMAGE_DOS_HEADER* header) {
    printf("Magic DOS signature MZ : %c%c\n", header->e_magic[0], header->e_magic[1]);
    printf("Bytes on last page of file : %x\n", header->e_cblp);
    printf("Pages in file : %x\n", header->e_cp);
    printf("Relocations : %x\n", header->e_crlc);
    printf("Size of header in paragraphs : %x\n", header->e_cparhdr);
    printf("intial(relative)SS value : %x\n", header->e_ss);
    printf("intial SP value : %x\n", header->e_sp);
    printf("intial IP value : %x\n", header->e_ip);
    printf("intial(relative)CS value : %x\n", header->e_cs);
}

void output_bin(FILE* file, char* bin_filename) {
    unsigned header_length = 0x200;
    FILE* bin_out;
    unsigned int rc;
	byte buf[MAX_LEN];
    fseek(file, header_length, SEEK_SET);
	bin_out = fopen(file, "wb");

    while ((rc = fread(buf, sizeof(byte), MAX_LEN, file)) != 0) {
        fwrite(buf, sizeof(byte), rc, bin_out);
    }
    fclose(bin_out);
}

unsigned int get_filesize(FILE* file) {
    unsigned int cur_offset = ftell(file);
	unsigned int size;
    fseek(file, 0, SEEK_END );
	size = ftell(file);
    fseek(file, cur_offset, SEEK_SET);
    return size;
}

void make_reloc_table(FILE* file, IMAGE_DOS_HEADER* header, word* reloc_table) {
    unsigned int cur_offset = ftell(file);
    fseek(file, header->e_lfarlc, SEEK_SET);
    fread(reloc_table, sizeof(dword), header->e_crlc, file);
    fseek(file, cur_offset, SEEK_SET);
}

int main(int argc, char *argv[]) {
    char *file1 = argv[1];
    char *file2 = argv[2];
    char *shell_name = "shell.bin";
    FILE *fin = fopen(file1, "rb"); // hello.exe
    FILE *fout = fopen(file2, "wb+"); // hello2.exe
    FILE *f_shell = fopen(shell_name, "rb");
	unsigned int fin_size;
	unsigned int shell_bin_size;
    unsigned int rc;
    byte buf[MAX_LEN];
    IMAGE_DOS_HEADER header;
	unsigned int header_length;
	SHELL_END shell_end;
	unsigned int reloc_offset;
	unsigned int total_size;
	unsigned int relocs;
	word* reloc_table;


	if (argc < 3) {
        printf("usage: %s sourcefile.exe targetfile.exe/n", argv[0]);
        return -1;
    }
    if (fin == NULL || fout == NULL) {
        printf("%s, %s", argv[1], "not exit/n");
        return -1;
    }
    if (f_shell == NULL) {
        printf("%s not exist!\n", shell_name);
        return -1;
    }
    fin_size = get_filesize(fin);
    shell_bin_size = get_filesize(f_shell);


    fread(&header, 0x200, 1,fin);
    print_image_head(&header);
    header_length = header.e_cparhdr*0x10;


    shell_end.e_crlc = header.e_crlc;
    shell_end.e_ss = header.e_ss;
    shell_end.e_sp = header.e_sp;
    shell_end.e_cs = header.e_cs;
    shell_end.e_ip = header.e_ip;
    reloc_offset = header.e_lfarlc;
    relocs = header.e_crlc;

    total_size = fin_size + shell_bin_size + 10 + relocs * 4; // Ԥ��shell��Ҫ����Ϣ�ռ�
    reloc_table = (word*)malloc(relocs * sizeof(dword));
    make_reloc_table(fin, &header, reloc_table); // �����ض�λ��

    //�޸��ļ�ͷ
    header.e_cblp = total_size%SECTOR_SIZE; // +2
    header.e_cp = total_size/SECTOR_SIZE + 1; // +4
    header.e_crlc = 0; // +6
    header.e_ip = (fin_size - header_length)%0x10000; // +14h
    header.e_cs = (fin_size - header_length)/0x10000 * 0x1000; // +16h
    print_image_head(&header);

    if(header_length > 0x200) {
        fseek(fin, 0, SEEK_SET);
        fread(&header, header_length, 1, fin);
    }

    fwrite(&header, header_length, 1, fout);
    fseek(fin, header_length, SEEK_SET);

    //����д��Hello2.exe
    while ((rc = fread(buf, sizeof(byte), MAX_LEN, fin)) != 0) {
		unsigned int i;
        for(i = 0; i < rc; i ++) {
            buf[i] ^= 0x33;
        }
        fwrite(buf, sizeof(byte), rc, fout);
    }

    //д��shell.bin
    while((rc = fread(buf, sizeof(byte), MAX_LEN, f_shell)) != 0) {
        fwrite(buf, sizeof(byte), rc, fout);
    }

    fwrite(&shell_end, sizeof(shell_end), 1, fout); // д��shell��Ҫ����Ϣ
    fwrite(reloc_table, relocs, sizeof(dword), fout);// �����д���ض�λ��

    fclose(fin);
    fclose(fout);
    return 0;
}