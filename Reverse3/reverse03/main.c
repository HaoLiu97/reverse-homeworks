// By 3160104994 Hao Liu 
// 2019/12/25
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef unsigned char BYTE;
typedef unsigned short WORD;
typedef unsigned int DWORD;

typedef struct _IMAGE_DOS_HEADER {
    char e_magic[2]; // Magic DOS signature MZ(4Dh 5Ah) DOS��ִ���ļ����
    WORD e_cblp; // Bytes on last page of file
    WORD e_cp; // Pages in file
    WORD e_crlc; // Relocations
    WORD e_cparhdr; // Size of header in paragraphs
    WORD e_minalloc; // Minimun extra paragraphs needs
    WORD e_maxalloc; // Maximun extra paragraphs needs
    WORD e_ss; // intial(relative)SS value DOS����ĳ�ʼ����ջSS
    WORD e_sp; // intial SP value DOS����ĳ�ʼ����ջָ��SP
    WORD e_csum; // Checksum
    WORD e_ip; // intial IP value DOS����ĳ�ʼ��ָ�����[ָ��IP]
    WORD e_cs; // intial(relative)CS value DOS����ĳ�ʼ��ջ���
    WORD e_lfarlc; // File Address of relocation table
    WORD e_ovno; // Overlay number
    WORD e_res[4]; // Reserved WORDs   helloc�ļ�ͷ�͵�����
    WORD e_oemid; // OEM identifier(for e_oeminfo)
    WORD e_oeminfo; // OEM information;e_oemid specific
    WORD e_res2[10]; // Reserved WORDs
    DWORD e_lfanew; // Offset to start of PE header ָ��PE�ļ�ͷ
    BYTE extra[0x200];
} DOS_HEADER;
typedef struct _IMAGE_FILE_HEADER {
    WORD Machine;                  //������ִ�е�CPUƽ̨:0X0:�κ�ƽ̨��0X14C:intel i386������������
    WORD NumberOfSections;         //��PE�ļ�����������
    DWORD TimeDateStamp;           //ʱ������������������ļ���ʱ���1969/12/31-16:00P:00��������
    DWORD PointerToSymbolTable;  //COFF���ű����ƫ��λ�á����ֶ�ֻ��COFF������Ϣ����
    DWORD NumberOfSymbols;       //COFF���ű����еķ��Ÿ�������ֵ����һ��ֵ��release�汾�ĳ�����Ϊ0
    WORD SizeOfOptionalHeader;   //IMAGE_OPTIONAL_HEADER�ṹ�Ĵ�С(�ֽ���):32λĬ��E0H,64λĬ��F0H(���޸�)
    WORD Characteristics;          //�������ļ�����,eg:
} FILE_HEADER;

typedef struct _IMAGE_OPTIONAL_HEADER {
    WORD Magic;                    //������(ħ��)��0x0107:ROM image,0x010B:32λPE��0X020B:64λPE
    BYTE MajorLinkerVersion;     //���������汾��
    BYTE MinorLinkerVersion;     //���������汾��
    DWORD SizeOfCode;              //���д���ε��ܺʹ�С,ע�⣺������FileAlignment��������,���ڵ�û��
    DWORD SizeOfInitializedData;   //�Ѿ���ʼ�����ݵĴ�С,ע�⣺������FileAlignment��������,���ڵ�û��
    DWORD SizeOfUninitializedData; //δ����ʼ�����ݵĴ�С,ע�⣺������FileAlignment��������,���ڵ�û��
    DWORD AddressOfEntryPoint;     //��������ڵ�ַOEP������һ��RVA(Relative Virtual Address),ͨ��������.textsection,���ֶζ���DLLs/EXEs�����á�
    DWORD BaseOfCode;              //�������ʼ��ַ(�����ַ),(����Ŀ�ʼ�ͳ����ޱ�Ȼ��ϵ)
    DWORD BaseOfData;              //���ݶ���ʼ��ַ(���ݻ�ַ)
    DWORD ImageBase;               //���ڴ澵���ַ(Ĭ��װ����ʼ��ַ),Ĭ��Ϊ4000H
    DWORD SectionAlignment;        //���ڴ����:һ��ӳ���ڴ��У�ÿһ��section��֤��һ������ֵ֮�������������ַ��ʼ
    DWORD FileAlignment;           //���ļ����룺�����200H��������1000H
    WORD MajorOperatingSystemVersion;    //�������ϵͳ���汾��
    WORD MinorOperatingSystemVersion;    //�������ϵͳ���汾��
    WORD MajorImageVersion;              //�Զ������汾��,ʹ���������Ĳ�������,eg:LINK /VERSION:2.0 myobj.obj
    WORD MinorImageVersion;              //�Զ��帱�汾��,ʹ���������Ĳ�������
    WORD MajorSubsystemVersion;          //������ϵͳ���汾��,������ֵ4.0(Windows 4.0/��Windows 95)
    WORD MinorSubsystemVersion;          //������ϵͳ���汾��
    DWORD Win32VersionValue;             //����0
    DWORD SizeOfImage;         //��PE�ļ����ڴ���ӳ���ܴ�С,sizeof(ImageBuffer),SectionAlignment�ı���
    DWORD SizeOfHeaders;       //��DOSͷ(64B)+PE���(4B)+��׼PEͷ(20B)+��ѡPEͷ+�ڱ����ܴ�С�������ļ�����(FileAlignment�ı���)
    DWORD CheckSum;            //PE�ļ�CRCУ��ͣ��ж��ļ��Ƿ��޸�
    WORD SubSystem;
    WORD DllCharacteristics;
    DWORD SizeOfStackReverse;
    DWORD SizeOfStackCommit;
    DWORD SizeOfHeapReverse;
    DWORD SizeOfHeapCommit;
    DWORD LoaderFlags;

    DWORD NumberOfRvaAndSizes;
    DWORD ExportVirtualAddress;
    DWORD ExportSize;
    DWORD ImportVirtualAddress;
    DWORD ImportSize;
    BYTE DataDirArray[0x70];
} OPTIONAL_HEADER;

typedef struct _IMAGE_PE_HEADER {
    char Signature[2]; //IMAGE_NT_SIGNATURE = 0x00004550
    FILE_HEADER FileHeader;
    OPTIONAL_HEADER OptionalHeader;
} PE_HEADER;

typedef struct _IMAGE_SECTION_HEADER {
    char Name[8];
    DWORD VirtualSize; // �ڵ��ڴ泤��
    DWORD VirtaulAddress; // �ڵ��ڴ�ƫ��
    DWORD SizeOfRawData; // �ڵ��ļ�����
    DWORD PointerToRawData; // �ڵ��ļ�ƫ��
    DWORD PointerToRelocations;
    DWORD PointerToLinenumbers;
    WORD NumberOfRelocations;
    WORD NumberOfLinenumbers;
    BYTE Characteristics[4];
} SECTION_HEADER;

typedef struct _IMPORT_DESCRIPTOR {
    DWORD OriginalFirstThunk; // ָ��API����ָ���
    DWORD TImeDateStamp;
    DWORD ForwarderChain;
    DWORD Name; // ָ��DLL��
    DWORD FirstThunk; // ָ�� API ��ַ��
} IMPORT_DESCRIPTOR;

unsigned int getFileAddr(SECTION_HEADER *sectionHeaders, unsigned int addr, unsigned int total) {
    unsigned int i;
    for (i = 0; i < total; i++) {
        if (addr < sectionHeaders[i].VirtaulAddress + sectionHeaders[i].VirtualSize) {
            break;
        }
    }
    return sectionHeaders[i].PointerToRawData + addr - sectionHeaders[i].VirtaulAddress;;
}


int main() {
    char filename[255];
    DOS_HEADER dosHeader;
    PE_HEADER peHeader;
    SECTION_HEADER *sectionHeaders;
    IMPORT_DESCRIPTOR importDescriptor;
    unsigned int peHeaderAddr;
    unsigned int importVirtualAddr;
    unsigned int importFileAddr;
    unsigned int sectionNumber;
    unsigned int APINameFileAddr;
    unsigned int dllNameFileAddr;
    unsigned int i;
    unsigned int total;
    char dllName[255];
    char APIName[255];
    unsigned int curImportAddr;
    unsigned int fileAddr;
    DWORD APINameTable[1000];
	FILE *fin;
    printf("Please input the filename:\n");
    scanf("%s", filename);
//    strcpy(filename, "PeSample/DllCallStatic.exe");
//    strcpy(filename, "PeSample/DllSample.dll");
    fin = fopen(filename, "rb");
    if (fin == NULL) {
        printf("%s, %s", filename, "not exists/n");
        return -1;
    }
    fread(&dosHeader, 0x200, 1, fin);
    peHeaderAddr = dosHeader.e_lfanew;
    fseek(fin, peHeaderAddr, SEEK_SET);
    fread(&peHeader, sizeof(PE_HEADER), 1, fin);
    importVirtualAddr = peHeader.OptionalHeader.ImportVirtualAddress;
    sectionNumber = peHeader.FileHeader.NumberOfSections;
    sectionHeaders = (SECTION_HEADER *) malloc(sizeof(SECTION_HEADER) * sectionNumber);
    fread(sectionHeaders, sizeof(SECTION_HEADER), sectionNumber, fin);
    importFileAddr = getFileAddr(sectionHeaders, importVirtualAddr, sectionNumber);

    fseek(fin, importFileAddr, SEEK_SET);

    fread(&importDescriptor, sizeof(importDescriptor), 1, fin);
    curImportAddr = ftell(fin);
    APINameFileAddr = getFileAddr(sectionHeaders, importDescriptor.OriginalFirstThunk, sectionNumber);

    // ��ÿ��dll�ļ���һ��ѭ��
    while(importDescriptor.OriginalFirstThunk != 0) {
        // ���dll�ļ���
        dllNameFileAddr = getFileAddr(sectionHeaders, importDescriptor.Name, sectionNumber);
        fseek(fin, dllNameFileAddr, SEEK_SET);
        fgets(dllName, 255, fin);
        printf("%s:\n", dllName);
        // ���ÿ��API��Ż�����
        fseek(fin, APINameFileAddr, SEEK_SET);
        i = -1;
        do {
            i++;
            fread(&(APINameTable[i]), sizeof(DWORD), 1, fin);
        } while (APINameTable[i] != 0);
        total = i;

        for (i = 0; i < total; i++) {
            if ((APINameTable[i] & 0x80000000) == 0) {
                fileAddr = getFileAddr(sectionHeaders, APINameTable[i], sectionNumber) + 2; // xx, xx ��APIName ���ļ�ƫ��
                fseek(fin, fileAddr, SEEK_SET);
                fgets(APIName, 255, fin);
              //printf("API name = %s\n", APIName);
				printf("%s\n", APIName);
            } else {
              //printf("API Ordinal Number = %x\n", APINameTable[i] & 0x7FFFFFFF);
				printf("%x\n", APINameTable[i] & 0x7FFFFFFF);
            }
        }

        fseek(fin, curImportAddr, SEEK_SET);
        fread(&importDescriptor, sizeof(importDescriptor), 1, fin);
        curImportAddr = ftell(fin);
        APINameFileAddr = getFileAddr(sectionHeaders, importDescriptor.OriginalFirstThunk, sectionNumber);
    }
	system("pause");
    return 0;
}