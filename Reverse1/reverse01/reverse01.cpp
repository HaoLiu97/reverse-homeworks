// reverse01.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <stdio.h>
#include <iostream>

using namespace std;

unsigned char ROL(unsigned char val, int n)
{
    return (val << n) | (val >> (8 - n));
}

unsigned char ROR(unsigned char val, int n)
{
    return (val >> n) | (val << (8 - n));
}

int main() {
    unsigned int magicNumber = 0xDEADBEEF;
    union Mcode{
        unsigned char byte[4];
        unsigned int Code;
    } MachineCode;
	printf("Please input your machine number :\n");
	scanf("%x", &MachineCode.Code);
	MachineCode.Code = 0x5E7F5EE6;
    printf("The machine code you input is :\n%X\n", MachineCode.Code);
    MachineCode.Code ^= magicNumber;
    //printf("%X\n", MachineCode.Code);
    MachineCode.byte[0] = ROR(MachineCode.byte[0], 2);
    //printf("%X\n", MachineCode.Code);
    MachineCode.byte[1] = ROL(MachineCode.byte[1], 3);
    //printf("%X\n", MachineCode.Code);
    MachineCode.byte[2] -= 0x42;
    //printf("%X\n", MachineCode.Code);
    MachineCode.byte[3] += 0x57;
    printf("The serial number for your machine is :\n%X\n", MachineCode.Code);
	system("pause");
    return 0;
}