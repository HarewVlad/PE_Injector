#include <stdio.h>
#include <io.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>

#define MAXBUFFSIZE 8192
#define DWORD 4
#define WORD 2
#define BYTE 1

#define BYTE_TYPE(x)			__asm _emit x 
#define WORD_TYPE(x)			BYTE_TYPE((x>>(0*8))&0xFF)	BYTE_TYPE((x>>(1*8))&0xFF)
#define DWORD_TYPE(x)			BYTE_TYPE((x>>(0*8))&0xFF)	BYTE_TYPE((x>>(1*8))&0xFF)	BYTE_TYPE((x>>(2*8))&0xFF)	BYTE_TYPE((x>>(3*8))&0xFF)

#define BEGIN 0x223344
#define DATA 0x102132
#define END 0x556677

// unsigned int littleToBig(const unsigned char source[], int size)
// {
// 	unsigned int result = 0;
// 	for (int i = size - 1; i >= 0; --i)
// 	{
// 		if (source[i] == 0)
// 			continue;
// 		else
// 		{
// 			result |= source[i];

// 			if (i != 0)
// 				result <<= 8;
// 		}
// 	}
// 	return result;
// }


unsigned int getPosOfCode(unsigned int funcPointer, unsigned int value)
{
	unsigned int result = 0;
	__asm
	{
		mov eax, funcPointer
		jmp m_2
	m_1:
		inc eax
	m_2:
		mov ebx, [eax]
		cmp ebx, value
		jnz m_1
		mov result, eax
	}
	return result;
}

void SaveRead(void *dst, size_t sizeOfDst, int numToRead, FILE *f)
{
	if (!fread(dst, sizeOfDst, numToRead, f))
	{
		perror("Goddamn");
	}
}

void SaveWrite(void *dst, size_t sizeOfDst, int numToRead, FILE *f)
{
	if (!fwrite(dst, sizeOfDst, numToRead, f))
	{
		perror("Goddamn");
	}
}

// struct uintToArray_return
// {
// 	unsigned char *arr;
// 	int size;
// };

// struct uintToArray_return *uintToArray(const unsigned int source) // Little Endian
// {
// 	struct uintToArray_return *uTA_return = malloc(sizeof(struct uintToArray_return));
// 	int size = 0;
// 	int temp = source;
// 	while (temp & 0xFF)
// 	{
// 		size++;
// 		temp >>= 8;
// 	}

// 	unsigned char *arr = malloc(size);
// 	temp = source;
// 	for (int i = 0; i < size; ++i)
// 	{
// 		arr[i] = temp & 0xFF;
// 		temp >>= 8;
// 	}

// 	uTA_return->arr = arr;
// 	uTA_return->size = size;
// 	return uTA_return;
// }

void jmpToOEP()
{
	__asm
	{
		DWORD_TYPE(BEGIN)

	main_0:
		pushad
		call main_1
	main_1:
		pop ebp
		sub ebp, offset main_1

		mov eax, dword ptr ss : [ebp + dw_OEP]
		jmp eax

		DWORD_TYPE(DATA)

	dw_OEP:
		DWORD_TYPE(0xCCCCCCCC)

		DWORD_TYPE(END)
	}
}

int main()
{
	FILE *f = fopen("test.exe", "r+");

	if (f == NULL)
	{
		printf("Goddamn\n");
	}

	// PE OFFSET //
	unsigned int PEoffset = 0;
	fseek(f, 0x3C, SEEK_SET);
	SaveRead(&PEoffset, sizeof(unsigned int), 1, f);
	printf("RVA of PE header -> %x\n", PEoffset);

	// PE Optional Header //
	unsigned int PEOH = PEoffset + 0x18;

	// PE Section Table //
	unsigned int PEST = PEoffset + 0x0F8;

	// Name of Code section //
	unsigned char Name1_code[8 + 1];
	fseek(f, PEST, SEEK_SET);
	SaveRead(&Name1_code, sizeof(char), sizeof(Name1_code), f);

	// Pointer to raw data of code section //
	unsigned int p_RawData_code = 0;
	fseek(f, PEST + 0x14, SEEK_SET);
	SaveRead(&p_RawData_code, sizeof(unsigned int), 1, f);
	printf("PointerToRawData of %s section -> %x\n", Name1_code, p_RawData_code);

	// Size of raw data of code section //
	unsigned int sizeOfRawData_code = 0;
	fseek(f, PEoffset + 0x1C, SEEK_SET);
	SaveRead(&sizeOfRawData_code, sizeof(unsigned int), 1, f);
	printf("Size of code of %s section-> %x\n", Name1_code, sizeOfRawData_code);

	// Virtual size of code section //
	unsigned int virtualSize_code = 0;
	fseek(f, PEST + 0x8, SEEK_SET);
	SaveRead(&virtualSize_code, sizeof(unsigned int), 1, f);
	printf("Virtual size of %s section -> %x\n", Name1_code, virtualSize_code);

	printf("Free space in %s section -> %x\n", Name1_code, (sizeOfRawData_code - virtualSize_code));

	// Name of data section //
	unsigned char Name1_data[8 + 1];
	fseek(f, PEST + 0x28, SEEK_SET);
	SaveRead(&Name1_data, sizeof(char), sizeof(Name1_data), f);

	// Pointer to raw data of data section //
	unsigned int p_RawData_data = 0;
	fseek(f, PEST + 0x28 + 0x14, SEEK_SET);
	SaveRead(&p_RawData_data, sizeof(unsigned int), 1, f);
	printf("PointerToRawData of %s section -> %x\n", Name1_data, p_RawData_data);

	// Image base //
	unsigned int imageBase = 0;
	fseek(f, PEoffset + 0x34, SEEK_SET);
	SaveRead(&imageBase, sizeof(unsigned int), 1, f);
	printf("Image base -> %x\n", imageBase);

	// Pointer to free block of memory insize code section //
	unsigned int p_FreeBlock = p_RawData_data - (sizeOfRawData_code - virtualSize_code);
	printf("Beginning of a free block -> %x\n", p_FreeBlock);

	// Original entry point //
	unsigned int OEP = 0;
	fseek(f, PEoffset + 0x28, SEEK_SET);
	SaveRead(&OEP, sizeof(unsigned int), 1, f);
	printf("OEP -> %x\n", OEP);

	// Original entry point + image base //
	unsigned int OEP_imageBase = OEP + imageBase;
	printf("OEP_imageBase -> %x\n", OEP_imageBase);

	// Modified original entry point //
	unsigned int mod_OEP = p_FreeBlock - p_RawData_code + 0x1000;
	fseek(f, PEoffset + 0x28, SEEK_SET);
	SaveWrite(&mod_OEP, sizeof(unsigned int), 1, f);
	printf("Mod. OEP -> %x\n", mod_OEP);

	// Modified original entry point + image base //
	unsigned int mod_OEP_imageBase = mod_OEP + imageBase;
	printf("Mod. OEP_imageBase -> %x\n", mod_OEP_imageBase);

	// Inject code to PE file //
	// unsigned int begin_jmpOEP = getPosOfCode((unsigned int)jmpToOEP, BEGIN) + 4;
	// unsigned int end_jmpOEP = getPosOfCode((unsigned int)jmpToOEP, END);
	// unsigned int size_jmpOEP = end_jmpOEP - begin_jmpOEP;

	// unsigned char *buff_jmpOEP = malloc(size_jmpOEP + 1);
	// memset(buff_jmpOEP, 0, size_jmpOEP + 1);
	// memcpy(buff_jmpOEP, begin_jmpOEP, size_jmpOEP);

	// unsigned int data_jmpOEP = getPosOfCode((unsigned int)&buff_jmpOEP, DATA) + 4;
	// printf("data_jmpOEP -> %x\n", data_jmpOEP);
	// memcpy((void *)data_jmpOEP, (void *)OEP_imageBase, sizeof(unsigned int));


	// fseek(f, p_FreeBlock, SEEK_SET);
	// SaveWrite((void *)begin_jmpOEP, sizeof(unsigned char), size_jmpOEP, f);

	// Get code //
	unsigned int begin_jmpOEP = getPosOfCode((unsigned int)jmpToOEP, BEGIN) + 4;
	unsigned int data_jmpOEP = getPosOfCode((unsigned int)jmpToOEP, DATA) + 4;
	unsigned int end_jmpOEP = getPosOfCode((unsigned int)jmpToOEP, END);
	unsigned int sizeCode_jmpOEP = data_jmpOEP - begin_jmpOEP;
	unsigned int sizeData_jmpOEP = end_jmpOEP - data_jmpOEP;

	printf("begin_jmpOEP -> %x\n", begin_jmpOEP);
	printf("end_jmpOEP -> %x\n", end_jmpOEP);
	printf("sizeCode_jmpOEP -> %x\n", sizeCode_jmpOEP);
	printf("sizeData_jmpOEP -> %x\n", sizeData_jmpOEP);

	unsigned char *buff_jmpOEP = malloc(sizeCode_jmpOEP + sizeData_jmpOEP + 1);
	memset((void *)buff_jmpOEP, 0, sizeCode_jmpOEP + sizeData_jmpOEP + 1);
	memcpy((void *)buff_jmpOEP, (void *)begin_jmpOEP, sizeCode_jmpOEP);
	memcpy(&buff_jmpOEP[sizeCode_jmpOEP], (void *)data_jmpOEP, sizeData_jmpOEP);

	// Fill the data //
	memcpy(&buff_jmpOEP[sizeCode_jmpOEP], (void *)&OEP_imageBase, sizeData_jmpOEP);

	// Inject //
	fseek(f, p_FreeBlock, SEEK_SET);
	SaveWrite((void *)buff_jmpOEP, sizeof(unsigned char), sizeCode_jmpOEP + sizeData_jmpOEP, f);

	// Change virtual size of code //
	unsigned int mod_VirtualSize_code = virtualSize_code + sizeCode_jmpOEP + sizeData_jmpOEP;
	fseek(f, PEST + 0x8, SEEK_SET);
	SaveWrite(&mod_VirtualSize_code, sizeof(unsigned int), 1, f);

	// Trying to call already imported function //
	unsigned int IAT = PEoffset + 0x80;
	printf("IAT -> %x\n", IAT);
	unsigned int orig_FirstChank = 0;
	fseek(f, IAT, SEEK_SET);
	SaveRead(&orig_FirstChank, sizeof(unsigned int), 1, f);
	printf("orig_FirstChank -> %x\n", orig_FirstChank);
}