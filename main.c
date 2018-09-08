#include <stdio.h>
#include <io.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>

#define MAX_BUFF 256
#define DWORD 4
#define WORD 2
#define BYTE 1

#define SECTION_ALIGN 0x1000
#define FILE_ALIGN 0x200

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

void SaveWrite(void *dst, size_t sizeOfDst, int numToWrite, FILE *f)
{
	if (!fwrite(dst, sizeOfDst, numToWrite, f))
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

unsigned int PEAlign(unsigned int from, unsigned int to)
{	
	return (((from + to - 1) / to) * to);
}

struct IMAGE_SECTION_HEADER
{
	unsigned char Name1[8];
	unsigned int virtualSize;
	unsigned int virtualAddress;
	unsigned int sizeOfRawData;
	unsigned int pointerToRawData;
	unsigned int pointerToRelocations;
	unsigned int pointerToLinenumbers;
	unsigned short numberOfRelocations;
	unsigned short numberOfLineNumbers;
	unsigned int characteristic;
} ish[64];

struct PEstuff
{
	unsigned int PEoffset;
	unsigned int PEOH;
	unsigned int PEST;

	unsigned int imageBase;
	unsigned int OEP;

	unsigned short numberOfSections;
	unsigned int sizeOfImage;

	struct IMAGE_SECTION_HEADER *p_ish;
};

void fillPEstuff(struct PEstuff *pes, FILE *f)
{
	// PE OFFSET //
	fseek(f, 0x3C, SEEK_SET);
	SaveRead(&pes->PEoffset, sizeof(unsigned int), 1, f);

	// PE Optional Header //
	pes->PEOH = pes->PEoffset + 0x18;

	// PE Section Table //
	pes->PEST = pes->PEoffset + 0x0F8;

	// Image base //
	fseek(f, pes->PEoffset + 0x34, SEEK_SET);
	SaveRead(&pes->imageBase, sizeof(unsigned int), 1, f);

	// Original entry point //
	fseek(f, pes->PEoffset + 0x28, SEEK_SET);
	SaveRead(&pes->OEP, sizeof(unsigned int), 1, f);

	// Number of sectionss //
	fseek(f, pes->PEoffset + 6, SEEK_SET);
	SaveRead(&pes->numberOfSections, sizeof(unsigned short), 1, f);

	// SizeOfImage //
	fseek(f, pes->PEoffset + 0x50, SEEK_SET);
	SaveRead(&pes->sizeOfImage, sizeof(unsigned int), 1, f);

	int offset = 0x0F8;
	for (int i = 0; i < pes->numberOfSections; i++)
	{
		fseek(f, pes->PEoffset + offset, SEEK_SET);
		SaveRead(&pes->p_ish[i], sizeof(struct IMAGE_SECTION_HEADER), 1, f);
		offset += 0x28;
	}
}

void printSections(struct PEstuff *pes, int i)
{
	printf("Name1 -> %s\n", pes->p_ish[i].Name1);
	printf("Virtual size -> %x\n", pes->p_ish[i].virtualSize);
	printf("Virtual address -> %x\n", pes->p_ish[i].virtualAddress);
	printf("Size of raw data -> %x\n", pes->p_ish[i].sizeOfRawData);
	printf("Pointer to raw data -> %x\n", pes->p_ish[i].pointerToRawData);
	printf("Characteristic -> %x\n", pes->p_ish[i].characteristic);
}

void alignSections(struct PEstuff *pes, FILE *f)
{
	for (int i = 0; i < pes->numberOfSections; i++)
	{
		// printf("Section %d -> \n", i);
		pes->p_ish[i].virtualSize = PEAlign(pes->p_ish[i].virtualSize, SECTION_ALIGN);
		pes->p_ish[i].virtualAddress = PEAlign(pes->p_ish[i].virtualAddress, SECTION_ALIGN);
		pes->p_ish[i].sizeOfRawData = PEAlign(pes->p_ish[i].sizeOfRawData, FILE_ALIGN);
		pes->p_ish[i].pointerToRawData = PEAlign(pes->p_ish[i].pointerToRawData, FILE_ALIGN);
		// printSections(pes, i);
	}
	// Write //
	int offset = 0x0F8;
	for (int i = 0; i < pes->numberOfSections; i++)
	{
		fseek(f, pes->PEoffset + offset, SEEK_SET);
		SaveWrite(&pes->p_ish[i], sizeof(struct IMAGE_SECTION_HEADER), 1, f);
		offset += 0x28;
	}

	// Change sizeOfImage //
	fseek(f, pes->PEoffset + 0x50, SEEK_SET);
	pes->sizeOfImage = pes->p_ish[pes->numberOfSections - 1].virtualAddress
	 + pes->p_ish[pes->numberOfSections - 1].virtualSize;
	SaveWrite(&pes->sizeOfImage, sizeof(unsigned int), 1, f);
}

void createNewSection(struct PEstuff *pes, FILE *f, unsigned int size)
{
	// Fill new section //
	unsigned char temp_Name1[8] = ".NEW";
	memcpy(pes->p_ish[pes->numberOfSections].Name1, temp_Name1, sizeof(temp_Name1));
	pes->p_ish[pes->numberOfSections].virtualAddress = PEAlign(pes->p_ish[pes->numberOfSections - 1].virtualAddress
		+ pes->p_ish[pes->numberOfSections - 1].virtualSize, SECTION_ALIGN);
	pes->p_ish[pes->numberOfSections].virtualSize = PEAlign(size, SECTION_ALIGN);
	pes->p_ish[pes->numberOfSections].sizeOfRawData = PEAlign(size, FILE_ALIGN);
	pes->p_ish[pes->numberOfSections].pointerToRawData = PEAlign(pes->p_ish[pes->numberOfSections - 1].pointerToRawData
		+ pes->p_ish[pes->numberOfSections - 1].sizeOfRawData, FILE_ALIGN);
	pes->p_ish[pes->numberOfSections].characteristic = 0xE0000040;

	// Write new section //
	int offset = 0x0F8 + pes->numberOfSections * 0x28;
	fseek(f, pes->PEoffset + offset, SEEK_SET);
	SaveWrite(&pes->p_ish[pes->numberOfSections], sizeof(struct IMAGE_SECTION_HEADER), 1, f);

	// Enlarge the file //
	fseek(f, 0, SEEK_END);
	unsigned int numToWrite = pes->p_ish[pes->numberOfSections].virtualSize;
	unsigned char *byte = malloc(numToWrite);
	SaveWrite(byte, sizeof(unsigned char), numToWrite, f);

	free(byte);

	// Change numberOfSections ++ //
	fseek(f, pes->PEoffset + 6, SEEK_SET);
	pes->numberOfSections++;
	SaveWrite(&pes->numberOfSections, sizeof(unsigned short), 1, f);
}

void injectCode(struct PEstuff *pes, FILE *f)
{
	unsigned int begin_jmpOEP = getPosOfCode((unsigned int)jmpToOEP, BEGIN) + 4;
	unsigned int data_jmpOEP = getPosOfCode((unsigned int)jmpToOEP, DATA) + 4;
	unsigned int end_jmpOEP = getPosOfCode((unsigned int)jmpToOEP, END);
	unsigned int sizeCode_jmpOEP = data_jmpOEP - begin_jmpOEP;
	unsigned int sizeData_jmpOEP = end_jmpOEP - data_jmpOEP;

	// printf("begin_jmpOEP -> %x\n", begin_jmpOEP);
	// printf("end_jmpOEP -> %x\n", end_jmpOEP);
	// printf("sizeCode_jmpOEP -> %x\n", sizeCode_jmpOEP);
	// printf("sizeData_jmpOEP -> %x\n", sizeData_jmpOEP);

	unsigned char *buff_jmpOEP = malloc(sizeCode_jmpOEP + sizeData_jmpOEP + 1);
	memset((void *)buff_jmpOEP, 0, sizeCode_jmpOEP + sizeData_jmpOEP + 1);
	memcpy((void *)buff_jmpOEP, (void *)begin_jmpOEP, sizeCode_jmpOEP);
	memcpy(&buff_jmpOEP[sizeCode_jmpOEP], (void *)data_jmpOEP, sizeData_jmpOEP);

	// Fill the data //
	unsigned int OEP_imageBase = pes->OEP + pes->imageBase;
	memcpy(&buff_jmpOEP[sizeCode_jmpOEP], &OEP_imageBase, sizeData_jmpOEP);

	// Inject //
	fseek(f, pes->p_ish[pes->numberOfSections - 1].pointerToRawData, SEEK_SET);
	SaveWrite(buff_jmpOEP, sizeof(unsigned char), sizeCode_jmpOEP + sizeData_jmpOEP, f);

	// Change OEP //
	fseek(f, pes->PEoffset + 0x28, SEEK_SET);
	SaveWrite(&pes->p_ish[pes->numberOfSections - 1].virtualAddress, sizeof(unsigned int), 1, f);
}

int main()
{
	FILE *f = fopen("test.exe", "r+");

	if (f == NULL)
	{
		printf("Goddamn\n");
	}

	struct PEstuff *pes = malloc(sizeof(struct PEstuff));
	pes->p_ish = &ish[0];

	fillPEstuff(pes, f);
	createNewSection(pes, f, 0x2000);
	alignSections(pes, f);
	injectCode(pes, f);
}
