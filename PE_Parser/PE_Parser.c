#include <stdio.h>
#include <Windows.h>

struct _IMAGE_DOS_HEADER dosHeader;

struct RichHeader {
	DWORD dansID;
	DWORD checksumedPadding[3];
	DWORDLONG compID[10];
};

struct CustomNTHeader {
	DWORD Signature;
	IMAGE_FILE_HEADER FileHeader;
};


struct ImportDirectory {
	DWORD   VirtualAddress;
	DWORD   Size;
} importDirectory;

struct RelocationDirectory {
	DWORD   VirtualAddress;
	DWORD   Size;
} relocDirectory;

struct CustomImageImportByName {
	WORD Hint;
};

struct Entry {
	WORD item;
};

byte* tmpSectionPointer;
int numOfSections = 0;

void read_dos_header();
void read_rich_header(HANDLE, int, DWORD);
int read_NT_header(HANDLE);
HANDLE read_section_headers(HANDLE);
void read_import_directory(TCHAR[]);
DWORD resolveOffset(DWORD);

void read_relocation_directory(TCHAR[]);

WORD magic = 0x0;

const DWORDLONG x64MSB = 1 << ((sizeof(DWORDLONG) * 8) - 1);
const DWORD x32MSB = 1 << ((sizeof(DWORD) * 8) - 1);



void main(int argc, TCHAR* args[])
{
	ZeroMemory(&dosHeader, sizeof(dosHeader));

	//printf("%d\n", sizeof(dosHeader));

	char* tmpPath = NULL;
	TCHAR path[100];

	if (argc < 2) {
		printf("\n plz enter the path.. \n");
		return;
	}
	else if (argc > 2) {
		printf("\n One one argument is required \n");
		return;
	}
	else if (argc == 2) {
		tmpPath = args[1];
		swprintf(path, sizeof(path), L"%hs", tmpPath);
	}

	HANDLE fileHandle = INVALID_HANDLE_VALUE;
	fileHandle = CreateFile(path, GENERIC_READ, 0, NULL, OPEN_EXISTING, NULL, NULL);

	if (fileHandle != INVALID_HANDLE_VALUE) {
		//printf("success opening file\n");

		DWORD byteRead;

		if (ReadFile(fileHandle, &dosHeader, sizeof(dosHeader), &byteRead, NULL) != 0) {
			//printf("success reading file %lu\n", byteRead);

			read_dos_header();
		}

		int rich_header_size = abs(sizeof(dosHeader) - dosHeader.e_lfanew);

		// reading rich header

		read_rich_header(fileHandle, rich_header_size, byteRead);

		// reading NT Header

		numOfSections = read_NT_header(fileHandle);

		HANDLE hHeapSectionHeader = read_section_headers(fileHandle);

		CloseHandle(fileHandle);

		read_import_directory(path);

		read_relocation_directory(path);

		HeapFree(hHeapSectionHeader, 0, tmpSectionPointer);
		CloseHandle(hHeapSectionHeader);

	}
}

void read_relocation_directory(TCHAR filePath[]) {
	printf("\n");
	printf("\n");
	printf("\n");
	printf("IMAGE BASE RELOCATION\n");
	printf("------------------------\n");
	printf("\n");

	printf("reloc directory RVA: %X\n", relocDirectory.VirtualAddress);

	int relocDirectoryOffset = resolveOffset(relocDirectory.VirtualAddress);

	printf("reloc Directory offset: %X\n", relocDirectoryOffset);

	printf("\n");

	struct _IMAGE_BASE_RELOCATION imageBaseRelocation;
	TCHAR *path = filePath;

	HANDLE hFile = INVALID_HANDLE_VALUE;

	int bytesRead = 0;

	hFile = CreateFile(path, GENERIC_READ, 0, NULL, OPEN_EXISTING, NULL, NULL);
	SetFilePointer(hFile, relocDirectoryOffset, NULL, FILE_BEGIN);
	char* virtualAddress = "virtual address";
	char* blockSize = "block size";
	char* item = "item";
	char* itemOffset = "offset";
	char* itemType = "type";

	do {

		if (ReadFile(hFile, &imageBaseRelocation, sizeof(imageBaseRelocation), &bytesRead, NULL) != 0) {
			if (imageBaseRelocation.SizeOfBlock != 0x0 && imageBaseRelocation.VirtualAddress != 0x0) {
				printf("%-15s: %-15X\n",virtualAddress, imageBaseRelocation.VirtualAddress);
				printf("%-15s: %-15X\n",blockSize, imageBaseRelocation.SizeOfBlock);
			}
		}

		HANDLE hHeap = GetProcessHeap();
		byte* block = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, imageBaseRelocation.SizeOfBlock);

		struct Entry entry;

		if (ReadFile(hFile, block, imageBaseRelocation.SizeOfBlock, &bytesRead, NULL) != 0) {

			int itemcount = 0;

			WORD offset;
			byte type;


			do {
				CopyMemory(&entry, block + (sizeof(entry) * itemcount), sizeof(entry));

				if (entry.item != 0x0) {

					WORD tmpOffset = entry.item << 4;
					offset = tmpOffset >> 4;

					type = entry.item >> 12;



					printf("%-6s: %-15X %-6s: %-15X %-6s: %-5X\n", item, entry.item, itemOffset, offset, itemType, type);
				}
				itemcount++;

			} while (entry.item != 0x0);
			itemcount = 0;
		}
		else {
			printf("error reading file");
		}

		HeapFree(hHeap, 0, block);
		CloseHandle(hHeap);

	} while (imageBaseRelocation.SizeOfBlock !=0x0 && imageBaseRelocation.SizeOfBlock != 0x0);

	CloseHandle(hFile);

}

void read_import_directory(TCHAR filePath[]) {

	printf("\n");
	printf("\n");
	printf("\n");
	printf("IMAGE IMPORT DISCRIPTOR\n");
	printf("------------------------\n");
	printf("\n");

	TCHAR *path = filePath;

	struct _IMAGE_IMPORT_DESCRIPTOR image_import_descriptor;

	DWORD offset = resolveOffset(importDirectory.VirtualAddress);

	//printf("import directory offset: %X\n", offset);

	HANDLE hFile = INVALID_HANDLE_VALUE;

	hFile = CreateFile(path, GENERIC_READ, 0, NULL, OPEN_EXISTING, NULL, NULL);

	if (hFile != INVALID_HANDLE_VALUE) {
		DWORD movedBytes = SetFilePointer(hFile, offset, NULL, FILE_BEGIN);
		//printf("moved bytes: %X\n", movedBytes);

		DWORD bytesRead = 0;

		int imageImportDescriptorCount = 0;

		while (1)
		{
			struct _IMAGE_IMPORT_DESCRIPTOR descriptor;
			if (ReadFile(hFile, &descriptor, sizeof(descriptor), &bytesRead, NULL) != 0) {
				if (descriptor.Name == 0x0 && descriptor.FirstThunk == 0x0) {
					break;
				}
				imageImportDescriptorCount++;
			}
		}

		//printf("descriptor count: %X\n", imageImportDescriptorCount);

		HANDLE hHeap = GetProcessHeap();

		byte* tmpImageImoprtDescriptorScape = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, sizeof(image_import_descriptor) * imageImportDescriptorCount);
		SetFilePointer(hFile, offset, NULL, FILE_BEGIN);


		if (ReadFile(hFile, tmpImageImoprtDescriptorScape, sizeof(image_import_descriptor) * imageImportDescriptorCount, &bytesRead, NULL) != 0) {

			for (int i = 0; i < imageImportDescriptorCount; i++) {
				CopyMemory(&image_import_descriptor, tmpImageImoprtDescriptorScape + (sizeof(image_import_descriptor) * i), sizeof(image_import_descriptor));

				printf("OrginalFirstThunk (ILT RVA): %X\n", image_import_descriptor.OriginalFirstThunk);

				printf("|----> IMPORT LOOKUP TABLE (struct _IMAGE_THUNK_DATA) <----|\n");

				if (magic == 0x10b) {

				}
				else if (magic == 0x20b) {
					struct _IMAGE_THUNK_DATA64 imageThunkData;

					int ILT_Offset = resolveOffset(image_import_descriptor.OriginalFirstThunk);

					printf("|----> ITL offset: %X\n", ILT_Offset);

					int imageThunkDataCount = 0;


					while(1) {
						SetFilePointer(hFile, ILT_Offset + (sizeof(imageThunkData) * imageThunkDataCount), NULL, FILE_BEGIN);

						if (ReadFile(hFile, &imageThunkData, sizeof(imageThunkData), &bytesRead, NULL) != 0) {
							if (imageThunkData.u1.AddressOfData == 0x0 && imageThunkData.u1.Ordinal == 0x0) {
								break;
							}
							imageThunkDataCount++;

						}
						else {
							break;
						}
					}

					printf("|----> imageThunkDataCount: %d\n", imageThunkDataCount);

					byte* tmpImageThunkDataSpace = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, sizeof(imageThunkData) * imageThunkDataCount);

					SetFilePointer(hFile, ILT_Offset, NULL, FILE_BEGIN);

					if (ReadFile(hFile, tmpImageThunkDataSpace, sizeof(imageThunkData) * imageThunkDataCount, &bytesRead, NULL) != 0) {
						for (int i = 0; i < imageThunkDataCount; i++) {
							CopyMemory(&imageThunkData, tmpImageThunkDataSpace + (sizeof(imageThunkData) * i), sizeof(imageThunkData));

							printf("|----> image hint RVA %llX\n", imageThunkData.u1.AddressOfData);

							if (imageThunkData.u1.AddressOfData & x64MSB) {

							}
							else {
								struct CustomImageImportByName customImageImportByName;

								int imageImportByNameOffset = resolveOffset(imageThunkData.u1.AddressOfData);
								printf("|----> import by name offset: %X\n", imageImportByNameOffset);

								SetFilePointer(hFile, imageImportByNameOffset, NULL, FILE_BEGIN);

								printf("|\n");
								printf("|--------> HINT (struct _IMPORT_BY_NAME) <----|\n");

								if (ReadFile(hFile, &customImageImportByName, sizeof(customImageImportByName), &bytesRead, NULL) != 0) {
									printf("|--------> Hint: %X\n", customImageImportByName.Hint);


									int nameCount = 0;
									byte name = 0x0;

									do {
										if (ReadFile(hFile, &name, sizeof(byte), &bytesRead, NULL) != 0) {
											nameCount++;
										}
										else
										{
											break;
										}
									} while (name != 0x0);

									//printf("name count: %d\n", nameCount);

									SetFilePointer(hFile, imageImportByNameOffset + sizeof(customImageImportByName), NULL, FILE_BEGIN);

									byte* namePointer = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, nameCount);

									if (ReadFile(hFile, namePointer, nameCount, &bytesRead, NULL) != 0) {
										printf("|--------> function name: %s\n", namePointer);
									}
									else {
										printf("\n Error Reading File \n");
									}

									HeapFree(hHeap, 0, namePointer);


								}
								else {
									printf("\n Error Reading File \n");
								}

							}

						}
					}
					else {
						printf("\n Error Reading File \n");
					}


					imageThunkDataCount = 0;

					HeapFree(hHeap, 0, tmpImageThunkDataSpace);



				}


				printf("TimeDateStamp: %X\n", image_import_descriptor.TimeDateStamp);
				printf("ForwarderChain: %X\n", image_import_descriptor.ForwarderChain);
				printf("Name RVA: %X\n", image_import_descriptor.Name);
				

				int nameOffset = resolveOffset(image_import_descriptor.Name);

				printf("|----> name offset: %X\n", nameOffset);

				
				int nameSize = 0;

				byte point = 0x0;

				do {
					SetFilePointer(hFile, nameOffset + nameSize, NULL, FILE_BEGIN);
					if (ReadFile(hFile, &point, sizeof(byte), &bytesRead, NULL) != 0) {
						nameSize++;
					}
					else {
						break;
					}
				} while (point != 0x0);

				//printf("name size: %d\n", nameSize);

				SetFilePointer(hFile, nameOffset, NULL, FILE_BEGIN);

				byte* name = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, nameSize);

				if (ReadFile(hFile, name, nameSize, &bytesRead, NULL) != 0) {
					printf("|----> name: %s\n", name);
				}

				printf("FirstThunk (IAT RVA): %X\n", image_import_descriptor.FirstThunk);

				printf("\n\n");

			}

		}

		HeapFree(hHeap, 0, tmpImageImoprtDescriptorScape);
		CloseHandle(hHeap);

	}
	else {
		printf("Invalid handle");
	}

	CloseHandle(hFile);

}

DWORD resolveOffset(DWORD virtualAddress) {
	DWORD offset = 0;

	struct _IMAGE_SECTION_HEADER imageSectionHeader;

	for (int i = 0; i < numOfSections; i++) {
		CopyMemory(&imageSectionHeader, tmpSectionPointer + (sizeof(imageSectionHeader) * i), sizeof(imageSectionHeader));
		if (virtualAddress >= imageSectionHeader.VirtualAddress && virtualAddress < (imageSectionHeader.VirtualAddress + imageSectionHeader.Misc.VirtualSize)) {
			break;
		}
	}

	offset = (virtualAddress - imageSectionHeader.VirtualAddress) + imageSectionHeader.PointerToRawData;

	return offset;
}



HANDLE read_section_headers(HANDLE fileHandle) {
	printf("\n");
	printf("\n");
	printf("\n");
	printf("SECTION HEADER\n");
	printf("---------------\n");
	printf("\n");

	char* Name = "Name";
	char* VirtualSize = "VirtualSize";
	char* VirtualAddress = "VirtualAddress";
	char* SizeOfRawData = "SizeOfRawData";
	char* PointerToRawData = "PointerToRawData";
	char* PointerToRelocations = "PointerToRelocations";
	char* PointerToLinenumbers = "PointerToLinenumbers";
	char* NumberOfRelocations = "NumberOfRelocations";
	char* NumberOfLinenumbers = "NumberOfLinenumbers";
	char* Characteristics = "Characteristics";

	printf("%-15s %-15s %-15s %-15s %-15s %-15s %-15s %-15s %-15s %-15s\n", 
		Name, 
		VirtualSize, 
		VirtualAddress, 
		SizeOfRawData, 
		PointerToRawData, 
		PointerToRelocations, 
		PointerToLinenumbers, 
		NumberOfRelocations, 
		NumberOfLinenumbers, 
		Characteristics);


	HANDLE hHeapSectionHeader = GetProcessHeap();

	struct _IMAGE_SECTION_HEADER imageSectionHeader;

	tmpSectionPointer = HeapAlloc(hHeapSectionHeader, HEAP_ZERO_MEMORY, sizeof(imageSectionHeader) * numOfSections);

	DWORD bytesRead = 0;

	if (ReadFile(fileHandle, tmpSectionPointer, sizeof(imageSectionHeader) * numOfSections, &bytesRead, NULL) != 0) {

		for (int i = 0; i < numOfSections; i++) {
			CopyMemory(&imageSectionHeader, tmpSectionPointer + (sizeof(imageSectionHeader) * i), sizeof(imageSectionHeader));

			printf("%-18.*s%-18X %-18X %-18X %-18X %-18X %-18X %-18X %-18X %-18X\n", 8, imageSectionHeader.Name,
				imageSectionHeader.Misc.VirtualSize,
				imageSectionHeader.VirtualAddress,
				imageSectionHeader.SizeOfRawData,
				imageSectionHeader.PointerToRawData,
				imageSectionHeader.PointerToRelocations,
				imageSectionHeader.PointerToLinenumbers,
				imageSectionHeader.NumberOfRelocations,
				imageSectionHeader.NumberOfLinenumbers,
				imageSectionHeader.Characteristics);

		}

	}

	return hHeapSectionHeader;
}

int read_NT_header(HANDLE fileHandle) {

	int numOfSection = 0;

	printf("\n");
	printf("\n");
	printf("\n");
	printf("NT HEADER\n");
	printf("---------------\n");
	printf("\n");

	struct CustomNTHeader customNTHeader;

	DWORD bytesRead;

	char* signature = "Signature";
	char* machine = "Machine";
	char* numOfSections = "Number Of Sections";
	char* timeDateStamp = "Time Date Stamp";
	char* pointerToSymbolTable = "Pointer To Symbol Table";
	char* numberOfSymbols = "Number Of Symbols";
	char* sizeOfOptionalHeader = "Size Of Optional Header";
	char* characteristics = "Characteristics";


	if (ReadFile(fileHandle, &customNTHeader, sizeof(customNTHeader), &bytesRead, NULL) != 0) {

		numOfSection = customNTHeader.FileHeader.NumberOfSections;

		printf("%-25s: %-25X\n", signature, customNTHeader.Signature);

		printf("\n");
		printf("\n");
		printf("[*] FILE HEADER: \n");
		printf("\n");

		printf("%-25s: %-25X\n", machine, customNTHeader.FileHeader.Machine);
		printf("%-25s: %-25X\n", numOfSections, customNTHeader.FileHeader.NumberOfSections);
		printf("%-25s: %-25X\n", timeDateStamp, customNTHeader.FileHeader.TimeDateStamp);
		printf("%-25s: %-25X\n", pointerToSymbolTable, customNTHeader.FileHeader.PointerToSymbolTable);
		printf("%-25s: %-25X\n", numberOfSymbols, customNTHeader.FileHeader.NumberOfSymbols);
		printf("%-25s: %-25X\n", sizeOfOptionalHeader, customNTHeader.FileHeader.SizeOfOptionalHeader);
		printf("%-25s: %-25X\n", characteristics, customNTHeader.FileHeader.Characteristics);

		HANDLE hHeap = GetProcessHeap();

		byte* tmpOptionalHeader = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, customNTHeader.FileHeader.SizeOfOptionalHeader);

		if (ReadFile(fileHandle, tmpOptionalHeader, customNTHeader.FileHeader.SizeOfOptionalHeader, &bytesRead, NULL) != 0) {

			CopyMemory(&magic, tmpOptionalHeader, sizeof(WORD));

			char* Magic = "Magic";
			char* MajorLinkerVersion = "MajorLinkerVersion";
			char* MinorLinkerVersion = "MinorLinkerVersion";
			char* SizeOfCode = "SizeOfCode";
			char* SizeOfInitializedData = "SizeOfInitializedData";
			char* SizeOfUninitializedData = "SizeOfUninitializedData";
			char* AddressOfEntryPoint = "AddressOfEntryPoint";
			char* BaseOfCode = "BaseOfCode";
			char* BaseOfData = "BaseOfData"; // only on 32 bits

			//
			// NT additional fields.
			//

			char* ImageBase = "ImageBase";
			char* SectionAlignment = "SectionAlignment";
			char* FileAlignment = "FileAlignment";
			char* MajorOperatingSystemVersion = "MajorOperatingSystemVersion";
			char* MinorOperatingSystemVersion = "MinorOperatingSystemVersion";
			char* MajorImageVersion = "MajorImageVersion";
			char* MinorImageVersion = "MinorImageVersion";
			char* MajorSubsystemVersion = "MajorSubsystemVersion";
			char* MinorSubsystemVersion = "MinorSubsystemVersion";
			char* Win32VersionValue = "Win32VersionValue";
			char* SizeOfImage = "SizeOfImage";
			char* SizeOfHeaders = "SizeOfHeaders";
			char* CheckSum = "CheckSum";
			char* Subsystem = "Subsystem";
			char* DllCharacteristics = "DllCharacteristics";
			char* SizeOfStackReserve = "SizeOfStackReserve";
			char* SizeOfStackCommit = "SizeOfStackCommit";
			char* SizeOfHeapReserve = "SizeOfHeapReserve";
			char* SizeOfHeapCommit = "SizeOfHeapCommit";
			char* LoaderFlags = "LoaderFlags";
			char* NumberOfRvaAndSizes = "NumberOfRvaAndSizes";

			char* ExportDirectory = "Export Directory";
			char* ImportDirectory = "Import Directory";
			char* ResourceDirectory = "Resource Directory";
			char* ExceptionDirectory = "Exception Directory";
			char* SecurityDirectory = "Security Directory";
			char* RelocationDirectory = "Relocation Directory";
			char* DebugDirectory = "Debug Directory";
			char* ArchitectureDirectory = "Architecture Directory";
			char* GlobalPtr = "Global Pointer Directory";
			char* TLSDirectory = "TLS Directory";
			char* ConfigurationDirectory = "Configuration Directory";
			char* BoundImportDirectory = "Bound Import Directory";
			char* IATDirectory = "IAT Directory";
			char* DelayImportDirectory = "Delay Import Directory";
			char* dotNetMetaDataDirectory = ".Net MetaData Directory";


			if (magic == 0x10b) {

			}
			else if (magic == 0x20b) {
				struct _IMAGE_OPTIONAL_HEADER64 imageOptionalHeader;

				CopyMemory(&imageOptionalHeader, tmpOptionalHeader, customNTHeader.FileHeader.SizeOfOptionalHeader);

				printf("\n");
				printf("\n");
				printf("[*] OPTIONAL HEADER: \n");
				printf("\n");

				printf("%-25s: %-25X\n", Magic, imageOptionalHeader.Magic);
				printf("%-25s: %-25X\n", MajorLinkerVersion, imageOptionalHeader.MajorLinkerVersion);
				printf("%-25s: %-25X\n", MinorLinkerVersion, imageOptionalHeader.MinorLinkerVersion);
				printf("%-25s: %-25X\n", SizeOfCode, imageOptionalHeader.SizeOfCode);
				printf("%-25s: %-25X\n", SizeOfInitializedData, imageOptionalHeader.SizeOfInitializedData);
				printf("%-25s: %-25X\n", SizeOfUninitializedData, imageOptionalHeader.SizeOfUninitializedData);
				printf("%-25s: %-25X\n", AddressOfEntryPoint, imageOptionalHeader.AddressOfEntryPoint);
				printf("%-25s: %-25X\n", BaseOfCode, imageOptionalHeader.BaseOfCode);
				printf("%-25s: %-25X\n", ImageBase, imageOptionalHeader.ImageBase);
				printf("%-25s: %-25X\n", SectionAlignment, imageOptionalHeader.SectionAlignment);
				printf("%-25s: %-25X\n", FileAlignment, imageOptionalHeader.FileAlignment);
				printf("%-25s: %-25X\n", MajorOperatingSystemVersion, imageOptionalHeader.MajorOperatingSystemVersion);
				printf("%-25s: %-25X\n", MinorOperatingSystemVersion, imageOptionalHeader.MinorOperatingSystemVersion);
				printf("%-25s: %-25X\n", MajorImageVersion, imageOptionalHeader.MajorImageVersion);
				printf("%-25s: %-25X\n", MinorImageVersion, imageOptionalHeader.MinorImageVersion);
				printf("%-25s: %-25X\n", MajorSubsystemVersion, imageOptionalHeader.MajorSubsystemVersion);
				printf("%-25s: %-25X\n", MinorSubsystemVersion, imageOptionalHeader.MinorSubsystemVersion);
				printf("%-25s: %-25X\n", Win32VersionValue, imageOptionalHeader.Win32VersionValue);
				printf("%-25s: %-25X\n", SizeOfImage, imageOptionalHeader.SizeOfImage);
				printf("%-25s: %-25X\n", SizeOfHeaders, imageOptionalHeader.SizeOfHeaders);
				printf("%-25s: %-25X\n", CheckSum, imageOptionalHeader.CheckSum);
				printf("%-25s: %-25X\n", Subsystem, imageOptionalHeader.Subsystem);
				printf("%-25s: %-25X\n", DllCharacteristics, imageOptionalHeader.DllCharacteristics);
				printf("%-25s: %-25X\n", SizeOfStackReserve, imageOptionalHeader.SizeOfStackReserve);
				printf("%-25s: %-25X\n", SizeOfStackCommit, imageOptionalHeader.SizeOfStackCommit);
				printf("%-25s: %-25X\n", SizeOfHeapReserve, imageOptionalHeader.SizeOfHeapReserve);
				printf("%-25s: %-25X\n", SizeOfHeapCommit, imageOptionalHeader.SizeOfHeapCommit);
				printf("%-25s: %-25X\n", LoaderFlags, imageOptionalHeader.LoaderFlags);
				printf("%-25s: %-25X\n", NumberOfRvaAndSizes, imageOptionalHeader.NumberOfRvaAndSizes);

				printf("\n");
				printf("\n");
				printf("[*] DATA DIRECTORIES: \n");
				printf("\n");

				for (int i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++) {
					switch (i)
					{
					case IMAGE_DIRECTORY_ENTRY_EXPORT:
						printf("%-25s rva: %-25X size: %-25X\n", ExportDirectory, imageOptionalHeader.DataDirectory[i].VirtualAddress, imageOptionalHeader.DataDirectory[i].Size);
						break;
					case IMAGE_DIRECTORY_ENTRY_IMPORT:
						printf("%-25s rva: %-25X size: %-25X\n", ImportDirectory, imageOptionalHeader.DataDirectory[i].VirtualAddress, imageOptionalHeader.DataDirectory[i].Size);
						CopyMemory(&importDirectory, &imageOptionalHeader.DataDirectory[i], sizeof(importDirectory));
						break;
					case IMAGE_DIRECTORY_ENTRY_RESOURCE:
						printf("%-25s rva: %-25X size: %-25X\n", ResourceDirectory, imageOptionalHeader.DataDirectory[i].VirtualAddress, imageOptionalHeader.DataDirectory[i].Size);
						break;
					case IMAGE_DIRECTORY_ENTRY_EXCEPTION:
						printf("%-25s rva: %-25X size: %-25X\n", ExceptionDirectory, imageOptionalHeader.DataDirectory[i].VirtualAddress, imageOptionalHeader.DataDirectory[i].Size);
						break;
					case IMAGE_DIRECTORY_ENTRY_SECURITY:
						printf("%-25s rva: %-25X size: %-25X\n", SecurityDirectory, imageOptionalHeader.DataDirectory[i].VirtualAddress, imageOptionalHeader.DataDirectory[i].Size);
						break;
					case IMAGE_DIRECTORY_ENTRY_BASERELOC:
						printf("%-25s rva: %-25X size: %-25X\n", RelocationDirectory, imageOptionalHeader.DataDirectory[i].VirtualAddress, imageOptionalHeader.DataDirectory[i].Size);
						CopyMemory(&relocDirectory, &imageOptionalHeader.DataDirectory[i], sizeof(relocDirectory));
						break;
					case IMAGE_DIRECTORY_ENTRY_DEBUG:
						printf("%-25s rva: %-25X size: %-25X\n", DebugDirectory, imageOptionalHeader.DataDirectory[i].VirtualAddress, imageOptionalHeader.DataDirectory[i].Size);
						break;
					case IMAGE_DIRECTORY_ENTRY_ARCHITECTURE:
						printf("%-25s rva: %-25X size: %-25X\n", ArchitectureDirectory, imageOptionalHeader.DataDirectory[i].VirtualAddress, imageOptionalHeader.DataDirectory[i].Size);
						break;
					case IMAGE_DIRECTORY_ENTRY_GLOBALPTR:
						printf("%-25s rva: %-25X size: %-25X\n", GlobalPtr, imageOptionalHeader.DataDirectory[i].VirtualAddress, imageOptionalHeader.DataDirectory[i].Size);
						break;
					case IMAGE_DIRECTORY_ENTRY_TLS:
						printf("%-25s rva: %-25X size: %-25X\n", TLSDirectory, imageOptionalHeader.DataDirectory[i].VirtualAddress, imageOptionalHeader.DataDirectory[i].Size);
						break;
					case IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG:
						printf("%-25s rva: %-25X size: %-25X\n", ConfigurationDirectory, imageOptionalHeader.DataDirectory[i].VirtualAddress, imageOptionalHeader.DataDirectory[i].Size);
						break;
					case IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT:
						printf("%-25s rva: %-25X size: %-25X\n", BoundImportDirectory, imageOptionalHeader.DataDirectory[i].VirtualAddress, imageOptionalHeader.DataDirectory[i].Size);
						break;
					case IMAGE_DIRECTORY_ENTRY_IAT:
						printf("%-25s rva: %-25X size: %-25X\n", IATDirectory, imageOptionalHeader.DataDirectory[i].VirtualAddress, imageOptionalHeader.DataDirectory[i].Size);
						break;
					case IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT:
						printf("%-25s rva: %-25X size: %-25X\n", DelayImportDirectory, imageOptionalHeader.DataDirectory[i].VirtualAddress, imageOptionalHeader.DataDirectory[i].Size);
						break;
					case IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR:
						printf("%-25s rva: %-25X size: %-25X\n", dotNetMetaDataDirectory, imageOptionalHeader.DataDirectory[i].VirtualAddress, imageOptionalHeader.DataDirectory[i].Size);
						break;
					default:
						break;
					}
				}

			}
		}


		HeapFree(hHeap, 0, tmpOptionalHeader);
		CloseHandle(hHeap);
	}

	return numOfSection;
}

void read_rich_header(HANDLE fileHandle, int rich_header_size, DWORD byteRead) {
	HANDLE hHeap = GetProcessHeap();

	byte* p = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, rich_header_size);


	int rich_index = -1;

	if (ReadFile(fileHandle, p, rich_header_size, &byteRead, NULL) != 0) {
		//printf("success reading file %lu\n", byteRead);

		for (int i = 0; i < rich_header_size; i++) {
			if (p[i] == 0x52 && p[i + 1] == 0x69) {
				//printf("RICH index: %d\n", i);

				rich_index = i;
				break;
			}
		}

		int rich_index_end = rich_index;
		int rich_index_start = rich_index_end;

		if (rich_index != -1) {
			byte key[4];

			CopyMemory(&key, p + (rich_index + 4), 4);


			while (1) {
				byte tmp[4];

				CopyMemory(&tmp, p + rich_index_start, 4);

				for (int i = 0; i < sizeof(tmp); i++) {
					tmp[i] = tmp[i] ^ key[i];
				}

				if (tmp[1] == 0x61 && tmp[0] == 0x44) {
					break;
				}
				rich_index_start -= 4;
			}

			/*printf("rich index start: %d\n", rich_index_start);
			printf("rich index start: %d\n", rich_index_end);*/


			byte tmp[4];

			CopyMemory(&tmp, p + rich_index_start, 4);

			for (int i = 0; i < sizeof(tmp); i++) {
				tmp[i] = tmp[i] ^ key[i];
			}



			int rich_header_size = rich_index_end - rich_index_start;

			//printf("rich header size: %d\n", rich_header_size);

			byte* rich_header_pointer = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, rich_header_size);

			CopyMemory(rich_header_pointer, p + rich_index_start, rich_header_size);


			for (int i = 0; i < rich_header_size; i += 4) {
				for (int j = 0; j < 4; j++) {
					rich_header_pointer[i + j] = rich_header_pointer[i + j] ^ key[j];
				}
			}

			/*for (int i = 1; i < rich_header_size + 1; i++) {
				printf("%-3X ", rich_header_pointer[i - 1]);

				if (i !=0 && i % 4 == 0) {
					printf("\n");
				}
			}*/

			struct RichHeader richHeader;

			//printf("\nRichHeader structure size: %d\n", sizeof(richHeader));

			CopyMemory(&richHeader, rich_header_pointer, sizeof(richHeader));


			printf("\n");
			printf("\n");
			printf("\n");
			printf("RICH HEADER\n");
			printf("---------------\n");
			printf("\n");

			char* dansID = "Dans ID";
			char* checksummedPadding = "Checksummed padding";
			char* compId = "Comp ID";
			char* richID = "RICH ID";
			char* checksum = "Checksum";

			printf("%-25s: %-25X\n", dansID, richHeader.dansID);


			for (int i = 0; i < sizeof(richHeader.checksumedPadding) / sizeof(DWORD); i++) {
				printf("%-25s: %-25X\n", checksummedPadding, richHeader.checksumedPadding[i]);
			}

			for (int i = 0; i < sizeof(richHeader.compID) / sizeof(DWORDLONG); i++) {

				printf("%-25s: %-25llX\n", compId, richHeader.compID[i]);
			}
		}


	}

	HeapFree(hHeap, 0, p);
	CloseHandle(hHeap);
}



void read_dos_header() {

	printf("\n");
	printf("\n");
	printf("\n");
	printf("DOS HEADER\n");
	printf("---------------\n");
	printf("\n");

	char* e_magic = "e_magic";
	char* e_clp = "e_clp";
	char* e_cp = "e_cp";
	char* e_crlc = "e_crlc";
	char* e_cparhdr = "e_cparhdr";
	char* e_minalloc = "e_minalloc";
	char* e_maxalloc = "e_maxalloc";
	char* e_ss = "e_ss";
	char* e_sp = "e_sp";
	char* e_csum = "e_csum";
	char* e_ip = "e_ip";
	char* e_cs = "e_cs";
	char* e_lfarlc = "e_lfarlc";
	char* e_ovno = "e_ovno";
	char* e_res = "e_res";
	char* e_oemid = "e_oemid";
	char* e_oeminfo = "e_oeminfo";
	char* e_res2 = "e_res2";
	char* e_lfanew = "e_lfanew";

	printf("%-15s: %-15X\n", e_magic, dosHeader.e_magic);
	printf("%-15s: %-15X\n", e_clp, dosHeader.e_cblp);
	printf("%-15s: %-15X\n", e_cp, dosHeader.e_cp);
	printf("%-15s: %-15X\n", e_crlc, dosHeader.e_crlc);
	printf("%-15s: %-15X\n", e_cparhdr, dosHeader.e_cparhdr);
	printf("%-15s: %-15X\n", e_minalloc, dosHeader.e_minalloc);
	printf("%-15s: %-15X\n", e_maxalloc, dosHeader.e_maxalloc);
	printf("%-15s: %-15X\n", e_ss, dosHeader.e_ss);
	printf("%-15s: %-15X\n", e_sp, dosHeader.e_sp);
	printf("%-15s: %-15X\n", e_csum, dosHeader.e_csum);
	printf("%-15s: %-15X\n", e_ip, dosHeader.e_ip);
	printf("%-15s: %-15X\n", e_cs, dosHeader.e_cs);
	printf("%-15s: %-15X\n", e_lfarlc, dosHeader.e_lfarlc);
	printf("%-15s: %-15X\n", e_ovno, dosHeader.e_ovno);

	printf("%-15s: \n", e_res);

	for (int i = 0; i < sizeof(dosHeader.e_res) / sizeof(WORD); i++) {
		printf("%18X\n", dosHeader.e_res[i]);
	}

	printf("%-15s: %-15X\n", e_oemid, dosHeader.e_oemid);
	printf("%-15s: %-15X\n", e_oeminfo, dosHeader.e_oeminfo);

	printf("%-15s: \n", e_res2);

	for (int i = 0; i < sizeof(dosHeader.e_res2) / sizeof(WORD); i++) {
		printf("%18X\n", dosHeader.e_res2[i]);
	}

	printf("%-15s: %-15X\n", e_lfanew, dosHeader.e_lfanew);
}




