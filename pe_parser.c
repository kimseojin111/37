#include <Windows.h>
#include <stdio.h>

int main(void)
{
    /*TODO: 본인 가상머신에 탑재된 x86 PE 파일의 경로로 대체하기*/
    
    char path_pefile[] = "C:\\Users\\바다남편\\Downloads\\ass3\\abex_crackme1.exe";
    
    //char path_pefile[] = "C:\\Users\\바다남편\\Downloads\\PEview\\PEview.exe";

    HANDLE hFile = NULL, hFileMap = NULL; /*Win32 API 호출 과정에서 사용되는 변수*/
    LPBYTE lpFileBase = NULL; /*메모리에 매핑된 파일 컨텐츠의 위치*/
    DWORD dwSize = 0; /*PE 파일 사이즈*/

    PIMAGE_DOS_HEADER pDosHeader = NULL; /*DOS 헤더 구조체의 포인터*/
    PIMAGE_NT_HEADERS pNtHeader = NULL; /*NT 헤더 구조체의 포인터*/

    hFile = CreateFileA(path_pefile, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        /*실습 중 여기에 진입하게 된다면,
        * 콘솔에서 출력되는 에러 코드를 확인한 뒤 MSDN
        "https://learn.microsoft.com/ko-kr/windows/win32/debug/system-error-codes--0-499-"
        에서 에러 코드의 의미를 확인해 볼 것.*/
        printf("CreateFileA() failed. Error code=%lu\n", GetLastError());
        return GetLastError();
    }
    dwSize = GetFileSize(hFile, 0);
    printf("File size=%lu bytes\n\n", dwSize);

    hFileMap = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    lpFileBase = (LPBYTE)MapViewOfFile(hFileMap, FILE_MAP_READ, 0, 0, dwSize);
    /*lpFileBase 포인터는 OS에 의해 메모리에 로드된 PE 파일의 가장 첫 바이트를 가리킴*/
    printf("File signature=%c%c\n", lpFileBase[0], lpFileBase[1]);

    pDosHeader = (PIMAGE_DOS_HEADER)lpFileBase;
    printf("Offset to the NT header=%#x\n\n", pDosHeader->e_lfanew);

    pNtHeader = (PIMAGE_NT_HEADERS)(lpFileBase + pDosHeader->e_lfanew);
    printf("OptionalHeader.BaseOfCode=%#x\n", pNtHeader->OptionalHeader.BaseOfCode);
    printf("OptionalHeader.SizeOfCode=%#x\n", pNtHeader->OptionalHeader.SizeOfCode);
    printf("OptionalHeader.AddressOfEntryPoint=%#x\n", pNtHeader->OptionalHeader.AddressOfEntryPoint);
    printf("OptionalHeader.BaseOfData=%#x\n", pNtHeader->OptionalHeader.BaseOfData);
    printf("OptionalHeader.ImageBase=%#x\n\n", pNtHeader->OptionalHeader.ImageBase);

    /*TODO: 여기서부터 코딩 시작*/


    DWORD sectionCount = pNtHeader->FileHeader.NumberOfSections; 
    printf("sectionCount : %#x\n", sectionCount);

    /*
    printf("%#x\n", pNtHeader);
    PIMAGE_DATA_DIRECTORY pDataDirectory = (PIMAGE_DATA_DIRECTORY)(pNtHeader->OptionalHeader.DataDirectory); 
    printf("pDataDirectory : %#x\n", (LPBYTE)pNtHeader->OptionalHeader.DataDirectory - lpFileBase);
    printf("VirtualAddress of Code section : %#x\n", pDataDirectory[1].VirtualAddress);
    */

    PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)(
        (LPBYTE)(&pNtHeader->OptionalHeader) + (pNtHeader->FileHeader.SizeOfOptionalHeader));
        
    int IAT_idx = sectionCount; // 
    PIMAGE_DATA_DIRECTORY pDataDirectory = (PIMAGE_DATA_DIRECTORY)(pNtHeader->OptionalHeader.DataDirectory);
    DWORD va = pDataDirectory[1].VirtualAddress; 

    for (int i=0; i < sectionCount; i++) {
        printf("%d번째 section: %s\n", i + 1, pSectionHeader[i].Name); 
        printf("PointerToRawdata: %#x\n", pSectionHeader[i].PointerToRawData); 
        printf("SizeOfRawdata: %#x\n", pSectionHeader[i].SizeOfRawData); 
        printf("VirtualAddress: %#x\n", pSectionHeader[i].VirtualAddress); 
        if (IAT_idx == sectionCount && va < pSectionHeader[i].VirtualAddress) IAT_idx = i; 
        printf("VirtualSize: %#x\n\n", pSectionHeader[i].Misc.VirtualSize); 
    }
    IAT_idx--; 
    printf("IAT_idx : %d\n", IAT_idx);
    
    printf("### IAT ###\n"); 
    printf("IAT가 저장된 섹션: %s\n",pSectionHeader[IAT_idx].Name);
    printf("RVA to RAW: %#x->%#x\n", pDataDirectory[1].VirtualAddress, pSectionHeader[IAT_idx].PointerToRawData);
    PIMAGE_IMPORT_DESCRIPTOR pIAT = (PIMAGE_IMPORT_DESCRIPTOR)(lpFileBase + pSectionHeader[IAT_idx].PointerToRawData); 
    int i = 0; 
    DWORD ra = pSectionHeader[IAT_idx].PointerToRawData; 
    while (1) {
        if (pIAT[i].Name == 0) break; 
        printf("ImportDescriptor[%d].Name=%s\n", i, lpFileBase + pIAT[i].Name - va + ra); 
        LPBYTE functions = lpFileBase + pIAT[i].OriginalFirstThunk - va + ra; 
        DWORD* functionPtr = (DWORD*)functions;
        while (*functionPtr != 0) {
            printf(" - function name (RVA=%#x), %s\n", *functionPtr, lpFileBase + *functionPtr - va + ra + 2);
            functionPtr++; 
        }
        i++;
    }


    /*Windows로부터 할당받은 리소스를 역순으로 반환*/
    UnmapViewOfFile(lpFileBase);
    CloseHandle(hFileMap);
    CloseHandle(hFile);
    /*main() 함수가 끝까지 실행되었음을 알리기 위해 0을 반환*/
    return 0;
}
