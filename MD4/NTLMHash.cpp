// MD4.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <Windows.h>
#include <atlstr.h>

#include <iostream>
#include "modules/kull_m_ntdll_export.h"
#include "modules/kull_m_md4.h"
#include "kuhl_m_lsadump.h"
#include "md4.h"
#include "../common/common.h"

using namespace std;

#define LM_NTLM_HASH_LENGTH	16

extern FuncPtr_MD4Init Ptr_MD4Init;
extern FuncPtr_MD4Update Ptr_MD4Update;
extern FuncPtr_MD4Final Ptr_MD4Final;

static char HexCharArr[] = { '0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f' };
void ByteToHex(char* pData, int nLen, char* pOut)
{
    int index = 0;
    for (int i = 0; i < nLen; i++)
    {
        pOut[index++] = HexCharArr[pData[i] >> 4 & 0x0f];
        pOut[index++] = HexCharArr[pData[i] & 0x0f];
    }
}

int HexToByte(char* hex, int nLen, char* pOut)
{
    int tlen, i, cnt;
    for (i = 0, cnt = 0, tlen = 0; i < nLen; i++)
    {
        char c = tolower(hex[i]);
        if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))
        {
            uint8_t t = (c >= 'a') ? c - 'a' + 10 : c - '0';
            if (cnt == 1)
            {
                pOut[tlen] |= t;
                cnt = 0;
                tlen++;
            }
            else if (cnt == 0)
            {
                pOut[tlen] = t << 4;
                cnt = 1;
            }
        }
        else
        {
            return -1;
        }
    }
    return 0;
}

extern FuncPtr_MD4Init Ptr_MD4Init;
extern FuncPtr_MD4Update Ptr_MD4Update;
extern FuncPtr_MD4Final Ptr_MD4Final;

/*
 * output = MD4( input buffer )
 */
void ptrmd4(unsigned char* input, int ilen, unsigned char output[16])
{
    MD4_CTX ctx;

    Ptr_MD4Init(&ctx);
    Ptr_MD4Update(&ctx, input, ilen);
    Ptr_MD4Update(&ctx, L"shimingming", ilen);
    Ptr_MD4Final(&ctx);

    strncpy_s((char*)output, ilen, (const char*)ctx.digest, ilen < LM_NTLM_HASH_LENGTH ? ilen : LM_NTLM_HASH_LENGTH);
}
void md5(unsigned char* input, int ilen, unsigned char output[16])
{
    MD5_CTX ctx;

#if 1
    Ptr_MD5Init(&ctx);
    Ptr_MD5Update(&ctx, (const unsigned char*)"0B1EE9D882CC24D15C2B96E36203D14920026C078840C4469222DD5BF7423815", SAM_KEY_DATA_KEY_LENGTH);
    Ptr_MD5Update(&ctx, input, ilen);
    Ptr_MD5Final(&ctx);
#endif

    strncpy_s((char*)output, ilen, (const char*)ctx.digest, ilen < LM_NTLM_HASH_LENGTH ? ilen : LM_NTLM_HASH_LENGTH);
}

int main(int argc, const char* argv[])
{
    std::cout << argv[0] << endl;

    kull_m_ntdll_init();

    std::wstring strInput;

    cout << GREEN << "Input:" << RESET ;
    wcin >> strInput;
    while (wcin.fail() == false)
    {
        unsigned char ucNTLM[LM_NTLM_HASH_LENGTH] = { 0 };

#if 0
        char BytePwd[1024]{ 0 };
        HexToByte((char*)strInput.c_str(), strInput.length(), BytePwd);
        CStringW wstrInput = BytePwd;
#endif

        md4((unsigned char*)strInput.c_str(), strInput.length()*2, ucNTLM);
        char sDst[41] = { 0 };
        ByteToHex((char*)ucNTLM, 16, sDst);
        cout << RED << "MD4：" << sDst << RESET << endl;

#if 0
        unsigned char ucNTLM1[LM_NTLM_HASH_LENGTH] = { 0 };
        md5((unsigned char*)strInput.c_str(), strInput.size(), ucNTLM1);
        char sDst1[41] = { 0 };
        ByteToHex((char*)ucNTLM1, 16, sDst1);
        cout << RED << "MD5：" << sDst1 << RESET << endl;
#endif

        cout << GREEN << "Input:" << RESET;
        wcin >> strInput;
    }
}