#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>
#include <search.h>

#include "winnt_types.h"
#include "log.h"
#include "util.h"
#include "winexports.h"

#ifndef E_NOINTERFACE
#define E_NOINTERFACE ((HRESULT)0x80004002L)
#endif

#ifndef E_NOTIMPL
#define E_NOTIMPL ((HRESULT)0x80004001L)
#endif

#ifndef E_FAIL
#define E_FAIL ((HRESULT)0x80004005L)
#endif

#ifndef DXGI_ERROR_NOT_FOUND
#define DXGI_ERROR_NOT_FOUND ((HRESULT)0x887A0002L)
#endif

#ifndef S_OK
#define S_OK ((HRESULT)0)
#endif

static HRESULT WINAPI FakeQueryInterface(void *self, const GUID *riid, void **ppv)
{
    static unsigned int log_count;
    if (log_count < 10) {
        LogMessage("DXGI QueryInterface(%p, %p)", riid, ppv);
        log_count++;
    }
    (void)self;
    (void)riid;
    if (ppv) {
        *ppv = NULL;
    }
    return E_NOINTERFACE;
}

static ULONG WINAPI FakeAddRef(void *self)
{
    static unsigned int log_count;
    if (log_count < 10) {
        LogMessage("DXGI AddRef(%p)", self);
        log_count++;
    }
    (void)self;
    return 1;
}

static ULONG WINAPI FakeRelease(void *self)
{
    static unsigned int log_count;
    if (log_count < 10) {
        LogMessage("DXGI Release(%p)", self);
        log_count++;
    }
    (void)self;
    return 1;
}

static HRESULT WINAPI FakeSetPrivateData(void *self, const GUID *name, UINT data_size, const void *data)
{
    (void)self;
    (void)name;
    (void)data_size;
    (void)data;
    return S_OK;
}

static HRESULT WINAPI FakeSetPrivateDataInterface(void *self, const GUID *name, const void *unknown)
{
    (void)self;
    (void)name;
    (void)unknown;
    return S_OK;
}

static HRESULT WINAPI FakeGetPrivateData(void *self, const GUID *name, UINT *data_size, void *data)
{
    (void)self;
    (void)name;
    (void)data;
    if (data_size) {
        *data_size = 0;
    }
    return DXGI_ERROR_NOT_FOUND;
}

static HRESULT WINAPI FakeGetParent(void *self, const GUID *riid, void **ppParent)
{
    (void)self;
    (void)riid;
    if (ppParent) {
        *ppParent = NULL;
    }
    return E_NOINTERFACE;
}

static HRESULT WINAPI FakeEnumAdapters(void *self, UINT index, void **ppAdapter)
{
    (void)self;
    (void)index;
    if (ppAdapter) {
        *ppAdapter = NULL;
    }
    return DXGI_ERROR_NOT_FOUND;
}

static HRESULT WINAPI FakeMakeWindowAssociation(void *self, HWND window, UINT flags)
{
    (void)self;
    (void)window;
    (void)flags;
    return S_OK;
}

static HRESULT WINAPI FakeGetWindowAssociation(void *self, HWND *window)
{
    (void)self;
    if (window) {
        *window = NULL;
    }
    return S_OK;
}

static HRESULT WINAPI FakeCreateSwapChain(void *self, void *device, void *desc, void **swapchain)
{
    (void)self;
    (void)device;
    (void)desc;
    if (swapchain) {
        *swapchain = NULL;
    }
    return DXGI_ERROR_NOT_FOUND;
}

static HRESULT WINAPI FakeCreateSoftwareAdapter(void *self, HANDLE module, void **adapter)
{
    (void)self;
    (void)module;
    if (adapter) {
        *adapter = NULL;
    }
    return DXGI_ERROR_NOT_FOUND;
}

static HRESULT WINAPI FakeEnumAdapters1(void *self, UINT index, void **ppAdapter)
{
    (void)self;
    (void)index;
    if (ppAdapter) {
        *ppAdapter = NULL;
    }
    return DXGI_ERROR_NOT_FOUND;
}

static BOOL WINAPI FakeIsCurrent(void *self)
{
    static unsigned int log_count;
    if (log_count < 10) {
        LogMessage("DXGI IsCurrent(%p)", self);
        log_count++;
    }
    (void)self;
    return TRUE;
}

static void *fake_dxgi_vtbl[] = {
    (void *)FakeQueryInterface,     // IUnknown::QueryInterface
    (void *)FakeAddRef,             // IUnknown::AddRef
    (void *)FakeRelease,            // IUnknown::Release
    (void *)FakeSetPrivateData,         // IDXGIObject::SetPrivateData
    (void *)FakeSetPrivateDataInterface,// IDXGIObject::SetPrivateDataInterface
    (void *)FakeGetPrivateData,         // IDXGIObject::GetPrivateData
    (void *)FakeGetParent,              // IDXGIObject::GetParent
    (void *)FakeEnumAdapters,           // IDXGIFactory::EnumAdapters
    (void *)FakeMakeWindowAssociation,  // IDXGIFactory::MakeWindowAssociation
    (void *)FakeGetWindowAssociation,   // IDXGIFactory::GetWindowAssociation
    (void *)FakeCreateSwapChain,        // IDXGIFactory::CreateSwapChain
    (void *)FakeCreateSoftwareAdapter,  // IDXGIFactory::CreateSoftwareAdapter
    (void *)FakeEnumAdapters1,          // IDXGIFactory1::EnumAdapters1
    (void *)FakeIsCurrent,          // IDXGIFactory1::IsCurrent
};

struct fake_dxgi_factory {
    void **vtable;
};

static struct fake_dxgi_factory g_fake_factory = {
    .vtable = fake_dxgi_vtbl,
};

static HRESULT WINAPI CreateDXGIFactory1(const GUID *riid, void **ppFactory)
{
    LogMessage("CreateDXGIFactory1(%p, %p)", riid, ppFactory);
    if (ppFactory) {
        *ppFactory = &g_fake_factory;
    }
    return S_OK;
}

DECLARE_CRT_EXPORT("CreateDXGIFactory1", CreateDXGIFactory1);
