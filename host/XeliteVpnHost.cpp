// XeliteVpnHost: process that hosts Xelite's VPN plug-in.
//
// The VPN platform starts the exe named by the vpnClient background task
// (-ServerName:Plugin...). Hosted in Xelite.exe, the plug-in ran inside a XAML
// application, so Windows suspended it together with the app as soon as the
// user switched to another app, freezing the tunnel. This host has no UI: it
// loads the plug-in from Xelite.dll (the same in-process server the manifest
// registers) and serves its activation factory through
// CoreApplication::RunWithActivationFactories.

#include <windows.h>
#include <roapi.h>
#include <winrt/Windows.ApplicationModel.Core.h>
#include <winrt/Windows.Foundation.h>

using DllGetActivationFactoryFn = HRESULT(WINAPI*)(HSTRING, ::IActivationFactory**);

namespace
{
    struct Factories : winrt::implements<Factories, winrt::Windows::Foundation::IGetActivationFactory>
    {
        explicit Factories(DllGetActivationFactoryFn getFactory) : m_getFactory(getFactory) {}

        winrt::Windows::Foundation::IInspectable GetActivationFactory(winrt::hstring const& activatableClassId)
        {
            winrt::com_ptr<::IActivationFactory> factory;
            winrt::check_hresult(m_getFactory(static_cast<HSTRING>(winrt::get_abi(activatableClassId)), factory.put()));
            return factory.as<winrt::Windows::Foundation::IInspectable>();
        }

    private:
        DllGetActivationFactoryFn m_getFactory;
    };
}

int WINAPI wWinMain(HINSTANCE, HINSTANCE, PWSTR, int)
{
    winrt::init_apartment();
    HMODULE plugin = LoadPackagedLibrary(L"Xelite.dll", 0);
    if (!plugin)
    {
        return static_cast<int>(GetLastError());
    }
    auto getFactory = reinterpret_cast<DllGetActivationFactoryFn>(GetProcAddress(plugin, "DllGetActivationFactory"));
    if (!getFactory)
    {
        return static_cast<int>(GetLastError());
    }
    winrt::Windows::ApplicationModel::Core::CoreApplication::RunWithActivationFactories(winrt::make<Factories>(getFactory));
    return 0;
}
