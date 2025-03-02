#include "DxeResolver.h"
#include "PeiResolver.h"
#include "binaryninjaapi.h"
#include <thread>

using namespace BinaryNinja;

extern "C"
{
BN_DECLARE_CORE_ABI_VERSION

BINARYNINJAPLUGIN void CorePluginDependencies()
{
	BinaryNinja::AddOptionalPluginDependency("arch_x86");
	BinaryNinja::AddOptionalPluginDependency("arch_armv7");
	BinaryNinja::AddOptionalPluginDependency("arch_arm64");
	BinaryNinja::AddOptionalPluginDependency("platform_efi");
}

static Ref<BackgroundTask> efiBackgroundTask = nullptr;

void Run(Ref<BinaryView> view)
{
	efiBackgroundTask = new BackgroundTask("Loading EFI protocol mappings!", true);
	thread resolverThread([view]() {
	  LogInfo("Entering new thread");

	  LogInfo("Identifying module type");
	  EFIModuleType moduleType = identifyModuleType(view);

#ifndef DEBUG_BUILD
	  auto undo = view->BeginUndoActions();
#endif
	  if (moduleType == PEI)
	  {
		  efiBackgroundTask->SetProgressText("Resolving PEIM...");
		  auto resolver = PeiResolver(view, efiBackgroundTask);
		  resolver.resolvePei();
          resolver.generateReport();
	  }
	  else if (moduleType == DXE)
	  {
		  efiBackgroundTask->SetProgressText("Resolving DXE protocols...");
		  auto resolver = DxeResolver(view, efiBackgroundTask);
		  resolver.resolveDxe();
		  efiBackgroundTask->SetProgressText("Resolving MM related protocols...");
		  resolver.resolveSmm();
          resolver.generateReport();
	  }

#ifndef DEBUG_BUILD
	  view->CommitUndoActions(undo);
#endif
	  efiBackgroundTask->Finish();
	});
	resolverThread.detach();
}

BINARYNINJAPLUGIN bool CorePluginInit()
{
	EfiGuidRenderer::Register();
    Ref<Settings> settings = Settings::Instance();
    settings->RegisterSetting("corePlugins.efiResolver.enableReport",R"(
    {
        "title" : "Automatic generate markdown report after analysis",
        "type" : "boolean",
        "default" : false,
        "description" : "Enable automatic generation of markdown report after analysis",
        "ignore" : ["SettingsProjectScope", "SettingsResourceScope"]
    })");

	PluginCommand::Register("EFI Resolver\\Resolve EFI Types And Protocols", "Resolve EFI Protocols", &Run);

	return true;
}
}
