#pragma once

#include <fstream>
#include <thread>

#include "GuidRenderer.h"
#include "ModuleType.h"
#include "TypePropagation.h"
#include "binaryninjaapi.h"
#include "highlevelilinstruction.h"
#include "lowlevelilinstruction.h"
#include "mediumlevelilinstruction.h"

using namespace BinaryNinja;
using namespace std;

typedef array<uint8_t, 16> EFI_GUID;

class Resolver
{
protected:
	Ref<BinaryView> m_view;
	Ref<BackgroundTask> m_task;
	size_t m_width;
	map<EFI_GUID, pair<string, string>> m_protocol;
	map<EFI_GUID, string> m_user_guids;

    // addr, service name
	vector<pair<uint64_t, string>> m_service_usages;
    // addr, service name, protocol name, guid name
	vector<tuple<uint64_t, string, string, string>> m_protocol_usages;
	vector<pair<uint64_t, EFI_GUID>> m_guid_usages;
    // addr, type(Get or Set), variable name, DataSize, guid
	vector<tuple<uint64_t, string, string, string, string>> m_variable_usages;

	bool parseUserGuidIfExists(const string& filePath);
	bool parseProtocolMapping(const string& filePath);

	Ref<Type> GetTypeFromViewAndPlatform(string type_name);
	void initProtocolMapping();

public:
	bool setModuleEntry(EFIModuleType fileType);
	pair<string, string> resolveGuidInterface(Ref<Function> func, uint64_t addr, int guid_pos, int interface_pos);
	Resolver(Ref<BinaryView> view, Ref<BackgroundTask> task);

	pair<string, string> lookupGuid(EFI_GUID guidBytes);
	pair<string, string> defineAndLookupGuid(uint64_t addr);

    void generateReport();

	string nonConflictingName(const string& basename);
	static string nonConflictingLocalName(Ref<Function> func, const string& basename);

    bool defineTypeAtCallsite(
		Ref<Function> func, uint64_t addr, string typeName, int paramIdx, bool followFields = false);
	vector<HighLevelILInstruction> HighLevelILExprsAt(Ref<Function> func, Ref<Architecture> arch, uint64_t addr);
};