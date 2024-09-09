#include "DxeResolver.h"

bool DxeResolver::resolveBootServices()
{
	m_task->SetProgressText("Resolving Boot Services...");
	auto refs = m_view->GetCodeReferencesForType(QualifiedName("EFI_BOOT_SERVICES"));
	// search reference of `EFI_BOOT_SERVICES` so that we can easily parse different services

	for (auto& ref : refs)
	{
		if (m_task->IsCancelled())
			return false;

		auto func = ref.func;
		auto mlil = func->GetMediumLevelIL();
		if (!mlil)
			continue;

		auto mlilSsa = mlil->GetSSAForm();
		size_t mlilIdx = mlil->GetInstructionStart(m_view->GetDefaultArchitecture(), ref.addr);
		auto instr = mlilSsa->GetInstruction(mlil->GetSSAInstructionIndex(mlilIdx));

		if (instr.operation == MLIL_CALL_SSA || instr.operation == MLIL_TAILCALL_SSA)
		{
			auto dest = instr.GetDestExpr();
			if (dest.operation != MLIL_LOAD_STRUCT_SSA)
				continue;
			auto offset = dest.GetOffset();

            auto bootService = m_view->GetTypeByName(QualifiedName("EFI_BOOT_SERVICES"));
            auto bootServiceStruct = bootService->GetStructure();
            StructureMember result;
            auto member = bootServiceStruct->GetMemberAtOffset(offset, result);
            m_service_usages.push_back(make_pair(ref.addr, result.name));

			if (offset == 0x18 + m_width * 16 || offset == 0x18 + m_width * 32)
			{
				// HandleProtocol, OpenProtocol
				// Guid:1, Interface:2
				auto namePair = resolveGuidInterface(ref.func, ref.addr, 1, 2);
                if (offset == 0x18 + m_width * 16)
                    m_protocol_usages.push_back(make_tuple(ref.addr, "HandleProtocol", namePair.first, namePair.second));
                else
                    m_protocol_usages.push_back(make_tuple(ref.addr, "OpenProtocol", namePair.first, namePair.second));
			}
			else if (offset == 0x18 + m_width * 37)
			{
				// LocateProtocol
				auto namePair = resolveGuidInterface(ref.func, ref.addr, 0, 2);
                m_protocol_usages.push_back(make_tuple(ref.addr, "LocateProtocol", namePair.first, namePair.second));
			}
		}
	}
	return true;
}

static uint64_t nearestDef(Ref<MediumLevelILFunction> mlil, Variable var, uint64_t addr)
{
    auto defs = mlil->GetVariableDefinitions(var);
    uint64_t nearest = 0;
    auto addrIdx = mlil->GetInstructionStart(mlil->GetArchitecture(), addr);
    for (auto def : defs)
    {
        if (def > nearest && def < addrIdx)
            nearest = def;
    }

    // Since DataSize field normally is an aliased variable, we also want to check the usage

    // TODO and we also need to check the usage of aliased variables
    auto uses = mlil->GetVariableUses(var);
    for (auto use : uses)
    {
        if (use > nearest && use < addrIdx)
        {
            // In this case, we want to check whether this is a SetVar or a Call
            // We only need to consider call here
            if (mlil->GetInstruction(use).operation == MLIL_CALL)
                nearest = use;
        }
    }
    return nearest;
}

bool DxeResolver::resolveRuntimeServices()
{
	m_task->SetProgressText("Resolving Runtime Services...");
	auto refs = m_view->GetCodeReferencesForType(QualifiedName("EFI_RUNTIME_SERVICES"));

	for (auto& ref : refs)
	{
		if (m_task->IsCancelled())
			return false;

		auto func = ref.func;
		auto mlil = func->GetMediumLevelIL();
		if (!mlil)
			continue;

		auto mlilSsa = mlil->GetSSAForm();
		size_t mlilIdx = mlil->GetInstructionStart(m_view->GetDefaultArchitecture(), ref.addr);
		auto instr = mlilSsa->GetInstruction(mlil->GetSSAInstructionIndex(mlilIdx));

		if (instr.operation == MLIL_CALL_SSA || instr.operation == MLIL_TAILCALL_SSA)
		{
			auto dest = instr.GetDestExpr();
			if (dest.operation != MLIL_LOAD_STRUCT_SSA)
				continue;
			auto offset = dest.GetOffset();
			if (offset == 0x18 + m_width * 6 || offset == 0x18 + m_width * 8)
			{
				// GetVariable and SetVariable
                auto params = instr.GetParameterExprs();
                if (params.size() < 5)
                    continue;

                auto varNamePtr = params[0];
                string varName;
                if (varNamePtr.operation == MLIL_CONST_PTR)
                {
                    auto varNameAddr = varNamePtr.GetConstant<MLIL_CONST_PTR>();
                    BNStringReference varNameRef;
                    m_view->GetStringAtAddress(varNameAddr, varNameRef);

                    char16_t varNameU16[256];
                    memset(varNameU16, 0, sizeof(varNameU16));
                    m_view->Read(&varNameU16, varNameAddr, varNameRef.length);
                    for (auto c : varNameU16)
                        if (c != 0)
                            varName.push_back(static_cast<char>(c));
                }
                else
                    varName = "UnresolvedVariable";

                auto guidParam = params[1];
                string guidName;
                if (guidParam.operation == MLIL_CONST_PTR)
                {
                    auto guidAddr = guidParam.GetConstant();
                    auto guidNamePair = defineAndLookupGuid(guidAddr);
                    guidName = guidNamePair.second;
                    if (guidName.empty())
                        guidName = "UnknownGuid";
                }
                else if (guidParam.operation == MLIL_VAR)
                {
                    auto var = guidParam.GetSourceVariable();
                    // TODO probably a GUID on stack, should be able to resolve it
                    auto defs = mlil->GetVariableDefinitions(var);
                    unsigned long nearest_def = 0;
                    // This may be an aliased variable, which will have multiple definitions
                    // So we only want to filter the shadowed definitions
                    for (auto def : defs)
                        if (def < ref.addr && def > nearest_def)
                            nearest_def = def;
                }
                else
                    guidName = "UnknownGuid";

                // The only difference between GetVariable and SetVariable is the DataSize parameter
                // where DataSize is a pointer in GetVariable and a value in SetVariable

                auto dataSizeParam = params[3];
                string serviceName;
                string dataSize;
                if (offset == 0x18 + m_width * 6)
                {
                    // GetVariable
                    serviceName = "GetVariable";
                    if (dataSizeParam.operation == MLIL_VAR_SSA)
                    {
                        auto dataSizeVar = dataSizeParam.GetSourceSSAVariable().var;
                        auto varDefs = mlil->GetVariableDefinitions(dataSizeVar);
                        for (auto def : varDefs)
                        {
                            auto defIns = mlil->GetInstruction(def);
                            if (defIns.operation == MLIL_SET_VAR)
                            {
                                auto sourceAddr = defIns.GetSourceExpr<MLIL_SET_VAR>();
                                if (sourceAddr.operation == MLIL_ADDRESS_OF)
                                {
                                    auto sourceVar = sourceAddr.GetSourceVariable<MLIL_ADDRESS_OF>();
                                    auto varUse = nearestDef(mlil, sourceVar, ref.addr);
                                    auto varUseIns = mlil->GetInstruction(varUse);
                                    if (varUseIns.operation == MLIL_SET_VAR)
                                    {
                                        auto dataSizeValue = varUseIns.GetSourceExpr<MLIL_SET_VAR>();
                                        if (dataSizeValue.operation == MLIL_CONST)
                                            dataSize = to_string(dataSizeValue.GetConstant());
                                    }
                                    else if (varUseIns.operation == MLIL_CALL)
                                    {
                                        // which means DataSize at ref is the same as this call instruction
                                        stringstream ss;
                                        ss << "Overwritten by Call at [0x" << hex << varUseIns.address
                                           << "](binaryninja://?expr=" << hex << varUseIns.address << ")";
                                        dataSize = ss.str();
                                    }
                                }
                                break;
                            }
                            else
                            {
                                // ignore other cases, might be a Phi node
                            }
                        }

                        if (dataSize.empty())
                        {
                            // Undetermined
                            LogInfo("Undetermined value of DataSize in GetVariable: 0x%llx", ref.addr);
                            dataSize = "Undetermined";
                        }
                    }
                }
                else if (offset == 0x18 + m_width * 8)
                {
                    // SetVariable
                    serviceName = "SetVariable";
                    if (dataSizeParam.operation == MLIL_CONST)
                        dataSize = to_string(dataSizeParam.GetConstant());
                }

                m_variable_usages.push_back(make_tuple(ref.addr, serviceName, varName, dataSize, guidName));
			}
		}
	}
	return true;
}

bool DxeResolver::resolveSmmTables(string serviceName, string tableName)
{
	m_task->SetProgressText("Defining MM tables...");
	auto refs = m_view->GetCodeReferencesForType(QualifiedName(serviceName));
	// both versions use the same type, so we only need to search for this one
	for (auto& ref : refs)
	{
		if (m_task->IsCancelled())
			return false;

		auto func = ref.func;
		auto mlil = func->GetMediumLevelIL();
		if (!mlil)
			continue;

		auto mlilSsa = mlil->GetSSAForm();
		size_t mlilIdx = mlil->GetInstructionStart(m_view->GetDefaultArchitecture(), ref.addr);
		auto instr = mlilSsa->GetInstruction(mlil->GetSSAInstructionIndex(mlilIdx));

		if (instr.operation != MLIL_CALL_SSA && instr.operation != MLIL_TAILCALL_SSA)
			continue;

		auto destExpr = instr.GetDestExpr();
		if (destExpr.operation != MLIL_LOAD_STRUCT_SSA)
			continue;

		if (destExpr.GetOffset() != 8)
			continue;

		auto params = instr.GetParameterExprs();
		if (params.size() < 2)
			continue;

		auto smstAddr = params[1];
		if (smstAddr.operation != MLIL_CONST_PTR)
			continue;

		QualifiedNameAndType result;
		string errors;
		bool ok = m_view->ParseTypeString(tableName, result, errors);
		if (!ok)
			return false;
		m_view->DefineDataVariable(smstAddr.GetValue().value, result.type);
		m_view->DefineUserSymbol(new Symbol(DataSymbol, "gMmst", smstAddr.GetValue().value));
		m_view->UpdateAnalysisAndWait();
	}
	return true;
}

bool DxeResolver::resolveSmmServices()
{
	m_task->SetProgressText("Resolving MM services...");
	auto refs = m_view->GetCodeReferencesForType(QualifiedName("EFI_MM_SYSTEM_TABLE"));
	auto refs_smm = m_view->GetCodeReferencesForType(QualifiedName("EFI_SMM_SYSTEM_TABLE2"));
	// These tables have same type information, we can just iterate once
	refs.insert(refs.end(), refs_smm.begin(), refs_smm.end());

	for (auto& ref : refs)
	{
		if (m_task->IsCancelled())
			return false;

		auto func = ref.func;
		auto mlil = func->GetMediumLevelIL();
		if (!mlil)
			continue;

		auto mlilSsa = mlil->GetSSAForm();
		size_t mlilIdx = mlil->GetInstructionStart(m_view->GetDefaultArchitecture(), ref.addr);
		auto instr = mlilSsa->GetInstruction(mlil->GetSSAInstructionIndex(mlilIdx));

		if (instr.operation == MLIL_CALL_SSA || instr.operation == MLIL_TAILCALL_SSA)
		{
			auto dest = instr.GetDestExpr();
			if (dest.operation != MLIL_LOAD_STRUCT_SSA)
				continue;
			auto offset = dest.GetOffset();

			if (offset == 0x18 + m_width * 0x14)
			{
				// SmmHandleProtocol
				resolveGuidInterface(ref.func, ref.addr, 1, 2);
			}
			else if (offset == 0x18 + m_width * 0x17)
			{
				// SmmLocateProtocol
				resolveGuidInterface(ref.func, ref.addr, 0, 2);
			}
		}
	}
	return true;
}

bool DxeResolver::resolveSmiHandlers()
{
	m_task->SetProgressText("Resolving SMI Handlers...");
	auto refs = m_view->GetCodeReferencesForType(QualifiedName("EFI_MM_SW_REGISTER"));
	auto refs_smm_sw = m_view->GetCodeReferencesForType(QualifiedName("EFI_SMM_SW_REGISTER2"));
	auto refs_mm_sx = m_view->GetCodeReferencesForType(QualifiedName("EFI_MM_SX_REGISTER"));
	auto refs_smm_sx = m_view->GetCodeReferencesForType(QualifiedName("EFI_SMM_SX_REGISTER2"));
	// Define them together

	refs.insert(refs.end(), refs_smm_sw.begin(), refs_smm_sw.end());
	refs.insert(refs.end(), refs_smm_sx.begin(), refs_smm_sw.end());
	refs.insert(refs.end(), refs_mm_sx.begin(), refs_mm_sx.end());

	for (auto& ref : refs)
	{
		if (m_task->IsCancelled())
			return false;

		auto func = ref.func;
		auto mlil = func->GetMediumLevelIL();
		if (!mlil)
			continue;

		auto mlilSsa = mlil->GetSSAForm();
		size_t mlilIdx = mlil->GetInstructionStart(m_view->GetDefaultArchitecture(), ref.addr);
		auto instr = mlilSsa->GetInstruction(mlil->GetSSAInstructionIndex(mlilIdx));

		if (instr.operation == MLIL_CALL_SSA || instr.operation == MLIL_TAILCALL_SSA)
		{
			auto dest = instr.GetDestExpr();
			if (dest.operation != MLIL_LOAD_STRUCT_SSA)
				continue;

			auto offset = dest.GetOffset();
			if (offset == 0)
			{
				auto parameters = instr.GetParameterExprs();
				if (parameters.size() < 4)
					continue;

				// TODO we should be able to parse registerContext, but it's normally an aliased variable
				//    and we have some issues relate to that
				auto dispatchFunction = parameters[1];
				if (dispatchFunction.operation != MLIL_CONST_PTR)
					continue;
				auto funcAddr = static_cast<uint64_t>(dispatchFunction.GetConstant());
				auto targetFunc = m_view->GetAnalysisFunction(m_view->GetDefaultPlatform(), funcAddr);
				auto funcType = targetFunc->GetType();
				std::ostringstream ss;
				ss << "SmiHandler_" << std::hex << funcAddr;
				string funcName = ss.str();

				// typedef enum
				string handleTypeStr =
					"EFI_STATUS SmiHandler(EFI_HANDLE DispatchHandle, VOID* Context, VOID* CommBuffer, UINTN* "
					"CommBufferSize);";
				QualifiedNameAndType result;
				string errors;
				bool ok = m_view->ParseTypeString(handleTypeStr, result, errors);
				if (!ok)
					return false;
				targetFunc->SetUserType(result.type);
				m_view->DefineUserSymbol(new Symbol(FunctionSymbol, funcName, funcAddr));
				m_view->UpdateAnalysisAndWait();

				// After setting the type, we want to propagate the parameters' type
				TypePropagation propagator(m_view);
				propagator.propagateFuncParamTypes(targetFunc);
			}
		}
	}
	return true;
}

bool DxeResolver::resolveDxe()
{
	if (!resolveBootServices())
		return false;
	if (!resolveRuntimeServices())
		return false;
	return true;
}

bool DxeResolver::resolveSmm()
{
	if (!resolveSmmTables("EFI_SMM_GET_SMST_LOCATION2", "EFI_SMM_SYSTEM_TABLE2*"))
		return false;
	if (!resolveSmmTables("EFI_MM_GET_MMST_LOCATION", "EFI_MM_SYSTEM_TABLE*"))
		return false;
	if (!resolveSmmServices())
		return false;
	if (!resolveSmiHandlers())
		return false;
	return true;
}

DxeResolver::DxeResolver(Ref<BinaryView> view, Ref<BackgroundTask> task) : Resolver(view, task)
{
	initProtocolMapping();
	setModuleEntry(DXE);
}
