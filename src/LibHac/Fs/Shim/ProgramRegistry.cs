﻿using System;
using LibHac.FsSrv;
using LibHac.FsSrv.Sf;
using LibHac.Ncm;
using LibHac.Sf;

namespace LibHac.Fs.Shim
{
    public static class ProgramRegistry
    {
        /// <inheritdoc cref="ProgramRegistryImpl.RegisterProgram"/>
        public static Result RegisterProgram(this FileSystemClient fs, ulong processId, ProgramId programId,
            StorageId storageId, ReadOnlySpan<byte> accessControlData, ReadOnlySpan<byte> accessControlDescriptor)
        {
            using ReferenceCountedDisposable<IProgramRegistry> registry = fs.GetProgramRegistryServiceObject();

            Result rc = registry.Target.SetCurrentProcess(fs.Hos.ProcessId.Value);
            if (rc.IsFailure()) return rc;

            return registry.Target.RegisterProgram(processId, programId, storageId, new InBuffer(accessControlData),
                new InBuffer(accessControlDescriptor));
        }

        /// <inheritdoc cref="ProgramRegistryImpl.UnregisterProgram"/>
        public static Result UnregisterProgram(this FileSystemClient fs, ulong processId)
        {
            using ReferenceCountedDisposable<IProgramRegistry> registry = fs.GetProgramRegistryServiceObject();

            Result rc = registry.Target.SetCurrentProcess(fs.Hos.ProcessId.Value);
            if (rc.IsFailure()) return rc;

            return registry.Target.UnregisterProgram(processId);
        }
    }
}
