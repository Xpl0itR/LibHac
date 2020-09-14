﻿using System;
using LibHac.Common;
using LibHac.Fs.Impl;
using LibHac.FsSrv;
using LibHac.FsSrv.Sf;
using LibHac.Util;

namespace LibHac.Fs.Shim
{
    public static class ContentStorage
    {
        public static Result MountContentStorage(this FileSystemClient fs, ContentStorageId storageId)
        {
            return MountContentStorage(fs, GetContentStorageMountName(storageId), storageId);
        }

        public static Result MountContentStorage(this FileSystemClient fs, U8Span mountName, ContentStorageId storageId)
        {
            Result rc = MountHelpers.CheckMountNameAcceptingReservedMountName(mountName);
            if (rc.IsFailure()) return rc;

            IFileSystemProxy fsProxy = fs.GetFileSystemProxyServiceObject();

            rc = fsProxy.OpenContentStorageFileSystem(out ReferenceCountedDisposable<IFileSystemSf> contentFs, storageId);
            if (rc.IsFailure()) return rc;

            using (contentFs)
            {
                var mountNameGenerator = new ContentStorageCommonMountNameGenerator(storageId);

                var fileSystemAdapter = new FileSystemServiceObjectAdapter(contentFs);

                return fs.Register(mountName, fileSystemAdapter, mountNameGenerator);
            }
        }

        public static U8String GetContentStorageMountName(ContentStorageId storageId)
        {
            switch (storageId)
            {
                case ContentStorageId.System:
                    return CommonMountNames.ContentStorageSystemMountName;
                case ContentStorageId.User:
                    return CommonMountNames.ContentStorageUserMountName;
                case ContentStorageId.SdCard:
                    return CommonMountNames.ContentStorageSdCardMountName;
                default:
                    throw new ArgumentOutOfRangeException(nameof(storageId), storageId, null);
            }
        }

        private class ContentStorageCommonMountNameGenerator : ICommonMountNameGenerator
        {
            private ContentStorageId StorageId { get; }

            public ContentStorageCommonMountNameGenerator(ContentStorageId storageId)
            {
                StorageId = storageId;
            }

            public Result GenerateCommonMountName(Span<byte> nameBuffer)
            {
                U8String mountName = GetContentStorageMountName(StorageId);

                int length = StringUtils.Copy(nameBuffer, mountName);
                nameBuffer[length] = (byte)':';
                nameBuffer[length + 1] = 0;

                return Result.Success;
            }
        }
    }
}
