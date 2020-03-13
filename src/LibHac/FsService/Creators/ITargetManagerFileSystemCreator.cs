﻿using System;
using LibHac.Fs;

namespace LibHac.FsService.Creators
{
    public interface ITargetManagerFileSystemCreator
    {
        Result Create(out IFileSystem fileSystem, bool openCaseSensitive);
        Result GetCaseSensitivePath(out bool isSuccess, Span<byte> path);
    }
}