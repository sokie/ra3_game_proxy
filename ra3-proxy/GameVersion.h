/*
Copyright (c) Anthony Beaumont
This source code is licensed under the MIT License
found in the LICENSE file in the root directory of this source tree.

Based on https://github.com/lanyizi/BegoneCrashers
All credits to lanyizi
*/

#pragma once

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <psapi.h>
#include <string>
#include <unordered_map>

#pragma comment(lib, "version.lib")

enum class GameRelease {
    UNKNOWN,
    RETAIL,   // SecuROM (DVD and legacy Steam version)
    DIGITAL,  // Online store (EA/Origin and Steam version)
};

struct GameVersionInfo {
    int major = 0;
    int minor = 0;
    GameRelease release = GameRelease::UNKNOWN;
    std::wstring executableName;
};

class GameVersion {
public:
    static GameVersion& GetInstance();

    GameVersion(const GameVersion&) = delete;
    GameVersion& operator=(const GameVersion&) = delete;

    const GameVersionInfo& GetInfo() const { return info_; }
    bool IsIdentified() const { return identified_; }

private:
    GameVersion();

    void Identify();
    bool GetFileVersion(TCHAR* szPath, int& major, int& minor);
    std::wstring GetFileName(TCHAR* szPath);
    GameRelease GetReleaseVersion(const std::string& version);

    using AddressMap = std::unordered_map<GameRelease, uintptr_t>;
    using GameVersionMap = std::unordered_map<std::string, AddressMap>;

    static const GameVersionMap VERSIONS;

    GameVersionInfo info_;
    bool identified_ = false;
};
