#pragma clang diagnostic push
#pragma ide diagnostic ignored "Simplify"
#pragma ide diagnostic ignored "cppcoreguidelines-narrowing-conversions"
#include <jni.h>
#include <string>
#include <iostream>
#include <thread>
#include <vector>
#include <capstone/capstone.h>
#include <algorithm>
#include <fstream>
#include <LIEF/LIEF.hpp>
#include <format>
#include <mutex>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#define BinaryData std::pair<std::vector<uint8_t>, std::vector<uint64_t>>
cs_mode mode;
cs_arch arch;
LIEF::Binary::FORMATS format;
unsigned int thread_count;
bool is_aarch64 = false;
std::mutex reg_mutex, calls_mutex, ph_address_mutex, pwmc_address_mutex;
std::string a, b, c, dfy = "0x42100000";
std::string e = "ffc0";
int progress = 0;
struct BuildLimit
{
    int16_t overworld = 320;
    int16_t end = 256;
    int16_t nether = 128;
    int64_t overworld_bottom = -64;
};
struct BuildLimit_Offsets
{
    uint64_t overworld = 0;
    uint64_t end = 0;
    uint64_t nether = 0;
    uint64_t overworld_bottom = 0;

};
JNIEnv *environment;
jobject obj;
void Logit(JNIEnv *env, jobject context, std::string LOG_TAG, std::string message)
{
    jclass cls = env->GetObjectClass(context);
    jmethodID method = env->GetMethodID(cls, "LogIt", "(Ljava/lang/String;Ljava/lang/String;)V");
    jstring tag = env->NewStringUTF(LOG_TAG.c_str());
    jstring msg = env->NewStringUTF(message.c_str());
    if (method == nullptr)
    {
        return;
    }
    env->CallVoidMethod(context, method, tag, msg);
}
#define LOG_TAG "MCPEPatcher"
#include "android/log_macros.h"
void disassemble_chunk(const uint8_t *chunk, size_t chunk_size, uint64_t address, std::vector<uint64_t> &reg_addrs, std::vector<std::pair<uint64_t, std::string>> &calls, std::vector<std::pair<uint64_t, std::string>> &ph_addrs, std::vector<uint64_t> &pwmc_addrs)
{
    csh handle;
    if (cs_open(arch, mode, &handle) != CS_ERR_OK)
    {
        return;
    }

    cs_option(handle, CS_OPT_DETAIL, CS_OPT_OFF);
    cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_ON);
    cs_insn *insn = cs_malloc(handle);
    std::string last_sm;
    std::vector<uint64_t> local_reg_addrs, local_pwmc_addrs;
    std::vector<std::pair<uint64_t, std::string>> local_calls, local_ph_addrs;
    std::string reg = is_aarch64 ? "sub" : "push";
    std::string call = is_aarch64 ? "bl" : "call";
    std::string_view mov = "mov";
    std::string_view w = "0x42100000";
    while (cs_disasm_iter(handle, &chunk, &chunk_size, &address, insn))
    {
        const uint64_t insn_addr = insn->address;
        std::string mnemonic = insn->mnemonic;
        std::string op_str = insn->op_str;
        if (mnemonic == mov || mnemonic == reg)
        {
            if (op_str.find(w) != std::string::npos)
            {
                local_pwmc_addrs.push_back(insn_addr);
            }
            if (op_str.find(a) != std::string::npos || op_str.find(b) != std::string::npos || op_str.find(c) != std::string::npos)
            {
                local_ph_addrs.emplace_back(insn_addr, mnemonic + op_str);
            }
            if (last_sm == "ret")
            {
                local_reg_addrs.push_back(insn_addr);
            }
            last_sm = mnemonic;
        }
        else if (mnemonic == call)
        {
            local_calls.emplace_back(insn_addr, op_str);
            local_ph_addrs.emplace_back(insn_addr, mnemonic + op_str);
        }
        else if (mnemonic == "ret")
        {
            last_sm = mnemonic;
        }
        progress += insn->size;
    }
    cs_free(insn, 1);
    cs_close(&handle);

    std::lock_guard<std::mutex> reg_lock(reg_mutex);
    reg_addrs.insert(reg_addrs.end(), local_reg_addrs.begin(), local_reg_addrs.end());
    std::lock_guard<std::mutex> calls_lock(calls_mutex);
    calls.insert(calls.end(), local_calls.begin(), local_calls.end());
    std::lock_guard<std::mutex> ph_lock(ph_address_mutex);
    ph_addrs.insert(ph_addrs.end(), local_ph_addrs.begin(), local_ph_addrs.end());
    std::lock_guard<std::mutex> pwmc_lock(pwmc_address_mutex);
    pwmc_addrs.insert(pwmc_addrs.end(), local_pwmc_addrs.begin(), local_pwmc_addrs.end());
}
std::vector<size_t> split_segments(size_t number, size_t numParts)
{
    std::vector<size_t> parts(numParts, 0);
    size_t basePart = (number / numParts) / 4 * 4;
    size_t remainder = number - basePart * numParts;

    for (int i = 0; i < numParts; i++)
        parts[i] = basePart;

    parts[numParts - 1] += remainder;

    if (parts[numParts - 1] % 4 != 0)
    {
        size_t adjustment = parts[numParts - 1] % 4;
        parts[numParts - 1] -= adjustment;
        parts[numParts - 2] += adjustment;
    }

    return parts;
}
uint32_t switch_endian(uint32_t big_endian)
{
    uint8_t byte0 = (big_endian >> 0) & 0xFF;
    uint8_t byte1 = (big_endian >> 8) & 0xFF;
    uint8_t byte2 = (big_endian >> 16) & 0xFF;
    uint8_t byte3 = (big_endian >> 24) & 0xFF;

    uint32_t result = (byte1 << 24) | (byte0 << 16) | (byte3 << 8) | byte2;
    return result;
}
BuildLimit_Offsets find_offsets(std::pair<std::vector<uint8_t>, std::vector<uint64_t>> data, BuildLimit ibl = BuildLimit()/* please use me :( */)
{
    a = std::format("0x{:x}", switch_endian(ibl.nether));
    b = std::format("0x{:x}", switch_endian(ibl.end));
    c = std::format("0x{:x}", ibl.overworld);
    dfy = std::format("0x{:x}", ibl.overworld_bottom);
    std::vector<uint8_t> code = data.first;
    uint64_t address = data.second[0];
    uint64_t file_offset = data.second[1];
    size_t code_size = code.size();
    std::vector<uint64_t> dc_addrs, reg_addrs, pwmc_addrs;
    std::vector<std::pair<uint64_t, std::string>> calls, ph_addrs;
    std::vector<std::thread> threads;
    if (is_aarch64)
    {
        std::vector<size_t> parts = split_segments(code_size, thread_count);
        for (size_t i = 0, offset = 0; i < thread_count; i++)
        {
            threads.emplace_back(disassemble_chunk, code.data() + offset, parts[i], address + offset, std::ref(reg_addrs), std::ref(calls), std::ref(ph_addrs), std::ref(pwmc_addrs));
            offset += parts[i];
        }
    }
    else
    {
        size_t chunk_size = code_size / thread_count;
        for (size_t i = 0; i < thread_count; ++i)
        {
            size_t start = i * chunk_size;
            size_t end = (i == thread_count - 1) ? code_size : (i + 1) * chunk_size;
            const uint8_t *chunk = code.data() + start;
            size_t size_chunk = end - start;
            threads.emplace_back(disassemble_chunk, chunk, size_chunk, address + start, std::ref(reg_addrs), std::ref(calls), std::ref(ph_addrs), std::ref(pwmc_addrs));
        }
    }
    int strike = 0;
    int last_progress = 0;
    while (progress < code_size)
    {
        if (last_progress == progress)
        {
            strike++;
        }
        if (strike > 4)
        {
            Logit(environment, obj, "Patching Process", "Break");
            break;
        }
        last_progress = progress;
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        Logit(environment, obj, "Progress", std::format("{:.2f}%", (static_cast<float>(progress) * 100) / code_size));
    }

    for (auto &thread : threads)
    {
        if (thread.joinable())
        {
            thread.join();
        }
    }

    uint64_t wmc_addr = 0, ohf_addr = 0, nh_addr = 0, eh_addr = 0, oh_addr = 0, obh_addr = 0;
    bool is_pe = format == LIEF::Binary::FORMATS::PE;
    bool is_64_bit = mode == CS_MODE_64;
    std::string df_addr;
    std::sort(pwmc_addrs.begin(), pwmc_addrs.end());
    for (size_t i = 0; i + 1 < pwmc_addrs.size(); i++)
    {
        if (pwmc_addrs[i + 1] - pwmc_addrs[i] < 0x100)
        {
            wmc_addr = pwmc_addrs[i];
            break;
        }
        if (i + 2 > pwmc_addrs.size()){
            wmc_addr = pwmc_addrs[i];
            break;
        }
    }

    std::sort(reg_addrs.begin(), reg_addrs.end());
    for (size_t i = 0; i < reg_addrs.size(); i++)
    {
        if (reg_addrs[i] < wmc_addr && reg_addrs[i + 1] > wmc_addr)
        {
            df_addr = std::format("0x{:x}", reg_addrs[i]);
        }
    }
    for (const auto &call : calls)
    {
        if (call.second.find(df_addr) != std::string::npos)
        {
            dc_addrs.push_back(call.first);
        }
    }
    std::string call = is_aarch64 ? "bl" : "call";
    std::sort(ph_addrs.begin(), ph_addrs.end());
    progress = 0;
    for (const auto &dc_addr : dc_addrs)
    {
        for (size_t j = 0; j + 2 < ph_addrs.size(); j++)
        {
            if (ph_addrs[j].first < dc_addr && ph_addrs[j + 2].first > dc_addr)
            {
                std::string op_str = ph_addrs[j].second;
                if (op_str.find(a) != std::string::npos && nh_addr == 0)
                {
                    nh_addr = ph_addrs[j].first;
                }
                if (op_str.find(b) != std::string::npos && eh_addr == 0)
                {
                    eh_addr = ph_addrs[j].first;
                }
                if (op_str.find(call) != std::string::npos && ohf_addr == 0)
                {
                    for (int offset = 0; offset < 3; offset++)
                    {
                        uint64_t fun = std::stoull(ph_addrs[j - offset].second.substr(call.length()), nullptr, 16);
                        Logit(environment, obj, "Patching Process", std::format("Checking function at 0x{:x}", fun));
                        int count = 0;
                        for (const auto &call2 : calls)
                        {
                            if (call2.second.find(std::format("0x{:x}", fun)) != std::string::npos)
                            {
                                count++;
                            }
                        }
                        if (count == 1)
                        {
                            ohf_addr = fun;

                            break;
                        }
                    }
                }
                if (op_str.find(c) != std::string::npos && oh_addr == 0)
                {
                    oh_addr = ph_addrs[j].first;
                }
            }
        }
    }
    if (oh_addr == 0)
    {
        for (auto & ph_addr : ph_addrs)
        {
            if ((ph_addr.first > ohf_addr && ph_addr.first < ohf_addr + 0x300) && ph_addr.second.find("0x140") != std::string::npos && ph_addr.second.find("mov") != std::string::npos)
            {
                oh_addr = ph_addr.first;
                obh_addr = ph_addr.first - 12;
            }
        }
    }
    BuildLimit_Offsets offsets;
    offsets.overworld = oh_addr - file_offset;
    offsets.end = eh_addr - file_offset;
    offsets.nether = nh_addr - file_offset;
    offsets.overworld_bottom = obh_addr - file_offset;
    return offsets;
}
std::pair<std::vector<uint8_t>, std::vector<uint64_t>> parse_elf(const std::string& file_name)
{
    format = LIEF::Binary::FORMATS::ELF;
    std::unique_ptr<LIEF::ELF::Binary> elfBinary = LIEF::ELF::Parser::parse(file_name);
    if (elfBinary == nullptr)
    {
        std::cout << "Failed to parse ELF file" << std::endl;
        exit(420);
    }
    mode = CS_MODE_ARM;
    arch = CS_ARCH_AARCH64;
    is_aarch64 = true;
    for (const LIEF::ELF::Section &section : elfBinary->sections())
    {
        if (section.name() == ".text")
        {
            std::vector<uint8_t> code(section.content().begin(), section.content().end());
            uint64_t file_offset = section.virtual_address() - section.offset();
            return {std::vector<uint8_t>(code.begin(), code.begin() + code.size()), {section.virtual_address(), file_offset}};
        }
    }
    std::cout << "Failed to find .text section" << std::endl;
    exit(69);
}
std::vector<int> convertHex(int input)
{
    if (input < 0)
    {
        input = 0x10000 + input;
    }
    if (input > 0xfff0 && input >= 0x80000)
    {
        return {static_cast<uint16_t>(((input >> 7) & 0xFFFFF) / 0x1000), static_cast<uint16_t>(0xA0 + (input / 0x8000000))};
    }
    else if (input <= 0xfff0)
    {
        return {static_cast<uint16_t>((input >> 3) & 0xFF), static_cast<uint16_t>(0x80 + (input / 0x800))};
    }
    return {};
}
void patch_aarch64(std::string& file_path, BuildLimit_Offsets offsets, BuildLimit nbl)
{
    std::ifstream file(file_path, std::ios::binary);
    if (!file.is_open())
    {
        std::cout << "Failed to open file" << std::endl;
        exit(420);
    }
    std::vector<uint8_t> buffer(std::istreambuf_iterator<char>(file), {});

    std::vector<int> oh = convertHex(nbl.overworld);
    std::vector<int> ob = convertHex(nbl.overworld_bottom);
    std::vector<int> nh = convertHex(switch_endian(nbl.nether));
    std::vector<int> eh = convertHex(switch_endian(nbl.end));
    buffer[offsets.overworld] = 0x0A;
    buffer[offsets.overworld + 1] = oh[0];
    buffer[offsets.overworld + 2] = oh[1];

    buffer[offsets.nether + 1] = nh[0];
    buffer[offsets.nether + 2] = nh[1];

    buffer[offsets.end + 1] = eh[0];
    buffer[offsets.end + 2] = eh[1];

    buffer[offsets.overworld_bottom + 1] = ob[0];
    buffer[offsets.overworld_bottom + 2] = ob[1];

    std::ofstream out_file(file_path, std::ios::binary);
    out_file.write(reinterpret_cast<const char *>(buffer.data()), buffer.size());
    out_file.close();
    file.close();
}
#pragma clang diagnostic push


extern "C" JNIEXPORT jstring JNICALL
Java_com_zeuroux_mcpepatcher_MainActivity_patchLib(
        JNIEnv *env,
        jobject  context ,
        jstring apkPath, jint overworld, jint end, jint nether, jint overworld_bottom, jstring overworld_offset, jstring end_offset, jstring nether_offset, jstring overworld_bottom_offset) {
    environment = env;
    obj = context;
    std::string input_path = env->GetStringUTFChars(apkPath, nullptr);
    BinaryData data = parse_elf(input_path);
    thread_count = 1;
    BuildLimit_Offsets offsets;
    std::string overworld_offset_str = env->GetStringUTFChars(overworld_offset, nullptr);
    std::string end_offset_str = env->GetStringUTFChars(end_offset, nullptr);
    std::string nether_offset_str = env->GetStringUTFChars(nether_offset, nullptr);
    std::string overworld_bottom_offset_str = env->GetStringUTFChars(overworld_bottom_offset, nullptr);
    if (overworld_offset_str != "-")
    {
        uint64_t overworld_offset_int = std::stoull(overworld_offset_str, nullptr, 16);
        uint64_t end_offset_int = std::stoull(end_offset_str, nullptr, 16);
        uint64_t nether_offset_int = std::stoull(nether_offset_str, nullptr, 16);
        uint64_t overworld_bottom_offset_int = std::stoull(overworld_bottom_offset_str, nullptr, 16);
        offsets.overworld = overworld_offset_int;
        offsets.end = end_offset_int;
        offsets.nether = nether_offset_int;
        offsets.overworld_bottom = overworld_bottom_offset_int;
    }
    else
    {
        Logit(env, context, "Patching Process", "Finding offsets...");
        offsets = find_offsets(data);
        std::stringstream ss;
        ss << "Offsets: " " O:" << std::hex << offsets.overworld << " E:" << std::hex << offsets.end << " N:" << std::hex << offsets.nether << " OB:" << std::hex << offsets.overworld_bottom;
        Logit(env, context, "Patching Process", "Done.");
        Logit(env, context, "Patching Process", ss.str());
    }
    BuildLimit new_build_limit;
    new_build_limit.overworld = overworld;
    new_build_limit.end = end;
    new_build_limit.nether = nether;
    new_build_limit.overworld_bottom = overworld_bottom;
    ALOGI("overworld: %d, end: %d, nether: %d, overworld_bottom: %d", overworld, end, nether, overworld_bottom);
    Logit(env, context, "Patching Process", "Replacing bytes...");
    patch_aarch64(input_path, offsets, new_build_limit);
    std::stringstream ss;
    ss << std::hex << offsets.overworld << std::endl;
    ss << std::hex << offsets.end << std::endl;
    ss << std::hex << offsets.nether << std::endl;
    ss << std::hex << offsets.overworld_bottom;
    return env->NewStringUTF(ss.str().c_str());
}
#pragma clang diagnostic pop