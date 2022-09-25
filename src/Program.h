#pragma once

#include <string>
#include <condition_variable>

#include <IpAddress.h>
#include <PcapLiveDeviceList.h>
#include <DnsLayer.h>

#include <argparse.hpp>

struct Interface {
    std::string name;
    pcpp::PcapLiveDevice* dev = nullptr;
};

struct Targets {
    bool hasExclusions = false;
    bool hasTargets = false;

    std::vector<pcpp::IPv4Address> V4; // IPv4 targets
    std::vector<pcpp::IPv4Address> exclusionsV4; // IPv4s to exclude
    std::vector<pcpp::IPv6Address> V6; // IPv6 targets
    std::vector<pcpp::IPv6Address> exclusionsV6; // IPv6s to exclude
};

struct Arguments
{
    Targets targets;
    pcpp::IPv4Address evilIPv4; // IP Address to poison the cache with
    pcpp::IPv6Address evilIPv6;
    pcpp::MacAddress gatewayMAC;
    pcpp::IPv4Address gatewayIP;
    
    std::string interface;

    uint32_t poisonTtl; // time-to-live for the poisoned responses
    std::vector<uint16_t> ports = { 53, 5353 }; // The port to which DNS requests are sent.

    bool specificDomains = false;
    std::vector<std::string> domains; // domains to poison

    bool poisonIPv6 = false;
};

class Program
{
public:
    Program(const std::string& name, int argc, char* argv[]);
    void Run();

    static const Arguments& GetArgs() {return args;}

private:
    void ParseArguments(int argc, char* argv[]);
    void InitCaptureInterface();
    static void OnPacketCapture(pcpp::RawPacket* packet, pcpp::PcapLiveDevice* dev, void* cookie);

    static bool PoisonDns(const pcpp::DnsLayer& original, pcpp::DnsLayer& poison);
private:
    const std::string name;
    argparse::ArgumentParser parser;
    static Arguments args;

    Interface interface;
    static bool isCapturing;

    std::mutex mtx;
    static std::condition_variable capturingEnded;
};

