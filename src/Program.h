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

struct Arguments
{
    std::vector<pcpp::IPv4Address> targetsV4; // IPv4 targets
    std::vector<pcpp::IPv6Address> targetsV6;
    pcpp::IPv4Address evilIPv4; // IP Address to poison the cache with
    pcpp::IPv6Address evilIPv6;
    
    Interface interface;

    uint32_t poisonTtl; // time-to-live for the poisoned responses
    uint16_t port = 53; // The port to which DNS requests are sent.

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

    static void PoisonDNSLayer(pcpp::DnsLayer& dnsLayer, const pcpp::DnsLayer& originalLayer);
    inline static void PoisonARecord(pcpp::DnsLayer& dnsLayer, pcpp::DnsQuery* const query); // Used for poisoning A records
    inline static void PoisonAAAARecord(pcpp::DnsLayer& dnsLayer, pcpp::DnsQuery* const query); // Used for poisoning AAAA records
private:
    const std::string name;
    argparse::ArgumentParser parser;
    static Arguments args;

    pcpp::PcapLiveDevice* dev;
    static bool isCapturing;

    std::mutex mtx;
    static std::condition_variable capturingEnded;
};

