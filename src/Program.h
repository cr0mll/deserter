#pragma once

#include <string>
#include <condition_variable>

#include <IpAddress.h>
#include <PcapLiveDeviceList.h>
#include <DnsLayer.h>


#include <argparse.hpp>


struct Arguments
{
    pcpp::IPv4Address targetIP; // IP Address of the victim
    pcpp::IPv4Address hostAddress; // IP Address to poison the cache with
    pcpp::IPv6Address hostv6Address;
    
    pcpp::IPv4Address interfaceAddress; // IP Address of the interface
    std::string interfaceName; // Name of the interface

    uint32_t poisonTtl; // time-to-live for the poisoned responses

    bool specificDomains = false;
    std::vector<std::string> domains; // domains to poison

    bool keepAlive = false;

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

