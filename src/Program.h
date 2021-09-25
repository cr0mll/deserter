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
    
    pcpp::IPv4Address interfaceAddress; // IP Address of the interface
    std::string interfaceName; // Name of the interface

    uint32_t poisonTtl; // time-to-live for the poisoned responses
    bool specificDomains = false;
    std::vector<std::string> domains; // domains to poison
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
    static void PoisonARecord(pcpp::DnsLayer& dnsLayer, pcpp::DnsQuery* const query); // Used for poisoning A records
private:
    const std::string name;
    argparse::ArgumentParser parser;
    static Arguments args;

    pcpp::PcapLiveDevice* dev;
    static bool isCapturing;

    std::mutex mtx;
    static std::condition_variable capturingEnded;
};

