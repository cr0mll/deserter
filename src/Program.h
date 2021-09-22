#pragma once

#include <string>

#include <IpAddress.h>
#include <PcapLiveDeviceList.h>

#include <argparse.hpp>


struct Arguments
{
    pcpp::IPv4Address targetIP; // IP Address of the victim
    pcpp::IPv4Address hostAddress; // IP Address to poison the cache with
    
    pcpp::IPv4Address interfaceAddress; // IP Address of the interface
    std::string interfaceName;
};

class Program
{
public:
    Program(const std::string& name, int argc, char* argv[]);
    const Arguments& GetArgs() const {return args;}

private:
    void ParseArguments(int argc, char* argv[]);
    void InitCaptureInterface();

private:
    const std::string name;
    argparse::ArgumentParser parser;
    Arguments args;

    pcpp::PcapLiveDevice* dev;
};

