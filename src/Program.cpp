#include "Program.h"

Program::Program(const std::string& name, int argc, char* argv[])
    : 
    name(name),
    parser(name)
{
    ParseArguments(argc, argv);
    InitCaptureInterface();
}

void Program::ParseArguments(int argc, char* argv[])
{
    parser.add_argument("-t", "--target").required().help("IP Address of the machine whose cache to poison");
    parser.add_argument("-i", "--interface").required().help("Network Interface to use (takes an IP address or a name");
    parser.add_argument("-b", "--bad_ip").required().help("IP Address to inject into the cache. This shold be the address of the server you want to redirect the victim to");

    std::vector<std::string> errors;
    try
    {
        parser.parse_args(argc, argv);

        args.hostAddress = pcpp::IPv4Address(parser.get("--bad_ip"));
        if (!args.hostAddress.isValid())
        {
            errors.push_back("Invalid malicious IP specified!");
        }

        args.interfaceAddress = pcpp::IPv4Address(parser.get("--interface"));
        if (!args.interfaceAddress.isValid())
        {
            args.interfaceName = parser.get("--interface"); // checking for a valid name is done later to keep the code cleaner
        }

        args.targetIP = pcpp::IPv4Address(parser.get("--target"));
        if(!args.targetIP.isValid())
        {
            errors.push_back("Invalid target IP specified!");
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
}